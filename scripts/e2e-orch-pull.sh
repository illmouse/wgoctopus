#!/usr/bin/env bash
# E2E for pull mode: the agent on a real host dials INTO a local orchestrator through
# an `ssh -R` forward (the test host cannot reach this machine directly) and the
# orchestrator reconciles the node only through that reverse tunnel.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HOST=${1:-}
[[ -n $HOST ]] || { printf 'Usage: %s root@HOST\n' "$0" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:--i /home/ill/.ssh/id_rsa -o StrictHostKeyChecking=accept-new}
E2E_BASELINE_FILTER=${E2E_BASELINE_FILTER:-}
E2E_BASELINE_NAT=${E2E_BASELINE_NAT:-}
ORCH=woct-orch-pull-$$
AGENT=woct-agent-pull-$$
VOLUME=woct-pull-state-$$
REMOTEDIR=/opt/woct-pull-e2e-$$
NODENAME=woct-pull-node
TMP=$(mktemp -d)
PASS=0 FAIL=0
FILTER_BEFORE= NAT_BEFORE= CONTAINERS_BEFORE=
TUNNEL_PID=
TOKEN=$(openssl rand -hex 32)
AGENT_TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" >"$TMP/api-token"; chmod 600 "$TMP/api-token"
openssl rand -base64 32 | tr -d '\n' >"$TMP/master-key"; chmod 600 "$TMP/master-key"
ssh-keygen -q -t ed25519 -N '' -C e2e-node -f "$TMP/nodekey"
ssh-keygen -q -t ed25519 -N '' -C e2e-bad -f "$TMP/badkey"
cp "${SSH_KEY:-/home/ill/.ssh/id_rsa}" "$TMP/id_rsa"; chmod 600 "$TMP/id_rsa"
mkdir -p "$TMP/db"

freeport() { local p; for p in $(seq "$1" "$2"); do if ! ss -H -ltn "sport = :$p" | grep -q .; then echo "$p"; return; fi; done; return 1; }
API=$(freeport 18900 18999) || exit 1
PULL=$(freeport 19000 19099) || exit 1
RP=$((28000 + $$ % 1000))

remote() { ssh $SSH_OPTS "$HOST" "bash -s" <<<"$1"; }
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then printf 'PASS %s\n' "$label"; PASS=$((PASS+1)); else printf 'FAIL %s\n' "$label"; FAIL=$((FAIL+1)); docker logs --tail 30 "$ORCH" 2>&1 | sed -E 's/(Bearer |token[=: ]+)[A-Za-z0-9._-]+/\1[REDACTED]/Ig' >&2; fi; }
pyjson() { python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if ($1) else 1)"; }
wait_for() { local i; for i in $(seq 1 "$1"); do if "${@:2}" >/dev/null 2>&1; then return 0; fi; sleep 1; done; return 1; }
agent_state() { remote "curl -fsS -H 'Authorization: Bearer $AGENT_TOKEN' http://127.0.0.1:18080/v1/state"; }
agent_metrics() { remote "curl -fsS -H 'Authorization: Bearer $AGENT_TOKEN' http://127.0.0.1:18080/metrics"; }
node_json() { api "http://127.0.0.1:$API/v1/nodes/$NID"; }
in_sync() {
  node_json | pyjson 'd.get("reconciler",{}).get("state")=="IN_SYNC" and d.get("observed",{}).get("applied_revision")==d.get("desired_revision")'
}
pull_connected() { node_json | pyjson 'd.get("pull_connected") is True'; }
pull_disconnected() { node_json | pyjson 'd.get("pull_connected") is False'; }
agent_peers() {
  agent_state | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.get("state",d); print(sum(len(i.get("peers",[])) for i in d.get("interfaces",[])))'
}
wait_peers() { local want=$1 i; for i in $(seq 1 90); do [[ $(agent_peers 2>/dev/null) == "$want" ]] && return 0; sleep 1; done; return 1; }
events_count() { api "http://127.0.0.1:$API/v1/events?limit=500" | python3 -c "import json,sys; d=json.load(sys.stdin); d=d.get('items',d) if isinstance(d,dict) else d; print(sum(1 for e in d if e.get('kind')=='$1'))"; }
metric() { api "http://127.0.0.1:$API/metrics" | grep -F "$1" | head -1 | awk '{print $NF}'; }
start_agent() {
  remote "docker rm -f $AGENT >/dev/null 2>&1 || true; docker run -d --name $AGENT --network host --cap-add NET_ADMIN --device /dev/net/tun -v $REMOTEDIR/token:/run/token:ro -v $REMOTEDIR/nodekey:/run/nodekey:ro -v $VOLUME:/var/lib/wgoctopus wgoctopus-agent:dev --listen 127.0.0.1:18080 --token-file /run/token --pull-server 127.0.0.1:$RP --pull-user $NODENAME --pull-key-file /run/nodekey --pull-host-key '$FP' >/dev/null"
}
start_orch() {
  docker rm -f "$ORCH" >/dev/null 2>&1
  docker run -d --name "$ORCH" --network host --user "$(id -u):$(id -g)" -e USER="${HOST%@*}" -e LOGNAME="${HOST%@*}" \
    -v "$TMP:/run/e2e:ro" -v "$TMP/db:/var/lib/wgoctopus" \
    -e WGOCTOPUS_MASTER_KEY_FILE=/run/e2e/master-key -e WGOCTOPUS_API_TOKEN_FILE=/run/e2e/api-token \
    -e WGOCTOPUS_TRANSPORT=ssh -e WGOCTOPUS_SSH_KEY_FILE=/run/e2e/id_rsa \
    -e WGOCTOPUS_SSH_KNOWN_HOSTS=/var/lib/wgoctopus/known_hosts -e WGOCTOPUS_SSH_TOFU=true -e WGOCTOPUS_SSH_CONNECT_TIMEOUT=5 \
    -e WGOCTOPUS_PULL_LISTEN="127.0.0.1:$PULL" -e WGOCTOPUS_PULL_HOST_KEY_FILE=/var/lib/wgoctopus/pull_host_key \
    -e WGOCTOPUS_RECONCILE_INTERVAL=5 -e WGOCTOPUS_RECONCILE_BLOCKED_RECHECK=10 -e WGOCTOPUS_RECONCILER_ENABLED=true -e WGOCTOPUS_AUTO_MIGRATE=true \
    -e WGOCTOPUS_FAILOVER_MODE=off -e WGOCTOPUS_API_HOST=0.0.0.0 -e WGOCTOPUS_API_PORT="$API" \
    wgoctopus-orchestrator:dev >/dev/null || return 1
  wait_for 60 curl -fsS "http://127.0.0.1:$API/readyz"
}
cleanup() {
  set +e
  docker logs "$ORCH" 2>&1 | tail -n 30 | sed -E 's/(Bearer |token[=: ]+)[A-Za-z0-9._-]+/\1[REDACTED]/Ig' >&2
  [[ -n $TUNNEL_PID ]] && kill "$TUNNEL_PID" 2>/dev/null
  docker rm -f "$ORCH" >/dev/null 2>&1
  remote "docker rm -f $AGENT >/dev/null 2>&1 || true; docker volume rm $VOLUME >/dev/null 2>&1 || true; ip link del woct0 2>/dev/null || true; for t in filter nat; do for c in WGOCT_FWD WGOCT_NAT; do while iptables -t \$t -S 2>/dev/null | grep -q -- \"-j \$c\"; do iptables -t \$t -D FORWARD -j \$c 2>/dev/null || iptables -t \$t -D POSTROUTING -j \$c 2>/dev/null || break; done; iptables -t \$t -F \$c 2>/dev/null || true; iptables -t \$t -X \$c 2>/dev/null || true; done; done; rm -rf $REMOTEDIR" >/dev/null 2>&1
  if [[ -n $FILTER_BEFORE ]]; then
    local f n c
    f=$(remote 'iptables -S | wc -l' 2>/dev/null); n=$(remote 'iptables -t nat -S | wc -l' 2>/dev/null)
    [[ $f == "$FILTER_BEFORE" && $n == "$NAT_BEFORE" ]] && { printf 'PASS host firewall baseline %s/%s\n' "$f" "$n"; PASS=$((PASS+1)); } || { printf 'FAIL host firewall baseline %s/%s (before %s/%s)\n' "$f" "$n" "$FILTER_BEFORE" "$NAT_BEFORE"; FAIL=$((FAIL+1)); }
    c=$(remote 'docker ps -q --no-trunc | sort' 2>/dev/null)
    [[ $c == "$CONTAINERS_BEFORE" ]] && { printf 'PASS host container IDs unchanged\n'; PASS=$((PASS+1)); } || { printf 'FAIL host container IDs changed\n'; FAIL=$((FAIL+1)); }
    check 'test interface absent' remote 'ip link show woct0 >/dev/null 2>&1 && exit 1 || exit 0'
  fi
  rm -rf "$TMP"
  printf '\nE2E orchestrator pull: %d PASS, %d FAIL\n' "$PASS" "$FAIL"
  [[ $FAIL == 0 ]]
}
trap cleanup EXIT

command -v jq >/dev/null || { printf 'jq is required locally\n'; exit 1; }
docker image inspect wgoctopus-agent:dev >/dev/null 2>&1 || make -C "$ROOT" agent-image || exit 1
docker image inspect wgoctopus-orchestrator:dev >/dev/null 2>&1 || make -C "$ROOT" orch-image || exit 1
FILTER_BEFORE=$(remote 'iptables -S | wc -l') || exit 1
NAT_BEFORE=$(remote 'iptables -t nat -S | wc -l') || exit 1
CONTAINERS_BEFORE=$(remote 'docker ps -q --no-trunc | sort') || exit 1
[[ -z $E2E_BASELINE_FILTER || $FILTER_BEFORE == "$E2E_BASELINE_FILTER" ]] || { printf 'FAIL unexpected filter baseline\n'; exit 1; }
[[ -z $E2E_BASELINE_NAT || $NAT_BEFORE == "$E2E_BASELINE_NAT" ]] || { printf 'FAIL unexpected nat baseline\n'; exit 1; }
AGENT_IMAGE_BEFORE=$(remote "docker image inspect -f '{{.Id}}' wgoctopus-agent:dev 2>/dev/null || true")
LOCAL_AGENT_IMAGE=$(docker image inspect -f '{{.Id}}' wgoctopus-agent:dev)
if [[ ${E2E_SKIP_SHIP:-0} != 1 && $LOCAL_AGENT_IMAGE != "$AGENT_IMAGE_BEFORE" ]]; then
  "$ROOT/scripts/ship-image.sh" wgoctopus-agent:dev "$HOST" || exit 1
fi

start_orch || { docker logs "$ORCH" >&2; exit 1; }
check 'orchestrator ready with pull listener' api "http://127.0.0.1:$API/v1/pull"
api "http://127.0.0.1:$API/v1/pull" | pyjson 'd["enabled"] is True' || { printf 'FAIL pull disabled\n'; exit 1; }
FP=$(api "http://127.0.0.1:$API/v1/pull" | jq -r .host_key_fingerprint)
[[ $FP == SHA256:* ]] || { printf 'FAIL no host key fingerprint\n'; exit 1; }

# Reverse path: remote 127.0.0.1:$RP -> local pull listener.
ssh $SSH_OPTS -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 -R "127.0.0.1:$RP:127.0.0.1:$PULL" "$HOST" &
TUNNEL_PID=$!
sleep 3
check 'ssh -R forward is up' kill -0 "$TUNNEL_PID"

NODEKEY_B64=$(base64 -w0 "$TMP/nodekey")
remote "mkdir -p $REMOTEDIR; chmod 700 $REMOTEDIR; printf '%s' '$AGENT_TOKEN' >$REMOTEDIR/token; chmod 600 $REMOTEDIR/token; printf '%s' '$NODEKEY_B64' | base64 -d >$REMOTEDIR/nodekey; chmod 600 $REMOTEDIR/nodekey; docker volume rm $VOLUME >/dev/null 2>&1 || true; docker volume create $VOLUME >/dev/null; ip link del woct0 2>/dev/null || true" || exit 1

instance=$(api -d '{"name":"woct0","listen_port":23440,"address":"10.222.0.1/24"}' "http://127.0.0.1:$API/v1/instances") || exit 1
IID=$(jq -r .id <<<"$instance")
PUBKEY=$(cut -d' ' -f1,2 "$TMP/nodekey.pub")
node=$(api -d "{\"name\":\"$NODENAME\",\"mgmt_mode\":\"pull\",\"pull_public_key\":\"$PUBKEY\",\"agent_port\":18080,\"agent_token\":\"$AGENT_TOKEN\"}" "http://127.0.0.1:$API/v1/nodes") || exit 1
NID=$(jq -r .id <<<"$node")
api -X PUT -d '{"role":"active"}' "http://127.0.0.1:$API/v1/instances/$IID/placements/$NID" >/dev/null || exit 1
PID1=$(api -d '{"name":"peer-one"}' "http://127.0.0.1:$API/v1/instances/$IID/peers" | jq -r .id) || exit 1
check 'node without tunnel is not connected' pull_disconnected

# Wrong key must be denied before the real agent exists.
ssh -i "$TMP/badkey" -p "$PULL" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "$NODENAME@127.0.0.1" true >/dev/null 2>&1
check 'wrong key denied and counted' bash -c "[[ \$(curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$API/v1/pull | jq -r .counters.connections_denied) -ge 1 ]]"

start_agent || exit 1
check 'agent connects through reverse tunnel' wait_for 60 pull_connected
check 'node reconciled only through the tunnel' wait_for 90 in_sync
check 'interface, address, UDP port and tagged rules' remote "ip link show woct0 | grep -q UP && ip -4 addr show woct0 | grep -q '10.222.0.1/24' && ss -ulnp | grep -q ':23440' && iptables -S | grep -q 'wgoct:'"
check 'agent has desired peer' wait_peers 1
check 'agent reports pull connected' bash -c "ssh $SSH_OPTS $HOST \"curl -fsS -H 'Authorization: Bearer $AGENT_TOKEN' http://127.0.0.1:18080/metrics\" | grep -q '^wgoctopus_pull_connected 1'"
check 'node.pull_connected event recorded' test "$(events_count node.pull_connected)" -ge 1
check 'metric pull_tunnel_up is 1' test "$(metric "wgoctopus_pull_tunnel_up{node=\"$NODENAME\"}")" = 1

# Changes flow through the tunnel.
PID2=$(api -d '{"name":"peer-two"}' "http://127.0.0.1:$API/v1/instances/$IID/peers" | jq -r .id)
check 'new peer converges through tunnel' wait_peers 2
api -X DELETE "http://127.0.0.1:$API/v1/peers/$PID2" >/dev/null
check 'peer removal converges through tunnel' wait_peers 1

# Orchestrator restart: the agent must reconnect on its own and the pinned host key must be unchanged.
CONNECTED_BEFORE=$(events_count node.pull_connected)
docker restart "$ORCH" >/dev/null
wait_for 60 curl -fsS "http://127.0.0.1:$API/readyz"
check 'host key fingerprint unchanged after restart' test "$(api "http://127.0.0.1:$API/v1/pull" | jq -r .host_key_fingerprint)" = "$FP"
check 'agent reconnects after orchestrator restart' wait_for 120 pull_connected
check 'in sync again after reconnect' wait_for 90 in_sync
check 'second connect event recorded' test "$(events_count node.pull_connected)" -gt "$CONNECTED_BEFORE"

# Agent restart restores the tunnel too.
remote "docker restart $AGENT >/dev/null"
check 'agent reconnects after agent restart' wait_for 120 pull_connected
check 'in sync after agent restart' wait_for 90 in_sync

# auto mode: SSH push is impossible (closed port) so the orchestrator must fall back to the tunnel.
api -X PATCH -d '{"mgmt_mode":"auto","ssh_host":"127.0.0.1","ssh_port":1,"ssh_user":"root"}' "http://127.0.0.1:$API/v1/nodes/$NID" >/dev/null
PID3=$(api -d '{"name":"peer-three"}' "http://127.0.0.1:$API/v1/instances/$IID/peers" | jq -r .id)
check 'auto mode falls back to pull tunnel' wait_peers 2
check 'in sync in auto mode' wait_for 90 in_sync

# Tunnel loss is reported: stop the reverse forward; the node must become unreachable.
kill "$TUNNEL_PID" 2>/dev/null; wait "$TUNNEL_PID" 2>/dev/null; TUNNEL_PID=
api -X PATCH -d '{"mgmt_mode":"pull"}' "http://127.0.0.1:$API/v1/nodes/$NID" >/dev/null
api -d '{"name":"peer-four"}' "http://127.0.0.1:$API/v1/instances/$IID/peers" >/dev/null
node_unreachable() { node_json | pyjson 'd.get("reconciler",{}).get("state")!="IN_SYNC" or d.get("observed",{}).get("applied_revision")!=d.get("desired_revision")'; }
check 'change not delivered without tunnel (no silent ssh)' wait_for 60 node_unreachable
ssh $SSH_OPTS -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 -R "127.0.0.1:$RP:127.0.0.1:$PULL" "$HOST" &
TUNNEL_PID=$!
check 'recovers when tunnel returns' wait_for 180 in_sync
check 'agent has all peers after recovery' wait_peers 3

# Remove the placement through the tunnel and verify the host is cleaned by the agent.
api -X DELETE "http://127.0.0.1:$API/v1/instances/$IID/placements/$NID" >/dev/null
check 'placement removal converges' wait_for 90 in_sync
check 'placement removal removes woct0' remote '! ip link show woct0 >/dev/null 2>&1'
