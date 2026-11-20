#!/usr/bin/env bash
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HOST=${1:-}
[[ -n $HOST ]] || { printf 'Usage: %s root@HOST\n' "$0" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:--i /home/ill/.ssh/id_rsa -o StrictHostKeyChecking=accept-new}
E2E_PROTECTED_IDS=${E2E_PROTECTED_IDS:-}
E2E_BASELINE_FILTER=${E2E_BASELINE_FILTER:-}
E2E_BASELINE_NAT=${E2E_BASELINE_NAT:-}
PORT=23440
ORCH=woct-orch-e2e-$$
AGENT=woct-agent-e2e-$$
VOLUME=woct-orch-e2e-state-$$
REMOTEDIR=/opt/woct-test-e2e-$$
TMP=$(mktemp -d)
PASS=0 FAIL=0
FILTER_BEFORE= NAT_BEFORE= CONTAINERS_BEFORE= AGENT_IMAGE_BEFORE=
TOKEN=$(openssl rand -hex 32)
AGENT_TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" >"$TMP/api-token"; chmod 600 "$TMP/api-token"
printf '%s' "$AGENT_TOKEN" >"$TMP/agent-token"; chmod 600 "$TMP/agent-token"
openssl rand -base64 32 | tr -d '\n' >"$TMP/master-key"; chmod 600 "$TMP/master-key"
cp "${SSH_KEY:-/home/ill/.ssh/id_rsa}" "$TMP/id_rsa"; chmod 600 "$TMP/id_rsa"
mkdir -p "$TMP/db"

remote() { ssh $SSH_OPTS "$HOST" "bash -s" <<<"$1"; }
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then printf 'PASS %s\n' "$label"; PASS=$((PASS+1)); else printf 'FAIL %s\n' "$label"; FAIL=$((FAIL+1)); if [[ -n $ORCH ]]; then docker logs --tail 40 "$ORCH" 2>&1 | sed -E 's/(Bearer |token[=: ]+)[A-Za-z0-9._-]+/\1[REDACTED]/Ig' >&2; fi; fi; }
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
status_ok() {
  local i json
  for i in $(seq 1 90); do
    json=$(api "http://127.0.0.1:$API/v1/status" 2>/dev/null || true)
    if python3 -c 'import json,sys; d=json.load(sys.stdin); s=d.get("nodes_by_state",{}); sys.exit(0 if s.get("IN_SYNC",0)>0 and not any(s.get(k,0) for k in ("BLOCKED_DANGEROUS","BLOCKED_REVISION_AHEAD","BLOCKED_INVALID","BLOCKED_AUTH","UNREACHABLE")) else 1)' <<<"$json" 2>/dev/null; then
      node=$(api "http://127.0.0.1:$API/v1/nodes/$NID" 2>/dev/null || true)
      python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("reconciler",{}).get("state")=="IN_SYNC" and d.get("observed",{}).get("applied_revision")==d.get("desired_revision") else 1)' <<<"$node" 2>/dev/null && return 0
    fi
    sleep 1
  done
  return 1
}
status_blocked_ahead() {
  local json i
  for i in $(seq 1 60); do
    json=$(api "http://127.0.0.1:$API/v1/status" 2>/dev/null || true)
    python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("nodes_by_state",{}).get("BLOCKED_REVISION_AHEAD",0)>0 else 1)' <<<"$json" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}
agent_state() { remote "curl -fsS -H 'Authorization: Bearer $AGENT_TOKEN' http://127.0.0.1:18080/v1/state"; }
outage_reported() {
  local json
  json=$(api "http://127.0.0.1:$API/v1/nodes/$NID" 2>/dev/null) || return 1
  python3 -c 'import json,sys; d=json.load(sys.stdin); x=d.get("observed",{}).get("last_error") or d.get("reconciler",{}).get("state",""); sys.exit(0 if x and x != "IN_SYNC" else 1)' <<<"$json"
}
wait_agent_count() {
  local count=$1 i state got
  for i in $(seq 1 90); do
    state=$(agent_state 2>/dev/null || true)
    got=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(len(i.get("peers",[])) for i in d.get("state",{}).get("interfaces",d.get("interfaces",[]))))' <<<"$state" 2>/dev/null || true)
    [[ $got == "$count" ]] && return 0
    sleep 1
  done
  return 1
}
cleanup() {
  set +e
  if [[ -n $ORCH ]]; then docker logs "$ORCH" 2>&1 | tail -n 40 | sed -E 's/(Bearer |token[=: ]+)[A-Za-z0-9._-]+/\1[REDACTED]/Ig' >&2; fi
  docker rm -f "$ORCH" >/dev/null 2>&1
  remote "docker rm -f $AGENT >/dev/null 2>&1 || true; docker volume rm $VOLUME >/dev/null 2>&1 || true; ip link del woct0 2>/dev/null || true; for t in filter nat; do for c in WGOCT_FWD WGOCT_NAT; do while iptables -t \$t -S 2>/dev/null | grep -q -- \"-j \$c\"; do iptables -t \$t -D FORWARD -j \$c 2>/dev/null || iptables -t \$t -D POSTROUTING -j \$c 2>/dev/null || break; done; iptables -t \$t -F \$c 2>/dev/null || true; iptables -t \$t -X \$c 2>/dev/null || true; done; done; rm -rf $REMOTEDIR" >/dev/null 2>&1
  rm -rf "$TMP"
  if [[ -n $FILTER_BEFORE ]]; then
    local f n c
    f=$(remote 'iptables -S | wc -l' 2>/dev/null); n=$(remote 'iptables -t nat -S | wc -l' 2>/dev/null)
    [[ $f == "$FILTER_BEFORE" && $n == "$NAT_BEFORE" ]] && { printf 'PASS host firewall baseline %s/%s\n' "$f" "$n"; PASS=$((PASS+1)); } || { printf 'FAIL host firewall baseline %s/%s (before %s/%s)\n' "$f" "$n" "$FILTER_BEFORE" "$NAT_BEFORE"; FAIL=$((FAIL+1)); }
    c=$(remote 'docker ps -q --no-trunc | sort' 2>/dev/null)
    [[ $c == "$CONTAINERS_BEFORE" ]] && { printf 'PASS host container IDs unchanged\n'; PASS=$((PASS+1)); } || { printf 'FAIL host container IDs changed\n'; FAIL=$((FAIL+1)); }
    check 'test interface absent' remote 'ip link show woct0 >/dev/null 2>&1 && exit 1 || exit 0'
  fi
  printf '\nE2E orchestrator: %d PASS, %d FAIL\n' "$PASS" "$FAIL"
  [[ $FAIL == 0 ]]
}
trap cleanup EXIT

command -v jq >/dev/null || { printf 'jq is required locally\n'; exit 1; }
mkdir -p "$TMP/db"
API=18900
for p in $(seq 18900 18999); do if ! ss -H -ltn "sport = :$p" | grep -q .; then API=$p; break; fi; done
docker image inspect wgoctopus-agent:dev >/dev/null 2>&1 || make -C "$ROOT" agent-image || exit 1
docker image inspect wgoctopus-orchestrator:dev >/dev/null 2>&1 || make -C "$ROOT" orch-image || exit 1
FILTER_BEFORE=$(remote 'iptables -S | wc -l') || exit 1
NAT_BEFORE=$(remote 'iptables -t nat -S | wc -l') || exit 1
CONTAINERS_BEFORE=$(remote 'docker ps -q --no-trunc | sort') || exit 1
[[ -z $E2E_BASELINE_FILTER || $FILTER_BEFORE == "$E2E_BASELINE_FILTER" ]] || { printf 'FAIL unexpected filter baseline\n'; exit 1; }
[[ -z $E2E_BASELINE_NAT || $NAT_BEFORE == "$E2E_BASELINE_NAT" ]] || { printf 'FAIL unexpected nat baseline\n'; exit 1; }
for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { printf 'FAIL configured protected container missing\n'; exit 1; }; done
AGENT_IMAGE_BEFORE=$(remote "docker image inspect -f '{{.Id}}' wgoctopus-agent:dev 2>/dev/null || true")
LOCAL_AGENT_IMAGE=$(docker image inspect -f '{{.Id}}' wgoctopus-agent:dev)
if [[ ${E2E_SKIP_SHIP:-0} != 1 ]] && [[ $LOCAL_AGENT_IMAGE != "$AGENT_IMAGE_BEFORE" ]]; then
  "$ROOT/scripts/ship-image.sh" wgoctopus-agent:dev "$HOST" || exit 1
fi
remote "mkdir -p $REMOTEDIR; chmod 700 $REMOTEDIR; printf '%s' '$AGENT_TOKEN' >$REMOTEDIR/token; chmod 600 $REMOTEDIR/token; docker rm -f $AGENT >/dev/null 2>&1 || true; docker volume rm $VOLUME >/dev/null 2>&1 || true; ip link del woct0 2>/dev/null || true; docker volume create $VOLUME >/dev/null; docker run -d --name $AGENT --network host --cap-add NET_ADMIN --device /dev/net/tun -v $REMOTEDIR/token:/run/token:ro -v $VOLUME:/var/lib/wgoctopus wgoctopus-agent:dev --listen 127.0.0.1:18080 --token-file /run/token >/dev/null" || exit 1
docker run -d --name "$ORCH" --network host --user "$(id -u):$(id -g)" -e USER="${HOST%@*}" -e LOGNAME="${HOST%@*}" -v "$TMP:/run/e2e:ro" -v "$TMP/db:/var/lib/wgoctopus" \
  -e WGOCTOPUS_MASTER_KEY_FILE=/run/e2e/master-key -e WGOCTOPUS_API_TOKEN_FILE=/run/e2e/api-token \
  -e WGOCTOPUS_TRANSPORT=ssh -e WGOCTOPUS_SSH_KEY_FILE=/run/e2e/id_rsa \
  -e WGOCTOPUS_SSH_KNOWN_HOSTS=/var/lib/wgoctopus/known_hosts -e WGOCTOPUS_SSH_TOFU=true \
  -e WGOCTOPUS_RECONCILE_INTERVAL=5 -e WGOCTOPUS_RECONCILE_BLOCKED_RECHECK=10 -e WGOCTOPUS_RECONCILER_ENABLED=true -e WGOCTOPUS_AUTO_MIGRATE=true \
  -e WGOCTOPUS_CLIENT_ENDPOINT_HOST="${HOST#*@}" -e WGOCTOPUS_API_HOST=0.0.0.0 -e WGOCTOPUS_API_PORT="$API" \
  wgoctopus-orchestrator:dev >/dev/null || exit 1
ready=0
for i in $(seq 1 60); do if curl -fsS "http://127.0.0.1:$API/readyz" >/dev/null 2>&1; then ready=1; break; fi; sleep 1; done
if (( ! ready )); then docker logs "$ORCH" >&2; exit 1; fi
check 'orchestrator ready' curl -fsS "http://127.0.0.1:$API/readyz"

auth=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')
instance=$(curl -fsS "${auth[@]}" -d '{"name":"woct0","listen_port":23440,"address":"10.222.0.1/24"}' "http://127.0.0.1:$API/v1/instances") || exit 1
IID=$(jq -r .id <<<"$instance")
node=$(curl -fsS "${auth[@]}" -d "{\"name\":\"woct-test-node\",\"ssh_host\":\"${HOST#*@}\",\"ssh_user\":\"${HOST%@*}\",\"agent_port\":18080,\"agent_token\":\"$AGENT_TOKEN\"}" "http://127.0.0.1:$API/v1/nodes") || exit 1
NID=$(jq -r .id <<<"$node")
curl -fsS "${auth[@]}" -X PUT -d '{"role":"active"}' "http://127.0.0.1:$API/v1/instances/$IID/placements/$NID" >/dev/null || exit 1
P1=$(curl -fsS "${auth[@]}" -d '{"name":"peer-one"}' "http://127.0.0.1:$API/v1/instances/$IID/peers") || exit 1
P2=$(curl -fsS "${auth[@]}" -d '{"name":"peer-two"}' "http://127.0.0.1:$API/v1/instances/$IID/peers") || exit 1
PID1=$(jq -r .id <<<"$P1"); PID2=$(jq -r .id <<<"$P2")
if status_ok; then
  check 'initial reconciliation at desired revision' true
else
  check 'initial reconciliation at desired revision' false
  node_diag=$(api "http://127.0.0.1:$API/v1/nodes/$NID" 2>/dev/null || true)
  printf 'DIAG node status: %s\n' "$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({"desired_revision":d.get("desired_revision"),"observed":d.get("observed"),"reconciler":d.get("reconciler")},sort_keys=True))' <<<"$node_diag" 2>/dev/null || printf 'unavailable')"
  remote "docker logs --tail 30 $AGENT 2>&1" >&2
fi
check 'interface, address, UDP port and tagged rules' remote "ip link show woct0 | grep -q UP && ip -4 addr show woct0 | grep -q '10.222.0.1/24' && ss -ulnp | grep -q ':23440' && iptables -S | grep -q 'wgoct:'"
check 'agent has both desired peers' wait_agent_count 2
result=$(curl -fsS "${auth[@]}" -X POST -d '{"confirm":true}' "http://127.0.0.1:$API/v1/nodes/$NID/apply-dangerous" 2>/dev/null || true)
check 'apply-dangerous on in-sync node returns up_to_date' python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("status")=="up_to_date" else 1)' <<<"$result"
config=$(api "http://127.0.0.1:$API/v1/peers/$PID1/config")
check 'peer configuration returned' test -n "$config"
curl -fsS "${auth[@]}" -X DELETE "http://127.0.0.1:$API/v1/peers/$PID2" >/dev/null || exit 1
check 'peer deletion converges to one peer' wait_agent_count 1
curl -fsS "${auth[@]}" -X PATCH -d '{"mtu":1380}' "http://127.0.0.1:$API/v1/instances/$IID" >/dev/null || exit 1
check 'MTU patch converges' status_ok

revision_before=$(agent_state | jq -r .revision)
docker restart "$ORCH" >/dev/null
for i in $(seq 1 60); do curl -fsS "http://127.0.0.1:$API/readyz" >/dev/null 2>&1 && break; sleep 1; done
if status_ok; then
  check 'restart preserves state and reconciles' true
else
  check 'restart preserves state and reconciles' false
  docker inspect -f 'DIAG orchestrator running={{.State.Running}} exit={{.State.ExitCode}} error={{.State.Error}}' "$ORCH" >&2 || true
  docker logs --tail 40 "$ORCH" >&2 || true
fi
revision_after=$(agent_state | jq -r .revision)
check 'revision does not move backward' test "$revision_after" -ge "$revision_before"
remote "docker stop $AGENT >/dev/null"
sleep 8
check 'agent outage reported' outage_reported
remote "docker start $AGENT >/dev/null"
check 'agent recovers' status_ok

# Kill the daemon inside the agent; require an actual replacement PID and continued convergence.
PID_OLD=$(remote "docker top $AGENT -eo pid,comm | awk '\$2==\"amneziawg-go\"{print \$1;exit}'")
remote "docker exec $AGENT sh -c 'for p in /proc/[0-9]*; do read c <\$p/comm; [ \"\$c\" = amneziawg-go ] && kill -9 \${p##*/}; done; true'"
PID_NEW=
for i in $(seq 1 60); do PID_NEW=$(remote "docker top $AGENT -eo pid,comm | awk '\$2==\"amneziawg-go\"{print \$1;exit}'"); [[ -n $PID_NEW && $PID_NEW != "$PID_OLD" ]] && break; sleep 1; done
check 'daemon restarted with a new PID' test -n "$PID_NEW" -a "$PID_NEW" != "$PID_OLD"
check 'orchestrator remains in sync after daemon restart' status_ok

# Removing a placement is not a dangerous config change: it converges normally.
printf 'SKIP dangerous flow: not reachable via API (covered by unit tests)\n'
check 'placement removal accepted' curl -fsS "${auth[@]}" -X DELETE "http://127.0.0.1:$API/v1/instances/$IID/placements/$NID"
check 'placement removal converges without block' status_ok
check 'placement removal removes woct0' remote '! ip link show woct0 >/dev/null 2>&1'
check 'placement restored' curl -fsS "${auth[@]}" -X PUT -d '{"role":"active"}' "http://127.0.0.1:$API/v1/instances/$IID/placements/$NID"
check 're-placement converges' status_ok
check 'woct0 restored after re-placement' remote 'ip link show woct0 >/dev/null 2>&1'

# Valid remote-ahead state: preserve content but advance revision, then verify block before volume reset recovery.
STATE=$(agent_state)
REMOTE_REV=$(( $(jq -r .revision <<<"$STATE") + 100 ))
BODY=$(jq -c --argjson r "$REMOTE_REV" '.state + {revision:$r}' <<<"$STATE")
check 'remote-ahead state installed' remote "printf '%s' '$BODY' >/tmp/wgoct-ahead.json; curl -fsS -X PUT -H 'Authorization: Bearer $AGENT_TOKEN' -H 'Content-Type: application/json' --data-binary @/tmp/wgoct-ahead.json http://127.0.0.1:18080/v1/state >/dev/null; rm -f /tmp/wgoct-ahead.json"
check 'remote-ahead state is blocked as REVISION_AHEAD' status_blocked_ahead
sleep 12
AFTER_AHEAD=$(agent_state | jq -r .revision)
check 'remote-ahead agent revision is not overwritten' test "$AFTER_AHEAD" -eq "$REMOTE_REV"
check 'fresh agent volume recreated' remote "docker rm -f $AGENT >/dev/null; docker volume rm $VOLUME >/dev/null; docker volume create $VOLUME >/dev/null; docker run -d --name $AGENT --network host --cap-add NET_ADMIN --device /dev/net/tun -v $REMOTEDIR/token:/run/token:ro -v $VOLUME:/var/lib/wgoctopus wgoctopus-agent:dev --listen 127.0.0.1:18080 --token-file /run/token >/dev/null"
check 'fresh agent volume recovers at orchestrator revision' status_ok
check 'woct0 restored after fresh volume recovery' remote 'ip link show woct0 | grep -q UP'
check 'peers restored after fresh volume recovery' wait_agent_count 1
