#!/usr/bin/env bash
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HOST=${1:-}
[[ -n $HOST ]] || { printf 'Usage: %s root@HOST\n' "$0" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:-"-i $HOME/.ssh/id_rsa -o StrictHostKeyChecking=accept-new"}
E2E_PROTECTED_IDS=${E2E_PROTECTED_IDS:-}
E2E_SKIP_SHIP=${E2E_SKIP_SHIP:-0}
SUFFIX=$$
API=; ORCH=woct-orch-hop-$SUFFIX; AGENT=woct-agent-hop-$SUFFIX
VOLUME=woct-orch-hop-state-$SUFFIX; DIR=/opt/woct-orch-hop-$SUFFIX
PORT=23551; AGENT_PORT=; TMP=$(mktemp -d)
PASS=0 FAIL=0 SKIP=0 GUARDED=0
FILTER_BEFORE= NAT_BEFORE= CONTAINERS_BEFORE= ALL_CONTAINERS_BEFORE= VOLUMES_BEFORE=
TOKEN=$(openssl rand -hex 32); AGENT_TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" >"$TMP/api-token"; chmod 600 "$TMP/api-token"
printf '%s' "$AGENT_TOKEN" >"$TMP/agent-token"; chmod 600 "$TMP/agent-token"
openssl rand -base64 32 | tr -d '\n' >"$TMP/master-key"; chmod 600 "$TMP/master-key"
cp "${SSH_KEY:-$HOME/.ssh/id_rsa}" "$TMP/id_rsa"; chmod 600 "$TMP/id_rsa"
mkdir -p "$TMP/db"
remote() { ssh $SSH_OPTS "$HOST" bash -s <<<"$1"; }
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then printf 'PASS %s\n' "$label"; PASS=$((PASS+1)); else printf 'FAIL %s\n' "$label"; FAIL=$((FAIL+1)); fi; }
skip() { printf 'SKIP %s\n' "$1"; SKIP=$((SKIP+1)); }
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
node_json() { api "http://127.0.0.1:$API/v1/nodes/$HID"; }
wait_sync() {
  local i d
  for i in $(seq 1 90); do
    d=$(node_json 2>/dev/null || true)
    if python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get("reconciler",{}).get("state")=="IN_SYNC" and d.get("observed",{}).get("applied_revision")==d.get("desired_revision") else 1)' <<<"$d" 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}
cleanup() {
  set +e
  if [[ $GUARDED == 1 ]]; then
    remote "state=\$(curl -fsS -H 'Authorization: Bearer $AGENT_TOKEN' http://127.0.0.1:$AGENT_PORT/v1/state 2>/dev/null || true)
      if [ -n \"\$state\" ]; then rev=\$(printf '%s' \"\$state\" | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"revision\"]+1)' 2>/dev/null); printf '{\"revision\":%s,\"interfaces\":[]}' \"\$rev\" >/tmp/e2e-orch-hop-empty.json; curl -fsS -X PUT -H 'Authorization: Bearer $AGENT_TOKEN' -H 'Content-Type: application/json' --data-binary @/tmp/e2e-orch-hop-empty.json http://127.0.0.1:$AGENT_PORT/v1/state >/dev/null 2>&1 || true; rm -f /tmp/e2e-orch-hop-empty.json; fi
      docker rm -f '$AGENT' >/dev/null 2>&1 || true
      for table in nat filter; do for chain in WGOCT_HOP_DNAT WGOCT_HOP_SNAT WGOCT_HOP_FWD; do
        for parent in PREROUTING OUTPUT POSTROUTING FORWARD; do
          while iptables -t \$table -C \$parent -j \$chain 2>/dev/null; do iptables -t \$table -D \$parent -j \$chain || break; done
        done
        iptables -t \$table -F \$chain 2>/dev/null || true; iptables -t \$table -X \$chain 2>/dev/null || true
      done; done
      docker volume rm '$VOLUME' >/dev/null 2>&1 || true; rm -rf '$DIR'"
  fi
  [[ -z $ORCH ]] || docker rm -f "$ORCH" >/dev/null 2>&1
  if [[ -n $FILTER_BEFORE ]]; then
    local f n c ac v
    f=$(remote 'iptables -S | wc -l'); n=$(remote 'iptables -t nat -S | wc -l')
    [[ $f == "$FILTER_BEFORE" && $n == "$NAT_BEFORE" ]] && { printf 'PASS firewall baseline restored (%s/%s)\n' "$f" "$n"; PASS=$((PASS+1)); } || { printf 'FAIL firewall baseline restored (%s/%s; expected %s/%s)\n' "$f" "$n" "$FILTER_BEFORE" "$NAT_BEFORE"; FAIL=$((FAIL+1)); }
    c=$(remote 'docker ps -q --no-trunc | sort'); ac=$(remote 'docker ps -aq --no-trunc | sort'); v=$(remote 'docker volume ls -q | sort')
    [[ $c == "$CONTAINERS_BEFORE" && $ac == "$ALL_CONTAINERS_BEFORE" && $v == "$VOLUMES_BEFORE" ]] && { printf 'PASS container IDs and volumes restored\n'; PASS=$((PASS+1)); } || { printf 'FAIL container IDs or volumes changed\n'; FAIL=$((FAIL+1)); }
    remote "test ! -e '$DIR'" && { printf 'PASS state directory removed\n'; PASS=$((PASS+1)); } || { printf 'FAIL state directory remains\n'; FAIL=$((FAIL+1)); }
    for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { printf 'FAIL protected container missing\n'; FAIL=$((FAIL+1)); }; done
    remote 'printf "Host cleanup evidence: filter=%s nat=%s\n" "$(iptables -S | wc -l)" "$(iptables -t nat -S | wc -l)"; docker ps -a --no-trunc; docker volume ls; ls -ld /opt/woct-orch-hop-* 2>/dev/null || true'
  fi
  rm -rf "$TMP"
  printf 'Summary: %d PASS, %d FAIL, %d SKIP\n' "$PASS" "$FAIL" "$SKIP"
  [[ $FAIL == 0 ]]
}
trap cleanup EXIT

command -v jq >/dev/null || { printf 'jq is required locally\n'; exit 1; }
for p in $(seq 18900 18999); do if ! ss -H -ltn "sport = :$p" | grep -q .; then API=$p; break; fi; done
[[ -n $API ]] || { printf 'No local API port available\n'; exit 1; }
docker image inspect wgoctopus-agent:dev >/dev/null 2>&1 || make -C "$ROOT" agent-image || exit 1
docker image inspect wgoctopus-orchestrator:dev >/dev/null 2>&1 || make -C "$ROOT" orch-image || exit 1
FILTER_BEFORE=$(remote 'iptables -S | wc -l') || exit 1
NAT_BEFORE=$(remote 'iptables -t nat -S | wc -l') || exit 1
CONTAINERS_BEFORE=$(remote 'docker ps -q --no-trunc | sort') || exit 1
ALL_CONTAINERS_BEFORE=$(remote 'docker ps -aq --no-trunc | sort') || exit 1
VOLUMES_BEFORE=$(remote 'docker volume ls -q | sort') || exit 1
for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { printf 'FAIL configured protected container missing\n'; exit 1; }; done
remote "test ! -e '$DIR' && ! docker inspect '$AGENT' >/dev/null 2>&1 && ! docker volume inspect '$VOLUME' >/dev/null 2>&1" || { printf 'FAIL unique test resource collision; refusing to continue\n'; exit 1; }
GUARDED=1
[[ ${E2E_SKIP_SHIP:-0} == 1 ]] || "$ROOT/scripts/ship-image.sh" wgoctopus-agent:dev "$HOST" || exit 1
WAN=$(remote "ip -4 route show default | awk 'NR==1{print \$5}'")
HOP_IP=$(remote "ip -4 route show default | awk 'NR==1{for(i=1;i<=NF;i++)if(\$i==\"src\"){print \$(i+1);exit}}'")
[[ -n $WAN && -n $HOP_IP ]] || { printf 'FAIL default route discovery\n'; exit 1; }
AGENT_PORT=$(remote "python3 -c 'import socket;s=socket.socket();s.bind((\"127.0.0.1\",0));print(s.getsockname()[1]);s.close()'")
[[ -n $AGENT_PORT ]] || exit 1
[[ $(remote "ss -H -lntu | awk '{print \$5}' | grep -Ec '[:.]$AGENT_PORT\$' || true") == 0 ]] || { printf 'FAIL selected agent port in use\n'; exit 1; }
remote "mkdir -p '$DIR'; chmod 700 '$DIR'; printf '%s' '$AGENT_TOKEN' >'$DIR/agent-token'; chmod 600 '$DIR/agent-token'; docker volume create '$VOLUME' >/dev/null; docker run -d --name '$AGENT' --network host --cap-add NET_ADMIN --device /dev/net/tun -v '$DIR/agent-token:/run/token:ro' -v '$VOLUME:/var/lib/wgoctopus' wgoctopus-agent:dev --hop-enabled --listen 127.0.0.1:$AGENT_PORT --token-file /run/token >/dev/null" || exit 1
for i in $(seq 1 45); do [[ $(remote "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$AGENT_PORT/healthz") == 200 ]] && break; sleep 1; done
docker run -d --name "$ORCH" --network host --user "$(id -u):$(id -g)" -e USER="${HOST%@*}" -e LOGNAME="${HOST%@*}" -v "$TMP:/run/e2e:ro" -v "$TMP/db:/var/lib/wgoctopus" -e WGOCTOPUS_MASTER_KEY_FILE=/run/e2e/master-key -e WGOCTOPUS_API_TOKEN_FILE=/run/e2e/api-token -e WGOCTOPUS_TRANSPORT=ssh -e WGOCTOPUS_SSH_KEY_FILE=/run/e2e/id_rsa -e WGOCTOPUS_SSH_KNOWN_HOSTS=/var/lib/wgoctopus/known_hosts -e WGOCTOPUS_SSH_TOFU=true -e WGOCTOPUS_RECONCILE_INTERVAL=2 -e WGOCTOPUS_RECONCILER_ENABLED=true -e WGOCTOPUS_AUTO_MIGRATE=true -e WGOCTOPUS_API_HOST=0.0.0.0 -e WGOCTOPUS_API_PORT="$API" wgoctopus-orchestrator:dev >/dev/null || exit 1
for i in $(seq 1 60); do curl -fsS "http://127.0.0.1:$API/readyz" >/dev/null 2>&1 && break; sleep 1; done
check 'orchestrator ready' curl -fsS "http://127.0.0.1:$API/readyz"
auth=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')
inst=$(curl -fsS "${auth[@]}" -d '{"name":"hop-test","listen_port":23551,"address":"10.223.0.1/24"}' "http://127.0.0.1:$API/v1/instances") || exit 1
IID=$(jq -r .id <<<"$inst")
for spec in 'backend-a 192.0.2.10' 'backend-b 192.0.2.11'; do
  read -r name ip <<<"$spec"
  result=$(curl -fsS "${auth[@]}" -d "{\"name\":\"$name\",\"ssh_host\":\"placeholder\",\"ssh_user\":\"placeholder\",\"backend_ip\":\"$ip\",\"enabled\":false}" "http://127.0.0.1:$API/v1/nodes") || exit 1
  id=$(jq -r .id <<<"$result"); role=standby; [[ $name == backend-a ]] && role=active
  curl -fsS "${auth[@]}" -X PUT -d "{\"role\":\"$role\"}" "http://127.0.0.1:$API/v1/instances/$IID/placements/$id" >/dev/null || exit 1
  [[ $name == backend-a ]] && AID=$id || BID=$id
done
hop=$(curl -fsS "${auth[@]}" -d "{\"name\":\"hop-router\",\"ssh_host\":\"${HOST#*@}\",\"ssh_user\":\"${HOST%@*}\",\"agent_port\":$AGENT_PORT,\"agent_token\":\"$AGENT_TOKEN\",\"kind\":\"hop\",\"wan_interface\":\"$WAN\",\"hop_ip\":\"$HOP_IP\"}" "http://127.0.0.1:$API/v1/nodes") || exit 1
HID=$(jq -r .id <<<"$hop")
curl -fsS "${auth[@]}" -X PUT -d '{}' "http://127.0.0.1:$API/v1/hops/$HID/links/$IID" >/dev/null || exit 1
check 'hop reconciles active backend' wait_sync
REV=$(node_json | jq -r .desired_revision)
check 'chains, tagged DNAT, and first-position jumps' remote "iptables -t nat -S WGOCT_HOP_DNAT | grep -F -- '--to-destination 192.0.2.10:23551' | grep -q 'wgoct:hop:23551' && iptables -t nat -S PREROUTING | sed -n '2p' | grep -q -- '-j WGOCT_HOP_DNAT' && iptables -t nat -S POSTROUTING | sed -n '2p' | grep -q -- '-j WGOCT_HOP_SNAT' && iptables -t filter -S FORWARD | sed -n '2p' | grep -q -- '-j WGOCT_HOP_FWD'"
DUMP=$(remote 'iptables-save -t nat; iptables-save -t filter' | grep -E 'WGOCT_HOP_|wgoct:hop:23551' || true)
check 'hop rule reconciliation is idempotent' wait_sync
DUMP2=$(remote 'iptables-save -t nat; iptables-save -t filter' | grep -E 'WGOCT_HOP_|wgoct:hop:23551' || true)
[[ $DUMP == "$DUMP2" ]] && { printf 'PASS identical rule dump after reconcile\n'; PASS=$((PASS+1)); } || { printf 'FAIL identical rule dump after reconcile\n'; FAIL=$((FAIL+1)); }
check 'agent hop route metric is one' remote "curl -fsS -H 'Authorization: Bearer $AGENT_TOKEN' http://127.0.0.1:$AGENT_PORT/metrics | grep -E '^wgoctopus_hop_routes[[:space:]]+1([.]0)?$'"
if remote "command -v conntrack >/dev/null || test -r /proc/net/nf_conntrack"; then
  if (echo x >/dev/udp/$HOP_IP/23551) 2>/dev/null; then
    sleep 2
    check 'UDP creates conntrack entry for backend A' remote "(conntrack -L -p udp 2>/dev/null || cat /proc/net/nf_conntrack 2>/dev/null) | grep -E 'dst=$HOP_IP .*dport=23551 .*src=192.0.2.10'"
  else skip 'UDP send from test runner failed; conntrack assertion not run'; fi
else skip 'conntrack unavailable on test host; UDP conntrack assertion not run'; fi
curl -fsS "${auth[@]}" -X POST -d "{\"node_id\":$BID}" "http://127.0.0.1:$API/v1/instances/$IID/switch" >/dev/null || exit 1
check 'switch converges to backend B' wait_sync
check 'switch advances desired revision' test "$(node_json | jq -r .desired_revision)" -gt "$REV"
check 'DNAT switched and stale backend A rule removed' remote "iptables -t nat -S WGOCT_HOP_DNAT | grep -F -- '--to-destination 192.0.2.11:23551' | grep -q 'wgoct:hop:23551' && ! iptables -t nat -S WGOCT_HOP_DNAT | grep -q '192.0.2.10'"
if remote 'command -v conntrack >/dev/null || test -r /proc/net/nf_conntrack'; then check 'stale conntrack to backend A flushed' remote "! (conntrack -L -p udp 2>/dev/null || cat /proc/net/nf_conntrack 2>/dev/null) | grep -E 'dst=$HOP_IP .*dport=23551 .*src=192.0.2.10'"; fi
REV=$(node_json | jq -r .desired_revision)
docker restart "$ORCH" >/dev/null
for i in $(seq 1 60); do curl -fsS "http://127.0.0.1:$API/readyz" >/dev/null 2>&1 && break; sleep 1; done
check 'restart preserves hop sync' wait_sync
check 'restart revision does not move backward' test "$(node_json | jq -r .desired_revision)" -ge "$REV"
curl -fsS "${auth[@]}" -X DELETE "http://127.0.0.1:$API/v1/hops/$HID/links/$IID" >/dev/null || exit 1
check 'deleted hop link converges' wait_sync
check 'deleted link removes tagged port rule' remote "! iptables-save | grep -q 'wgoct:hop:23551'"
check 'hop route metric is zero' remote "curl -fsS -H 'Authorization: Bearer $AGENT_TOKEN' http://127.0.0.1:$AGENT_PORT/metrics | grep -E '^wgoctopus_hop_routes[[:space:]]+0([.]0)?$'"
