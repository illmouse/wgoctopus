#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MODE=${1:-}
[[ $MODE == local || $MODE == ssh ]] || { echo "Usage: $0 local | ssh user@host" >&2; exit 2; }
HOST=${2:-}
[[ $MODE != ssh || -n $HOST ]] || { echo "Usage: $0 ssh user@host" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:-"-i $HOME/.ssh/id_rsa -o StrictHostKeyChecking=accept-new"}
PORT=${E2E_PORT:-23440}
CONTAINER=woct-agent
STATE_VOLUME=e2e-woct-state-$$
[[ $MODE == local ]] && CONTAINER=e2e-woct-agent
TMP=$(mktemp -d)
TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" >"$TMP/token"
chmod 600 "$TMP/token"
PASS=0; FAIL=0

run() {
  if [[ $MODE == local ]]; then bash -s <<<"$1"; else ssh $SSH_OPTS "$HOST" bash -s <<<"$1"; fi
}
target_setup() {
  local tok
  if [[ $MODE == ssh ]]; then
    tok=$TOKEN
    run "mkdir -p /opt/woct-test; chmod 700 /opt/woct-test; printf '%s' '$tok' >/opt/woct-test/token; chmod 600 /opt/woct-test/token; docker rm -f $CONTAINER >/dev/null 2>&1 || true; ip link del woct0 2>/dev/null || true"
  else
    run "docker rm -f $CONTAINER >/dev/null 2>&1 || true; ip link del woct0 2>/dev/null || true"
  fi
}
check() {
  local name=$1 cmd=$2
  if run "$cmd" >/dev/null 2>&1; then printf 'PASS %s\n' "$name"; PASS=$((PASS+1)); else printf 'FAIL %s\n' "$name"; FAIL=$((FAIL+1)); fi
}
cleanup() {
  set +e
  run "docker rm -f $CONTAINER >/dev/null 2>&1 || true; docker volume rm $STATE_VOLUME >/dev/null 2>&1 || true; ip link del woct0 2>/dev/null || true; for t in filter nat; do for c in WGOCT_FWD WGOCT_NAT; do while iptables -t \$t -S 2>/dev/null | grep -q -- \"-j \$c\"; do iptables -t \$t -D FORWARD -j \$c 2>/dev/null || iptables -t \$t -D POSTROUTING -j \$c 2>/dev/null || break; done; iptables -t \$t -F \$c 2>/dev/null || true; iptables -t \$t -X \$c 2>/dev/null || true; done; done"
  if [[ $MODE == ssh ]]; then run 'rm -rf /opt/woct-test'; else rm -rf "$TMP"; fi
  if [[ $MODE == ssh && -n ${FILTER_BEFORE:-} ]]; then
    local filt nat
    filt=$(run "iptables -S | wc -l"); nat=$(run "iptables -t nat -S | wc -l")
    [[ $filt == "$FILTER_BEFORE" && $nat == "$NAT_BEFORE" ]] || { echo "FAIL remote iptables cleanup (filter $filt/$FILTER_BEFORE nat $nat/$NAT_BEFORE)"; FAIL=$((FAIL+1)); }
    [[ $filt == 29 && $nat == 13 ]] || { echo "FAIL expected final iptables counts 29/13, got $filt/$nat"; FAIL=$((FAIL+1)); }
    [[ $(run "docker ps -q --no-trunc | sort") == "$CONTAINERS_BEFORE" ]] || { echo 'FAIL protected containers changed'; FAIL=$((FAIL+1)); }
  fi
  printf 'Summary: %d PASS, %d FAIL\n' "$PASS" "$FAIL"
}
trap cleanup EXIT

if [[ $MODE == ssh ]]; then
  if [[ ${E2E_SKIP_SHIP:-0} != 1 ]]; then docker image inspect wgoctopus-agent:dev >/dev/null 2>&1 || (cd "$ROOT" && make agent-image); "$ROOT/scripts/ship-image.sh" wgoctopus-agent:dev "$HOST"; fi
  FILTER_BEFORE=$(run 'iptables -S | wc -l'); NAT_BEFORE=$(run 'iptables -t nat -S | wc -l')
  CONTAINERS_BEFORE=$(run "docker ps -q --no-trunc | sort")
  printf '%s\n' "$CONTAINERS_BEFORE" | grep -q 0cdbc8b9df39 || { echo 'Expected amneziawg container missing' >&2; exit 1; }
  printf '%s\n' "$CONTAINERS_BEFORE" | grep -q 8c71548c40b5 || { echo 'Expected wgeasy container missing' >&2; exit 1; }
  run "mkdir -p /opt/woct-test; chmod 700 /opt/woct-test; printf '%s' '$TOKEN' >/opt/woct-test/token; chmod 600 /opt/woct-test/token"
fi
target_setup
if [[ $MODE == local ]]; then
  echo 'NOTE local mode exercises the API only; Docker lacks host networking privileges here, so link/firewall and daemon-restart checks may FAIL.'
  docker image inspect wgoctopus-agent:dev >/dev/null 2>&1 || (cd "$ROOT" && make agent-image)
  if ss -H -lun "sport = :$PORT" | grep -q .; then
    for PORT in $(seq 23440 23540); do ss -H -lun "sport = :$PORT" | grep -q . || break; done
  fi
  docker run -d --name "$CONTAINER" --network host --cap-add NET_ADMIN --device /dev/net/tun -v "$TMP/token:/run/token:ro" -v "$STATE_VOLUME:/var/lib/wgoctopus" wgoctopus-agent:dev --listen 127.0.0.1:18080 --token-file /run/token >/dev/null
else
  run "docker run -d --name $CONTAINER --network host --cap-add NET_ADMIN --device /dev/net/tun -v /opt/woct-test/token:/run/token:ro -v $STATE_VOLUME:/var/lib/wgoctopus wgoctopus-agent:dev --listen 127.0.0.1:18080 --token-file /run/token >/dev/null"
fi
AUTH="Authorization: Bearer $TOKEN"
curlrun() { run "curl -sS -o /tmp/e2e-response -w '%{http_code}' -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' $*"; }
for i in $(seq 1 30); do [[ $(curlrun "http://127.0.0.1:18080/healthz") == 200 ]] && break; sleep 1; done
check 'agent start and healthz' 'curl -fsS http://127.0.0.1:18080/healthz >/dev/null'

K1=$(openssl rand -base64 32); K2=$(openssl rand -base64 32); K3=$(openssl rand -base64 32); P1=$(openssl rand -base64 32); P2=$(openssl rand -base64 32); P3=$(openssl rand -base64 32)
python3 - "$TMP/state.json" "$PORT" "$K1" "$K2" "$K3" "$P1" "$P2" "$P3" <<'PY'
import json,sys
f,port,k1,k2,k3,p1,p2,p3=sys.argv[1:]
o={"revision":1,"interfaces":[{"name":"woct0","listen_port":int(port),"private_key":k1,"address":"10.222.0.1/24","obfuscation":{"jc":4,"jmin":40,"jmax":70,"s1":15,"s2":18,"s3":20,"s4":23,"h1":"100-200","h2":"300-400","h3":"500-600","h4":"700-800"},"peers":[{"public_key":p1,"allowed_ips":["10.222.0.2/32"]},{"public_key":p2,"allowed_ips":["10.222.0.3/32"]}]}]}
json.dump(o,open(f,"w"))
PY
push_state() { local query=${1:-} encoded; encoded=$(base64 -w0 "$TMP/state.json"); run "printf '%s' '$encoded' | base64 -d >/tmp/e2e-state.json; curl -sS -o /tmp/e2e-response -w '%{http_code}' -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' --data-binary @/tmp/e2e-state.json 'http://127.0.0.1:18080/v1/state$query'"; }
code=$(push_state); check 'PUT revision 1' "test '$code' = 204"
check 'GET revision 1' "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:18080/v1/state | jq -e '.revision == 1' >/dev/null"
check 'link/address/port/firewall/metrics configured' "ip link show woct0 | grep -q UP && ip -4 addr show woct0 | grep -q '10.222.0.1/24' && ss -ulnp | grep -q ':$PORT' && iptables -S | grep -q 'wgoct:' && curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:18080/metrics | grep -q 'wg_interface_up.*1'"
capture() { run "docker top $CONTAINER -eo pid,comm | awk '\$2 == \"amneziawg-go\" {print \$1; exit}'; ip -o link show woct0 | cut -d: -f1 | cut -d@ -f1; iptables -S | grep 'wgoct:' | sort"; }
BEFORE=$(capture)
jq '.revision=2' "$TMP/state.json" >"$TMP/next.json" && mv "$TMP/next.json" "$TMP/state.json"
code=$(push_state); check 'identical PUT revision 2' "test '$code' = 204"
RULES=$(printf '%s\n' "$BEFORE" | sed -n '3,$p' | base64 -w0)
check 'idempotent daemon/link/tagged rules' "test \"\$(docker top $CONTAINER -eo pid,comm | awk '\$2 == \"amneziawg-go\" {print \$1; exit}')\" = '$(printf '%s\n' "$BEFORE" | sed -n '1p')' && test \"\$(ip -o link show woct0 | cut -d: -f1 | cut -d@ -f1)\" = '$(printf '%s\n' "$BEFORE" | sed -n '2p')' && test \"\$(iptables -S | grep 'wgoct:' | sort | base64 -w0)\" = '$RULES'"
jq '.revision=3 | .interfaces[0].peers=[.interfaces[0].peers[0], {"public_key":"'"$P3"'","allowed_ips":["10.222.0.4/32"]}]' "$TMP/state.json" >"$TMP/next.json" && mv "$TMP/next.json" "$TMP/state.json"
code=$(push_state); check 'peer add/remove revision 3' "test '$code' = 204"
check 'peer metric updated' "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:18080/metrics | grep -E 'peer.*2|peers.*2' >/dev/null"
jq '.revision=4 | .interfaces[0].obfuscation.jc=5' "$TMP/state.json" >"$TMP/next.json" && mv "$TMP/next.json" "$TMP/state.json"
code=$(push_state); check 'dangerous obfuscation change refused' "test '$code' = 409"
check 'rejected change leaves revision 3' "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:18080/v1/state | jq -e '.revision == 3' >/dev/null"
code=$(push_state '?allow_dangerous=true'); check 'dangerous obfuscation change allowed' "test '$code' = 204"
jq '.revision=3' "$TMP/state.json" >"$TMP/next.json" && mv "$TMP/next.json" "$TMP/state.json"
code=$(push_state); check 'stale revision rejected' "test '$code' = 409"
jq '.revision=5 | .interfaces[0].listen_port=70000' "$TMP/state.json" >"$TMP/next.json" && mv "$TMP/next.json" "$TMP/state.json"
code=$(push_state); check 'invalid port rejected' "test '$code' = 422"
jq '.revision=5 | .interfaces[0].listen_port='"$PORT"' | .interfaces[0].obfuscation.h2=.interfaces[0].obfuscation.h1' "$TMP/state.json" >"$TMP/next.json" && mv "$TMP/next.json" "$TMP/state.json"
code=$(push_state); check 'overlapping h ranges rejected' "test '$code' = 422"

PID=$(run "docker exec $CONTAINER sh -c 'for p in /proc/[0-9]*; do read c <\$p/comm; [ \"\$c\" = amneziawg-go ] && basename \$p; done' | head -n1 || true")
[[ -n $PID ]] || { echo 'FAIL daemon PID lookup'; FAIL=$((FAIL+1)); }
run "docker exec $CONTAINER sh -c 'for p in /proc/[0-9]*; do read c <\$p/comm; [ \"\$c\" = amneziawg-go ] && kill -9 \${p##*/}; done; true'"
for i in $(seq 1 15); do [[ $(run "docker exec $CONTAINER sh -c 'for p in /proc/[0-9]*; do read c <\$p/comm; [ \"\$c\" = amneziawg-go ] && basename \$p; done' | head -n1 || true") != "$PID" ]] && break; sleep 1; done
check 'daemon restarted after SIGKILL' "test \"\$(docker exec $CONTAINER sh -c 'for p in /proc/[0-9]*; do read c <\$p/comm; [ \"\$c\" = amneziawg-go ] && basename \$p; done' | head -n1)\" != '$PID' && ss -ulnp | grep -q ':$PORT' && curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:18080/metrics | grep -E 'wgoctopus_daemon_restarts_total.*[1-9]'"
SAVED_REV=$(run "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:18080/v1/state | jq -r .revision")
run "docker restart $CONTAINER >/dev/null"
for i in $(seq 1 30); do [[ $(curlrun "http://127.0.0.1:18080/healthz") == 200 ]] && break; sleep 1; done
check 'container restart restores woct0' 'ip link show woct0 | grep -q UP'
check 'container restart restores listen port' "ss -ulnp | grep -q ':$PORT'"
RESTORED_REV=$(run "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:18080/v1/state | jq -r .revision")
printf 'Revision before/after restart: %s/%s\n' "$SAVED_REV" "$RESTORED_REV"
check 'container restart preserves revision' "test '$RESTORED_REV' = '$SAVED_REV'"
jq '.revision=5 | .interfaces=[]' "$TMP/state.json" >"$TMP/next.json" && mv "$TMP/next.json" "$TMP/state.json"
code=$(push_state); check 'empty interfaces removal response observed' "test '$code' = 204 || test '$code' = 422"
if [[ $code == 204 ]]; then check 'empty interfaces removes woct0' '! ip link show woct0 >/dev/null 2>&1'; else echo 'NOTE empty interfaces are rejected with 422; interface remains configured.'; fi
run "docker stats --no-stream --format '{{.MemUsage}}' $CONTAINER"
