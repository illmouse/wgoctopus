#!/usr/bin/env bash
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MODE=${1:-local}; HOST=${2:-}
[[ $MODE == local || $MODE == ssh ]] || { printf 'Usage: %s local | ssh user@host\n' "$0" >&2; exit 2; }
[[ $MODE != ssh || -n $HOST ]] || { printf 'Usage: %s ssh user@host\n' "$0" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:-"-i $HOME/.ssh/id_rsa -o StrictHostKeyChecking=accept-new"}
SUFFIX=$(printf '%s' "$$-$RANDOM" | tr -cd '[:alnum:]' | tail -c 12)
CONTAINER=e2e-awg3-$SUFFIX; VOLUME=e2e-awg3-state-$SUFFIX; IFACE=wga${SUFFIX:0:5}
PORT=${E2E_PORT:-23461}; API=18080; TOKEN=$(openssl rand -hex 32); TMP=$(mktemp -d)
PASS=0; FAIL=0; SKIP=0; GUARDED=0; HAD_FWD=0; HAD_NAT=0
run() { if [[ $MODE == local ]]; then bash -s <<<"$1"; else ssh $SSH_OPTS "$HOST" bash -s <<<"$1"; fi; }
pass() { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf 'SKIP %s\n' "$1"; SKIP=$((SKIP+1)); }
check() { if [[ $1 == 204 ]]; then pass "$2"; else fail "$2 (HTTP $1)"; fi; }
cleanup() {
  set +e
  if [[ $GUARDED == 1 ]]; then
    run "docker rm -f $CONTAINER >/dev/null 2>&1 || true; docker volume rm $VOLUME >/dev/null 2>&1 || true; ip link del $IFACE 2>/dev/null || true; if [ $HAD_FWD = 0 ]; then while iptables -t filter -C FORWARD -j WGOCT_FWD 2>/dev/null; do iptables -t filter -D FORWARD -j WGOCT_FWD; done; iptables -t filter -F WGOCT_FWD 2>/dev/null || true; iptables -t filter -X WGOCT_FWD 2>/dev/null || true; fi; if [ $HAD_NAT = 0 ]; then while iptables -t nat -C POSTROUTING -j WGOCT_NAT 2>/dev/null; do iptables -t nat -D POSTROUTING -j WGOCT_NAT; done; iptables -t nat -F WGOCT_NAT 2>/dev/null || true; iptables -t nat -X WGOCT_NAT 2>/dev/null || true; fi; rm -rf /tmp/$CONTAINER"
  fi
  if [[ $MODE == ssh && -n ${FILTER_BEFORE:-} ]]; then
    local f n ids
    f=$(run 'iptables -S | wc -l'); n=$(run 'iptables -t nat -S | wc -l'); ids=$(run 'docker ps -q --no-trunc | sort')
    [[ $f == "$FILTER_BEFORE" && $n == "$NAT_BEFORE" ]] && pass 'host firewall baseline restored' || fail "host firewall baseline (filter=$f/$FILTER_BEFORE nat=$n/$NAT_BEFORE)"
    [[ $ids == "$CONTAINERS_BEFORE" ]] && pass 'running container IDs unchanged' || fail 'running container IDs changed'
    for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] && pass "protected container $id preserved" || fail 'protected container missing'; done
  fi
  rm -rf "$TMP"
  printf 'Summary: %d PASS, %d FAIL, %d SKIP\n' "$PASS" "$FAIL" "$SKIP"
  [[ $FAIL == 0 ]]
}
trap cleanup EXIT

if [[ $MODE == ssh ]]; then
  FILTER_BEFORE=$(run 'iptables -S | wc -l'); NAT_BEFORE=$(run 'iptables -t nat -S | wc -l'); CONTAINERS_BEFORE=$(run 'docker ps -q --no-trunc | sort')
  if [[ -n ${E2E_PROTECTED_IDS:-} ]]; then for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { fail 'configured protected container absent'; exit 1; }; done; fi
  [[ $FILTER_BEFORE == 29 && $NAT_BEFORE == 13 ]] || { printf 'FAIL unexpected host baseline filter=%s nat=%s\n' "$FILTER_BEFORE" "$NAT_BEFORE"; exit 1; }
fi
if [[ ${E2E_SKIP_SHIP:-0} != 1 ]]; then
  docker image inspect wgoctopus-agent:dev >/dev/null 2>&1 || (cd "$ROOT" && make agent-image) || exit 1
  if [[ $MODE == ssh ]]; then "$ROOT/scripts/ship-image.sh" wgoctopus-agent:dev "$HOST" || exit 1; fi
fi
GUARDED=1
HAD_FWD=$(run 'iptables -t filter -S WGOCT_FWD >/dev/null 2>&1 && echo 1 || echo 0')
HAD_NAT=$(run 'iptables -t nat -S WGOCT_NAT >/dev/null 2>&1 && echo 1 || echo 0')
K=$(openssl rand -base64 32); P=$(openssl rand -base64 32); HPK=$(openssl rand -base64 32)
printf '%s' "$TOKEN" >"$TMP/token"; chmod 600 "$TMP/token"
python3 - "$TMP/state.json" "$PORT" "$K" "$P" "$HPK" "$IFACE" <<'PY'
import json,sys
f,port,k,p,h,name=sys.argv[1:]
o={"revision":1,"interfaces":[{"name":name,"listen_port":int(port),"private_key":k,"address":"10.222.30.1/24","obfuscation":{"jc":4,"jmin":40,"jmax":70,"s1":12,"s2":13,"s3":14,"s4":15,"h1":"100-200","h2":"300-400","h3":"500-600","h4":"700-800","header_protection_key":h,"content_padding_addition":"16-64","rekey_after_time":"100-110","rekey_timeout":"5-7","reject_after_time":"180-200","keepalive_timeout":"10-12","max_handshake_attempts":"15-20","random_trailers":True,"disable_cookies":False},"peers":[{"public_key":p,"allowed_ips":["10.222.30.2/32"]}]}]}
json.dump(o,open(f,"w"))
PY
STATE=$(base64 -w0 "$TMP/state.json")
run "mkdir -p /tmp/$CONTAINER; chmod 700 /tmp/$CONTAINER; printf '%s' '$TOKEN' >/tmp/$CONTAINER/token; chmod 600 /tmp/$CONTAINER/token; docker volume create $VOLUME >/dev/null; docker run -d --name $CONTAINER --network host --cap-add NET_ADMIN --device /dev/net/tun -v /tmp/$CONTAINER/token:/run/token:ro -v $VOLUME:/var/lib/wgoctopus wgoctopus-agent:dev --listen 127.0.0.1:$API --token-file /run/token >/dev/null"
if [[ $MODE == local ]]; then echo 'NOTE local mode may fail without Docker, NET_ADMIN, and tun privileges.'; fi
curlrun() { run "curl -sS -o /tmp/$CONTAINER/response -w '%{http_code}' -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' $*"; }
put() { local rev=$1 query=${2:-}; local body; body=$(python3 - "$TMP/state.json" "$rev" <<'PY'
import json,sys
o=json.load(open(sys.argv[1])); o['revision']=int(sys.argv[2]); print(json.dumps(o,separators=(',',':')))
PY
); local enc; enc=$(printf '%s' "$body" | base64 -w0); run "printf '%s' '$enc' | base64 -d >/tmp/$CONTAINER/state.json; curl -sS -o /tmp/$CONTAINER/response -w '%{http_code}' -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' --data-binary @/tmp/$CONTAINER/state.json 'http://127.0.0.1:$API/v1/state$query'"; }
for _ in $(seq 1 30); do [[ $(curlrun "http://127.0.0.1:$API/healthz") == 200 ]] && break; sleep 1; done
code=$(put 1); check "$code" 'PUT all AWG 3.x fields; daemon accepts config'
if run "ip link show $IFACE | grep -q UP" >/dev/null 2>&1; then pass 'interface is up'; else fail 'interface is up'; fi

# Live UAPI assertions are intentionally silent so key material never reaches logs.
uapi_check() {
  local expected=$1; run "command -v socat >/dev/null || exit 77; pid=\$(docker top $CONTAINER -eo pid,comm | awk '\$2==\"amneziawg-go\" {print \$1; exit}'); test -n \"\$pid\"; printf 'get=1\\n\\n' | socat - UNIX-CONNECT:/proc/\$pid/root/var/run/amneziawg/$IFACE.sock > /tmp/$CONTAINER/live; $expected"
}
UAPI=0
if run 'command -v socat >/dev/null' >/dev/null 2>&1; then
  UAPI=1
  HEX=$(printf '%s' "$HPK" | base64 -d | od -An -tx1 | tr -d ' \n')
  if uapi_check "grep -qx 'header_protection_key=$HEX' /tmp/$CONTAINER/live && grep -qx 'content_padding_addition=16-64' /tmp/$CONTAINER/live && grep -qx 'rekey_after_time=100-110' /tmp/$CONTAINER/live && grep -qx 'random_trailers=1' /tmp/$CONTAINER/live && grep -qx 'max_handshake_attempts=15-20' /tmp/$CONTAINER/live"; then pass 'live UAPI contains AWG 3.x fields'; else fail 'live UAPI contains AWG 3.x fields'; fi
else skip 'live UAPI inspection (socat unavailable)'; fi
pid_before=$(run "docker inspect -f '{{.State.Pid}}' $CONTAINER"); idx_before=$(run "cat /sys/class/net/$IFACE/ifindex 2>/dev/null")
code=$(put 2); check "$code" 'identical PUT revision 2'
[[ $(run "docker inspect -f '{{.State.Pid}}' $CONTAINER") == "$pid_before" && $(run "cat /sys/class/net/$IFACE/ifindex") == "$idx_before" ]] && pass 'idempotent PUT preserves PID and ifindex' || fail 'idempotent PUT preserves PID and ifindex'
python3 - "$TMP/state.json" <<'PY'
import json,sys
f=sys.argv[1]; o=json.load(open(f)); x=o['interfaces'][0]['obfuscation']; x['rekey_timeout']='5-8'; x['keepalive_timeout']='10-14'; json.dump(o,open(f,'w'))
PY
code=$(put 3); check "$code" 'timer-only PUT without dangerous acknowledgement'; [[ $(run "docker inspect -f '{{.State.Pid}}' $CONTAINER") == "$pid_before" ]] && pass 'timer update preserves agent PID' || fail 'timer update preserves agent PID'
if [[ $UAPI == 1 ]]; then uapi_check "grep -qx 'rekey_timeout=5-8' /tmp/$CONTAINER/live && grep -qx 'keepalive_timeout=10-14' /tmp/$CONTAINER/live" && pass 'live UAPI timer values updated' || fail 'live UAPI timer values updated'; fi
python3 - "$TMP/state.json" <<'PY'
import json,sys
f=sys.argv[1]; o=json.load(open(f)); o['interfaces'][0]['obfuscation']['random_trailers']=False; json.dump(o,open(f,'w'))
PY
code=$(put 4); if [[ $code == 409 ]] && run "grep -q random_trailers /tmp/$CONTAINER/response"; then pass 'dangerous change rejected with reason'; else fail 'dangerous change rejected with reason'; fi
code=$(put 4 '?allow_dangerous=true'); check "$code" 'dangerous change accepted with allow_dangerous'
if [[ $UAPI == 1 ]]; then uapi_check "grep -qx 'random_trailers=0' /tmp/$CONTAINER/live" && pass 'live UAPI reflects dangerous change' || fail 'live UAPI reflects dangerous change'; fi
python3 - "$TMP/state.json" <<'PY'
import json,sys
f=sys.argv[1]; o=json.load(open(f)); del o['interfaces'][0]['obfuscation']['content_padding_addition']; json.dump(o,open(f,'w'))
PY
code=$(put 5 '?allow_dangerous=true'); check "$code" 'clear content padding'; if [[ $UAPI == 1 ]]; then uapi_check "! grep -q '^content_padding_addition=' /tmp/$CONTAINER/live" && pass 'cleared padding absent from live UAPI' || fail 'cleared padding absent from live UAPI'; fi
python3 - "$TMP/state.json" <<'PY'
import json,sys
f=sys.argv[1]; o=json.load(open(f)); o['revision']=6; x=o['interfaces'][0]['obfuscation']; x['header_protection_key']='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='; x['s1']=5; json.dump(o,open(f,'w'))
PY
enc=$(base64 -w0 "$TMP/state.json"); code=$(run "printf '%s' '$enc' | base64 -d >/tmp/$CONTAINER/state.json; curl -sS -o /tmp/$CONTAINER/response -w '%{http_code}' -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' --data-binary @/tmp/$CONTAINER/state.json http://127.0.0.1:$API/v1/state")
if [[ $code == 422 ]] && ! run "grep -q 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=' /tmp/$CONTAINER/response"; then pass 'invalid short s1 rejected without key disclosure'; else fail 'invalid short s1 rejected without key disclosure'; fi
run "docker restart $CONTAINER >/dev/null"
for _ in $(seq 1 30); do [[ $(curlrun "http://127.0.0.1:$API/healthz") == 200 ]] && break; sleep 1; done
if run "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$API/v1/state | python3 -c 'import json,sys;o=json.load(sys.stdin);assert o[\"revision\"]==5'" >/dev/null 2>&1; then pass 'restart restores revision 5'; else fail 'restart restores revision 5'; fi
if [[ $UAPI == 1 ]]; then uapi_check "grep -qx 'random_trailers=0' /tmp/$CONTAINER/live && grep -qx 'rekey_timeout=5-8' /tmp/$CONTAINER/live && ! grep -q '^content_padding_addition=' /tmp/$CONTAINER/live" && pass 'restart restores live AWG 3.x values' || fail 'restart restores live AWG 3.x values'; fi
python3 - "$TMP/empty.json" <<'PY'
import json,sys
json.dump({'revision':6,'interfaces':[]},open(sys.argv[1],'w'))
PY
enc=$(base64 -w0 "$TMP/empty.json"); code=$(run "printf '%s' '$enc' | base64 -d >/tmp/$CONTAINER/state.json; curl -sS -o /tmp/$CONTAINER/response -w '%{http_code}' -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' --data-binary @/tmp/$CONTAINER/state.json http://127.0.0.1:$API/v1/state"); check "$code" 'remove interface with empty interfaces'
