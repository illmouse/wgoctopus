#!/usr/bin/env bash
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HOST=${1:-}
[[ -n $HOST ]] || { printf 'Usage: %s root@host\n' "$0" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:-"-i $HOME/.ssh/id_rsa -o StrictHostKeyChecking=accept-new"}
E2E_PROTECTED_IDS=${E2E_PROTECTED_IDS:-}
E2E_SKIP_SHIP=${E2E_SKIP_SHIP:-0}
DIR=/opt/woct-probe-test
SRV=woct-probe-srv CLI=woct-probe-cli
TMP=$(mktemp -d)
TOK_S=$(openssl rand -hex 32) TOK_C=$(openssl rand -hex 32)
printf '%s' "$TOK_S" >"$TMP/srv-token"; printf '%s' "$TOK_C" >"$TMP/cli-token"
chmod 600 "$TMP"/*
PASS=0 FAIL=0 SKIP=0 FILTER_BEFORE= NAT_BEFORE= CONTAINERS_BEFORE= ALL_CONTAINERS_BEFORE= VOLUMES_BEFORE= FWD_BEFORE= WGOCTNAT_BEFORE= GUARDED=0
run() { ssh $SSH_OPTS "$HOST" bash -s <<<"$1"; }
check() { if run "$2" >/dev/null 2>&1; then printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); else printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); fi; }
skip() { printf 'SKIP %s\n' "$1"; SKIP=$((SKIP+1)); }
cleanup() {
  set +e
  if [[ $GUARDED == 1 ]]; then
    run "docker rm -f $SRV $CLI >/dev/null 2>&1 || true
      for n in wps0 wpc0; do ip link del \$n 2>/dev/null || true; done
      if [ -z '$FWD_BEFORE' ] && iptables -t filter -S WGOCT_FWD >/dev/null 2>&1 && [ \$(iptables -t filter -S WGOCT_FWD | wc -l) -eq 1 ]; then iptables -t filter -D FORWARD -j WGOCT_FWD 2>/dev/null || true; iptables -t filter -X WGOCT_FWD 2>/dev/null || true; fi
      if [ -z '$WGOCTNAT_BEFORE' ] && iptables -t nat -S WGOCT_NAT >/dev/null 2>&1 && [ \$(iptables -t nat -S WGOCT_NAT | wc -l) -eq 1 ]; then iptables -t nat -D POSTROUTING -j WGOCT_NAT 2>/dev/null || true; iptables -t nat -X WGOCT_NAT 2>/dev/null || true; fi
      rm -rf $DIR"
  fi
  if [[ -n $FILTER_BEFORE ]]; then
    local f n
    f=$(run 'iptables -S | wc -l'); n=$(run 'iptables -t nat -S | wc -l')
    [[ $f == "$FILTER_BEFORE" && $n == "$NAT_BEFORE" ]] || { printf 'FAIL cleanup iptables filter=%s/%s nat=%s/%s\n' "$f" "$FILTER_BEFORE" "$n" "$NAT_BEFORE"; FAIL=$((FAIL+1)); }
    [[ $(run 'docker ps -q --no-trunc | sort') == "$CONTAINERS_BEFORE" ]] || { printf 'FAIL running container IDs changed\n'; FAIL=$((FAIL+1)); }
    [[ $(run 'docker ps -aq --no-trunc | sort') == "$ALL_CONTAINERS_BEFORE" ]] || { printf 'FAIL all container IDs changed\n'; FAIL=$((FAIL+1)); }
    [[ $(run 'docker volume ls -q | sort') == "$VOLUMES_BEFORE" ]] || { printf 'FAIL Docker volumes changed\n'; FAIL=$((FAIL+1)); }
    check 'test state directory removed' "test ! -e $DIR"
    check 'test containers absent' "! docker ps -a --format '{{.Names}}' | grep -Eq '^woct-probe-(srv|cli)$'"
    for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { printf 'FAIL protected container missing\n'; FAIL=$((FAIL+1)); }; done
    run 'printf "Host cleanup: iptables filter=%s nat=%s\n" "$(iptables -S | wc -l)" "$(iptables -t nat -S | wc -l)"; printf "containers:\n"; docker ps -a --no-trunc; printf "volumes:\n"; docker volume ls'
  fi
  rm -rf "$TMP"
  printf 'Summary: %d PASS, %d FAIL, %d SKIP\n' "$PASS" "$FAIL" "$SKIP"
}
trap cleanup EXIT

FILTER_BEFORE=$(run 'iptables -S | wc -l') || exit 1
NAT_BEFORE=$(run 'iptables -t nat -S | wc -l') || exit 1
CONTAINERS_BEFORE=$(run 'docker ps -q --no-trunc | sort') || exit 1
ALL_CONTAINERS_BEFORE=$(run 'docker ps -aq --no-trunc | sort') || exit 1
VOLUMES_BEFORE=$(run 'docker volume ls -q | sort') || exit 1
FWD_BEFORE=$(run 'iptables -t filter -S WGOCT_FWD 2>/dev/null || true') || exit 1
WGOCTNAT_BEFORE=$(run 'iptables -t nat -S WGOCT_NAT 2>/dev/null || true') || exit 1
run "test ! -e $DIR" || { printf 'FAIL %s exists; refusing cleanup\n' "$DIR"; FAIL=$((FAIL+1)); exit 1; }
run "! docker inspect $SRV $CLI >/dev/null 2>&1" || { printf 'FAIL probe container name exists; refusing cleanup\n'; FAIL=$((FAIL+1)); exit 1; }
for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { printf 'FAIL configured protected container missing\n'; exit 1; }; done
docker image inspect wgoctopus-agent:dev >/dev/null 2>&1 || make -C "$ROOT" agent-image || exit 1
if [[ $E2E_SKIP_SHIP != 1 ]]; then "$ROOT/scripts/ship-image.sh" wgoctopus-agent:dev "$HOST" || exit 1; fi
GUARDED=1
TOKS=$(<"$TMP/srv-token"); TOKC=$(<"$TMP/cli-token")
run "mkdir -m 700 $DIR; mkdir -m 700 $DIR/srv $DIR/cli; printf '%s' '$TOKS' >$DIR/srv/token; printf '%s' '$TOKC' >$DIR/cli/token; chmod 600 $DIR/srv/token $DIR/cli/token
docker run -d --name $SRV --network host --cap-add NET_ADMIN --device /dev/net/tun -v $DIR/srv:/var/lib/wgoctopus wgoctopus-agent:dev --listen 127.0.0.1:18090 --token-file /var/lib/wgoctopus/token >/dev/null
docker run -d --name $CLI --network host --cap-add NET_ADMIN --device /dev/net/tun -v $DIR/cli:/var/lib/wgoctopus wgoctopus-agent:dev --listen 127.0.0.1:18091 --token-file /var/lib/wgoctopus/token >/dev/null" || { FAIL=$((FAIL+1)); exit 1; }
for _ in $(seq 1 40); do [[ $(run 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18090/healthz') == 200 && $(run 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18091/healthz') == 200 ]] && break; sleep 1; done
check 'both agent healthz endpoints' 'curl -fsS http://127.0.0.1:18090/healthz >/dev/null && curl -fsS http://127.0.0.1:18091/healthz >/dev/null'
KEYS=$(python3 - <<'PY'
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
for _ in range(2):
 k=X25519PrivateKey.generate()
 print(base64.b64encode(k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode())
 print(base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode())
PY
) || { printf 'FAIL local python cryptography key generation unavailable\n'; FAIL=$((FAIL+1)); exit 1; }
mapfile -t K <<<"$KEYS"; SK=${K[0]} SP=${K[1]} CK=${K[2]} CP=${K[3]}
HOSTIP=$(run "ip -4 route get 1.1.1.1 | sed -n 's/.* src \\([0-9.]*\\).*/\\1/p' | head -n1")
[[ -n $HOSTIP ]] || { printf 'FAIL host IPv4 discovery\n'; FAIL=$((FAIL+1)); exit 1; }
OB='"obfuscation":{"jc":0,"jmin":0,"jmax":0,"s1":0,"s2":0,"s3":0,"s4":0,"h1":"1","h2":"2","h3":"3","h4":"4"}'
put() { local port=$1 tok=$2 body=$3; run "printf '%s' '$body' >/tmp/woct-probe.json; curl -sS -o /tmp/woct-probe-response -w '%{http_code}' -X PUT -H 'Authorization: Bearer $tok' -H 'Content-Type: application/json' --data-binary @/tmp/woct-probe.json http://127.0.0.1:$port/v1/state"; }
S1="{\"revision\":1,\"interfaces\":[{\"name\":\"wps0\",\"listen_port\":23451,\"private_key\":\"$SK\",\"address\":\"10.77.0.1/24\",$OB,\"peers\":[{\"public_key\":\"$CP\",\"allowed_ips\":[\"10.77.0.2/32\"]}]}]}"
C1="{\"revision\":1,\"interfaces\":[{\"name\":\"wpc0\",\"mode\":\"client\",\"listen_port\":0,\"private_key\":\"$CK\",\"address\":\"10.77.0.2/32\",$OB,\"peers\":[{\"public_key\":\"$SP\",\"allowed_ips\":[\"10.77.0.1/32\"],\"endpoint\":\"$HOSTIP:23451\",\"persistent_keepalive\":5}]}]}"
CODE=$(put 18090 "$TOKS" "$S1"); [[ $CODE == 204 ]] && { printf 'PASS server config revision 1\n'; PASS=$((PASS+1)); } || { printf 'FAIL server config revision 1 (HTTP %s)\n' "$CODE"; run 'cat /tmp/woct-probe-response; docker logs --tail 20 woct-probe-srv 2>&1 | sed -E "s/[A-Za-z0-9+/]{43}=/[redacted-key]/g"'; FAIL=$((FAIL+1)); }
CODE=$(put 18091 "$TOKC" "$C1"); [[ $CODE == 204 ]] && { printf 'PASS client config revision 1\n'; PASS=$((PASS+1)); } || { printf 'FAIL client config revision 1 (HTTP %s)\n' "$CODE"; run 'cat /tmp/woct-probe-response; docker logs --tail 20 woct-probe-cli 2>&1 | sed -E "s/[A-Za-z0-9+/]{43}=/[redacted-key]/g"'; FAIL=$((FAIL+1)); }
handshake() { run "curl -fsS -H 'Authorization: Bearer $TOKC' http://127.0.0.1:18091/metrics | awk '/wg_peer_last_handshake_timestamp_seconds.*interface=\"wpc0\"/ && \$NF>0 {c=1} END{exit !c}' && curl -fsS -H 'Authorization: Bearer $TOKS' http://127.0.0.1:18090/metrics | awk '/wg_peer_last_handshake_timestamp_seconds.*interface=\"wps0\"/ && \$NF>0 {c=1} END{exit !c}'"; }
ok=0; for _ in $(seq 1 20); do if handshake; then ok=1; break; fi; sleep 2; done
[[ $ok == 1 ]] && { printf 'PASS client/server handshake metrics\n'; PASS=$((PASS+1)); } || { printf 'FAIL client/server handshake metrics within 40s\n'; FAIL=$((FAIL+1)); }
skip 'image has no UAPI-capable tool; live UAPI peer dump unavailable'
check 'client has no tagged firewall rules and server has tagged rules' "! iptables -S | grep -q 'wgoct:wpc0' && ! iptables -t nat -S | grep -q 'wgoct:wpc0' && iptables -S | grep -q 'wgoct:wps0'"
PID=$(run "docker top $CLI -eo pid,comm | awk '\$2==\"amneziawg-go\"{print \$1;exit}'")
IFINDEX=$(run "ip -o link show wpc0 | cut -d: -f1")
check 'client has nonzero ephemeral UDP listen port' "ss -ulnpH | grep -F 'pid=$PID,' | grep -Eq ':[1-9][0-9]*[[:space:]]'"
[[ $(put 18091 "$TOKC" "${C1/\"revision\":1/\"revision\":2}") == 204 ]] && { printf 'PASS identical client revision 2\n'; PASS=$((PASS+1)); } || { printf 'FAIL identical client revision 2\n'; FAIL=$((FAIL+1)); }
check 'idempotent client daemon PID and link ifindex' "test \"\$(docker top $CLI -eo pid,comm | awk '\$2==\"amneziawg-go\"{print \$1;exit}')\" = '$PID' && test \"\$(ip -o link show wpc0 | cut -d: -f1)\" = '$IFINDEX'"
C3=${C1/\"revision\":1/\"revision\":3}; C3=${C3/\"persistent_keepalive\":5/\"persistent_keepalive\":7}
[[ $(put 18091 "$TOKC" "$C3") == 204 ]] && { printf 'PASS client keepalive revision 3\n'; PASS=$((PASS+1)); } || { printf 'FAIL client keepalive revision 3\n'; FAIL=$((FAIL+1)); }
if handshake; then printf 'PASS handshake after keepalive update\n'; PASS=$((PASS+1)); else printf 'FAIL handshake after keepalive update\n'; FAIL=$((FAIL+1)); fi
[[ $(put 18091 "$TOKC" '{"revision":4,"interfaces":[]}') == 204 ]] && { printf 'PASS client removal\n'; PASS=$((PASS+1)); } || { printf 'FAIL client removal\n'; FAIL=$((FAIL+1)); }
[[ $(put 18090 "$TOKS" '{"revision":2,"interfaces":[]}') == 204 ]] && { printf 'PASS server removal\n'; PASS=$((PASS+1)); } || { printf 'FAIL server removal\n'; FAIL=$((FAIL+1)); }
check 'interfaces and tagged rules removed' '! ip link show wpc0 >/dev/null 2>&1 && ! ip link show wps0 >/dev/null 2>&1 && ! iptables-save | grep -E "wgoct:(wpc0|wps0)"'
exit "$((FAIL > 0))"
