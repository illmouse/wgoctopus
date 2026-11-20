#!/usr/bin/env bash
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HOST=${1:-}
[[ -n $HOST ]] || { printf 'Usage: %s root@host\n' "$0" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:-"-i $HOME/.ssh/id_rsa -o StrictHostKeyChecking=accept-new"}
E2E_PROTECTED_IDS=${E2E_PROTECTED_IDS:-}
E2E_SKIP_SHIP=${E2E_SKIP_SHIP:-0}
AGENT=e2e-woct-hop
DISABLED=e2e-woct-hop-disabled
DIR=/opt/woct-hop-test
PORT=25871
TMP=$(mktemp -d)
TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" >"$TMP/token"; chmod 600 "$TMP/token"
PASS=0 FAIL=0 SKIP=0 FILTER_BEFORE= NAT_BEFORE= CONTAINERS_BEFORE= ALL_CONTAINERS_BEFORE= VOLUMES_BEFORE= DOCKER_RULES_BEFORE= GUARDED=0
run() { ssh $SSH_OPTS "$HOST" bash -s <<<"$1"; }
check() {
  local name=$1 command=$2
  if run "$command" >/dev/null 2>&1; then printf 'PASS %s\n' "$name"; PASS=$((PASS+1)); else printf 'FAIL %s\n' "$name"; FAIL=$((FAIL+1)); fi
}
skip() { printf 'SKIP %s\n' "$1"; SKIP=$((SKIP+1)); }
cleanup() {
  set +e
  if [[ $GUARDED == 1 ]]; then run "docker rm -f $AGENT $DISABLED >/dev/null 2>&1 || true
    for table in nat filter; do
      for chain in WGOCT_HOP_DNAT WGOCT_HOP_SNAT WGOCT_HOP_FWD; do
        for parent in PREROUTING OUTPUT POSTROUTING FORWARD; do
          while iptables -t \$table -C \$parent -j \$chain 2>/dev/null; do iptables -t \$table -D \$parent -j \$chain || break; done
        done
        iptables -t \$table -F \$chain 2>/dev/null || true; iptables -t \$table -X \$chain 2>/dev/null || true
      done
    done
    rm -rf $DIR"; fi
  if [[ -n $FILTER_BEFORE ]]; then
    local f n c
    f=$(run 'iptables -S | wc -l'); n=$(run 'iptables -t nat -S | wc -l'); c=$(run 'docker ps -q --no-trunc | sort')
    [[ $f == "$FILTER_BEFORE" && $n == "$NAT_BEFORE" ]] || { printf 'FAIL baseline restore filter=%s/%s nat=%s/%s\n' "$f" "$FILTER_BEFORE" "$n" "$NAT_BEFORE"; FAIL=$((FAIL+1)); }
    [[ $c == "$CONTAINERS_BEFORE" ]] || { printf 'FAIL running container IDs changed\n'; FAIL=$((FAIL+1)); }
    [[ $(run 'docker ps -aq --no-trunc | sort') == "$ALL_CONTAINERS_BEFORE" ]] || { printf 'FAIL all container IDs changed\n'; FAIL=$((FAIL+1)); }
    [[ $(run 'docker volume ls -q | sort') == "$VOLUMES_BEFORE" ]] || { printf 'FAIL Docker volumes changed\n'; FAIL=$((FAIL+1)); }
    run "test ! -e $DIR" || { printf 'FAIL %s remains\n' "$DIR"; FAIL=$((FAIL+1)); }
    run 'printf "Host cleanup: iptables filter=%s nat=%s; running container IDs:\\n" "$(iptables -S | wc -l)" "$(iptables -t nat -S | wc -l)"; docker ps -q --no-trunc | sort; printf "all containers:\\n"; docker ps -a --no-trunc; printf "volumes:\\n"; docker volume ls; printf "state dir:\\n"; ls -ld /opt/woct-hop-test 2>&1 || true'
    for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { printf 'FAIL protected container missing\n'; FAIL=$((FAIL+1)); }; done
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
DOCKER_RULES_BEFORE=$(run "iptables-save | grep -E -- '(^-N DOCKER|^-A .*DOCKER)' | sort") || exit 1
run "test ! -e $DIR" || { printf 'FAIL %s already exists; refusing to remove it\n' "$DIR"; FAIL=$((FAIL+1)); exit 1; }
run "! docker inspect $AGENT $DISABLED >/dev/null 2>&1" || { printf 'FAIL test container name already exists; refusing to remove it\n'; FAIL=$((FAIL+1)); exit 1; }
GUARDED=1
for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { printf 'FAIL protected container missing\n'; FAIL=$((FAIL+1)); exit 1; }; done
[[ $(run 'sysctl -n net.ipv4.ip_forward') == 1 ]] || { skip 'net.ipv4.ip_forward is not 1; left unchanged'; exit 0; }
WAN=$(run "ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if(\$i==\"dev\") {print \$(i+1); exit}}'")
HOP_IP=$(run "ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if(\$i==\"src\") {print \$(i+1); exit}}'")
[[ -n $WAN && -n $HOP_IP ]] || { printf 'FAIL route discovery\n'; FAIL=$((FAIL+1)); exit 1; }
[[ $(run "ss -H -lntu | awk '{print \$5}' | grep -Ec '[:.]$PORT$' || true") == 0 ]] || { printf 'FAIL port $PORT in use\n'; FAIL=$((FAIL+1)); exit 1; }
docker image inspect wgoctopus-agent:dev >/dev/null 2>&1 || make -C "$ROOT" agent-image || exit 1
if [[ $E2E_SKIP_SHIP != 1 ]]; then "$ROOT/scripts/ship-image.sh" wgoctopus-agent:dev "$HOST" || { FAIL=$((FAIL+1)); exit 1; }; fi
TOKEN2=$(openssl rand -hex 32)
printf '%s' "$TOKEN2" >"$TMP/token2"; chmod 600 "$TMP/token2"
TOK=$(<"$TMP/token")
TOK2=$(<"$TMP/token2")
run "mkdir -p $DIR; chmod 700 $DIR; printf '%s' '$TOK' >$DIR/token; printf '%s' '$TOK2' >$DIR/token2; chmod 600 $DIR/token $DIR/token2; docker rm -f $AGENT $DISABLED >/dev/null 2>&1 || true; docker run -d --name $AGENT --network host --cap-add NET_ADMIN --device /dev/net/tun -v $DIR/token:/run/token:ro -v $DIR/state:/var/lib/wgoctopus wgoctopus-agent:dev --hop-enabled --listen 127.0.0.1:18080 --token-file /run/token >/dev/null" || { FAIL=$((FAIL+1)); exit 1; }
for _ in $(seq 1 45); do [[ $(run "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/healthz") == 200 ]] && break; sleep 1; done
api() { local body=$1; run "printf '%s' '$body' >/tmp/e2e-hop.json; curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'Authorization: Bearer $TOK' -H 'Content-Type: application/json' --data-binary @/tmp/e2e-hop.json http://127.0.0.1:18080/v1/state"; }
state() { local rev=$1 routes=$2; printf '{"revision":%s,"interfaces":[],"hop":{"wan_interface":"%s","hop_ip":"%s","routes":%s}}' "$rev" "$WAN" "$HOP_IP" "$routes"; }
code=$(api "$(state 1 "[{\"listen_port\":$PORT,\"backend_ip\":\"192.0.2.10\",\"backend_port\":7,\"name\":\"t1\"}]")")
[[ $code == 204 ]] && { printf 'PASS route install\n'; PASS=$((PASS+1)); } || { printf 'FAIL route install (%s)\n' "$code"; FAIL=$((FAIL+1)); }
check 'chains, tagged DNAT and first-position jumps' "iptables -t nat -S WGOCT_HOP_DNAT | grep -q -- '--to-destination 192.0.2.10:7' && iptables -t nat -S WGOCT_HOP_SNAT | grep -q 'wgoct:hop:$PORT' && iptables -t filter -S WGOCT_HOP_FWD | grep -q 'wgoct:hop:$PORT' && iptables -t nat -S PREROUTING | sed -n '2p' | grep -q -- '-j WGOCT_HOP_DNAT' && iptables -t nat -S POSTROUTING | sed -n '2p' | grep -q -- '-j WGOCT_HOP_SNAT' && iptables -t filter -S FORWARD | sed -n '2p' | grep -q -- '-j WGOCT_HOP_FWD'"
OWN=$(run 'iptables-save -t nat | grep WGOCT_HOP_; iptables-save -t filter | grep WGOCT_HOP_')
code=$(api "$(state 2 "[{\"listen_port\":$PORT,\"backend_ip\":\"192.0.2.10\",\"backend_port\":7,\"name\":\"t1\"}]")")
AFTER=$(run 'iptables-save -t nat | grep WGOCT_HOP_; iptables-save -t filter | grep WGOCT_HOP_')
[[ $code == 204 && $OWN == "$AFTER" ]] && { printf 'PASS idempotent rules\n'; PASS=$((PASS+1)); } || { printf 'FAIL idempotent rules\n'; FAIL=$((FAIL+1)); }
if (echo x >/dev/udp/$HOP_IP/$PORT) 2>/dev/null; then sleep 2; check 'UDP conntrack to backend 1' "(cat /proc/net/nf_conntrack 2>/dev/null || conntrack -L -p udp 2>/dev/null) | grep -E 'dst=$HOP_IP .*dport=$PORT .*src=192.0.2.10'"; else skip 'local UDP send to remote HOP_IP failed; conntrack path unavailable'; fi
code=$(api "$(state 3 "[{\"listen_port\":$PORT,\"backend_ip\":\"192.0.2.11\",\"backend_port\":7,\"name\":\"t1\"}]")")
SNAT_BEFORE=$(run 'iptables -t nat -S WGOCT_HOP_SNAT'); FWD_BEFORE=$(run 'iptables -t filter -S WGOCT_HOP_FWD')
check 'switch backend changes only DNAT and flushes old conntrack' "test '$code' = 204 && iptables -t nat -S WGOCT_HOP_DNAT | grep -q -- '--to-destination 192.0.2.11:7' && test \"\$(iptables -t nat -S WGOCT_HOP_SNAT)\" = '$SNAT_BEFORE' && test \"\$(iptables -t filter -S WGOCT_HOP_FWD)\" = '$FWD_BEFORE' && ! (cat /proc/net/nf_conntrack 2>/dev/null || conntrack -L -p udp 2>/dev/null) | grep -E 'dst=$HOP_IP .*dport=$PORT .*src=192.0.2.10'"
if (echo x >/dev/udp/$HOP_IP/$PORT) 2>/dev/null; then sleep 2; check 'new UDP conntrack to backend 2' "(cat /proc/net/nf_conntrack 2>/dev/null || conntrack -L -p udp 2>/dev/null) | grep -E 'dst=$HOP_IP .*dport=$PORT .*src=192.0.2.11'"; else skip 'local UDP send to remote HOP_IP failed; conntrack path unavailable'; fi
ORIG=$(run "iptables-save | grep 'wgoct:hop:$PORT '")
code=$(api "$(state 4 "[{\"listen_port\":$PORT,\"backend_ip\":\"192.0.2.11\",\"backend_port\":7,\"name\":\"t1\"},{\"listen_port\":$((PORT+1)),\"backend_ip\":\"192.0.2.10\",\"backend_port\":7,\"name\":\"t2\"}]")")
[[ $code == 204 && $ORIG == "$(run "iptables-save | grep 'wgoct:hop:$PORT '")" ]] && check 'second route installed without changing first' "iptables -t nat -S WGOCT_HOP_DNAT | grep -q -- '--dport $((PORT+1))'" || { printf 'FAIL second route install/preservation\n'; FAIL=$((FAIL+1)); }
code=$(api "$(state 5 "[{\"listen_port\":$PORT,\"backend_ip\":\"192.0.2.11\",\"backend_port\":7,\"name\":\"t1\"}]")")
check 'second route removed' "test '$code' = 204 && ! iptables -t nat -S WGOCT_HOP_DNAT | grep -q -- '--dport $((PORT+1))'"
run "docker run -d --name $DISABLED --network host --cap-add NET_ADMIN --device /dev/net/tun -v $DIR/token2:/run/token:ro -v $DIR/state2:/var/lib/wgoctopus wgoctopus-agent:dev --listen 127.0.0.1:18081 --token-file /run/token >/dev/null" >/dev/null || { printf 'FAIL disabled agent start\n'; FAIL=$((FAIL+1)); }
for _ in $(seq 1 30); do [[ $(run "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/healthz") == 200 ]] && break; sleep 1; done
DISABLED_CODE=$(run "printf '%s' '{\"revision\":1,\"interfaces\":[],\"hop\":{\"wan_interface\":\"$WAN\",\"hop_ip\":\"$HOP_IP\",\"routes\":[]}}' >/tmp/e2e-disabled.json; curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'Authorization: Bearer $TOKEN2' -H 'Content-Type: application/json' --data-binary @/tmp/e2e-disabled.json http://127.0.0.1:18081/v1/state")
[[ $DISABLED_CODE == 422 ]] && { printf 'PASS hop disabled rejection\n'; PASS=$((PASS+1)); } || { printf 'FAIL hop disabled response %s\n' "$DISABLED_CODE"; FAIL=$((FAIL+1)); }
run "docker rm -f $DISABLED >/dev/null" >/dev/null
REV=$(run "curl -fsS -H 'Authorization: Bearer $TOK' http://127.0.0.1:18080/v1/state | jq -r .revision")
run "docker restart $AGENT >/dev/null" >/dev/null
for _ in $(seq 1 30); do [[ $(run "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/healthz") == 200 ]] && break; sleep 1; done
RESTORED=$(run "curl -fsS -H 'Authorization: Bearer $TOK' http://127.0.0.1:18080/v1/state | jq -r .revision")
[[ $REV == "$RESTORED" ]] && check 'restart restores hop rules' "iptables -t nat -S WGOCT_HOP_DNAT | grep -q -- '--to-destination 192.0.2.11:7'" || { printf 'FAIL restart persistence/rules\n'; FAIL=$((FAIL+1)); }
code=$(run "printf '%s' '{\"revision\":6,\"interfaces\":[]}' >/tmp/e2e-empty.json; curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'Authorization: Bearer $TOK' -H 'Content-Type: application/json' --data-binary @/tmp/e2e-empty.json http://127.0.0.1:18080/v1/state")
[[ $code == 204 ]] && { printf 'PASS hop removal\n'; PASS=$((PASS+1)); } || { printf 'FAIL hop removal (%s)\n' "$code"; FAIL=$((FAIL+1)); }
check 'hop chains and jumps removed; baseline and Docker rules unchanged' "! iptables-save | grep -q WGOCT_HOP && test \"\$(iptables -S | wc -l)\" = '$FILTER_BEFORE' && test \"\$(iptables -t nat -S | wc -l)\" = '$NAT_BEFORE' && test \"\$(iptables-save | grep -E -- '(^-N DOCKER|^-A .*DOCKER)' | sort)\" = '$DOCKER_RULES_BEFORE'"
exit "$((FAIL > 0))"
