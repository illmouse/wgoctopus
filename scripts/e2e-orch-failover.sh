#!/usr/bin/env bash
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HOST=${1:-}; [[ -n $HOST ]] || { printf 'Usage: %s root@HOST\n' "$0" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:-"-i $HOME/.ssh/id_rsa -o StrictHostKeyChecking=accept-new"}
E2E_PROTECTED_IDS=${E2E_PROTECTED_IDS:-}
SUFFIX=$$
ORCH=woct-orch-fo-$SUFFIX; NET=woct-e2e-net-$SUFFIX
HOP=woct-fo-hop-$SUFFIX; SERVER=woct-fo-server-$SUFFIX; STANDBY=woct-fo-standby-$SUFFIX; RUNNER=woct-fo-runner-$SUFFIX
HV=woct-fo-hop-state-$SUFFIX; SV=woct-fo-server-state-$SUFFIX; BV=woct-fo-standby-state-$SUFFIX; RV=woct-fo-runner-state-$SUFFIX
DIR=/opt/woct-e2e-fo-$SUFFIX; TMP=$(mktemp -d)
API=; HP=; SP=; BP=; RP=; PASS=0; FAIL=0; SKIP=0; GUARDED=0
FILTER_BEFORE=; NAT_BEFORE=; CONTAINERS_BEFORE=; ALL_CONTAINERS_BEFORE=; VOLUMES_BEFORE=
TOKEN=$(openssl rand -hex 32); HT=$(openssl rand -hex 32); ST=$(openssl rand -hex 32); BT=$(openssl rand -hex 32); RT=$(openssl rand -hex 32)
printf '%s' "$TOKEN" >"$TMP/api-token"; printf '%s' "$(openssl rand -base64 32 | tr -d '\n')" >"$TMP/master-key"
for f in api-token master-key; do chmod 600 "$TMP/$f"; done
mkdir -p "$TMP/db"
cp "${SSH_KEY:-$HOME/.ssh/id_rsa}" "$TMP/id_rsa"; chmod 600 "$TMP/id_rsa"
remote() { ssh $SSH_OPTS "$HOST" bash -s <<<"$1"; }
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then printf 'PASS %s\n' "$label"; PASS=$((PASS+1)); else printf 'FAIL %s\n' "$label"; FAIL=$((FAIL+1)); fi; }
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
node_json() { api "http://127.0.0.1:$API/v1/nodes/$1"; }
wait_sync() {
  local id=$1 i d
  for i in $(seq 1 90); do
    d=$(node_json "$id" 2>/dev/null || true)
    if jq -e '.reconciler.state == "IN_SYNC" and .observed.applied_revision == .desired_revision' <<<"$d" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}
wait_probe() {
  local wanted=$1 seconds=$2 i
  for i in $(seq 1 "$seconds"); do
    [[ $(api "http://127.0.0.1:$API/v1/probes/$PID" 2>/dev/null | jq -r '.status // empty' 2>/dev/null) == "$wanted" ]] && return 0
    sleep 1
  done
  return 1
}
cleanup() {
  set +e
  if [[ $GUARDED == 1 ]]; then
    remote "for spec in '$HOP:$HP:$HT' '$SERVER:$SP:$ST' '$STANDBY:$BP:$BT' '$RUNNER:$RP:$RT'; do IFS=: read -r name port token <<<\"\$spec\"; [ -n \"\$port\" ] || continue; s=\$(curl -fsS -H \"Authorization: Bearer \$token\" http://127.0.0.1:\$port/v1/state 2>/dev/null || true); if [ -n \"\$s\" ]; then r=\$(printf '%s' \"\$s\" | python3 -c 'import json,sys;print(json.load(sys.stdin)["revision"]+1)' 2>/dev/null); printf '{\"revision\":%s,\"interfaces\":[]}' \"\$r\" >/tmp/woct-empty-\$name.json; curl -fsS -X PUT -H \"Authorization: Bearer \$token\" -H 'Content-Type: application/json' --data-binary @/tmp/woct-empty-\$name.json http://127.0.0.1:\$port/v1/state >/dev/null 2>&1 || true; rm -f /tmp/woct-empty-\$name.json; fi; done
      docker rm -f '$HOP' '$SERVER' '$STANDBY' '$RUNNER' >/dev/null 2>&1 || true
      docker network rm '$NET' >/dev/null 2>&1 || true
      iptables -D FORWARD -i woct-e2e0 -o woct-e2e0 -p udp -j WGOCT_HOP_FWD 2>/dev/null || true
      iptables -t nat -D PREROUTING -d 198.51.100.1/32 -i woct-e2e0 -p udp -j WGOCT_HOP_DNAT 2>/dev/null || true
      iptables -t nat -D POSTROUTING -o woct-e2e0 -p udp -j WGOCT_HOP_SNAT 2>/dev/null || true
      for table in nat filter; do for chain in WGOCT_HOP_DNAT WGOCT_HOP_SNAT WGOCT_HOP_FWD; do iptables -t \$table -F \$chain 2>/dev/null || true; iptables -t \$table -X \$chain 2>/dev/null || true; done; done
      docker volume rm '$HV' '$SV' '$BV' '$RV' >/dev/null 2>&1 || true; rm -rf '$DIR'"
  fi
  [[ -z $ORCH ]] || docker rm -f "$ORCH" >/dev/null 2>&1
  if [[ -n $FILTER_BEFORE ]]; then
    local f n c ac v
    f=$(remote 'iptables -S | wc -l'); n=$(remote 'iptables -t nat -S | wc -l')
    [[ $f == "$FILTER_BEFORE" && $n == "$NAT_BEFORE" ]] && { printf 'PASS firewall baseline restored (%s/%s)\n' "$f" "$n"; PASS=$((PASS+1)); } || { printf 'FAIL firewall baseline restored (%s/%s; expected %s/%s)\n' "$f" "$n" "$FILTER_BEFORE" "$NAT_BEFORE"; FAIL=$((FAIL+1)); }
    c=$(remote 'docker ps -q --no-trunc | sort'); ac=$(remote 'docker ps -aq --no-trunc | sort'); v=$(remote 'docker volume ls -q | sort')
    [[ $c == "$CONTAINERS_BEFORE" && $ac == "$ALL_CONTAINERS_BEFORE" && $v == "$VOLUMES_BEFORE" ]] && { printf 'PASS container IDs and volumes restored\n'; PASS=$((PASS+1)); } || { printf 'FAIL container IDs or volumes changed\n'; FAIL=$((FAIL+1)); }
    check 'e2e bridge link removed' remote '! ip link show woct-e2e0'
    check 'no WGOCT_HOP chains remain' remote '! iptables-save | grep -q WGOCT_HOP'
    remote 'printf "Host cleanup evidence: filter=%s nat=%s\n" "$(iptables -S | wc -l)" "$(iptables -t nat -S | wc -l)"; docker ps -a --no-trunc; docker network ls; docker volume ls'
  fi
  rm -rf "$TMP"
  printf 'Summary: %d PASS, %d FAIL, %d SKIP\n' "$PASS" "$FAIL" "$SKIP"
  [[ $FAIL == 0 ]]
}
trap cleanup EXIT

command -v jq >/dev/null && command -v ss >/dev/null || { printf 'jq and ss are required locally\n'; exit 1; }
for p in $(seq 18900 18999); do if ! ss -H -ltn "sport = :$p" | grep -q .; then API=$p; break; fi; done
[[ -n $API ]] || { printf 'No local API port available\n'; exit 1; }
make -C "$ROOT" orch-image || exit 1
FILTER_BEFORE=$(remote 'iptables -S | wc -l') || exit 1
NAT_BEFORE=$(remote 'iptables -t nat -S | wc -l') || exit 1
CONTAINERS_BEFORE=$(remote 'docker ps -q --no-trunc | sort') || exit 1
ALL_CONTAINERS_BEFORE=$(remote 'docker ps -aq --no-trunc | sort') || exit 1
VOLUMES_BEFORE=$(remote 'docker volume ls -q | sort') || exit 1
for id in ${E2E_PROTECTED_IDS//,/ }; do [[ $CONTAINERS_BEFORE == *"$id"* ]] || { printf 'FAIL configured protected container missing\n'; exit 1; }; done
remote "! docker network inspect '$NET' >/dev/null 2>&1 && ! docker inspect '$HOP' '$SERVER' '$STANDBY' '$RUNNER' >/dev/null 2>&1 && ! docker volume inspect '$HV' '$SV' '$BV' '$RV' >/dev/null 2>&1 && ! ip -4 route show | grep -q '198.51.100.0/24' && ! ip link show woct-e2e0 >/dev/null 2>&1" || { printf 'FAIL subnet, bridge, or unique resource collision; refusing to continue\n'; exit 1; }
GUARDED=1
[[ ${E2E_SKIP_SHIP:-0} == 1 ]] || "$ROOT/scripts/ship-image.sh" wgoctopus-agent:dev "$HOST" || exit 1
PORTS=$(remote "python3 -c 'import socket; ss=[socket.socket() for _ in range(4)]; [s.bind((\"127.0.0.1\",0)) for s in ss]; print(\" \".join(str(s.getsockname()[1]) for s in ss)); [s.close() for s in ss]'" ) || exit 1
read -r HP SP BP RP <<<"$PORTS"
remote "mkdir -p '$DIR'; chmod 700 '$DIR'; printf '%s' '$HT' >'$DIR/hop-token'; printf '%s' '$ST' >'$DIR/server-token'; printf '%s' '$BT' >'$DIR/standby-token'; printf '%s' '$RT' >'$DIR/runner-token'; chmod 600 '$DIR/'*-token; docker volume create '$HV' >/dev/null; docker volume create '$SV' >/dev/null; docker volume create '$BV' >/dev/null; docker volume create '$RV' >/dev/null; docker network create --subnet 198.51.100.0/24 --gateway 198.51.100.1 -o com.docker.network.bridge.name=woct-e2e0 '$NET' >/dev/null
docker run -d --name '$HOP' --network host --cap-add NET_ADMIN --device /dev/net/tun -v '$DIR/hop-token:/run/token:ro' -v '$HV:/var/lib/wgoctopus' wgoctopus-agent:dev --hop-enabled --listen 127.0.0.1:$HP --token-file /run/token >/dev/null
docker run -d --name '$SERVER' --network '$NET' --ip 198.51.100.3 --cap-add NET_ADMIN --device /dev/net/tun -p 127.0.0.1:$SP:18080 -v '$DIR/server-token:/run/token:ro' -v '$SV:/var/lib/wgoctopus' wgoctopus-agent:dev --listen 0.0.0.0:18080 --allow-public-listen --token-file /run/token >/dev/null
docker run -d --name '$STANDBY' --network '$NET' --ip 198.51.100.4 --cap-add NET_ADMIN --device /dev/net/tun -p 127.0.0.1:$BP:18080 -v '$DIR/standby-token:/run/token:ro' -v '$BV:/var/lib/wgoctopus' wgoctopus-agent:dev --listen 0.0.0.0:18080 --allow-public-listen --token-file /run/token >/dev/null
docker run -d --name '$RUNNER' --network '$NET' --ip 198.51.100.2 --cap-add NET_ADMIN --device /dev/net/tun -p 127.0.0.1:$RP:18080 -v '$DIR/runner-token:/run/token:ro' -v '$RV:/var/lib/wgoctopus' wgoctopus-agent:dev --listen 0.0.0.0:18080 --allow-public-listen --token-file /run/token >/dev/null"
for pair in "$HP:$HT" "$SP:$ST" "$BP:$BT" "$RP:$RT"; do port=${pair%%:*}; tok=${pair#*:}; for i in $(seq 1 60); do [[ $(remote "curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer $tok' http://127.0.0.1:$port/healthz") == 200 ]] && break; sleep 1; done; done
docker run -d --name "$ORCH" --network host --user "$(id -u):$(id -g)" -e USER="${HOST%@*}" -e LOGNAME="${HOST%@*}" -v "$TMP:/run/e2e:ro" -v "$TMP/db:/var/lib/wgoctopus" -e WGOCTOPUS_MASTER_KEY_FILE=/run/e2e/master-key -e WGOCTOPUS_API_TOKEN_FILE=/run/e2e/api-token -e WGOCTOPUS_TRANSPORT=ssh -e WGOCTOPUS_SSH_KEY_FILE=/run/e2e/id_rsa -e WGOCTOPUS_SSH_KNOWN_HOSTS=/var/lib/wgoctopus/known_hosts -e WGOCTOPUS_SSH_TOFU=true -e WGOCTOPUS_RECONCILE_INTERVAL=2 -e WGOCTOPUS_FAILOVER_MODE=confirm -e WGOCTOPUS_FAILOVER_DOWN_SECONDS=20 -e WGOCTOPUS_FAILOVER_EVAL_INTERVAL=3 -e WGOCTOPUS_FAILOVER_COOLDOWN=5 -e WGOCTOPUS_FAILOVER_PROPOSAL_TTL=900 -e WGOCTOPUS_RECONCILER_ENABLED=true -e WGOCTOPUS_AUTO_MIGRATE=true -e WGOCTOPUS_API_HOST=0.0.0.0 -e WGOCTOPUS_API_PORT="$API" wgoctopus-orchestrator:dev >/dev/null || exit 1
for i in $(seq 1 60); do curl -fsS "http://127.0.0.1:$API/readyz" >/dev/null 2>&1 && break; sleep 1; done
check 'orchestrator ready' curl -fsS "http://127.0.0.1:$API/readyz"
auth=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')
printf 'Creating probe topology through API\n'
inst=$(api -d '{"name":"fo-e2e","listen_port":23552,"address":"10.224.0.1/24"}' "http://127.0.0.1:$API/v1/instances") || { printf 'FAIL creating instance\n'; exit 1; }
IID=$(jq -r .id <<<"$inst")
node_create() { api -d "$1" "http://127.0.0.1:$API/v1/nodes"; }
hop=$(node_create "{\"name\":\"fo-hop\",\"ssh_host\":\"${HOST#*@}\",\"ssh_user\":\"${HOST%@*}\",\"agent_port\":$HP,\"agent_token\":\"$HT\",\"kind\":\"hop\",\"wan_interface\":\"woct-e2e0\",\"hop_ip\":\"198.51.100.1\"}") || { printf 'FAIL creating hop node\n'; exit 1; }
server=$(node_create "{\"name\":\"fo-server\",\"ssh_host\":\"${HOST#*@}\",\"ssh_user\":\"${HOST%@*}\",\"agent_port\":$SP,\"agent_token\":\"$ST\",\"kind\":\"awg\",\"backend_ip\":\"198.51.100.3\"}") || { printf 'FAIL creating server node\n'; exit 1; }
runner=$(node_create "{\"name\":\"fo-runner\",\"ssh_host\":\"${HOST#*@}\",\"ssh_user\":\"${HOST%@*}\",\"agent_port\":$RP,\"agent_token\":\"$RT\",\"kind\":\"awg\",\"backend_ip\":\"198.51.100.2\"}") || { printf 'FAIL creating runner node\n'; exit 1; }
standby=$(node_create "{\"name\":\"fo-standby\",\"ssh_host\":\"${HOST#*@}\",\"ssh_user\":\"${HOST%@*}\",\"agent_port\":$BP,\"agent_token\":\"$BT\",\"kind\":\"awg\",\"backend_ip\":\"198.51.100.4\"}") || { printf 'FAIL creating standby node\n'; exit 1; }
BID=$(jq -r .id <<<"$standby")
HID=$(jq -r .id <<<"$hop"); SID=$(jq -r .id <<<"$server"); RID=$(jq -r .id <<<"$runner")
api -X PUT -d "{\"role\":\"active\"}" "http://127.0.0.1:$API/v1/instances/$IID/placements/$SID" >/dev/null || exit 1
api -X PUT -d '{"role":"standby"}' "http://127.0.0.1:$API/v1/instances/$IID/placements/$BID" >/dev/null || exit 1
api -X PUT -d '{}' "http://127.0.0.1:$API/v1/hops/$HID/links/$IID" >/dev/null || exit 1
probe=$(api -X POST -d "{\"hop_id\":$HID,\"instance_id\":$IID,\"runner_node_id\":$RID}" "http://127.0.0.1:$API/v1/probes") || exit 1
PID=$(jq -r .id <<<"$probe")
check 'hop reaches IN_SYNC' wait_sync "$HID"
check 'server reaches IN_SYNC' wait_sync "$SID"
check 'standby reaches IN_SYNC' wait_sync "$BID"
check 'runner reaches IN_SYNC' wait_sync "$RID"
check 'hop tagged DNAT targets server instance' remote "iptables -t nat -S WGOCT_HOP_DNAT | grep -F -- '--to-destination 198.51.100.3:23552' | grep -q 'wgoct:hop:23552'"
check 'probe becomes UP' wait_probe UP 150
probe_age_numeric() { api "http://127.0.0.1:$API/v1/probes/$PID" | jq -e '.handshake_age_seconds | type == "number"'; }
check 'probe exposes numeric handshake age' probe_age_numeric
check 'server observed a real peer handshake' remote "curl -fsS -H 'Authorization: Bearer $ST' http://127.0.0.1:$SP/metrics | grep -E '^wg_peer_last_handshake_timestamp_seconds[^ ]* [1-9][0-9.]*(e[+]?[0-9]+)?$'"
event_count() { api "http://127.0.0.1:$API/v1/events?limit=1000" | jq "[.[] | select(.kind == \"$1\")] | length"; }
event_count_is() { [[ $(event_count "$1") == "$2" ]]; }
event_exists() { [[ $(event_count "$1") -ge 1 ]]; }
check 'probe.up event exists' event_exists probe.up
pub=$(api "http://127.0.0.1:$API/v1/instances/$IID" | jq -r .public_key)
if [[ -z $pub || $pub == null ]]; then printf 'FAIL instance public key unavailable\n'; FAIL=$((FAIL+1)); else
  metrics=$(curl -fsS "http://127.0.0.1:$API/metrics"); probes=$(api "http://127.0.0.1:$API/v1/probes")
  if [[ $metrics$probes != *"$pub"* && $metrics$probes != *"$TOKEN"* && $metrics$probes != *"$HT"* && $metrics$probes != *"$ST"* && $metrics$probes != *"$RT"* ]]; then printf 'PASS probe and metrics secret safety\n'; PASS=$((PASS+1)); else printf 'FAIL probe and metrics secret safety\n'; FAIL=$((FAIL+1)); fi
fi

# ---- failover scenario ----
fo_list() { api "http://127.0.0.1:$API/v1/failovers?$1"; }
wait_proposal() {
  local i
  for i in $(seq 1 "$1"); do
    [[ $(fo_list 'state=pending' 2>/dev/null | jq 'length' 2>/dev/null) == 1 ]] && return 0
    sleep 1
  done
  return 1
}
check 'no proposal while path is healthy' bash -c "[[ \$(curl -fsS -H 'Authorization: Bearer $TOKEN' 'http://127.0.0.1:$API/v1/failovers' | jq length) == 0 ]]"
printf 'Killing active backend container\n'
remote "docker stop '$SERVER' >/dev/null"
check 'probe becomes DOWN after active backend dies' wait_probe DOWN 330
check 'failover proposal created (confirm mode)' wait_proposal 120
FID=$(fo_list 'state=pending' | jq -r '.[0].id')
check 'proposal targets standby node' bash -c "[[ \$(curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$API/v1/failovers/$FID | jq -r '.from_node_id == $SID and .to_node_id == $BID') == true ]]"
check 'failover.proposed event exists' event_exists failover.proposed
check 'hop still points to dead backend (no auto switch in confirm mode)' remote "iptables -t nat -S WGOCT_HOP_DNAT | grep -F -- '--to-destination 198.51.100.3:23552'"
sleep 8
check 'only one pending proposal (no duplicates)' bash -c "[[ \$(curl -fsS -H 'Authorization: Bearer $TOKEN' 'http://127.0.0.1:$API/v1/failovers?state=pending' | jq length) == 1 ]]"
conf=$(api -X POST "http://127.0.0.1:$API/v1/failovers/$FID/confirm") || conf='{}'
check 'confirm executes proposal' bash -c "[[ \$(jq -r '.state' <<<'$conf') == executed ]]"
check 'proposal decided by api' bash -c "[[ \$(jq -r '.decided_by' <<<'$conf') == api ]]"
check 'second confirm is rejected with 409' bash -c "[[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$API/v1/failovers/$FID/confirm) == 409 ]]"
check 'hop converges after switch' wait_sync "$HID"
check 'hop DNAT now targets standby' remote "iptables -t nat -S WGOCT_HOP_DNAT | grep -F -- '--to-destination 198.51.100.4:23552' | grep -q 'wgoct:hop:23552'"
check 'old backend DNAT removed' remote "! iptables -t nat -S WGOCT_HOP_DNAT | grep -F -- '198.51.100.3'"
check 'instance.switched event exists' event_exists instance.switched
check 'failover.executed event exists' event_exists failover.executed
check 'probe returns UP via standby' wait_probe UP 240
check 'standby observed a real peer handshake' remote "curl -fsS -H 'Authorization: Bearer $BT' http://127.0.0.1:$BP/metrics | grep -E '^wg_peer_last_handshake_timestamp_seconds[^ ]* [1-9][0-9.]*(e[+]?[0-9]+)?$'"
metric_executed_is_one() { curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$API/metrics" | grep -qE '^wgoctopus_failover_proposals[{]state="executed"[}] 1$'; }
check 'failover metrics report executed proposal' metric_executed_is_one
sleep 10
check 'no new proposal after recovery' bash -c "[[ \$(curl -fsS -H 'Authorization: Bearer $TOKEN' 'http://127.0.0.1:$API/v1/failovers?state=pending' | jq length) == 0 ]]"
