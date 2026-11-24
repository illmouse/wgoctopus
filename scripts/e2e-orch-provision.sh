#!/usr/bin/env bash
# E2E for orchestrator-driven host provisioning: a local orchestrator installs
# docker (if needed), a restricted management user, the agent token and the agent
# container on a real host over SSH, then reconciles the node through that user.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HOST=${1:-}
[[ -n $HOST ]] || { printf 'Usage: %s root@HOST\n' "$0" >&2; exit 2; }
SSH_OPTS=${SSH_OPTS:--i /home/ill/.ssh/id_rsa -o StrictHostKeyChecking=accept-new}
E2E_BASELINE_FILTER=${E2E_BASELINE_FILTER:-}
E2E_BASELINE_NAT=${E2E_BASELINE_NAT:-}
ORCH=woct-orch-prov-$$
NODENAME=woct-prov-node
MGMT=wgoctopus
IMAGE=wgoctopus-agent:dev
TMP=$(mktemp -d)
PASS=0 FAIL=0
FILTER_BEFORE= NAT_BEFORE= CONTAINERS_BEFORE=
TOKEN=$(openssl rand -hex 32)
AGENT_TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" >"$TMP/api-token"; chmod 600 "$TMP/api-token"
openssl rand -base64 32 | tr -d '\n' >"$TMP/master-key"; chmod 600 "$TMP/master-key"
cp "${SSH_KEY:-/home/ill/.ssh/id_rsa}" "$TMP/id_rsa"; chmod 600 "$TMP/id_rsa"
mkdir -p "$TMP/db"

freeport() { local p; for p in $(seq "$1" "$2"); do if ! ss -H -ltn "sport = :$p" | grep -q .; then echo "$p"; return; fi; done; return 1; }
API=$(freeport 19100 19199) || exit 1

remote() { ssh $SSH_OPTS "$HOST" "bash -s" <<<"$1"; }
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then printf 'PASS %s\n' "$label"; PASS=$((PASS+1)); else printf 'FAIL %s\n' "$label"; FAIL=$((FAIL+1)); docker logs --tail 30 "$ORCH" 2>&1 | sed -E 's/(Bearer |token[=: ]+)[A-Za-z0-9._-]+/\1[REDACTED]/Ig' >&2; fi; }
pyjson() { python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if ($1) else 1)"; }
wait_for() { local i; for i in $(seq 1 "$1"); do if "${@:2}" >/dev/null 2>&1; then return 0; fi; sleep 1; done; return 1; }
node_json() { api "http://127.0.0.1:$API/v1/nodes/$NID"; }
job_json() { api "http://127.0.0.1:$API/v1/provision/jobs/$1"; }
job_done() { job_json "$1" | pyjson 'd["state"] in ("succeeded","failed","cancelled")'; }
job_ok() { job_json "$1" | pyjson 'd["state"]=="succeeded"'; }
in_sync() { node_json | pyjson 'd.get("reconciler",{}).get("state")=="IN_SYNC" and d.get("observed",{}).get("applied_revision")==d.get("desired_revision")'; }
run_job() {
  local jid
  jid=$(api -d "$1" "http://127.0.0.1:$API/v1/nodes/$NID/provision" | jq -r .job_id) || return 1
  [[ -n $jid && $jid != null ]] || return 1
  JID=$jid
  wait_for "${2:-600}" job_done "$jid"
}
step_states() { job_json "$1" | jq -r '[.steps[] | "\(.name)=\(.state)"] | join(",")'; }
start_orch() {
  docker rm -f "$ORCH" >/dev/null 2>&1
  docker run -d --name "$ORCH" --network host --user "$(id -u):$(id -g)" -e USER="${HOST%@*}" -e LOGNAME="${HOST%@*}" \
    -v "$TMP:/run/e2e:ro" -v "$TMP/db:/var/lib/wgoctopus" \
    -e WGOCTOPUS_MASTER_KEY_FILE=/run/e2e/master-key -e WGOCTOPUS_API_TOKEN_FILE=/run/e2e/api-token \
    -e WGOCTOPUS_TRANSPORT=ssh -e WGOCTOPUS_SSH_KEY_FILE=/run/e2e/id_rsa \
    -e WGOCTOPUS_SSH_KNOWN_HOSTS=/var/lib/wgoctopus/known_hosts -e WGOCTOPUS_SSH_TOFU=true -e WGOCTOPUS_SSH_CONNECT_TIMEOUT=10 \
    -e WGOCTOPUS_RECONCILE_INTERVAL=5 -e WGOCTOPUS_RECONCILE_BLOCKED_RECHECK=10 -e WGOCTOPUS_RECONCILER_ENABLED=true -e WGOCTOPUS_AUTO_MIGRATE=true \
    -e WGOCTOPUS_FAILOVER_MODE=off -e WGOCTOPUS_API_HOST=0.0.0.0 -e WGOCTOPUS_API_PORT="$API" \
    wgoctopus-orchestrator:dev >/dev/null || return 1
  wait_for 60 curl -fsS "http://127.0.0.1:$API/readyz"
}
cleanup() {
  set +e
  docker logs "$ORCH" 2>&1 | tail -n 30 | sed -E 's/(Bearer |token[=: ]+)[A-Za-z0-9._-]+/\1[REDACTED]/Ig' >&2
  docker rm -f "$ORCH" >/dev/null 2>&1
  remote "docker rm -f wgoctopus-agent >/dev/null 2>&1 || true; docker volume rm wgoctopus-agent-state >/dev/null 2>&1 || true; ip link del woct0 2>/dev/null || true; for t in filter nat; do for c in WGOCT_FWD WGOCT_NAT; do while iptables -t \$t -S 2>/dev/null | grep -q -- \"-j \$c\"; do iptables -t \$t -D FORWARD -j \$c 2>/dev/null || iptables -t \$t -D POSTROUTING -j \$c 2>/dev/null || break; done; iptables -t \$t -F \$c 2>/dev/null || true; iptables -t \$t -X \$c 2>/dev/null || true; done; done; pkill -KILL -u $MGMT; sleep 1; userdel -r $MGMT >/dev/null 2>&1 || true; rm -rf /etc/wgoctopus /etc/sysctl.d/99-wgoctopus.conf" >/dev/null 2>&1
  if [[ -n $FILTER_BEFORE ]]; then
    local f n c
    f=$(remote 'iptables -S | wc -l' 2>/dev/null); n=$(remote 'iptables -t nat -S | wc -l' 2>/dev/null)
    [[ $f == "$FILTER_BEFORE" && $n == "$NAT_BEFORE" ]] && { printf 'PASS host firewall baseline %s/%s\n' "$f" "$n"; PASS=$((PASS+1)); } || { printf 'FAIL host firewall baseline %s/%s (before %s/%s)\n' "$f" "$n" "$FILTER_BEFORE" "$NAT_BEFORE"; FAIL=$((FAIL+1)); }
    c=$(remote 'docker ps -q --no-trunc | sort' 2>/dev/null)
    [[ $c == "$CONTAINERS_BEFORE" ]] && { printf 'PASS host containers restored\n'; PASS=$((PASS+1)); } || { printf 'FAIL host containers differ\n'; FAIL=$((FAIL+1)); }
    check 'management user removed' remote "! id $MGMT >/dev/null 2>&1"
    check 'test interface absent' remote 'ip link show woct0 >/dev/null 2>&1 && exit 1 || exit 0'
  fi
  rm -rf "$TMP"
  printf '\nE2E orchestrator provisioning: %d PASS, %d FAIL\n' "$PASS" "$FAIL"
  [[ $FAIL == 0 ]]
}
trap cleanup EXIT

command -v jq >/dev/null || { printf 'jq is required locally\n'; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || make -C "$ROOT" agent-image || exit 1
docker image inspect wgoctopus-orchestrator:dev >/dev/null 2>&1 || make -C "$ROOT" orch-image || exit 1
remote 'command -v docker >/dev/null' || { printf 'FAIL docker must be present on the test host\n'; exit 1; }
FILTER_BEFORE=$(remote 'iptables -S | wc -l') || exit 1
NAT_BEFORE=$(remote 'iptables -t nat -S | wc -l') || exit 1
CONTAINERS_BEFORE=$(remote 'docker ps -q --no-trunc | sort') || exit 1
[[ -z $E2E_BASELINE_FILTER || $FILTER_BEFORE == "$E2E_BASELINE_FILTER" ]] || { printf 'FAIL unexpected filter baseline\n'; exit 1; }
[[ -z $E2E_BASELINE_NAT || $NAT_BEFORE == "$E2E_BASELINE_NAT" ]] || { printf 'FAIL unexpected nat baseline\n'; exit 1; }
[[ -z $CONTAINERS_BEFORE ]] || { printf 'FAIL host already runs containers; use an empty test host\n'; exit 1; }
remote "id $MGMT >/dev/null 2>&1 && exit 1; [ ! -e /etc/wgoctopus ]" || { printf 'FAIL host already has %s user or /etc/wgoctopus\n' "$MGMT"; exit 1; }

# The image is delivered by the orchestrator (docker load), not pre-shipped.
docker save "$IMAGE" -o "$TMP/agent.tar" || exit 1
chmod 644 "$TMP/agent.tar"
remote "docker image rm -f $IMAGE >/dev/null 2>&1 || true"

start_orch || { docker logs "$ORCH" >&2; exit 1; }
HOSTADDR=${HOST#*@}
instance=$(api -d '{"name":"woct0","listen_port":23440,"address":"10.222.0.1/24"}' "http://127.0.0.1:$API/v1/instances") || exit 1
IID=$(jq -r .id <<<"$instance")
node=$(api -d "{\"name\":\"$NODENAME\",\"ssh_host\":\"$HOSTADDR\",\"ssh_user\":\"${HOST%@*}\",\"agent_port\":18080,\"agent_token\":\"$AGENT_TOKEN\"}" "http://127.0.0.1:$API/v1/nodes") || exit 1
NID=$(jq -r .id <<<"$node")
api -X PUT -d '{"role":"active"}' "http://127.0.0.1:$API/v1/instances/$IID/placements/$NID" >/dev/null || exit 1
api -d '{"name":"peer-one"}' "http://127.0.0.1:$API/v1/instances/$IID/peers" >/dev/null || exit 1

OPTS="{\"options\":{\"image\":\"$IMAGE\",\"image_archive\":\"/run/e2e/agent.tar\",\"mgmt_user\":\"$MGMT\",\"health_attempts\":60,\"health_interval\":2}}"

# Unknown options are rejected before any work.
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"options":{"bogus":1}}' "http://127.0.0.1:$API/v1/nodes/$NID/provision")
check 'unknown provision option rejected' test "$code" = 422

# Protected nodes require explicit confirmation.
api -X PATCH -d '{"protected":true}' "http://127.0.0.1:$API/v1/nodes/$NID" >/dev/null
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$OPTS" "http://127.0.0.1:$API/v1/nodes/$NID/provision")
check 'protected node needs confirmation' test "$code" = 409
api -X PATCH -d '{"protected":false}' "http://127.0.0.1:$API/v1/nodes/$NID" >/dev/null

run_job "$OPTS"
J1=$JID
check 'first provisioning job succeeded' job_ok "$J1"
printf 'steps: %s\n' "$(step_states "$J1")"
check 'no secrets in job log' bash -c "! curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$API/v1/provision/jobs/$J1 | grep -q '$AGENT_TOKEN'"
check 'agent image loaded from archive' remote "docker image inspect $IMAGE >/dev/null"
check 'agent container running' remote "[ \"\$(docker inspect -f '{{.State.Running}}' wgoctopus-agent)\" = true ]"
check 'token file mode 0600 and not world readable' remote "[ \"\$(stat -c %a /etc/wgoctopus/token)\" = 600 ]"
check 'management user key is restricted' remote "grep -q '^restrict,port-forwarding,permitopen=\"127.0.0.1:18080\" ' /home/$MGMT/.ssh/authorized_keys"
check 'management user has no shell' bash -c "! ssh $SSH_OPTS -o BatchMode=yes $MGMT@$HOSTADDR true"
check 'ip_forward enabled' remote '[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]'
check 'node ssh_user switched to management user' bash -c "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$API/v1/nodes/$NID | jq -e '.ssh_user==\"$MGMT\"'"

# The node must now converge through the restricted user's forward only.
check 'node reconciled via management user' wait_for 120 in_sync
check 'interface, address, UDP port and tagged rules' remote "ip link show woct0 | grep -q UP && ip -4 addr show woct0 | grep -q '10.222.0.1/24' && ss -ulnp | grep -q ':23440' && iptables -S | grep -q 'wgoct:'"

# Re-provisioning is idempotent: same container, steps skipped.
CID1=$(remote 'docker inspect -f "{{.Id}}" wgoctopus-agent')
run_job "$OPTS"
J2=$JID
check 'second provisioning job succeeded' job_ok "$J2"
printf 'steps: %s\n' "$(step_states "$J2")"
check 'agent container unchanged by re-provisioning' test "$(remote 'docker inspect -f "{{.Id}}" wgoctopus-agent')" = "$CID1"
check 'node still in sync after re-provisioning' wait_for 60 in_sync
check 'provision events recorded' bash -c "curl -fsS -H 'Authorization: Bearer $TOKEN' 'http://127.0.0.1:$API/v1/events?limit=200' | jq -e '[.[] | select(.kind==\"provision.succeeded\")] | length >= 2'"
check 'provision metric exposes succeeded jobs' bash -c "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$API/metrics | grep -q '^wgoctopus_provision_jobs{state=\"succeeded\"} 2'"

# Cleanup of the host happens in the EXIT trap.
