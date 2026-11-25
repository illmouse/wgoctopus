#!/bin/sh
# Local UI stand: orchestrator from the working tree in Docker, demo data, no real hosts.
#   scripts/ui-stand.sh up       start (seeds on first run), prints URL and accounts
#   scripts/ui-stand.sh restart  pick up code/template changes
#   scripts/ui-stand.sh logs | down | reset
# Source is mounted, so templates and Python changes need only `restart`.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
dir=${UI_STAND_DIR:-/tmp/wgoctopus-ui-stand}
name=wgoctopus-ui-stand
port=${UI_STAND_PORT:-18080}
case "${1:-up}" in
  down) docker rm -f "$name" >/dev/null 2>&1 || true ;;
  reset) docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$dir/data" ;;
  logs) docker logs -f "$name" ;;
  restart) docker restart "$name" >/dev/null; echo "restarted: http://127.0.0.1:$port/" ;;
  up)
    docker rm -f "$name" >/dev/null 2>&1 || true
    mkdir -p "$dir/data" "$dir/home"
    [ -f "$dir/master.key" ] || python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' > "$dir/master.key"
    [ -f "$dir/api.token" ] || python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > "$dir/api.token"
    docker run -d --name "$name" --user "$(id -u):$(id -g)" -p "127.0.0.1:$port:8080" \
      -e HOME=/home/stand -e PATH=/home/stand/.local/bin:/usr/local/bin:/usr/bin:/bin \
      -e WGOCTOPUS_MASTER_KEY="$(cat "$dir/master.key")" -e WGOCTOPUS_API_TOKEN="$(cat "$dir/api.token")" \
      -e WGOCTOPUS_DATABASE_URL=sqlite:////data/stand.db -e WGOCTOPUS_API_HOST=0.0.0.0 \
      -e WGOCTOPUS_WEB_COOKIE_SECURE=false -e WGOCTOPUS_FAILOVER_MODE=confirm -e WGOCTOPUS_FAILOVER_EVAL_INTERVAL=86400 \
      -e WGOCTOPUS_BOOTSTRAP_FILE=/work/scripts/ui-stand/bootstrap.yaml -e STAND_AGENT_TOKEN=stand-agent-token \
      -e WGOCTOPUS_AGENT_REQUEST_TIMEOUT=1 \
      -v "$root:/work" -v "$dir/data:/data" -v "$dir/home:/home/stand" -w /work/orchestrator \
      python:3.12-slim sh -c '
        pip install -q -e . >/dev/null 2>&1 &&
        { [ -e /data/.seeded ] || { python /work/scripts/ui-stand/seed.py /work/scripts/ui-stand/bootstrap.yaml && touch /data/.seeded; }; } &&
        exec python -m wgoctopus_orch' >/dev/null
    i=0
    until curl -fs "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; do
      i=$((i+1)); [ "$i" -lt 120 ] || { docker logs --tail 40 "$name"; exit 1; }; sleep 1
    done
    sleep 3
    docker exec "$name" python /work/scripts/ui-stand/pending.py
    echo "UI stand: http://127.0.0.1:$port/"
    echo "accounts: admin / ops (operator) / view (viewer), password stand-password-1"
    echo "/v1 bearer token: $dir/api.token" ;;
  *) echo "usage: $0 up|restart|logs|down|reset" >&2; exit 2 ;;
esac
