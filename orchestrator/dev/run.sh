#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/orchestrator"
python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
mkdir -p .dev
if python3 -m venv .venv 2>/dev/null; then
    .venv/bin/pip install -e '.[dev]'
    export WGOCTOPUS_DATABASE_URL="sqlite:///$ROOT/orchestrator/.dev/dev.db"
    export WGOCTOPUS_MASTER_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    export WGOCTOPUS_WEB_COOKIE_SECURE=false WGOCTOPUS_WEB_ENABLED=true
    export WGOCTOPUS_API_TOKEN=local-only-dev-api-token
    export WGOCTOPUS_API_HOST=127.0.0.1 WGOCTOPUS_API_PORT=8080 WGOCTOPUS_TRANSPORT=direct
    export WGOCTOPUS_ALERTS_ENABLED=false WGOCTOPUS_AUTO_MIGRATE=true
    .venv/bin/python dev/seed.py
    exec .venv/bin/uvicorn wgoctopus_orch.api:create_app --factory --host 127.0.0.1 --port 8080 --reload --reload-dir "$ROOT/orchestrator/src" --reload-dir "$ROOT/orchestrator/dev"
fi

command -v docker >/dev/null || { echo "Python venv support (python3-venv) or Docker is required" >&2; exit 1; }
exec docker run --rm -p 127.0.0.1:8080:8080 \
    -v "$ROOT/orchestrator:/work/orchestrator" -v "$ROOT/schema:/work/schema:ro" \
    -w /work/orchestrator -e PYTHONPATH=/work/orchestrator/src \
    -e WGOCTOPUS_DATABASE_URL=sqlite:////work/orchestrator/.dev/dev.db \
    -e WGOCTOPUS_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
    -e WGOCTOPUS_WEB_COOKIE_SECURE=false -e WGOCTOPUS_WEB_ENABLED=true \
    -e WGOCTOPUS_API_TOKEN=local-only-dev-api-token \
    -e WGOCTOPUS_API_HOST=0.0.0.0 -e WGOCTOPUS_API_PORT=8080 \
    -e WGOCTOPUS_TRANSPORT=direct -e WGOCTOPUS_ALERTS_ENABLED=false \
    -e WGOCTOPUS_AUTO_MIGRATE=true python:3.12-slim sh -c \
    'pip install -e ".[dev]" && python dev/seed.py && uvicorn wgoctopus_orch.api:create_app --factory --host 0.0.0.0 --port 8080 --reload --reload-dir src --reload-dir dev'
