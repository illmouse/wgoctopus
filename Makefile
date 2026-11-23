.PHONY: help schema-check schema-validate ship agent-image orchestrator-image orch-image orch-smoke agent-build agent-test e2e e2e-orch e2e-hop e2e-probe e2e-orch-hop e2e-orch-probe e2e-orch-failover orch-test orch-lint

help:
	@printf '%s\n' 'Targets: help schema-check ship IMAGE=.. HOST=.. agent-build agent-test agent-image orchestrator-image e2e e2e-orch e2e-hop e2e-probe e2e-orch-hop e2e-orch-probe e2e-orch-failover HOST=.. orch-test orch-lint'

e2e:
	@./scripts/e2e.sh local

e2e-orch:
	@test -n "$(HOST)" || { printf '%s\n' 'Usage: make e2e-orch HOST=root@host' >&2; exit 2; }
	@./scripts/e2e-orch.sh "$(HOST)"

e2e-hop:
	@test -n "$(HOST)" || { printf '%s\n' 'Usage: make e2e-hop HOST=root@host' >&2; exit 2; }
	@./scripts/e2e-hop.sh "$(HOST)"

e2e-probe:
	@test -n "$(HOST)" || { printf '%s\n' 'Usage: make e2e-probe HOST=root@host' >&2; exit 2; }
	@./scripts/e2e-probe.sh "$(HOST)"

e2e-orch-hop:
	@test -n "$(HOST)" || { printf '%s\n' 'Usage: make e2e-orch-hop HOST=root@host' >&2; exit 2; }
	@./scripts/e2e-orch-hop.sh "$(HOST)"

e2e-orch-probe:
	@test -n "$(HOST)" || { printf '%s\n' 'Usage: make e2e-orch-probe HOST=root@host' >&2; exit 2; }
	@./scripts/e2e-orch-probe.sh "$(HOST)"

e2e-orch-failover:
	@test -n "$(HOST)" || { printf '%s\n' 'Usage: make e2e-orch-failover HOST=root@host' >&2; exit 2; }
	@./scripts/e2e-orch-failover.sh "$(HOST)"

schema-check:
	@if command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then \
		$(MAKE) schema-validate; \
	else \
	if python3 -c 'import jsonschema' >/dev/null 2>&1; then \
		python3 -c 'import json, jsonschema; schema=json.load(open("schema/state.schema.json")); data=json.load(open("schema/examples/state.example.json")); jsonschema.Draft202012Validator(schema).validate(data); print("schema example valid")'; \
	else \
		printf '%s\n' 'WARNING: python3 jsonschema is unavailable; checking JSON syntax only'; \
		python3 -c 'import json, pathlib; json.load(open("schema/state.schema.json")); [json.load(p.open()) for p in pathlib.Path("schema/examples").glob("*.json")]; print("JSON syntax valid")'; \
	fi; \
	fi

schema-validate:
	@if [ ! -d /tmp/opencode/ajv/node_modules ]; then \
		mkdir -p /tmp/opencode/ajv && cd /tmp/opencode/ajv && npm init -y >/dev/null 2>&1; \
		cd /tmp/opencode/ajv && npm i ajv ajv-formats --no-audit --no-fund; \
	fi
	@NODE_PATH=/tmp/opencode/ajv/node_modules node scripts/schema-validate.js

ship:
	@test -n "$(IMAGE)" -a -n "$(HOST)" || { printf '%s\n' 'Usage: make ship IMAGE=<image:tag> HOST=<ssh-target>' >&2; exit 2; }
	@./scripts/ship-image.sh "$(IMAGE)" "$(HOST)"

agent-build:
	go build -o build/wgoctopus-agent ./cmd/wgoctopus-agent

agent-test:
	go test -race ./...

agent-image:
	docker build -f agent/Dockerfile -t wgoctopus-agent:dev --build-arg VERSION=dev .

orchestrator-image:
	$(MAKE) orch-image

orch-image:
	docker build -f orchestrator/Dockerfile -t wgoctopus-orchestrator:dev .

orch-smoke:
	@./scripts/orch-smoke.sh

orch-test:
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp -e PIP_CACHE_DIR=/tmp/pip -v "$(CURDIR):/work" -w /work/orchestrator python:3.12-slim sh -c 'pip install -e ".[dev]" && PATH=/tmp/.local/bin:$$PATH pytest --cov=wgoctopus_orch --cov-report=term-missing --cov-fail-under=85 -q'

orch-lint:
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp -e PIP_CACHE_DIR=/tmp/pip -v "$(CURDIR):/work" -w /work/orchestrator python:3.12-slim sh -c 'pip install -e ".[dev]" && PATH=/tmp/.local/bin:$$PATH ruff check src tests migrations'
