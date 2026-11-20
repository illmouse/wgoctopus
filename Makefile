.PHONY: help schema-check ship agent-image orchestrator-image orch-image orch-smoke agent-build agent-test e2e orch-test orch-lint

help:
	@printf '%s\n' 'Targets: help schema-check ship IMAGE=.. HOST=.. agent-build agent-test agent-image orchestrator-image e2e orch-test orch-lint'

e2e:
	@./scripts/e2e.sh local

schema-check:
	@if python3 -c 'import jsonschema' >/dev/null 2>&1; then \
		python3 -c 'import json, jsonschema; schema=json.load(open("schema/state.schema.json")); data=json.load(open("schema/examples/state.example.json")); jsonschema.Draft202012Validator(schema).validate(data); print("schema example valid")'; \
	else \
		printf '%s\n' 'WARNING: python3 jsonschema is unavailable; checking JSON syntax only'; \
		python3 -c 'import json; json.load(open("schema/state.schema.json")); json.load(open("schema/examples/state.example.json")); print("JSON syntax valid")'; \
	fi

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
