.PHONY: help schema-check ship agent-image orchestrator-image agent-build agent-test e2e

help:
	@printf '%s\n' 'Targets: help schema-check ship IMAGE=.. HOST=.. agent-build agent-test agent-image orchestrator-image e2e'

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
	@printf '%s\n' 'not implemented yet'
