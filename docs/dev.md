# Local development

Agent development requires Go 1.24 and Docker for image builds. The orchestrator remains a skeleton.

## Prerequisites and checks

Install Make, Go 1.24, and Python 3. For schema validation, install Python `jsonschema`. Run:

```sh
make help
make schema-check
make agent-test
make agent-image
bash -n scripts/ship-image.sh
```

Without `jsonschema`, `schema-check` reports a warning and checks that the example is valid JSON only. The image targets are placeholders until their implementation stages.

## End-to-end agent test

Run `make e2e` to exercise the agent locally with Docker. To run against a dedicated test host, run `scripts/e2e.sh ssh user@test-host` (override `SSH_OPTS` if needed). The test starts and removes its own container, link, and owned firewall rules; use only a disposable test host.

## Orchestrator end-to-end test

Run `make e2e-orch HOST=root@<test-host>` to test the orchestrator against a real agent over SSH. The script builds missing images, ships the agent unless `E2E_SKIP_SHIP=1`, and cleans up its containers, `woct0`, owned firewall rules, and `/opt/woct-test`. It checks host firewall counts and container IDs before and after; use only the designated disposable test host.

## Manual image delivery

Build an image locally, then transfer and load it on a remote test host with Docker access and SSH access:

```sh
make ship IMAGE=example:tag HOST=user@host
```

Build with `make agent-image`, then run `make ship IMAGE=wgoctopus-agent:dev HOST=user@test-host`. The helper streams `docker save` over SSH into `docker load`; it does not deploy or start the image. Confirm image and target before use. This is a manual test workflow, not a release pipeline.

Production example (create `/etc/wgoctopus/token` securely before launch):

```sh
docker run -d --name wgoctopus-agent --restart unless-stopped \
  --network host --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 -v wgoctopus-state:/var/lib/wgoctopus \
  -v /etc/wgoctopus/token:/run/secrets/wgoctopus-token:ro \
  wgoctopus-agent:dev --listen 10.8.0.2:8080 \
  --token-file /run/secrets/wgoctopus-token
```

Compose equivalent:

```yaml
services:
  agent:
    image: wgoctopus-agent:dev
    restart: unless-stopped
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun:/dev/net/tun]
    sysctls: { net.ipv4.ip_forward: "1" }
    volumes:
      - wgoctopus-state:/var/lib/wgoctopus
      - /etc/wgoctopus/token:/run/secrets/wgoctopus-token:ro
    command: ["--listen", "10.8.0.2:8080", "--token-file", "/run/secrets/wgoctopus-token"]
volumes:
  wgoctopus-state:
```
