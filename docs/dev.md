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

## Hop-mode end-to-end test

Run against a disposable test host only; it exercises iptables and removes its test state during cleanup:

```sh
make e2e-hop HOST=root@test-host
```

The target is supplied at invocation time. SSH uses `~/.ssh/id_rsa` and `StrictHostKeyChecking=accept-new` by default; set `SSH_OPTS` to override.

`make e2e-orch-hop HOST=root@<test-host>` exercises the orchestrator driving a real hop agent over SSH, including backend switching, conntrack cleanup, restart persistence, and cleanup checks. The script ships the agent image unless `E2E_SKIP_SHIP=1` and removes only uniquely named resources; use only a dedicated disposable host.

`make e2e-probe HOST=root@<test-host>` tests a client-mode peer handshake between two agents on one disposable host. It ships the image unless `E2E_SKIP_SHIP=1`; SSH options and protected container IDs can be set with `SSH_OPTS` and `E2E_PROTECTED_IDS`.

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
