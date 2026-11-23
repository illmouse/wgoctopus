# Agent

The Go module is at repository root (`github.com/illmouse/wgoctopus`); build with `go build ./cmd/wgoctopus-agent`. Flags: `--listen` (required), `--token` or `--token-file` (required; token-file contents are trimmed), `--state-dir` (default `/var/lib/wgoctopus`), `--daemon-bin` (default `amneziawg-go`), `--sock-dir` (default `/var/run/amneziawg`), `--iptables-bin` (default `iptables`), `--hop-enabled` (default false; env `WGOCTOPUS_HOP_ENABLED`), `--metrics-public`, `--allow-public-listen`, `--log-level` (`debug|info|warn|error`), and `--version`. Environment fallbacks are supported for listen, token, and state dir (`WGOCTOPUS_LISTEN`, `WGOCTOPUS_TOKEN`, `WGOCTOPUS_STATE_DIR`). Logs are JSON to stdout; tokens and key-bearing state values are redacted. Public bind addresses, including empty-host, `0.0.0.0`, and `[::]`, require `--allow-public-listen`.

The API provides authenticated `PUT`/`GET /v1/state`, open `/healthz`, and protected `/metrics` unless `--metrics-public`. Dangerous changes require `?allow_dangerous=true`; stale revisions return 409 unless `?force=true`. Hop forwarding is opt-in with `--hop-enabled` (or `WGOCTOPUS_HOP_ENABLED=true`); hop changes are not dangerous. Its container must use `network_mode: host` and `NET_ADMIN`. IPv4 forwarding must already be enabled (`net.ipv4.ip_forward=1`); the agent does not change it. Assign the configured hop IP to the configured WAN interface.

Build using `make agent-image`. Production requires root-equivalent networking permissions, TUN, and host networking to avoid publishing dynamically configured UDP ports. Put the token in a protected host file (for example `/etc/wgoctopus/token`) and bind-mount it read-only; do not put it in shell history or image configuration:

```sh
docker run -d --name wgoctopus-agent --restart unless-stopped \
  --network host --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -v wgoctopus-state:/var/lib/wgoctopus \
  -v /etc/wgoctopus/token:/run/secrets/wgoctopus-token:ro \
  wgoctopus-agent:dev --listen 10.8.0.2:8080 \
  --token-file /run/secrets/wgoctopus-token
```

Equivalent Compose service:

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

The image uses `iptables-nft`, matching the build host default. On hosts using legacy iptables, select/install the matching legacy implementation on the host or use a compatible image variant. No HEALTHCHECK is included. This container has no shell tooling beyond BusyBox.

SIGINT/SIGTERM gracefully shuts down the API; daemon children are intended to receive SIGTERM and are killed after the grace period.

Planned Go package layout:

```text
cmd/wgoctopus-agent/
internal/
  api/       authenticated management API
  state/     desired/applied state and persistence
  uapi/      AWG UAPI client and parser
  reconcile/ UAPI diff and apply
  metrics/   health and Prometheus metrics
  netsetup/  interface addresses and forwarding/NAT rules
```

The agent supervises AWG daemons, reconciles interfaces and owned iptables rules, persists applied state, and retries boot reconciliation every 30 seconds. SIGINT/SIGTERM shuts down HTTP gracefully and then stops managed daemons.
# Client (probe) mode

Client mode configures an interface as a synthetic probe peer. It adds no
firewall rules; `listen_port: 0` lets the daemon choose a random port. Peer
endpoints must use an IP literal (not a hostname). Use this mode for a
synthetic probe orchestrated from the orchestrator.
