# Architecture

## Client (probe) mode

Client mode configures a synthetic probe interface and installs no firewall
rules. `listen_port: 0` lets the daemon choose a random port, and peer endpoints
must be IP literals rather than hostnames. It is intended for synthetic probes
orchestrated from the orchestrator.

The client keeper periodically re-arms configured peers with persistent keepalive
after 20 seconds without a first handshake or 150 seconds since the last one.
It rate-limits re-arms to once per peer per 30 seconds. The default interval is
10 seconds; `--keeper-interval` changes it and `--keeper-disable` turns it off.

## Components

The agent accepts `--apply-timeout` (default `60s`) to bound how long its management API waits for a state apply; expired requests receive HTTP 504.

- **Orchestrator:** central source of truth for servers, interfaces, peers, and obfuscation parameters. Initially FastAPI with SQLite; PostgreSQL may replace SQLite later. It renders desired state, reconciles it to agents, exposes a REST API for bot/UI clients, and monitors liveness. The initial Telegram bot is a module in this service.
- **Agent:** one per node, managing N AWG interfaces alongside `amneziawg-go`. It accepts declarative state over an authenticated management API, applies incremental UAPI changes, sets up tunnel addresses and forwarding/NAT rules, persists last applied state, and restarts a failed daemon.

On shutdown, the agent stops managed daemons but leaves its owned iptables rules in place. This avoids unnecessary firewall changes during process shutdown; the next boot idempotently reconciles rules to the persisted desired state.
- **Management WireGuard:** planned small sidecar establishing management tunnels to nodes and hops. Management connectivity establishes node liveness only, not client-path health.
- **Hop:** planned statically configured UDP DNAT forwarder. The orchestrator selects a backend; switching requires conntrack cleanup.

### Hop mode

**Implemented.** The agent-owned nat chains are `WGOCT_HOP_DNAT` and `WGOCT_HOP_SNAT`; the filter chain is `WGOCT_HOP_FWD`. Rules are tagged `wgoct:hop:<listen_port>`. Backend switch rewrites the DNAT rule and flushes conntrack entries for that listen port. Conntrack entries for added, changed and removed ports are flushed after the rules are applied, because flows created while the route was absent bypass NAT. Hop support is opt-in with `--hop-enabled`. IPv4 forwarding must already be enabled and the hop IP assigned to its WAN interface; the agent does not modify either. Changing `backend_ip` is normal failover and is not dangerous.

Hop nodes use the same orchestrator push/reconcile path and `/v1/state` agent contract as AWG nodes, with empty `interfaces` and a `hop` section. Start their agent with `--hop-enabled`.

### Failover

The failover engine evaluates each linked instance with a synthetic probe. A probe must remain `DOWN` for `WGOCTOPUS_FAILOVER_DOWN_SECONDS`; `UNKNOWN` neither triggers nor resets the timer, while `UP` resets it. The probe runner may be the active node (it is not an independent vantage point, but is permitted). The hop must be `IN_SYNC`, and when multiple probes exist, failover is suppressed if all are down. A runner that is not `IN_SYNC` has an `UNKNOWN` probe status and does not trigger failover.

Candidates are enabled AWG standby placements with `IN_SYNC` node status and a successful latest scrape showing the instance interface up. Highest placement weight wins, then lowest node ID. No candidate emits one `failover.no_candidate` event per down episode. One pending proposal per instance and the post-execution cooldown prevent repeated switching. Proposals expire, cancel if the signal/active placement/candidate becomes invalid, and can be confirmed or rejected; `auto` executes immediately and `off` disables evaluation. Switching updates placement and hop revisions through the normal service path. Signal timers reset on restart.

## Data flows

1. An operator or bot/UI updates desired configuration through the orchestrator API.
2. The orchestrator validates and stores it, renders a complete per-node state with a monotonic revision, and pushes it to the node agent.
3. The agent compares desired state with live device state, applies changes through AWG UAPI without replacing all peers, and reports applied revision/checksum.
4. Agents expose health and Prometheus metrics. The orchestrator uses management-WireGuard reachability for node liveness. A synthetic peer probed through the hop endpoint is planned to verify the client path.

All nodes of one logical server share the same server keys, peers, and obfuscation settings. Failover therefore requires clients to re-handshake; sessions are not replicated. Active/standby comes first. Active-active with hop selection by client source IP using nftables `jhash` is a later option.

## Reconciliation

The orchestrator periodically compares rendered desired state with each enabled agent and pushes revisions that are not applied. Unreachable nodes use exponential backoff starting at 5 seconds and capped at 300 seconds, with ±20% jitter. Dangerous changes require an explicit `apply_dangerous` action; revision-ahead, invalid, unauthorized, and dangerous responses are blocked and rechecked after 300 seconds. Events such as unreachable, recovered, and blocked are emitted only on state transitions. If the agent's checksum changes without a revision change, the orchestrator reports `node.drift` and does not auto-fix it. Reconciliation status and retry deadlines are memory-only and are lost on restart.

If an agent already holds the desired revision but the orchestrator has no matching observation, reconciliation adopts that applied revision without sending another PUT.

## Failure modes

| Failure | Effect | Recovery / limitation |
| --- | --- | --- |
| Orchestrator unavailable | Existing data plane continues on last applied state; peer edits and automatic failover stop. | Agent retains persisted state; reconcile when control plane returns. |
| Agent or AWG daemon exits | That node's interfaces become unavailable. | Agent restarts the daemon; orchestrator detects loss and may later fail over. |
| Management tunnel unavailable | Node cannot be managed or confirmed live over the management path. | Does not itself prove client traffic is broken; investigate separately. |
| Hop backend failure | Client traffic through that hop fails. | Probe the client path; later switch backend and flush conntrack. |
| Orchestrator store lost | Central desired state is lost. | Back up the orchestrator store; node backups are unnecessary. |
| Obfuscation S/H parameters changed | Existing client compatibility is broken. | Treat as a dangerous change and require explicit acknowledgement. |

## Trust and security

The push control plane uses an outbound SSH connection from the orchestrator to each node. SSH forwards an ephemeral orchestrator loopback port to `127.0.0.1:<agent_port>` on the node; HTTP requests then use bearer authentication. The agent remains loopback-bound and is not exposed publicly. SSH host keys are strictly checked against `WGOCTOPUS_SSH_KNOWN_HOSTS` by default; an unknown key is rejected. With `WGOCTOPUS_SSH_TOFU=true`, the first presented key is recorded atomically in the known-hosts file (created mode 0600), and subsequent connections verify it strictly; a changed key is rejected even when TOFU remains enabled. TOFU is vulnerable to interception during first enrollment, so verify host keys out of band whenever possible. The agent token is decrypted only when opening a session. Logs and event data must not contain tokens, request bodies, private keys, or PSKs. Protect and back up the orchestrator store, which contains sensitive desired state.
## API and lifecycle

The HTTP API exposes the synchronous service layer at `/v1`. FastAPI owns a SQLAlchemy session per request and commits only after successful completion. Startup optionally migrates the database, then starts the in-process reconciler and (unless failover mode is `off`) a periodic failover evaluator; shutdown signals and awaits these tasks. Proposal listing/decision endpoints expose the failover engine through bearer-authenticated API routes. Run one Uvicorn worker only. Mutations kick affected nodes. A bearer token is required unless development-only no-auth mode is explicitly enabled; `/healthz` and `/readyz` are public. Readiness checks database access and encryption. The peer-config endpoint is the sole API response containing client secrets; OpenAPI is disabled by default.
# Monitoring environment

`WGOCTOPUS_METRICS_PUBLIC` defaults to `false`; set it to `true` to disable bearer authentication on `/metrics` only. Restrict public metrics at the network boundary.
# Alerts

The alert dispatcher reads persisted events and delivers plain-text Telegram notifications for node, probe, and switch events. Its `alert_state` cursor prevents historical replay; it supports flap suppression and a per-minute rate limit. Promotion confirmation buttons are part of the failover stage.

| Variable | Default | Purpose |
|---|---|---|
| `WGOCTOPUS_TELEGRAM_TOKEN` / `_FILE` | unset | Telegram bot token; file wins |
| `WGOCTOPUS_TELEGRAM_CHAT_ID` | unset | Destination chat |
| `WGOCTOPUS_TELEGRAM_API_BASE` | `https://api.telegram.org` | Telegram API base |
| `WGOCTOPUS_ALERTS_ENABLED` | `auto` | `auto`, `true`, or `false` |
| `WGOCTOPUS_ALERT_DELAY_SECONDS` | `60` | Flap suppression delay |
| `WGOCTOPUS_ALERT_MAX_PER_MINUTE` | `20` | Delivery limit |
| `WGOCTOPUS_ALERT_POLL_SECONDS` | `5` | Event polling interval |
| `WGOCTOPUS_ALERT_KINDS` | empty | Optional comma-separated event kinds |
# Telegram failover confirmation

The orchestrator can attach Confirm/Reject inline buttons to failover proposals. A long-polling `getUpdates` client accepts callbacks only from configured Telegram user IDs and only in the configured chat. Updates are persisted in `alert_state` to avoid replay after restart. This is outbound-only; configure no Telegram webhook, and run only one orchestrator instance per bot token because Telegram does not support concurrent pollers reliably. Callback decisions use the same failover engine as the API.
# AWG 3.x adds optional header protection, content padding, rekey/reject/keepalive timing, handshake attempts, random trailers, and cookie disabling. Header protection, random trailers, cookie disabling, and content padding changes require `allow_dangerous`; timing changes do not.
# Pull connectivity

Agents may optionally establish an outbound, host-key-pinned SSH connection
and reverse-forward their API to the orchestrator. This is a fallback to the
usual orchestrator-initiated tunnel; API authentication and bearer-token
requirements remain unchanged.
# Pull mode (orchestrator side)

In pull mode the orchestrator accepts agent-initiated SSH connections and exposes only an SSH reverse TCP forward bound to loopback. The node's configured OpenSSH public key authenticates the connection; HTTP requests to the forwarded agent API retain the existing bearer-token contract. Configure the listener and pinned host key fingerprint out of band.
