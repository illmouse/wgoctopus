# Architecture

## Components

The agent accepts `--apply-timeout` (default `60s`) to bound how long its management API waits for a state apply; expired requests receive HTTP 504.

- **Orchestrator:** central source of truth for servers, interfaces, peers, and obfuscation parameters. Initially FastAPI with SQLite; PostgreSQL may replace SQLite later. It renders desired state, reconciles it to agents, exposes a REST API for bot/UI clients, and monitors liveness. The initial Telegram bot is a module in this service.
- **Agent:** one per node, managing N AWG interfaces alongside `amneziawg-go`. It accepts declarative state over an authenticated management API, applies incremental UAPI changes, sets up tunnel addresses and forwarding/NAT rules, persists last applied state, and restarts a failed daemon.

On shutdown, the agent stops managed daemons but leaves its owned iptables rules in place. This avoids unnecessary firewall changes during process shutdown; the next boot idempotently reconciles rules to the persisted desired state.
- **Management WireGuard:** planned small sidecar establishing management tunnels to nodes and hops. Management connectivity establishes node liveness only, not client-path health.
- **Hop:** planned statically configured UDP DNAT forwarder. The orchestrator selects a backend; switching requires conntrack cleanup.

## Data flows

1. An operator or bot/UI updates desired configuration through the orchestrator API.
2. The orchestrator validates and stores it, renders a complete per-node state with a monotonic revision, and pushes it to the node agent.
3. The agent compares desired state with live device state, applies changes through AWG UAPI without replacing all peers, and reports applied revision/checksum.
4. Agents expose health and Prometheus metrics. The orchestrator uses management-WireGuard reachability for node liveness. A synthetic peer probed through the hop endpoint is planned to verify the client path.

All nodes of one logical server share the same server keys, peers, and obfuscation settings. Failover therefore requires clients to re-handshake; sessions are not replicated. Active/standby comes first. Active-active with hop selection by client source IP using nftables `jhash` is a later option.

## Reconciliation

The orchestrator periodically compares rendered desired state with each enabled agent and pushes revisions that are not applied. Unreachable nodes use exponential backoff starting at 5 seconds and capped at 300 seconds, with ±20% jitter. Dangerous changes require an explicit `apply_dangerous` action; revision-ahead, invalid, unauthorized, and dangerous responses are blocked and rechecked after 300 seconds. Events such as unreachable, recovered, and blocked are emitted only on state transitions. If the agent's checksum changes without a revision change, the orchestrator reports `node.drift` and does not auto-fix it. Reconciliation status and retry deadlines are memory-only and are lost on restart.

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

The HTTP API exposes the synchronous service layer at `/v1`. FastAPI owns a SQLAlchemy session per request and commits only after successful completion. Startup optionally migrates the database, then starts the in-process reconciler when enabled; shutdown signals and awaits its task. Run one Uvicorn worker only. Mutations kick affected nodes. A bearer token is required unless development-only no-auth mode is explicitly enabled; `/healthz` and `/readyz` are public. Readiness checks database access and encryption. The peer-config endpoint is the sole API response containing client secrets; OpenAPI is disabled by default.
