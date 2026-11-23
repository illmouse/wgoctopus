# Orchestrator data model

SQLAlchemy 2.x models are migrated by Alembic into one SQLite database (WAL and foreign keys enabled).

| Table | Purpose |
|---|---|
| `instances` | Shared server interface, listen port, CIDR, keys, AWG obfuscation, and optional network defaults. |
| `nodes` | Management connection metadata, agent token, node network overrides, enablement, and `kind` (`awg` or `hop`). Hop nodes also store `wan_interface` and IPv4 `hop_ip`; `backend_ip` is the IPv4 address DNAT targets (the public reachable address for an AWG node). |
| `placements` | Instance-to-node placement, active/standby role, and weight; both roles render the complete interface configuration. |
| `hop_links` | Links hop nodes to instances whose traffic they forward. |
| `probes` | Associates a hop and instance with an AWG runner and the peer identity used for synthetic client probes. |
| `peers` | Client public key, encrypted re-issuable private key and PSK, assigned host address, ownership, and enablement. Disabled peers are retained but not rendered. |
| `node_revisions` | Monotonic desired revision and SHA-256 checksum of canonical rendered content excluding revision. |
| `node_observed` | Agent-reported applied revision/checksum, health, last-seen time, error, and raw JSON. Kept separate from desired state. |
| `events` | Small audit records for service operations; secret values are never placed in event data. |

Instance private keys, peer private keys, peer preshared keys, and node bearer tokens are Fernet encrypted at rest. The Fernet key is provided through `WGOCTOPUS_MASTER_KEY` or `WGOCTOPUS_MASTER_KEY_FILE`; losing it makes encrypted data unrecoverable. Public keys and other configuration remain plaintext. Secret values must never be logged.

One UDP port belongs to each instance and is reused by its rendered node interface and client endpoint. Node egress/SNAT overrides take precedence over instance defaults. Interface names must meet the agent's 1–15 character syntax. Desired revisions only increase when rendered state content changes; observed agent state is updated independently. Rendering a disabled node remains supported; callers decide whether it should be contacted.

Peer allocation walks addresses in the instance subnet, skips the server interface address and addresses already assigned to peers, and raises when exhausted. IPv4 client addresses render as `/32` and IPv6 as `/128`.

Hop nodes have no instance placements and render an empty `interfaces` array. For each linked instance, the hop route targets its active placement's `backend_ip`; when there are multiple active placements, highest weight wins, then lowest node ID. Instances without an active placement or whose active node has no backend address have no route.

## Probes

A probe's identity is a normal `peers` row owned by `__probe__`; its encrypted private key and PSK are used on the runner, while its public key and `/32` allowed IP render as a regular server-side peer. The runner receives a client interface named `wgp<probe-id>` with ephemeral listen port `0`. Its endpoint is derived from the linked hop's `hop_ip` and instance `listen_port` (`hop_ip:listen_port`), so the handshake exercises the client-to-hop-to-active-node path. If the runner is also the active instance node, its probe `/32` address coexists with the instance `/24`; a standby or different node is recommended for an independent view.
