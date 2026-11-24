# Orchestrator data model

Nodes support `mgmt_mode` values `push`, `pull`, and `auto`. `pull_public_key` is an optional normalized OpenSSH public key used to authenticate agent-initiated pull tunnels; it is safe to expose in API responses.

## CPS signature packets (I1-I5)

The standalone `awgcps.py` generator builds I1 protocol-shaped signatures
(QUIC Initial, TLS ClientHello, DNS, WireGuard Noise, or SIP) and entropy tags
for I2-I5 by default; `mimic_all` repeats the selected profile. `<c>` is off by
default because amneziawg-go does not support that tag. Chains observe the
3,200-byte kernel-module budget. Wiring these generated values into instance
creation comes in the next step.

Synthetic probe status (UNKNOWN, UP, DOWN) is evaluated from runner scrapes in memory; first-seen grace and handshake staleness are configurable. Status/events reset on orchestrator restart.

SQLAlchemy 2.x models are migrated by Alembic into one SQLite database (WAL and foreign keys enabled).

## Bot users

`bot_users` stores normalized lowercase Telegram usernames, optional unique Telegram IDs, role, enabled status, configuration limit (`-1` means unlimited), language, and disable metadata. `user_requests` stores access/limit requests, decisions, and notification references; `admin_username_history` reserves usernames previously used by administrators. `peers.owner` remains a free-form username string (not a foreign key) for importer and probe compatibility. User disable/enable operations cascade to owned peers and update rendered node revisions; user deletion removes owned peers. Only Telegram IDs, usernames, and requested first/last names are stored for bot identity; user/request audit events contain only usernames or request IDs, never personal names.

| Table | Purpose |
|---|---|
| `instances` | Shared server interface, listen port, CIDR, keys, AWG obfuscation, and optional network defaults. |
| `nodes` | Management connection metadata, agent token, node network overrides, enablement, and `kind` (`awg` or `hop`). Hop nodes also store `wan_interface` and IPv4 `hop_ip`; `backend_ip` is the IPv4 address DNAT targets (the public reachable address for an AWG node). |
| `nodes.pull_public_key` | Nullable OpenSSH public key line used to authenticate pull-mode agents. |
| `placements` | Instance-to-node placement, active/standby role, and weight; both roles render the complete interface configuration. |
| `hop_links` | Links hop nodes to instances whose traffic they forward. |
| `probes` | Associates a hop and instance with an AWG runner and the peer identity used for synthetic client probes. |
| `peers` | Client public key, encrypted re-issuable private key and PSK, assigned host address, ownership, and enablement. Disabled peers are retained but not rendered. |
| `node_revisions` | Monotonic desired revision and SHA-256 checksum of canonical rendered content excluding revision. |
| `node_observed` | Agent-reported applied revision/checksum, health, last-seen time, error, and raw JSON. Kept separate from desired state. |
| `events` | Small audit records for service operations; secret values are never placed in event data. |
| `failover_proposals` | Persisted failover decision, selected source/target, expiry, and outcome; instance/node deletion cascades. |

Instance private keys, peer private keys, peer preshared keys, and node bearer tokens are Fernet encrypted at rest. The Fernet key is provided through `WGOCTOPUS_MASTER_KEY` or `WGOCTOPUS_MASTER_KEY_FILE`; losing it makes encrypted data unrecoverable. Public keys and other configuration remain plaintext. Secret values must never be logged.

One UDP port belongs to each instance and is reused by its rendered node interface and client endpoint. Node egress/SNAT overrides take precedence over instance defaults. Interface names must meet the agent's 1–15 character syntax. Desired revisions only increase when rendered state content changes; observed agent state is updated independently. Rendering a disabled node remains supported; callers decide whether it should be contacted.

Instances created without explicit obfuscation receive randomized AWG 2.0-compatible `Jc/Jmin/Jmax`, `S1-S4`, and non-overlapping ranged `H1-H4` values. AWG 3.0/3.1 generation is supported by the pure parameter generator with the 12-byte S floor; 3.1 callers should select MTU 1280. Explicit API obfuscation remains untouched. CPS profiles are applied only at instance creation; rotating CPS later is a dangerous change that requires `allow_dangerous`, because clients must be updated to match.

Peer allocation walks addresses in the instance subnet, skips the server interface address and addresses already assigned to peers, and raises when exhausted. IPv4 client addresses render as `/32` and IPv6 as `/128`.

Hop nodes have no instance placements and render an empty `interfaces` array. For each linked instance, the hop route targets its active placement's `backend_ip`; when there are multiple active placements, highest weight wins, then lowest node ID. Instances without an active placement or whose active node has no backend address have no route.

## Probes

A probe's identity is a normal `peers` row owned by `__probe__`; its encrypted private key and PSK are used on the runner, while its public key and `/32` allowed IP render as a regular server-side peer. The runner receives a client interface named `wgp<probe-id>` with ephemeral listen port `0`. Its endpoint is derived from the linked hop's `hop_ip` and instance `listen_port` (`hop_ip:listen_port`), so the handshake exercises the client-to-hop-to-active-node path. If the runner is also the active instance node, its probe `/32` address coexists with the instance `/24`; a standby or different node is recommended for an independent view.
# Alert state

`alert_state` stores dispatcher cursors (currently `last_event_id`) so event processing resumes after restart without replaying history.

## Failover proposals

Proposals are stored as `pending`, then become `executed`, `rejected`, `expired`, `cancelled`, or `failed`. Creation records the mode and expiry; decisions record the actor/time. The down-duration tracker is in memory, so it resets on orchestrator restart.

Instances may also store `endpoint_host`, comma-separated `client_dns`, `client_keepalive`, and comma-separated `client_allowed_ips` for generated client configurations. Existing AWG servers can be imported with `create_instance(private_key=...)` and `import_peer(...)`; these preserve supplied keys, PSKs, and addresses while encrypting secret keys at rest. Key import is an offline-CLI/service operation only, never an HTTP operation, to avoid exposing long-lived private keys to the API.
# AWG 3.x obfuscation

AWG 3.x interfaces may include header protection, content padding, rekey/reject/keepalive timers, and maximum handshake attempts. AWG 3.1 may additionally enable random trailers. These values are carried in desired state and client configs. Rotating or changing these values (especially the header protection key and S values) is dangerous and may disconnect every client; coordinate updates and distribute the matching client config.
