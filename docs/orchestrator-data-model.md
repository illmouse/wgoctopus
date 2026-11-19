# Orchestrator data model

SQLAlchemy 2.x models are migrated by Alembic into one SQLite database (WAL and foreign keys enabled).

| Table | Purpose |
|---|---|
| `instances` | Shared server interface, listen port, CIDR, keys, AWG obfuscation, and optional network defaults. |
| `nodes` | Management connection metadata, agent token, node network overrides, and enablement. |
| `placements` | Instance-to-node placement, active/standby role, and weight; both roles render the complete interface configuration. |
| `peers` | Client public key, encrypted re-issuable private key and PSK, assigned host address, ownership, and enablement. Disabled peers are retained but not rendered. |
| `node_revisions` | Monotonic desired revision and SHA-256 checksum of canonical rendered content excluding revision. |
| `node_observed` | Agent-reported applied revision/checksum, health, last-seen time, error, and raw JSON. Kept separate from desired state. |
| `events` | Small audit records for service operations; secret values are never placed in event data. |

Instance private keys, peer private keys, peer preshared keys, and node bearer tokens are Fernet encrypted at rest. The Fernet key is provided through `WGOCTOPUS_MASTER_KEY` or `WGOCTOPUS_MASTER_KEY_FILE`; losing it makes encrypted data unrecoverable. Public keys and other configuration remain plaintext. Secret values must never be logged.

One UDP port belongs to each instance and is reused by its rendered node interface and client endpoint. Node egress/SNAT overrides take precedence over instance defaults. Interface names must meet the agent's 1–15 character syntax. Desired revisions only increase when rendered state content changes; observed agent state is updated independently. Rendering a disabled node remains supported; callers decide whether it should be contacted.

Peer allocation walks addresses in the instance subnet, skips the server interface address and addresses already assigned to peers, and raises when exhausted. IPv4 client addresses render as `/32` and IPv6 as `/128`.
