# Node desired-state contract

The normative JSON shape is [`schema/state.schema.json`](../schema/state.schema.json); a non-production example is [`schema/examples/state.example.json`](../schema/examples/state.example.json).

## Fields

- `revision` — non-negative integer assigned by the orchestrator. A node applies a newer revision atomically as far as practical; a repeated revision with identical content is an idempotent no-op. A stale revision must not roll back newer applied state. The agent reports the applied revision and a checksum of canonical applied state.
- `interfaces` — complete desired interface set for the node. Interfaces omitted from a later state are candidates for removal.
- `interfaces[].name` — device/interface name; must be unique within the array.
- `listen_port` — UDP listen port, 1–65535.
- `private_key` — base64 encoding of exactly 32 key bytes; secret.
- `address` — interface address in CIDR notation.
- `mtu` — optional link MTU (576–9000); omitted or zero uses the default.
- `egress_interface` — optional outbound Linux interface name (1–15 characters from `[A-Za-z0-9_=+.-]`); default-route interface is detected when omitted.
- `snat_ip` — optional IPv4 or IPv6 source address; when omitted, MASQUERADE is used.
- `obfuscation` — required AWG parameters: `jc`, `jmin`, `jmax`, `s1`–`s4`, and `h1`–`h4`; optional `i1`–`i5` strings. H fields are decimal strings or inclusive `min-max` ranges (for example `100-200`), as required by AWG 3.1 UAPI; S fields are 16-bit unsigned values.
- `peers` — complete desired peer set for this interface. `public_key` must be unique within the array; schema-level uniqueness of an object property is not expressible in JSON Schema.
- `peers[].public_key` — base64 encoding of exactly 32 key bytes.
- `peers[].preshared_key` — optional base64 encoding of exactly 32 key bytes; secret.
- `peers[].allowed_ips` — non-empty list of CIDR ranges routed through the peer.
- Obfuscation values are authoritative: omitted optional `i1`–`i5` values and zero-valued numeric fields reset the device field to its default/zero; they do not mean “leave unchanged.” Missing obfuscation values in a device snapshot are treated as defaults.
- Allowed-IP prefixes are normalized by masking host bits before comparison and serialization (`10.0.0.2/24` equals `10.0.0.0/24`).

JSON Schema provides shape-level checks; the agent must also reject duplicate interface names or peer public keys, semantically invalid obfuscation values, and unsafe network changes. UAPI updates should change only what differs, remove extra peers, and avoid replacing all peers so unchanged peers retain sessions.

## Idempotency and dangerous changes

Sending the same revision and state repeatedly must not cause further mutations. Equal revision with different content is a conflict; lower revisions are rejected. The checksum is over a documented canonical representation (implementation detail to define before agent stage).

Changes to `mtu`, `egress_interface`, or `snat_ip` are not dangerous. Changes to `private_key`, `listen_port`, `jc`, `jmin`, `jmax`, `s1`–`s4`, `h1`–`h4`, or `i1`–`i5` are dangerous and require explicit acknowledgement. Initial interface creation (when the device has no private key) is not dangerous. Address is not currently managed by device UAPI. Peer changes are not dangerous. Key material is base64 in state and UAPI hex on the wire.
