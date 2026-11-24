# Orchestrator API

The single-process FastAPI service is mounted under `/v1`. Supply `Authorization: Bearer <token>`; the token is loaded from `WGOCTOPUS_API_TOKEN` or `WGOCTOPUS_API_TOKEN_FILE`. `/healthz` and `/readyz` are public. Missing credentials prevent startup unless the explicitly development-only `WGOCTOPUS_API_ALLOW_NO_AUTH=true` is set. Never expose unauthenticated mode to a network.

| Method/path | Purpose |
|---|---|
| POST/GET `/v1/instances`; GET/PATCH/DELETE `/v1/instances/{id}` | Instance lifecycle; patch allows mtu, egress_interface, snat_ip only |
| GET `/v1/bootstrap`; POST `/v1/bootstrap/apply` | Bootstrap status and admin-authenticated transactional apply (`{"dry_run":true}` or inline `{"document":{...}}`); validation errors return JSON-pointer paths. |
| POST `/v1/nodes/{id}/provision`; GET `/v1/provision/jobs[?node_id=]`, `/v1/provision/jobs/{id}`; POST `/v1/provision/jobs/{id}/cancel` | Host provisioning over SSH, see below. |

`POST /v1/instances` accepts optional `cps_profile` (`none`, `quic_initial`, `tls_client_hello`, `dns_query`, `wireguard_noise`, `sip`, or `random`) and `intensity` (`low`, `medium`, or `high`, default `medium`). CPS is generated only when `obfuscation` is omitted; explicit obfuscation takes precedence.
It also accepts `awg_version` (`2.0`, `3.0`, or `3.1`, default `2.0`), used only when `obfuscation` is omitted. Instance responses redact `header_protection_key` and expose only `header_protection_key_set`; the shared key is returned only in `GET /v1/peers/{id}/config`.
| PUT/DELETE `/v1/instances/{id}/placements/{node_id}` | Placement |
| POST `/v1/instances/{id}/switch` | Switch active placement (`{"node_id":...}`) |
| POST/GET `/v1/nodes`; GET/PATCH/DELETE `/v1/nodes/{id}` | Node lifecycle |
Node management modes are `push`, `pull`, and `auto`. Node responses include the normalized `pull_public_key` and live `pull_connected` status. Pull nodes may omit SSH host/user (stored as `-`/`pull`); push/auto require them. PATCH `pull_public_key: null` clears the key.
| GET `/v1/pull` | Pull listener status, public host-key fingerprint, connected node IDs, and connection counters |
| GET `/v1/hops/{hop_id}/links`; PUT/DELETE `/v1/hops/{hop_id}/links/{instance_id}` | Hop routes, linked instance lifecycle |
| POST/GET `/v1/instances/{id}/peers`; GET/PATCH/DELETE `/v1/peers/{id}` | Peer lifecycle; list supports owner, enabled, limit, and offset |
| GET `/v1/peers/{id}/config` | Secret-bearing client configuration; requires endpoint_host or `WGOCTOPUS_CLIENT_ENDPOINT_HOST` |
| POST `/v1/nodes/{id}/reconcile`; POST `/v1/nodes/{id}/apply-dangerous` | Trigger reconcile (202) or confirm dangerous apply |
| GET `/v1/events`; GET `/v1/status` | Event history (limit/kind/subject filters) and aggregate status |
| POST/GET `/v1/probes`; GET/DELETE `/v1/probes/{id}` | Synthetic probe lifecycle |
| GET `/healthz`; GET `/readyz` | Public liveness and readiness probes |
| GET `/metrics` | Prometheus text exposition (0.0.4) |
Pull metrics: `wgoctopus_pull_server_enabled`, `wgoctopus_pull_tunnel_up{node=...}`, and `wgoctopus_pull_connections_total{result=...}`. No keys or addresses are exposed.
Pull lifecycle events `node.pull_connected` and `node.pull_disconnected` are recorded in `/v1/events`.
| GET `/v1/alerts` | Alert enablement, button settings (`buttons_enabled`, `failover_buttons`), and delivery counters |
| POST `/v1/alerts/test` | Send a test notification (202); 409 when disabled, 502 on delivery failure |
| GET `/v1/failover` | Failover mode and evaluation settings |
| GET `/v1/failovers`; GET `/v1/failovers/{id}` | List proposals (state, instance_id, limit, offset) or retrieve one |
| POST `/v1/failovers/{id}/confirm`; POST `/v1/failovers/{id}/reject` | Confirm or reject a pending proposal; optional `{"by":"api"|"telegram","actor":"name"}` body (defaults to API) |

Failover errors use the standard error envelope: unknown ids are 404 `not_found`; proposals that cannot be decided (including expired, stale, or no candidate) are 409. Example: `curl -X POST -H 'Authorization: Bearer <token>' http://localhost:8080/v1/failovers/1/confirm`.

Alert endpoints require bearer authentication. Responses never include Telegram credentials or chat identifiers.

When the separate `bot/` module is deployed, set `WGOCTOPUS_TELEGRAM_BUTTONS=false` to prevent competing `getUpdates` polling and `WGOCTOPUS_TELEGRAM_FAILOVER_BUTTONS=true` to attach confirmation buttons to failover alerts. The bot reports decisions through the API using `by: "telegram"`.

### Monitoring

`GET /metrics` returns `text/plain; version=0.0.4; charset=utf-8`. It requires the same bearer administrator token as `/v1`; set `WGOCTOPUS_METRICS_PUBLIC=true` only when access is restricted by the network. The exposition contains no agent credentials, keys, PSKs, SSH details, or node addresses. Reconcile outcome counters are in memory and reset on process restart.

| Environment variable | Default | Meaning |
|---|---|---|
| `WGOCTOPUS_METRICS_PUBLIC` | `false` | Allow unauthenticated metrics access. |
| `WGOCTOPUS_SCRAPE_ENABLED` | `true` | Enable best-effort AWG agent scrapes. |
| `WGOCTOPUS_SCRAPE_TIMEOUT` | `10` | Maximum seconds for one agent metrics scrape. |
| `WGOCTOPUS_PROBE_STALE_SECONDS` | `180` | Handshake age after which a synthetic probe is DOWN. |
| `WGOCTOPUS_PROBE_GRACE_SECONDS` | `60` | Grace after first interface observation before a never-handshaken probe is DOWN. |

| Metric | Meaning / labels |
|---|---|
| `wgoctopus_build_info` | Build version (`version`) |
| `wgoctopus_nodes`, `wgoctopus_instances`, `wgoctopus_peers`, `wgoctopus_peers_enabled` | Configuration counts (`kind`, `instance`) |
| `wgoctopus_node_state`, `wgoctopus_node_enabled`, `wgoctopus_node_consecutive_failures` | Node reconciler state (one-hot), enabled flag, and failures (`node`, `kind`, `state`) |
| `wgoctopus_node_desired_revision`, `wgoctopus_node_applied_revision`, `wgoctopus_node_last_seen_timestamp_seconds` | Node desired/observed revisions and observation time (`node`) |
| `wgoctopus_instance_active_node` | Active placement (`instance`, `node`) |
| `wgoctopus_hop_route` | Resolved hop route (`hop`, `instance`, `port`); addresses are omitted |
| `wgoctopus_events_total` | Persisted event counts (`kind`) |
| `wgoctopus_reconcile_outcomes_total`, `wgoctopus_reconcile_last_duration_seconds` | Process-lifetime outcomes and most recent push duration (`outcome` / `node`) |
| `wgoctopus_node_scrape_success`, `wgoctopus_node_scrape_timestamp_seconds` | Latest best-effort agent metrics scrape status and time (`node`) |
| `wgoctopus_interface_up` | Interface status (`node`, `instance`) |
| `wgoctopus_peer_last_handshake_timestamp_seconds`, `wgoctopus_peer_handshake_age_seconds`, `wgoctopus_peer_rx_bytes_total`, `wgoctopus_peer_tx_bytes_total` | Known peer handshake and traffic (`node`, `instance`, `peer`) |
| `wgoctopus_instance_peers_active`, `wgoctopus_unknown_peers` | Known peers with handshake age <= 180 seconds, and unrecognized peer count (`node`, `instance`) |
| `wgoctopus_probe_state`, `wgoctopus_probe_handshake_age_seconds` | Synthetic probe one-hot state and known handshake age (`probe`, `hop`, `instance`, `runner`, optionally `state`) |

Agent metrics are scraped best-effort after a successful in-sync push, over the same transport. Scrape failures never affect node state or create events; stale data is retained and marked unsuccessful. Scrapes are memory-only and reset on orchestrator restart. Public keys are used only for database matching and are never exposed. Set `WGOCTOPUS_SCRAPE_ENABLED=false` to disable; `WGOCTOPUS_SCRAPE_TIMEOUT` defaults to 10 seconds.

Credentials, private keys, and PSKs are never returned except in the peer config endpoint (text/plain, `Cache-Control: no-store`). Agent tokens are write-only. Errors use `{"error":"...","detail":"..."}`; 404 means unknown id, 409 conflict, 422 invalid input, and readiness returns 503 when the database or encryption key is unavailable. Obfuscation, listen port, address and server keys cannot be changed through PATCH. OpenAPI and Swagger are disabled unless `WGOCTOPUS_API_DOCS=true`.

Node responses expose `kind` (`awg` or `hop`), `wan_interface`, `hop_ip`, and `backend_ip`; hop creation requires its WAN interface and hop IPv4 address. AWG nodes cannot set hop-only fields. `backend_ip` is the IPv4 address used by hop routes. Instance responses include placement roles and `active_node_id`. Hop-link listings report active backend resolution and a `reason` when a route is omitted. Switch and hop-link mutations kick reconciliation; switch returns `from_node_id`, `to_node_id`, and `changed`.

```sh
curl -H 'Authorization: Bearer <token>' https://example.invalid/v1/instances
curl -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"name":"wg-main","listen_port":51820,"address":"10.0.0.1/24"}' \
  http://localhost:8080/v1/instances
```

## Host provisioning

`POST /v1/nodes/{id}/provision` body `{"options": {...}, "confirm_protected": false}` starts a background job (202 `{job_id}`). Options are merged over the node's stored `provision` options (set via node create/PATCH or bootstrap `provision:`): `mgmt_user`, `image`, `image_archive` (path on the orchestrator, streamed to `docker load`), `force_image`, `pull_server`, `pull_host_key`, `health_attempts`, `health_interval`; `auto: true` (stored only) makes the orchestrator provision the node at start until one job succeeded. Unknown options or wrong types: 422. A node with `protected: true` needs `confirm_protected: true` (otherwise 409 `confirmation_required`); a second active job for a node returns 409 `conflict`. `GET /v1/provision/jobs/{id}` returns the job with its steps (`pending|running|ok|skipped|failed`) and redacted logs; secrets (agent token, keys) are never logged. Steps are idempotent: re-running a failed job's node is the resume mechanism. With `mgmt_user` the node's `ssh_user` is switched to that restricted user (key `restrict,port-forwarding,permitopen="127.0.0.1:<agent_port>"`) after success; in pull mode the generated node public key is stored on the node. Metric: `wgoctopus_provision_jobs{state}`.

## Probes

Create a synthetic client with `POST /v1/probes` and `{ "hop_id": 1, "instance_id": 1, "runner_node_id": 2 }`. The runner must be an enabled AWG node, distinct from the instance's active node; the hop must have a hop IP and be linked to the instance. The API returns probe metadata and its `wgp<id>` interface name, never peer keys or addresses. List probes with optional `hop_id`, `instance_id`, and `runner_node_id` filters; retrieve or delete by id. Deletion removes the interface and managed peer. The system-owned peer uses the reserved owner `__probe__`; it is excluded from normal peer endpoints, counts, and peer metrics, and cannot be managed through peer endpoints. In general, choose a runner other than the active instance node.
# Telegram failover callbacks

`GET /v1/alerts` includes `buttons_enabled`. When enabled, `failover.proposed` messages include Telegram Confirm/Reject buttons; the existing authenticated API decision endpoints remain available.
# Instance client settings

Instance responses expose `endpoint_host`, `client_dns`, `client_keepalive`, and
`client_allowed_ips` (nullable). Instance creation and PATCH accept these
settings. DNS and allowed IPs are comma-separated values; PATCH null clears a
setting. Client settings do not change agent desired state or node revisions.
PATCH also accepts `mtu`, `egress_interface`, and `snat_ip`, which retain their
existing desired-state revision behavior. Private key import is deliberately
not available through HTTP.

## Bot users, requests and devices

Used by the peer-management bot; all endpoints need the admin bearer token. Users are keyed by lowercase Telegram username; a device is a peer whose `owner` is that username (probe peers are never exposed).

- `POST /v1/users/resolve` `{tg_id, username?, language?}` resolves the caller (binds a pre-registered username to a Telegram id, follows username renames); 404 for unknown users.
- `PUT /v1/users/{username}` `{role?, config_limit?}` creates/ensures a user (201 created, 200 existed). `GET /v1/users?status=&role=`, `GET|PATCH|DELETE /v1/users/{username}` (PATCH: `config_limit` (-1 unlimited), `role`; promotion needs a Telegram id, the last admin cannot be demoted).
- `POST /v1/users/{username}/disable` `{by}` / `enable`: disables or enables all owned devices (admins cannot be disabled); node revisions are bumped and reconciled.
- `POST|GET /v1/requests` (`type` access|limit), `GET /v1/requests/{id}`, `POST /v1/requests/{id}/approve` `{admin_tg_id, admin_username, default_limit}` / `decline`, `PUT /v1/requests/{id}/refs` `{refs: [[chat_id, message_id], ...]}`. Decisions are atomic; a second decision returns 409.
- `GET /v1/users/{username}/devices`, `POST /v1/users/{username}/devices` `{instance_id, name?, admin_bypass?}` (403 at the device limit, 409 duplicate name, auto name = 8 hex chars), `GET|PATCH|DELETE /v1/devices/{id}` (PATCH: `name`, `enabled`). `GET /v1/devices` lists devices with optional `owner`, `enabled`, and scrape-derived `active` filters, plus `limit` (default 50, max 200) and `offset`; response is `{total, items}` ordered by peer id. Device objects include `latest_handshake_at`, `rx`, `tx` and `active` (handshake within 180 s) from the cached node scrapes. The client config is `GET /v1/peers/{id}/config`.
