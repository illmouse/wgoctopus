# Orchestrator API

The single-process FastAPI service is mounted under `/v1`. Supply `Authorization: Bearer <token>`; the token is loaded from `WGOCTOPUS_API_TOKEN` or `WGOCTOPUS_API_TOKEN_FILE`. `/healthz` and `/readyz` are public. Missing credentials prevent startup unless the explicitly development-only `WGOCTOPUS_API_ALLOW_NO_AUTH=true` is set. Never expose unauthenticated mode to a network.

| Method/path | Purpose |
|---|---|
| POST/GET `/v1/instances`; GET/PATCH/DELETE `/v1/instances/{id}` | Instance lifecycle; patch allows mtu, egress_interface, snat_ip only |
| PUT/DELETE `/v1/instances/{id}/placements/{node_id}` | Placement |
| POST `/v1/instances/{id}/switch` | Switch active placement (`{"node_id":...}`) |
| POST/GET `/v1/nodes`; GET/PATCH/DELETE `/v1/nodes/{id}` | Node lifecycle |
| GET `/v1/hops/{hop_id}/links`; PUT/DELETE `/v1/hops/{hop_id}/links/{instance_id}` | Hop routes, linked instance lifecycle |
| POST/GET `/v1/instances/{id}/peers`; GET/PATCH/DELETE `/v1/peers/{id}` | Peer lifecycle; list supports owner, enabled, limit, and offset |
| GET `/v1/peers/{id}/config` | Secret-bearing client configuration; requires endpoint_host or `WGOCTOPUS_CLIENT_ENDPOINT_HOST` |
| POST `/v1/nodes/{id}/reconcile`; POST `/v1/nodes/{id}/apply-dangerous` | Trigger reconcile (202) or confirm dangerous apply |
| GET `/v1/events`; GET `/v1/status` | Event history (limit/kind/subject filters) and aggregate status |
| GET `/healthz`; GET `/readyz` | Public liveness and readiness probes |
| GET `/metrics` | Prometheus text exposition (0.0.4) |

### Monitoring

`GET /metrics` returns `text/plain; version=0.0.4; charset=utf-8`. It requires the same bearer administrator token as `/v1`; set `WGOCTOPUS_METRICS_PUBLIC=true` only when access is restricted by the network. The exposition contains no agent credentials, keys, PSKs, SSH details, or node addresses. Reconcile outcome counters are in memory and reset on process restart.

| Environment variable | Default | Meaning |
|---|---|---|
| `WGOCTOPUS_METRICS_PUBLIC` | `false` | Allow unauthenticated metrics access. |
| `WGOCTOPUS_SCRAPE_ENABLED` | `true` | Enable best-effort AWG agent scrapes. |
| `WGOCTOPUS_SCRAPE_TIMEOUT` | `10` | Maximum seconds for one agent metrics scrape. |

| Metric | Meaning / labels |
|---|---|
| `wgoctopus_build_info` | Build version (`version`) |
| `wgoctopus_nodes`, `wgoctopus_instances`, `wgoctopus_peers`, `wgoctopus_peers_enabled` | Configuration counts (`kind`, `instance`) |
| `wgoctopus_node_state`, `wgoctopus_node_enabled`, `wgoctopus_node_consecutive_failures` | Node reconciler state (one-hot), enabled flag, and failures (`node`, `kind`, `state`) |
| `wgoctopus_node_desired_revision`, `wgoctopus_node_applied_revision`, `wgoctopus_node_last_seen_timestamp_seconds` | Node desired/observed revisions and observation time (`node`) |
| `wgoctopus_instance_active_node` | Active placement (`instance`, `node`) |
| `wgoctopus_hop_route` | Resolved hop route (`hop`, `instance`, `backend_ip`, `port`) |
| `wgoctopus_events_total` | Persisted event counts (`kind`) |
| `wgoctopus_reconcile_outcomes_total`, `wgoctopus_reconcile_last_duration_seconds` | Process-lifetime outcomes and most recent push duration (`outcome` / `node`) |
| `wgoctopus_node_scrape_success`, `wgoctopus_node_scrape_timestamp_seconds` | Latest best-effort agent metrics scrape status and time (`node`) |
| `wgoctopus_interface_up` | Interface status (`node`, `instance`) |
| `wgoctopus_peer_last_handshake_timestamp_seconds`, `wgoctopus_peer_handshake_age_seconds`, `wgoctopus_peer_rx_bytes_total`, `wgoctopus_peer_tx_bytes_total` | Known peer handshake and traffic (`node`, `instance`, `peer`) |
| `wgoctopus_instance_peers_active`, `wgoctopus_unknown_peers` | Known peers with handshake age <= 180 seconds, and unrecognized peer count (`node`, `instance`) |

Agent metrics are scraped best-effort after a successful in-sync push, over the same transport. Scrape failures never affect node state or create events; stale data is retained and marked unsuccessful. Scrapes are memory-only and reset on orchestrator restart. Public keys are used only for database matching and are never exposed. Set `WGOCTOPUS_SCRAPE_ENABLED=false` to disable; `WGOCTOPUS_SCRAPE_TIMEOUT` defaults to 10 seconds.

Credentials, private keys, and PSKs are never returned except in the peer config endpoint (text/plain, `Cache-Control: no-store`). Agent tokens are write-only. Errors use `{"error":"...","detail":"..."}`; 404 means unknown id, 409 conflict, 422 invalid input, and readiness returns 503 when the database or encryption key is unavailable. Obfuscation, listen port, address and server keys cannot be changed through PATCH. OpenAPI and Swagger are disabled unless `WGOCTOPUS_API_DOCS=true`.

Node responses expose `kind` (`awg` or `hop`), `wan_interface`, `hop_ip`, and `backend_ip`; hop creation requires its WAN interface and hop IPv4 address. AWG nodes cannot set hop-only fields. `backend_ip` is the IPv4 address used by hop routes. Instance responses include placement roles and `active_node_id`. Hop-link listings report active backend resolution and a `reason` when a route is omitted. Switch and hop-link mutations kick reconciliation; switch returns `from_node_id`, `to_node_id`, and `changed`.

```sh
curl -H 'Authorization: Bearer <token>' https://example.invalid/v1/instances
curl -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"name":"wg-main","listen_port":51820,"address":"10.0.0.1/24"}' \
  http://localhost:8080/v1/instances
```
