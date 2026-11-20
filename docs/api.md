# Orchestrator API

The single-process FastAPI service is mounted under `/v1`. Supply `Authorization: Bearer <token>`; the token is loaded from `WGOCTOPUS_API_TOKEN` or `WGOCTOPUS_API_TOKEN_FILE`. `/healthz` and `/readyz` are public. Missing credentials prevent startup unless the explicitly development-only `WGOCTOPUS_API_ALLOW_NO_AUTH=true` is set. Never expose unauthenticated mode to a network.

| Method/path | Purpose |
|---|---|
| POST/GET `/v1/instances`; GET/PATCH/DELETE `/v1/instances/{id}` | Instance lifecycle; patch allows mtu, egress_interface, snat_ip only |
| PUT/DELETE `/v1/instances/{id}/placements/{node_id}` | Placement |
| POST/GET `/v1/nodes`; GET/PATCH/DELETE `/v1/nodes/{id}` | Node lifecycle |
| POST/GET `/v1/instances/{id}/peers`; GET/PATCH/DELETE `/v1/peers/{id}` | Peer lifecycle; list supports owner, enabled, limit, and offset |
| GET `/v1/peers/{id}/config` | Secret-bearing client configuration; requires endpoint_host or `WGOCTOPUS_CLIENT_ENDPOINT_HOST` |
| POST `/v1/nodes/{id}/reconcile`; POST `/v1/nodes/{id}/apply-dangerous` | Trigger reconcile (202) or confirm dangerous apply |
| GET `/v1/events`; GET `/v1/status` | Event history (limit/kind/subject filters) and aggregate status |
| GET `/healthz`; GET `/readyz` | Public liveness and readiness probes |

Credentials, private keys, and PSKs are never returned except in the peer config endpoint (text/plain, `Cache-Control: no-store`). Agent tokens are write-only. Errors use `{"error":"...","detail":"..."}`; 404 means unknown id, 409 conflict, 422 invalid input, and readiness returns 503 when the database or encryption key is unavailable. Obfuscation, listen port, address and server keys cannot be changed through PATCH. OpenAPI and Swagger are disabled unless `WGOCTOPUS_API_DOCS=true`.

```sh
curl -H 'Authorization: Bearer <token>' https://example.invalid/v1/instances
curl -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"name":"wg-main","listen_port":51820,"address":"10.0.0.1/24"}' \
  http://localhost:8080/v1/instances
```
