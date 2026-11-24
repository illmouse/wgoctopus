# Admin web UI, bootstrap and host provisioning (stage 7)

## User journey

1. Deploy the orchestrator in your own environment (k3s, Docker).
2. Either open the web UI and log in, or provide a single `bootstrap.yaml` (plus secret env vars / files) for an unattended setup.
3. Describe instances, hosts and placements; trigger provisioning of new hosts. The orchestrator installs Docker and the agent over SSH and then manages the host through the agent.

Scope of the first version: **admin panel only**. End users keep using the Telegram bot; there is no self-service web page.

## Decisions

| Topic | Decision |
|---|---|
| Frontend | Server-rendered Jinja2 templates + HTMX served by the orchestrator itself. No Node build chain, one image. The REST API stays the single source of behaviour; pages call the same service layer. |
| Authentication | Local admin accounts (password hash stored in the DB, scrypt) and OIDC login (authorization code + PKCE). The static admin bearer token stays for the bot and automation, API only. |
| OIDC authorization | Users are provisioned on first login. Groups from a configurable claim map to roles via config: `admin`, `operator`, `viewer`. No match => access denied. Roles are re-evaluated on every login. |
| Sessions | Signed, HttpOnly, SameSite=Lax cookie with server-side session id; CSRF token on every state-changing form/HTMX request. |
| Host provisioning | The orchestrator installs everything itself over SSH (asyncssh), as idempotent steps, executed as a background job with a persisted log. |
| Bootstrap | One declarative YAML, applied at start and on demand; upsert by name, no deletion unless `prune: true`. |

## Roles

- `viewer`: read everything except secrets.
- `operator`: viewer + manage peers, switch active node, confirm failover, trigger reconcile.
- `admin`: operator + manage instances, nodes, hops, users, provisioning, bootstrap apply, web accounts.

Secrets (private keys, tokens, SSH keys) are never rendered in the UI; the peer client config download is an explicit audited action (already an event).

## Local authentication

`POST /auth/login` accepts `{username,password}` and sets the `wgoctopus_session` cookie; `GET /auth/me` reports the current identity and CSRF token, and `POST /auth/logout` requires `X-CSRF-Token`. Sessions use absolute and idle expiry. `/v1` continues to require its static bearer token; account management is at `GET/POST /v1/web-accounts` and `PATCH/DELETE /v1/web-accounts/{username}`. Bootstrap the first local admin with `WGOCTOPUS_WEB_ADMIN_PASSWORD` or `_FILE` (file takes precedence), optionally set `WGOCTOPUS_WEB_ADMIN_USERNAME`.

## Bootstrap YAML

Mounted as a file (`WGOCTOPUS_BOOTSTRAP_FILE`). Applied on start when `WGOCTOPUS_BOOTSTRAP_APPLY=true` (default) and via `POST /v1/bootstrap/apply` (supports `dry_run`). Secrets are referenced, never inlined: `{env: NAME}` or `{file: /path}`.

```yaml
version: 1
settings:
  prune: false              # delete objects missing from the file (default false)
instances:
  - name: awg-main
    listen_port: 13440
    address: 10.100.0.1/24
    awg_version: "3.1"      # generation settings used only at creation
    cps_profile: quic_initial
    endpoint_host: vpn.example.org
    mtu: 1280
nodes:
  - name: node-1
    kind: awg               # awg | hop
    mgmt_mode: push         # push | pull | auto
    ssh: {host: 203.0.113.10, port: 22, user: root}
    backend_ip: 203.0.113.10
  - name: hop-1
    kind: hop
    wan_interface: eth0
    hop_ip: 198.51.100.5
    ssh: {host: 198.51.100.5, user: root}
placements:
  - {instance: awg-main, node: node-1, role: active}
hop_links:
  - {hop: hop-1, instance: awg-main}
users:                      # bot users
  - {username: alice, role: admin}
```

Rules: strict schema validation runs before writes; re-applying unchanged data is a no-op; imported private keys are only accepted through the offline import CLI. Node entries also accept `protected: true` and `provision: {...}` (options listed in api.md, `auto: true` provisions the node at start). The SSH key used by the orchestrator is global (`WGOCTOPUS_SSH_KEY_FILE`, host keys via known_hosts or `WGOCTOPUS_SSH_TOFU`); the agent image comes from `WGOCTOPUS_AGENT_IMAGE` or the `image`/`image_archive` options.

## Host provisioning over SSH

Input: node record with SSH access (host, port, user, key reference). Steps (each idempotent, each logged, stop on first failure, resumable by re-run):

1. connect, TOFU/pinned host key, detect OS (Debian/Ubuntu supported), check root or passwordless sudo;
2. base packages and sysctl (`ip_forward=1`);
3. Docker engine (official repo) if missing;
4. management user and authorized key for the orchestrator (`restrict,port-forwarding,permitopen="127.0.0.1:18080"`), so day-2 control does not need root;
5. agent token file (generated, stored encrypted in the DB), agent image: pull from the registry, or upload a `docker save` stream when the host cannot reach it;
6. run the agent container (hop flag for hops, pull flags for pull mode);
7. wait for `/healthz`, switch the node to normal reconcile.

After provisioning the root key is no longer needed. Jobs are stored in the DB (`provision_jobs`, `provision_steps`), visible in the UI with live log, and never log secrets. Production hosts can be protected with `protected: true` in the node record; provisioning them requires explicit confirmation.

Egress (secondary IP, policy routing) stays an optional step driven by node fields (`egress_interface`, `snat_ip`, `gateway`).

## Stages

7.1 bootstrap YAML (schema, loader, API, tests); 7.2 SSH provisioning + e2e on the test host; 7.3 web authentication (7.3 done); 7.4 web UI pages; k3s manifests and backups.


## OIDC login

Authorization code flow with PKCE (S256). Enabled when `WGOCTOPUS_OIDC_ISSUER`, `_CLIENT_ID`, `_REDIRECT_URL` (the public URL of `/auth/oidc/callback`) and `_ROLE_MAP` are set.

| Variable | Default | Meaning |
|---|---|---|
| `WGOCTOPUS_OIDC_ISSUER` | - | Issuer URL; endpoints come from `/.well-known/openid-configuration` and must share its scheme and `issuer` value. |
| `WGOCTOPUS_OIDC_CLIENT_ID`, `WGOCTOPUS_OIDC_CLIENT_SECRET[_FILE]` | - | Confidential client credentials (secret via `client_secret_post`; file wins). |
| `WGOCTOPUS_OIDC_REDIRECT_URL` | - | Registered redirect URI. |
| `WGOCTOPUS_OIDC_SCOPES` | `openid profile email groups` | Requested scopes. |
| `WGOCTOPUS_OIDC_GROUPS_CLAIM` | `groups` | ID-token claim with the group list. |
| `WGOCTOPUS_OIDC_USERNAME_CLAIM` | `preferred_username` | Account name; falls back to `email`, then `sub`. |
| `WGOCTOPUS_OIDC_ROLE_MAP` | - | `group=role` pairs, e.g. `wg-admins=admin,wg-ops=operator`; highest matching role wins; no match = denied. |

Endpoints: `GET /auth/methods`, `GET /auth/oidc/login` (303 to the IdP, state bound to a short-lived HttpOnly cookie), `GET /auth/oidc/callback` (verifies state, exchanges the code with the PKCE verifier, validates the ID token: RS/ES/PS algorithms only, signature via JWKS with one refetch on unknown key, `iss`, `aud`, `exp`, `iat`, `nonce`; then creates a session and redirects to `/`). Accounts are provisioned at the first login (`source=oidc`, no password) and the role is re-evaluated on every login. A disabled account, a name already used by another account, or a missing group mapping is denied (event `web.login_denied` with a reason, no tokens or claims logged). Failures return generic `oidc_denied` (403) or 502 for IdP/network errors.
