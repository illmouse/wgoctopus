# Orchestrator

The orchestrator is the central desired-state store, REST API, and in-process reconciler. It provides SQLite persistence, key management, transactional service operations, rendering, and client configuration generation.

## Layout and checks

Offline imports: see [`../docs/import.md`](../docs/import.md) for AmneziaWG and wg-easy CLI usage.

- `src/wgoctopus_orch/`: configuration, encryption, database, models, key helpers, service operations, and rendering.
- `migrations/`: Alembic environment and versioned schema.
- `tests/`: unit and integration tests.

Run `make orch-test` (Docker, Python 3.12, migrations and coverage) and `make orch-lint`. Or locally, install `.[dev]` and run `pytest --cov=wgoctopus_orch --cov-fail-under=85 -q`.

## Configuration

Alerts: `WGOCTOPUS_TELEGRAM_TOKEN` or `_FILE` (file takes precedence), `WGOCTOPUS_TELEGRAM_CHAT_ID`, `WGOCTOPUS_TELEGRAM_API_BASE` (default `https://api.telegram.org`), `WGOCTOPUS_ALERTS_ENABLED` (`auto`), `WGOCTOPUS_ALERT_DELAY_SECONDS` (60), `WGOCTOPUS_ALERT_MAX_PER_MINUTE` (20), `WGOCTOPUS_ALERT_POLL_SECONDS` (5), and `WGOCTOPUS_ALERT_KINDS` (empty uses defaults).

Failover settings: `WGOCTOPUS_FAILOVER_MODE` (`confirm`; `off`, `confirm`, or `auto`), `WGOCTOPUS_FAILOVER_DOWN_SECONDS` (120), `WGOCTOPUS_FAILOVER_PROPOSAL_TTL` (900), `WGOCTOPUS_FAILOVER_COOLDOWN` (600), and `WGOCTOPUS_FAILOVER_EVAL_INTERVAL` (15 seconds; lifecycle wiring comes in the next stage).

- `WGOCTOPUS_DATABASE_URL` (default `sqlite:///./wgoctopus.db`).
- `WGOCTOPUS_MASTER_KEY` (URL-safe base64 Fernet key) or `WGOCTOPUS_MASTER_KEY_FILE`; one is required before encryption/decryption.
- `WGOCTOPUS_SCHEMA_PATH` (optional; defaults to this repository's `schema/state.schema.json`).

SQLite uses WAL and foreign keys. Master keys and secrets must not be logged. The schema-path default references the source repository and should be overridden when packaging without the repository schema.
### Agent transport

Push delivery defaults to an SSH local-forward tunnel from the orchestrator to the node. Configure a client private-key file and a known-hosts file; strict host-key checking is the default. `WGOCTOPUS_SSH_TOFU=true` accepts and records the first presented key in the known-hosts file (mode 0600), then verifies it strictly. A MITM during initial enrollment can therefore be pinned; verify keys out of band when possible. Changed keys are rejected. The optional passphrase is read from a protected file. The agent bearer token is decrypted only when opening the connection. HTTP request bodies, tokens, and private keys are never logged. Direct HTTP is for local development only and requires `WGOCTOPUS_TRANSPORT=direct`.

Nodes may store their own SSH private key and bootstrap password; both are encrypted with the orchestrator master key and are never returned by the API. Provisioning uses the global key as a fallback for initial access, installs a generated per-node management key, verifies key-based SSH and passwordless sudo before applying SSH hardening, and discards the bootstrap password after the key is active.

| Variable | Default | Purpose |
|---|---|---|
| `WGOCTOPUS_TRANSPORT` | `ssh` | `ssh` or explicitly selected `direct` |
| `WGOCTOPUS_PULL_LISTEN` | (disabled) | Optional inbound pull listener address (`host:port`). |
| `WGOCTOPUS_PULL_HOST_KEY_FILE` | (generated in memory) | Ed25519 SSH server host-key path; existing files must be private. |
| `WGOCTOPUS_PULL_LOGIN_TIMEOUT` | `20` | SSH login timeout in seconds. |
| `WGOCTOPUS_SSH_KEY_FILE` | — | SSH client private-key path |
| `WGOCTOPUS_SSH_KEY_PASSPHRASE_FILE` | — | Optional protected passphrase file |
| `WGOCTOPUS_SSH_KNOWN_HOSTS` | `~/.ssh/known_hosts` | Known-hosts file; TOFU creates it with mode 0600 |
| `WGOCTOPUS_SSH_TOFU` | `false` | On first use, record the presented key atomically (0600 file); strictly verify every later use and reject changed keys. First-use interception risk remains. |
| `WGOCTOPUS_SSH_CONNECT_TIMEOUT` | `15` | SSH connection timeout, seconds |
| `WGOCTOPUS_AGENT_REQUEST_TIMEOUT` | `30` | Agent HTTP request timeout, seconds; apply uses 75 seconds |
| `WGOCTOPUS_RECONCILE_INTERVAL` | `30` | Reconciliation interval, seconds |
| `WGOCTOPUS_RECONCILE_CONCURRENCY` | `4` | Maximum concurrent node reconciliations |
| `WGOCTOPUS_RECONCILE_MAX_BACKOFF` | `300` | Maximum unreachable-node retry backoff, seconds |
| `WGOCTOPUS_RECONCILE_BLOCKED_RECHECK` | `300` | Retry delay for blocked node states, seconds |
| `WGOCTOPUS_RECONCILE_NODE_TIMEOUT` | `120` | Per-node reconciliation timeout, seconds |

The agent requires `allow_dangerous=true` as a query parameter on `PUT /v1/state`; it is never part of the state JSON. Push attempts are not retried. Revision is the synchronization key; a remote-ahead revision is reported without overwriting.
# Orchestrator

Install with `pip install .` and run `WGOCTOPUS_MASTER_KEY=<fernet-key> WGOCTOPUS_API_TOKEN=<token> python -m wgoctopus_orch`. The service uses one process/worker because reconciliation runs in-process. Docker: `make orch-image`, then mount `/var/lib/wgoctopus` and provide master key and API token.

| Variable | Default | Purpose |
|---|---|---|
| `WGOCTOPUS_API_TOKEN` / `WGOCTOPUS_API_TOKEN_FILE` | required | Admin bearer token, direct value or file |
| `WGOCTOPUS_API_ALLOW_NO_AUTH` | false | Development-only auth bypass |
| `WGOCTOPUS_API_HOST` / `WGOCTOPUS_API_PORT` | 127.0.0.1 / 8080 | Listen address |
| `WGOCTOPUS_API_DOCS` | false | Enable OpenAPI and Swagger docs |
| `WGOCTOPUS_RECONCILER_ENABLED` | true | Run reconciler within API process |
| `WGOCTOPUS_AUTO_MIGRATE` | true | Migrate on application startup |
| `WGOCTOPUS_CLIENT_ENDPOINT_HOST` | unset | Default client config endpoint |
| `WGOCTOPUS_BOOTSTRAP_FILE` | unset | Optional declarative YAML bootstrap file |
| `WGOCTOPUS_BOOTSTRAP_APPLY` | true | Apply configured bootstrap file at startup |
| `WGOCTOPUS_AGENT_IMAGE` | ghcr.io/illmouse/wgoctopus-agent:latest | Agent image used by host provisioning (overridable per job with `image`) |
| `WGOCTOPUS_WEB_ENABLED` | true | Enable local web authentication endpoints |
| `WGOCTOPUS_WEB_SESSION_TTL` / `WGOCTOPUS_WEB_SESSION_IDLE` | 28800 / 3600 | Absolute and idle session lifetimes, seconds |
| `WGOCTOPUS_WEB_COOKIE_SECURE` | auto | Cookie Secure flag; `false` disables it |
| `WGOCTOPUS_WEB_ADMIN_USERNAME` | admin | Username for first-admin bootstrap |
| `WGOCTOPUS_WEB_ADMIN_PASSWORD` / `_FILE` | unset | Optional first-admin password; file takes precedence |

Set `WGOCTOPUS_MASTER_KEY` or `WGOCTOPUS_MASTER_KEY_FILE` and configure DB/transport using the existing settings. `mgmt_mode=pull` is accepted for compatibility but is not implemented by the reconciler.

Offline AmneziaWG and wg-easy imports are available with `python -m wgoctopus_orch import`; see [`docs/import.md`](../docs/import.md). 5.4a import tooling is done; applying to the real DB and cutover are pending. Imports never place instances on nodes.
# Telegram callback environment

| Variable | Default | Description |
|---|---:|---|
| `WGOCTOPUS_TELEGRAM_BUTTONS` | `auto` | `auto`, `true`, or `false`; auto requires alerts and a non-empty user allowlist. |
| `WGOCTOPUS_TELEGRAM_FAILOVER_BUTTONS` | `auto` | `auto`, `true`, or `false`; attach Confirm/Reject to proposed failover alerts; auto follows alerts. |
| `WGOCTOPUS_TELEGRAM_ALLOWED_USER_IDS` | empty | Comma-separated Telegram numeric user IDs. Empty disables callbacks; required when buttons are true. |
| `WGOCTOPUS_TELEGRAM_POLL_TIMEOUT` | `25` | Long-poll timeout in seconds. |

When deploying the separate `bot/` module, keep orchestrator polling off (`WGOCTOPUS_TELEGRAM_BUTTONS=false`) and set `WGOCTOPUS_TELEGRAM_FAILOVER_BUTTONS=true`; only the bot module should poll `getUpdates`.

OIDC login is configured with `WGOCTOPUS_OIDC_ISSUER`, `WGOCTOPUS_OIDC_CLIENT_ID`, `WGOCTOPUS_OIDC_CLIENT_SECRET[_FILE]`, `WGOCTOPUS_OIDC_REDIRECT_URL`, `WGOCTOPUS_OIDC_ROLE_MAP` (optional: `_SCOPES`, `_GROUPS_CLAIM`, `_USERNAME_CLAIM`); see docs/web-ui.md.
