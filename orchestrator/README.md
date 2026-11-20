# Orchestrator

The orchestrator is the central desired-state store. This stage implements the SQLite data model, key management, transactional service operations, renderer, and client configuration generation; API and reconciliation are later work.

## Layout and checks

- `src/wgoctopus_orch/`: configuration, encryption, database, models, key helpers, service operations, and rendering.
- `migrations/`: Alembic environment and versioned schema.
- `tests/`: unit and integration tests.

Run `make orch-test` (Docker, Python 3.12, migrations and coverage) and `make orch-lint`. Or locally, install `.[dev]` and run `pytest --cov=wgoctopus_orch --cov-fail-under=85 -q`.

## Configuration

- `WGOCTOPUS_DATABASE_URL` (default `sqlite:///./wgoctopus.db`).
- `WGOCTOPUS_MASTER_KEY` (URL-safe base64 Fernet key) or `WGOCTOPUS_MASTER_KEY_FILE`; one is required before encryption/decryption.
- `WGOCTOPUS_SCHEMA_PATH` (optional; defaults to this repository's `schema/state.schema.json`).

SQLite uses WAL and foreign keys. Master keys and secrets must not be logged. The schema-path default references the source repository and should be overridden when packaging without the repository schema.
### Agent transport

Push delivery defaults to an SSH local-forward tunnel from the orchestrator to the node. Configure a client private-key file and a known-hosts file; strict host-key checking is the default. `WGOCTOPUS_SSH_TOFU=true` accepts and records the first presented key in the known-hosts file (mode 0600), then verifies it strictly. A MITM during initial enrollment can therefore be pinned; verify keys out of band when possible. Changed keys are rejected. The optional passphrase is read from a protected file. The agent bearer token is decrypted only when opening the connection. HTTP request bodies, tokens, and private keys are never logged. Direct HTTP is for local development only and requires `WGOCTOPUS_TRANSPORT=direct`.

| Variable | Default | Purpose |
|---|---|---|
| `WGOCTOPUS_TRANSPORT` | `ssh` | `ssh` or explicitly selected `direct` |
| `WGOCTOPUS_SSH_KEY_FILE` | — | SSH client private-key path |
| `WGOCTOPUS_SSH_KEY_PASSPHRASE_FILE` | — | Optional protected passphrase file |
| `WGOCTOPUS_SSH_KNOWN_HOSTS` | `~/.ssh/known_hosts` | Known-hosts file; TOFU creates it with mode 0600 |
| `WGOCTOPUS_SSH_TOFU` | `false` | On first use, record the presented key atomically (0600 file); strictly verify every later use and reject changed keys. First-use interception risk remains. |
| `WGOCTOPUS_SSH_CONNECT_TIMEOUT` | `15` | SSH connection timeout, seconds |
| `WGOCTOPUS_AGENT_REQUEST_TIMEOUT` | `30` | Agent HTTP request timeout, seconds; apply uses 75 seconds |

The agent requires `allow_dangerous=true` as a query parameter on `PUT /v1/state`; it is never part of the state JSON. Push attempts are not retried. Revision is the synchronization key; a remote-ahead revision is reported without overwriting.
