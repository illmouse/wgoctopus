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
