# Offline instance import

Import an AmneziaWG directory or wg-easy backup into the orchestrator database:

```sh
WGOCTOPUS_MASTER_KEY=<fernet-key> python -m wgoctopus_orch import amnezia \
  --source /path/to/backup --name imported --dry-run
WGOCTOPUS_MASTER_KEY=<fernet-key> python -m wgoctopus_orch import wgeasy \
  --source /path/to/backup --name imported --verify-wg0 /path/to/wg0.conf
python -m wgoctopus_orch import wgeasy --source /path/to/backup \
  --name imported --bot-db /path/to/bot.db --db /path/to/orchestrator.db
```

The wg-easy source database is opened read-only. `--db` accepts a SQLAlchemy
URL or SQLite path. A real import requires the orchestrator master key; a
dry-run uses a fresh temporary encryption key.

Every invocation prints a stable key/value report containing mode and kind,
instance settings and counts, warnings/problems, verification counts, a
rendered-state SHA-256, and result. Sensitive values (including imported
names, addresses and endpoint hosts) are redacted. Exit codes: `0` success,
`1` validation, verification or apply failure, `2` duplicate instance name or
listen port (also argparse's usage-error code).

Dry-run imports into a temporary SQLite database, renders and schema-validates
the state, then discards it. This staging is necessary because service
operations commit independently; rollback cannot safely simulate a run.
`--verify-wg0` compares enabled source peers against IPv4 peer entries in a
WireGuard config; IPv6 entries are ignored. Review the counts, warnings and
checksum, verify the source backup independently, and run dry-run before
committing. The importer does not import nodes, placements, observed state,
or runtime configuration. It does not place instances on nodes. Place the
instance explicitly after import and before cutover.

## Import a server `.conf` through the API

`POST /v1/instances/import` accepts `{"name":"wg0","config":"[Interface]..."}`.
The config must contain one server `[Interface]` with `Address` and
`ListenPort`; an omitted `PrivateKey` is generated and reported as a warning.
Peer sections may contain `PublicKey`, `AllowedIPs`, and `PresharedKey`.
JSON requests and multipart form uploads (`file` or `config`)
are supported; the configuration is limited to 256 KiB. Optional `address` and
`endpoint_host` fields override the parsed address and client endpoint. Keys are encrypted at
rest and never included in the response. Client-side peer private keys are not
imported by this endpoint; a config containing one is rejected.

## Legacy Telegram users

Import the old bot's `users.db` read-only with
`python -m wgoctopus_orch import-users --source /path/to/users.db [--dry-run] [--db URL]`.
Users, requests, and admin username history are imported transactionally and
idempotently. The key/value report contains counts only; invalid usernames or
Telegram ID conflicts abort the whole import. Dry-run validates then rolls
back. Exit codes are `0` success and `1` failure (`2` for usage errors).
