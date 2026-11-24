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
