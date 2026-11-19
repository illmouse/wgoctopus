# Orchestrator

Planned Python/FastAPI service with an initial SQLite store (PostgreSQL may follow):

```text
app/          REST API for operators and bot/UI clients
store/        servers, interfaces, peers, and revisions
renderer/     per-node desired-state generation
reconciler/   push and track agent state
monitoring/   liveness and later client-path probes
bot/          initial Telegram bot module
```

The orchestrator is the central source of truth. No implementation is present yet.
