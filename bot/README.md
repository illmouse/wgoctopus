# wgoctopus-bot

Telegram peer-management bot; it communicates only with the orchestrator REST API. Configure `BOT_TOKEN`, `ORCH_URL`, `ORCH_TOKEN`, and `BOT_INSTANCE`. Credentials may alternatively use `_FILE` variables. Seed `ADMIN_USERNAMES` and `USERNAMES` as comma-separated lowercase Telegram usernames before start; the bot service itself does not have a separate initialization API bootstrap yet. Admins see only their own device list in this stage because the API has no all-devices endpoint.

Build with `make bot-image`; run tests with `make bot-test` and lint with `make bot-lint`.

## Failover confirmation (single bot)

The orchestrator only *sends* failover proposals (with Confirm/Reject inline buttons, `WGOCTOPUS_TELEGRAM_FAILOVER_BUTTONS`); it must NOT poll the same token (`WGOCTOPUS_TELEGRAM_BUTTONS=false`). This bot receives the `fo:c:<id>` / `fo:r:<id>` callbacks, allows them for admins only and calls `POST /v1/failovers/{id}/confirm|reject` with `by=telegram` and the admin's username. Set `WGOCTOPUS_TELEGRAM_CHAT_ID` to the admins' chat ids (comma-separated) and use the same `BOT_TOKEN`.
