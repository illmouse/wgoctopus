# wgoctopus-bot

Telegram peer-management bot; it communicates only with the orchestrator REST API. Configure `BOT_TOKEN`, `ORCH_URL`, `ORCH_TOKEN`, and `BOT_INSTANCE`. Credentials may alternatively use `_FILE` variables. Seed `ADMIN_USERNAMES` and `USERNAMES` as comma-separated lowercase Telegram usernames before start; the bot service itself does not have a separate initialization API bootstrap yet. Admins see only their own device list in this stage because the API has no all-devices endpoint.

Build with `make bot-image`; run tests with `make bot-test` and lint with `make bot-lint`.
