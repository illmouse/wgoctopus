# Локальный стенд оркестратора

Запустите `make orch-dev` (нужен Python 3.12+). Команда создаёт `orchestrator/.venv`,
SQLite-базу в `orchestrator/.dev/`, применяет миграции и запускает Uvicorn с
автоперезагрузкой на `http://127.0.0.1:8080`. Для сброса данных остановите сервер
и удалите `orchestrator/.dev/dev.db`.

Локальные учётные записи: `admin / dev-admin-password`,
`operator / dev-operator-password`, `viewer / dev-viewer-password`.
Секреты стенда фиксированные и небезопасны для внешнего доступа. OIDC и Telegram
не настроены; тестовые сервисы/ноды реальными SSH-вызовами не управляют.
