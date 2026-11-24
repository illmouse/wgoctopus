"""Translation catalogs for the bot."""

import string

RU = {
    "menu": "Главное меню",
    "devices": "Устройства",
    "add": "Добавить устройство",
    "limit": "Запросить лимит",
    "all": "Все",
    "active": "Активные",
    "enabled": "Включённые",
    "disabled": "Выключенные",
    "none": "Устройств нет",
    "limit_line": "Устройства: {used}/{limit}",
    "status_on": "Включено",
    "status_off": "Выключено",
    "device": "<b>{name}</b>\nВладелец: {owner}\nСтатус: {status}\nIP: {ip}\nСоздано: {created}\nПоследняя активность: {activity}\nОтправлено: {rx}\nПолучено: {tx}",
    "download": "Скачать конфиг",
    "rename": "Переименовать",
    "delete": "Удалить",
    "toggle_on": "Выключить",
    "toggle_off": "Включить",
    "back": "Назад",
    "close": "Закрыть",
    "ask_name": "Введите имя (1–15 символов: латиница, цифры, _ или -):",
    "ask_rename": "Введите новое имя:",
    "ask_limit": "Введите новый лимит (-1 для безлимитного):",
    "limit_invalid": "Недопустимый лимит.",
    "invalid_name": "Недопустимое имя устройства.",
    "device_limit_reached": "Достигнут лимит устройств ({used}/{limit}).",
    "name_taken": "Это имя уже используется.",
    "forbidden": "Недостаточно прав.",
    "not_found": "Не найдено.",
    "api_error": "Ошибка сервиса. Попробуйте позже.",
    "account_disabled": "Учётная запись отключена.",
    "request_pending": "Запрос уже ожидает рассмотрения.",
    "request_sent": "Запрос отправлен администраторам.",
    "no_admin": "Нет доступных администраторов.",
    "registered": "Доступ предоставлен. Лимит: {limit}.",
    "declined": "Запрос отклонён.",
    "already_processed": "Запрос уже обработан.",
    "admin_use_limit_cmd": "Администраторы меняют лимит командой.",
    "config_sent_private": "Конфигурация отправлена в личный чат.",
    "config_caption": "Настройка: AmneziaWG или WG Tunnel.",
    "cancelled": "Отменено.",
    "created": "Устройство {name} создано.",
    "renamed": "Устройство переименовано: {name}.",
    "access_request_admin": "Запрос доступа #{id}\nПользователь: @{username} ({name})",
    "limit_request_admin": "Запрос лимита #{id}\n@{username}: {current} → {requested}",
    "request_done_admin": "Запрос #{id}: {status} (обработал {by}).",
    "approve": "✅ Одобрить",
    "decline_button": "❌ Отклонить",
    "request_pending_admin": "Ожидает рассмотрения",
    "start": "Выберите действие:",
    "open_private_chat": "Откройте личный чат с ботом, чтобы получить конфигурацию.",
}

EN = {
    "menu": "Main menu",
    "devices": "Devices",
    "add": "Add device",
    "limit": "Request limit",
    "all": "All",
    "active": "Active",
    "enabled": "Enabled",
    "disabled": "Disabled",
    "none": "No devices",
    "limit_line": "Devices: {used}/{limit}",
    "status_on": "Enabled",
    "status_off": "Disabled",
    "device": "<b>{name}</b>\nOwner: {owner}\nStatus: {status}\nIP: {ip}\nCreated: {created}\nLast activity: {activity}\nUploaded: {rx}\nDownloaded: {tx}",
    "download": "Download cfg",
    "rename": "Rename",
    "delete": "Delete",
    "toggle_on": "Disable",
    "toggle_off": "Enable",
    "back": "Back",
    "close": "Close",
    "ask_name": "Enter a name (1–15 letters, digits, _ or -):",
    "ask_rename": "Enter the new name:",
    "ask_limit": "Enter the new limit (-1 for unlimited):",
    "limit_invalid": "Invalid limit.",
    "invalid_name": "Invalid device name.",
    "device_limit_reached": "Device limit reached ({used}/{limit}).",
    "name_taken": "That name is already in use.",
    "forbidden": "You are not allowed to do that.",
    "not_found": "Not found.",
    "api_error": "Service error. Please try again later.",
    "account_disabled": "Your account is disabled.",
    "request_pending": "A request is already pending.",
    "request_sent": "Request sent to administrators.",
    "no_admin": "No administrators are available.",
    "registered": "Access granted. Limit: {limit}.",
    "declined": "Request declined.",
    "already_processed": "This request has already been processed.",
    "admin_use_limit_cmd": "Admins must change limits with the command.",
    "config_sent_private": "Configuration sent in a private chat.",
    "config_caption": "Install with AmneziaWG or WG Tunnel.",
    "cancelled": "Cancelled.",
    "created": "Device {name} created.",
    "renamed": "Device renamed: {name}.",
    "access_request_admin": "Access request #{id}\nUser: @{username} ({name})",
    "limit_request_admin": "Limit request #{id}\n@{username}: {current} → {requested}",
    "request_done_admin": "Request #{id}: {status} (handled by {by}).",
    "approve": "✅ Approve",
    "decline_button": "❌ Decline",
    "request_pending_admin": "Pending review",
    "start": "Choose an action:",
    "open_private_chat": "Open a private chat with the bot to receive your configuration.",
}

CATALOGS = {"ru": RU, "en": EN}


def lang_from_code(code: str | None) -> str:
    """Normalize Telegram's language code."""
    return "ru" if (code or "").lower().startswith("ru") else "en"


def t(lang: str, key: str, **fmt: object) -> str:
    """Look up and format a translated string."""
    return CATALOGS.get(lang, EN)[key].format(**fmt)


def placeholders(catalog: dict[str, str]) -> dict[str, set[str]]:
    """Return each catalog entry's format fields."""
    return {
        key: {field for _, field, _, _ in string.Formatter().parse(value) if field}
        for key, value in catalog.items()
    }
