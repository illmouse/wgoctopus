"""Thin python-telegram-bot integration."""

import logging
from io import BytesIO
from typing import Any

from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputFile,
    KeyboardButton,
    ReplyKeyboardMarkup,
    Update,
)
from telegram.error import BadRequest, Forbidden, TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from .api import ApiError, OrchApi
from .config import Config
from .i18n import lang_from_code, t
from .router import (
    Actor,
    AskInput,
    EditAdminCopies,
    Notify,
    ResultBundle,
    SendDocument,
    ShowScreen,
    Toast,
    cmd_admin,
    cmd_create,
    cmd_givemepowers,
    handle_callback,
    handle_input,
)
from .screens import main_menu

logger = logging.getLogger(__name__)


def _services(context: ContextTypes.DEFAULT_TYPE) -> tuple[Any, Config]:
    return context.application.bot_data["api"], context.application.bot_data["config"]


async def resolve_actor(update: Update, api: Any) -> Actor | None:
    user = update.effective_user
    if user is None:
        return None
    language = lang_from_code(user.language_code)
    try:
        data = await api.resolve(user.id, user.username, language)
    except ApiError as exc:
        if exc.status == 404:
            return None
        if exc.status == 403:
            await _disabled(update, language)
            return None
        raise
    if data.get("status") == "disabled":
        await _disabled(update, language)
        return None
    return Actor(data.get("username", (user.username or "").lower()), user.id, data.get("role", "user"), lang_from_code(data.get("language") or language))


async def _disabled(update: Update, language: str) -> None:
    message = update.effective_message
    if message:
        await message.reply_text(t(language, "account_disabled"))


async def render(result: Any, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    message = update.effective_message
    if isinstance(result, ResultBundle):
        for item in result.results:
            await render(item, update, context)
    elif isinstance(result, ShowScreen):
        screen = result.screen
        markup = InlineKeyboardMarkup([[InlineKeyboardButton(button.label, callback_data=button.data) for button in row] for row in screen.buttons])
        try:
            if query and result.edit:
                await query.edit_message_text(screen.text, parse_mode="HTML", reply_markup=markup)
            elif message:
                await message.reply_text(screen.text, parse_mode="HTML", reply_markup=markup)
        except BadRequest as exc:
            if "message is not modified" not in str(exc).lower():
                raise
    elif isinstance(result, SendDocument):
        user = update.effective_user
        if message and user and message.chat.type != "private":
            try:
                await context.bot.send_document(user.id, InputFile(BytesIO(result.content), filename=result.filename), caption=result.caption)
            except Forbidden:
                await message.reply_text(t(_language(update), "open_private_chat"))
            else:
                await message.reply_text(t(_language(update), "config_sent_private"))
        elif message:
            await message.reply_document(InputFile(BytesIO(result.content), filename=result.filename), caption=result.caption)
    elif isinstance(result, Notify):
        try:
            await context.bot.send_message(result.tg_id, result.screen.text if hasattr(result.screen, "text") else result.screen, parse_mode="HTML")
        except TelegramError:
            logger.info("Telegram notification failed")
    elif isinstance(result, EditAdminCopies):
        for chat_id, message_id in result.refs:
            try:
                await context.bot.edit_message_text(result.text, chat_id=chat_id, message_id=message_id, parse_mode="HTML")
            except TelegramError:
                logger.info("Telegram admin-copy edit failed")
    elif isinstance(result, AskInput):
        context.user_data["input"] = (result.kind, result.payload)
        if message:
            await message.reply_text(result.prompt)
    elif isinstance(result, Toast):
        if query:
            await query.answer(result.text or None, show_alert=result.alert)
        elif message and result.text:
            await message.reply_text(result.text)


def _language(update: Update) -> str:
    return lang_from_code(update.effective_user.language_code if update.effective_user else None)


async def send_admin(context: ContextTypes.DEFAULT_TYPE, tg_id: int, screen: Any) -> tuple[int, int] | None:
    try:
        sent = await context.bot.send_message(tg_id, screen.text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(button.label, callback_data=button.data) for button in row] for row in screen.buttons]))
    except TelegramError:
        return None
    return sent.chat_id, sent.message_id


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    api, _ = _services(context)
    actor = await resolve_actor(update, api)
    message = update.effective_message
    if actor and message and message.chat.type == "private":
        language = actor.lang
        buttons = [KeyboardButton(t(language, "devices")), KeyboardButton(t(language, "add"))]
        if actor.role == "admin": buttons.extend([KeyboardButton(t(language, "users")), KeyboardButton(t(language, "requests_menu", count=""))])
        keyboard = ReplyKeyboardMarkup([buttons, [KeyboardButton(t(language, "limit"))]], resize_keyboard=True)
        await message.reply_text(t(language, "start"), reply_markup=keyboard)


async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    api, _ = _services(context)
    actor = await resolve_actor(update, api)
    if actor:
        await render(ShowScreen(main_menu(actor.lang, actor.role)), update, context)


async def create(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    api, config = _services(context)
    actor = await resolve_actor(update, api)
    if actor and update.effective_message:
        if context.args:
            result = await handle_input("create_name", {}, actor, api, context.args[0], config)
        else:
            result = await cmd_create(actor, api, config)
        await render(result, update, context)


async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    api, config = _services(context)
    actor = await resolve_actor(update, api)
    if actor and update.effective_message:
        command = update.effective_message.text.split()[0].split("@", 1)[0].lstrip("/")
        await render(await cmd_admin(command, context.args, actor, api, config), update, context)


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data.pop("input", None)
    if update.effective_message:
        language = _language(update)
        await update.effective_message.reply_text(t(language, "cancelled"))


async def powers(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    api, _ = _services(context)
    user = update.effective_user
    if user is None:
        return
    telegram_user = type("TelegramUser", (), {"id": user.id, "username": user.username, "first_name": user.first_name, "last_name": user.last_name, "lang": user.language_code})()
    results = await cmd_givemepowers(telegram_user, api, lambda tg_id, screen: send_admin(context, tg_id, screen))
    for result in results:
        await render(result, update, context)


async def callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    api, config = _services(context)
    actor = await resolve_actor(update, api)
    if actor:
        await render(await handle_callback(query.data or "", actor, api, config), update, context)
    else:
        await query.answer()


async def text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if message is None or not message.text:
        return
    api, config = _services(context)
    actor = await resolve_actor(update, api)
    if actor is None:
        return
    labels = {t(actor.lang, "devices"): "menu:devices", t(actor.lang, "add"): "create:self", t(actor.lang, "limit"): "reqlim"}
    labels.update({"Requests": "menu:requests", "Заявки": "menu:requests"})
    if message.text in labels:
        context.user_data.pop("input", None)
        await render(await handle_callback(labels[message.text], actor, api, config), update, context)
        return
    pending = context.user_data.pop("input", None)
    if pending:
        kind, payload = pending
        await render(await handle_input(kind, payload, actor, api, message.text, config), update, context)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Unhandled bot error: %s", type(context.error).__name__)


async def post_init(application: Application) -> None:
    api = application.bot_data["api"]
    config = application.bot_data["config"]
    succeeded = 0
    failed = 0
    for role, names in (("admin", config.admin_usernames), ("user", config.usernames)):
        for username in names:
            try:
                if role == "admin":
                    await api.ensure_user(username, role="admin")
                else:
                    await api.ensure_user(username, role="user", config_limit=config.default_config_limit)
                succeeded += 1
            except (TimeoutError, ApiError, OSError) as exc:
                failed += 1
                logger.warning("User seeding failed: %s", type(exc).__name__)
    logger.info("User seeding complete: %d succeeded, %d failed", succeeded, failed)


async def post_shutdown(application: Application) -> None:
    await application.bot_data["api"].close()


def build_application(config: Config, api: OrchApi | None = None) -> Application:
    application = Application.builder().token(config.bot_token).post_init(post_init).post_shutdown(post_shutdown).build()
    application.bot_data["api"] = api or OrchApi(config.orch_url, config.orch_token)
    application.bot_data["config"] = config
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("menu", menu))
    application.add_handler(CommandHandler("create", create))
    for command in ("users", "requests", "limit", "deluser", "disable", "enable", "adduser"):
        application.add_handler(CommandHandler(command, admin_command))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CommandHandler("givemepowers", powers))
    application.add_handler(CallbackQueryHandler(callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text))
    application.add_error_handler(error_handler)
    return application
