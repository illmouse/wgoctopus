from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fakes import FakeApi
from telegram.error import BadRequest, Forbidden

from wgoctopus_bot.api import ApiError
from wgoctopus_bot.config import Config
from wgoctopus_bot.handlers import (
    build_application,
    callback,
    cancel,
    post_init,
    render,
    resolve_actor,
    start,
    text,
)
from wgoctopus_bot.router import AskInput, EditAdminCopies, Notify, SendDocument, ShowScreen, Toast
from wgoctopus_bot.screens import Screen


def fixture_update(private=True, callback_data=None, username="alice"):
    user = SimpleNamespace(id=1, username=username, language_code="en", first_name="Alice", last_name=None)
    message = SimpleNamespace(chat=SimpleNamespace(type="private" if private else "group"), reply_text=AsyncMock(), reply_document=AsyncMock())
    message.text = "device_1"
    query = SimpleNamespace(data=callback_data, answer=AsyncMock(), edit_message_text=AsyncMock()) if callback_data is not None else None
    return SimpleNamespace(effective_user=user, effective_message=message, callback_query=query), message, query


def context(api=None):
    return SimpleNamespace(application=SimpleNamespace(bot_data={"api": api or FakeApi(), "config": Config("123:abc", bot_instance="test")}), user_data={}, args=[], bot=SimpleNamespace(send_message=AsyncMock(), send_document=AsyncMock(), edit_message_text=AsyncMock()))


@pytest.mark.asyncio
async def test_unknown_and_disabled_actor():
    update, message, _ = fixture_update(username="unknown")
    api = FakeApi()
    assert await resolve_actor(update, api) is None
    api.resolve = AsyncMock(side_effect=ApiError(403, "disabled"))
    assert await resolve_actor(update, api) is None
    message.reply_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_unknown_callback_answered_and_start_keyboard():
    update, _, query = fixture_update(callback_data="menu")
    ctx = context()
    ctx.application.bot_data["api"].resolve = AsyncMock(side_effect=ApiError(404, "unknown"))
    await callback(update, ctx)
    query.answer.assert_awaited_once()
    update, message, _ = fixture_update()
    await start(update, context())
    assert "keyboard" in message.reply_text.await_args.kwargs["reply_markup"].to_dict()


@pytest.mark.asyncio
async def test_ask_input_and_cancel():
    update, _, _ = fixture_update()
    ctx = context()
    ctx.user_data["input"] = ("create_name", {})
    await text(update, ctx)
    assert "input" not in ctx.user_data
    ctx.user_data["input"] = ("rename", {"id": 1})
    await cancel(update, ctx)
    assert "input" not in ctx.user_data


@pytest.mark.asyncio
async def test_render_document_group_and_private_forbidden():
    update, message, _ = fixture_update(private=False)
    ctx = context()
    await render(SendDocument("x.conf", b"config", "caption"), update, ctx)
    ctx.bot.send_document.assert_awaited_once()
    message.reply_text.assert_awaited_once()
    ctx.bot.send_document.side_effect = Forbidden("no")
    await render(SendDocument("x.conf", b"config", "caption"), update, ctx)
    assert message.reply_text.await_count == 2


@pytest.mark.asyncio
async def test_render_result_types():
    update, _message, query = fixture_update(callback_data="menu")
    ctx = context()
    await render(ShowScreen(Screen("hello", []), True), update, ctx)
    await render(Toast("ok"), update, ctx)
    query.answer.assert_awaited_once()
    query.edit_message_text.side_effect = BadRequest("Message is not modified")
    await render(ShowScreen(Screen("hello", []), True), update, ctx)
    await render(AskInput("rename", {}, "name?"), update, ctx)
    assert ctx.user_data["input"][0] == "rename"
    await render(Notify(2, "hello"), update, ctx)
    await render(EditAdminCopies([[2, 3]], "done"), update, ctx)
    assert ctx.bot.edit_message_text.await_count == 1


@pytest.mark.asyncio
async def test_post_init_seeds_users():
    api = FakeApi()
    api.ensure_user = AsyncMock()
    app = context(api).application
    app.bot_data["config"] = Config("123:abc", admin_usernames=frozenset({"root"}), usernames=frozenset({"alice"}), default_config_limit=4)
    await post_init(app)
    assert api.ensure_user.await_count == 2


def test_build_application_registers_handlers():
    app = build_application(Config("123:abc", bot_instance="test"), FakeApi())
    assert app.handlers[0]
    assert app.post_init is not None
