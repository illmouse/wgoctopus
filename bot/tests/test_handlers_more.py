import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fakes import FakeApi
from telegram.error import Forbidden

from wgoctopus_bot.api import ApiError
from wgoctopus_bot.config import Config
from wgoctopus_bot.handlers import (
    admin_command,
    build_application,
    callback,
    cancel,
    create,
    error_handler,
    menu,
    post_init,
    post_shutdown,
    powers,
    render,
    resolve_actor,
    start,
    text,
)
from wgoctopus_bot.i18n import t
from wgoctopus_bot.router import SendDocument


def update(private=True, username="alice", text_value="hello", callback_data=None, user=True):
    person = SimpleNamespace(id=1, username=username, language_code="en", first_name="Alice", last_name="") if user else None
    msg = SimpleNamespace(chat=SimpleNamespace(type="private" if private else "group"), text=text_value,
                          reply_text=AsyncMock(), reply_document=AsyncMock())
    query = SimpleNamespace(data=callback_data, answer=AsyncMock(), edit_message_text=AsyncMock()) if callback_data is not None else None
    return SimpleNamespace(effective_user=person, effective_message=msg, callback_query=query), msg, query


def ctx(api=None):
    return SimpleNamespace(application=SimpleNamespace(bot_data={"api": api or FakeApi(), "config": Config("123:abc", bot_instance="test")}),
                           user_data={}, args=[], bot=SimpleNamespace(send_message=AsyncMock(), send_document=AsyncMock(), edit_message_text=AsyncMock()))


@pytest.mark.asyncio
async def test_actor_commands_and_private_gate():
    api = FakeApi()
    upd, _, _ = update(user=False)
    assert await resolve_actor(upd, api) is None
    upd, msg, _ = update(username="unknown")
    assert await resolve_actor(upd, api) is None
    upd, msg, _ = update()
    api.resolve = AsyncMock(side_effect=ApiError(403, "disabled"))
    assert await resolve_actor(upd, api) is None
    msg.reply_text.assert_awaited_once()
    api.resolve = FakeApi().resolve

    upd, msg, _ = update(private=False)
    await start(upd, ctx(api))
    msg.reply_text.assert_not_awaited()
    upd, msg, _ = update()
    await start(upd, ctx(api))
    assert msg.reply_text.await_count == 1
    await menu(upd, ctx(api))
    await create(upd, ctx(api))
    upd, msg, _ = update(text_value="/limit")
    c = ctx(api); c.args = ["alice", "4"]
    await admin_command(upd, c)
    assert msg.reply_text.await_count == 1


@pytest.mark.asyncio
async def test_text_triggers_input_and_cancel():
    for lang in ("en", "ru"):
        api = FakeApi()
        upd, msg, _ = update()
        c = ctx(api)
        c.user_data["input"] = ("create_name", {})
        await text(upd, c)
        assert "input" not in c.user_data
        for label in (t(lang, "devices"), t(lang, "add"), t(lang, "limit")):
            msg.text = label
            await text(upd, c)
        msg.text = "some input"
        c.user_data["input"] = ("unknown_state", {})
        await text(upd, c)
        assert "input" not in c.user_data
        c.user_data["input"] = ("create_name", {})
        await cancel(upd, c)
        assert "input" not in c.user_data


@pytest.mark.asyncio
async def test_callback_power_admin_and_document_delivery():
    upd, _, query = update(callback_data="menu")
    await callback(upd, ctx())
    assert query.answer.await_count == 1
    api = FakeApi(); api.resolve = AsyncMock(side_effect=ApiError(404, "missing"))
    await callback(upd, ctx(api))
    assert query.answer.await_count == 2
    upd, msg, _ = update(text_value="/givemepowers")
    api = FakeApi(); api.admins = []
    await powers(upd, ctx(api))
    assert msg.reply_text.await_count
    upd, msg, _ = update(private=False)
    c = ctx()
    await render(SendDocument("x.conf", b"secret", "caption"), upd, c)
    c.bot.send_document.assert_awaited_once()
    assert msg.reply_text.await_count == 1
    c.bot.send_document.side_effect = Forbidden("blocked")
    await render(SendDocument("x.conf", b"x", "caption"), upd, c)
    assert msg.reply_text.await_count == 2


@pytest.mark.asyncio
async def test_lifecycle_logging_and_registration(caplog):
    api = FakeApi()
    config = Config("123:abc", admin_usernames=frozenset({"root"}), usernames=frozenset({"alice"}), default_config_limit=8, bot_instance="test")
    app = ctx(api).application
    app.bot_data["config"] = config
    await post_init(app)
    assert api.users["alice"]["config_limit"] == 8
    api.close = AsyncMock()
    await post_shutdown(app)
    api.close.assert_awaited_once()
    built = build_application(config, api)
    registered = [h.callback for group in built.handlers.values() for h in group]
    assert start in registered and menu in registered and admin_command in registered and text in registered
    assert built.post_init and built.post_shutdown

    err = RuntimeError("token=supersecret")
    with caplog.at_level(logging.ERROR):
        await error_handler(None, SimpleNamespace(error=err))
    assert "RuntimeError" in caplog.text and "supersecret" not in caplog.text


@pytest.mark.asyncio
async def test_callback_close_deletes_message():
    upd, _, query = update(callback_data="close")
    query.delete_message = AsyncMock()
    await callback(upd, ctx())
    query.delete_message.assert_awaited_once()
