from types import SimpleNamespace

import pytest
from fakes import FakeApi

from wgoctopus_bot.api import ApiError
from wgoctopus_bot.i18n import t
from wgoctopus_bot.router import Actor, ShowScreen, Toast, cmd_admin

ADMIN = Actor("root", 2, "admin")
USER = Actor("alice", 1, "user")
CFG = SimpleNamespace(default_config_limit=6, default_limit=3, bot_instance="test")


@pytest.mark.asyncio
async def test_admin_command_success_and_confirmation():
    api = FakeApi()
    assert isinstance(await cmd_admin("users", [], ADMIN, api, CFG), ShowScreen)
    assert isinstance(await cmd_admin("limit", ["alice", "5"], ADMIN, api, CFG), ShowScreen)
    assert isinstance(await cmd_admin("deluser", ["alice"], ADMIN, api, CFG), ShowScreen)
    assert (await cmd_admin("disable", ["alice"], ADMIN, api, CFG)).text == ""
    assert (await cmd_admin("enable", ["alice"], ADMIN, api, CFG)).text == ""
    assert (await cmd_admin("adduser", ["default"], ADMIN, api, CFG)).text == ""
    assert api.users["default"]["config_limit"] == 6
    assert (await cmd_admin("adduser", ["custom", "9"], ADMIN, api, CFG)).text == ""
    assert api.users["custom"]["config_limit"] == 9


@pytest.mark.asyncio
async def test_admin_command_usage_denial_and_not_found():
    api = FakeApi()
    cases = [("users", ["extra"]), ("users", ["x", "y"]), ("limit", []),
             ("limit", ["alice"]), ("limit", ["alice", "bad"]), ("limit", ["alice", "-2"]),
             ("deluser", []), ("deluser", ["alice", "x"]), ("disable", []),
             ("enable", ["alice", "x"]), ("adduser", []), ("adduser", ["x", "bad"]),
             ("adduser", ["x", "1", "extra"]), ("unknown", [])]
    for command, args in cases:
        result = await cmd_admin(command, args, ADMIN, api, CFG)
        assert isinstance(result, Toast) and result.text == t("en", "usage")
    denied = await cmd_admin("users", [], USER, api, CFG)
    assert denied.alert and denied.text == t("en", "forbidden")

    api.patch_user = _fail(ApiError(404, "missing"))
    result = await cmd_admin("limit", ["missing", "2"], ADMIN, api, CFG)
    assert isinstance(result, Toast) and result.text == t("en", "usage")
    api.get_user = _fail(ApiError(404, "missing"))
    assert (await cmd_admin("deluser", ["missing"], ADMIN, api, CFG)).text == t("en", "usage")


def _fail(exc):
    async def fail(*args, **kwargs):
        raise exc
    return fail
