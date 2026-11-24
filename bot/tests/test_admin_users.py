import pytest
from fakes import FakeApi

from wgoctopus_bot.api import ApiError
from wgoctopus_bot.i18n import EN, RU, t
from wgoctopus_bot.router import (
    Actor,
    AskInput,
    ShowScreen,
    Toast,
    cmd_admin,
    handle_callback,
    handle_input,
)
from wgoctopus_bot.screens import user_card, users_screen

CFG = type("Settings", (), {"bot_instance": "test", "default_limit": 3, "default_config_limit": 3})()
ADMIN = Actor("root", 2, "admin")
USER = Actor("alice", 1, "user")


def buttons(screen):
    return [b.data for row in screen.buttons for b in row]


@pytest.mark.asyncio
async def test_user_list_filters_pages_admins_and_card():
    api = FakeApi()
    assert isinstance(await handle_callback("menu:users", ADMIN, api, CFG), ShowScreen)
    for cb in ("users:all:0", "users:enabled:0", "users:disabled:0", "users:all:999"):
        assert isinstance(await handle_callback(cb, ADMIN, api, CFG), ShowScreen)
    api.admins = []
    assert isinstance(await handle_callback("users:all:0", ADMIN, api, CFG), ShowScreen)
    card = await handle_callback("user:alice", ADMIN, api, CFG)
    assert isinstance(card, ShowScreen)
    assert {"udev:alice", "ulimit:alice", "userdis:alice", "userena:alice", "urole:alice:admin", "udel:alice"} <= set(buttons(card.screen))
    for cb in ("menu:users", "users:all:0", "user:alice", "udev:alice", "ulimit:alice", "userdis:alice", "userena:alice", "urole:alice:admin", "udel:alice", "udelok:alice"):
        denied = await handle_callback(cb, USER, api, CFG)
        assert isinstance(denied, Toast) and denied.alert and denied.text == t("en", "forbidden")


@pytest.mark.asyncio
async def test_user_limit_validation_and_success():
    api = FakeApi()
    assert isinstance(await handle_callback("ulimit:alice", ADMIN, api, CFG), AskInput)
    for text in ("x", "-2"):
        assert (await handle_input("user_limit", {"username": "alice"}, ADMIN, api, text, CFG)).text == t("en", "limit_invalid")
    for value in ("-1", "5"):
        result = await handle_input("user_limit", {"username": "alice"}, ADMIN, api, value, CFG)
        assert isinstance(result, ShowScreen)
        assert api.users["alice"]["config_limit"] == int(value)


@pytest.mark.asyncio
async def test_user_status_role_and_delete_flows():
    api = FakeApi()
    assert isinstance(await handle_callback("userdis:alice", ADMIN, api, CFG), ShowScreen)
    assert api.users["alice"]["status"] == "disabled"
    await handle_callback("userena:alice", ADMIN, api, CFG)
    assert api.users["alice"]["status"] == "enabled"
    assert (await handle_callback("userdis:root", ADMIN, api, CFG)).text == t("en", "user_admin_protected")
    await handle_callback("urole:alice:admin", ADMIN, api, CFG)
    assert api.users["alice"]["role"] == "admin"
    await handle_callback("urole:alice:user", ADMIN, api, CFG)
    assert api.users["alice"]["role"] == "user"
    api.users["alice"]["tg_id"] = None
    assert (await handle_callback("urole:alice:admin", ADMIN, api, CFG)).text == t("en", "user_tg_required")
    api.admins = []
    assert (await handle_callback("urole:root:user", ADMIN, api, CFG)).text == t("en", "user_admin_protected")
    confirmation = await handle_callback("udel:alice", ADMIN, api, CFG)
    assert isinstance(confirmation, ShowScreen) and "udel:alice" in buttons(confirmation.screen)
    await handle_callback("udelok:alice", ADMIN, api, CFG)
    assert "alice" not in api.users


@pytest.mark.asyncio
async def test_user_api_errors_commands_and_language_catalogs():
    api = FakeApi()
    api.patch_user = _raises(ApiError(409, "conflict"))
    result = await handle_input("user_limit", {"username": "alice"}, ADMIN, api, "7", CFG)
    assert isinstance(result, Toast) and result.text == t("en", "request_pending")
    assert isinstance(await cmd_admin("users", [], ADMIN, api, CFG), ShowScreen)
    assert (await cmd_admin("limit", ["alice", "-2"], ADMIN, api, CFG)).text == t("en", "usage")
    assert (await cmd_admin("users", [], USER, api, CFG)).alert
    assert EN.keys() == RU.keys()


@pytest.mark.asyncio
async def test_admin_commands_and_user_callback_errors():
    api = FakeApi()
    assert isinstance(await cmd_admin("deluser", ["alice"], ADMIN, api, CFG), ShowScreen)
    assert (await cmd_admin("disable", ["alice"], ADMIN, api, CFG)).text == ""
    assert api.users["alice"]["status"] == "disabled"
    assert (await cmd_admin("enable", ["alice"], ADMIN, api, CFG)).text == ""
    assert (await cmd_admin("adduser", ["fresh"], ADMIN, api, CFG)).text == ""
    assert (await cmd_admin("adduser", ["fresh2", "-1"], ADMIN, api, CFG)).text == ""
    assert isinstance(await cmd_admin("limit", ["alice", "4"], ADMIN, api, CFG), ShowScreen)
    assert (await cmd_admin("unknown", [], ADMIN, api, CFG)).text == t("en", "usage")
    assert (await handle_input("user_limit", {}, USER, api, "1", CFG)).alert
    api.admins = [api.users["root"]]
    api.patch_user = _raises(ApiError(422, "last admin"))
    result = await handle_callback("urole:root:user", ADMIN, api, CFG)
    assert isinstance(result, Toast) and result.text == t("en", "user_admin_protected")


@pytest.mark.asyncio
async def test_admin_command_adduser_validation_and_api_failure():
    api = FakeApi()
    assert (await cmd_admin("adduser", ["fresh", "bad"], ADMIN, api, CFG)).text == t("en", "usage")
    api.ensure_user = _raises(ApiError(422, "invalid"))
    assert (await cmd_admin("adduser", ["fresh"], ADMIN, api, CFG)).text == t("en", "usage")


@pytest.mark.parametrize("lang", ["en", "ru"])
def test_user_screens_callback_data_limits(lang):
    user = {"username": "u" * 40, "role": "user", "status": "enabled", "config_limit": 3}
    for screen in (users_screen(lang, [user], "all", 0), user_card(lang, user)):
        assert all(len(data.encode()) <= 64 for data in buttons(screen))
    admin_card = user_card(lang, {**user, "role": "admin"})
    assert f"urole:{user['username']}:user" in buttons(admin_card)


def _raises(exc):
    async def fail(*args, **kwargs):
        raise exc
    return fail
