import pytest
from fakes import FakeApi

from wgoctopus_bot.api import ApiError
from wgoctopus_bot.i18n import t
from wgoctopus_bot.router import Actor, ShowScreen, Toast, handle_callback
from wgoctopus_bot.screens import device_card, devices_screen

CFG = type("Settings", (), {"bot_instance": "test", "default_limit": 3})()
ADMIN = Actor("root", 2, "admin")
USER = Actor("alice", 1, "user")


def callbacks(screen):
    return [button.data for row in screen.buttons for button in row]


@pytest.mark.asyncio
async def test_admin_device_list_filters_pages_and_user_view():
    api = FakeApi()
    await api.create_device("alice", 9, "one")
    api.devices_data[0]["active"] = True
    for data in ("menu:devices", "dev:all:0", "dev:active:0", "dev:enabled:0", "dev:disabled:0", "dev:all:999"):
        result = await handle_callback(data, ADMIN, api, CFG)
        assert isinstance(result, ShowScreen)
    assert isinstance(await handle_callback("udev:alice", ADMIN, api, CFG), ShowScreen)
    assert isinstance(await handle_callback("dev:all:0", USER, api, CFG), ShowScreen)


@pytest.mark.asyncio
async def test_device_toggle_delete_confirmation_and_denial():
    api = FakeApi()
    await api.create_device("alice", 9, "device")
    card = await handle_callback("dev_del:1", ADMIN, api, CFG)
    assert isinstance(card, ShowScreen)
    assert "dev_delok:1" in callbacks(card.screen)
    assert isinstance(await handle_callback("dev_toggle:1", ADMIN, api, CFG), ShowScreen)
    assert api.devices_data[0]["enabled"] is False
    assert isinstance(await handle_callback("dev_delok:1", ADMIN, api, CFG), ShowScreen)
    assert not api.devices_data
    for cb in ("dev_toggle:1", "dev_del:1", "dev_delok:1"):
        denied = await handle_callback(cb, USER, api, CFG)
        assert isinstance(denied, Toast) and denied.alert and denied.text == t("en", "forbidden")


@pytest.mark.parametrize("lang", ["en", "ru"])
def test_device_screens_and_callback_data_limits(lang):
    device = {"id": 9, "name": "x", "owner": "a" * 40, "enabled": True, "active": True}
    for screen in (devices_screen(lang, [device], "all", 0, 1, -1), device_card(lang, device, True)):
        assert all(len(data.encode()) <= 64 for data in callbacks(screen))


@pytest.mark.asyncio
async def test_device_api_error_toast_mapping():
    api = FakeApi()
    api.all_devices = _raises(ApiError(503, "unavailable"))
    result = await handle_callback("menu:devices", ADMIN, api, CFG)
    assert isinstance(result, Toast) and result.text == t("en", "api_error")


def _raises(exc):
    async def fail(*args, **kwargs):
        raise exc
    return fail
