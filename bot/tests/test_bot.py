from datetime import UTC, datetime, timedelta

import pytest
from fakes import FakeApi

from wgoctopus_bot.i18n import EN, RU, lang_from_code, placeholders, t
from wgoctopus_bot.router import (
    Actor,
    AskInput,
    EditAdminCopies,
    Notify,
    ResultBundle,
    SendDocument,
    ShowScreen,
    Toast,
    cmd_create,
    cmd_givemepowers,
    handle_callback,
    handle_input,
)
from wgoctopus_bot.screens import (
    device_card,
    devices_screen,
    format_bytes,
    handshake_age,
    main_menu,
    request_admin_screen,
)

CFG = type("Settings", (), {"bot_instance": "test", "default_limit": 3})()


def callbacks(screen):
    return [button.data for row in screen.buttons for button in row]


def test_catalogs_and_languages():
    assert EN.keys() == RU.keys()
    assert placeholders(EN) == placeholders(RU)
    assert lang_from_code("ru-RU") == "ru"
    assert lang_from_code("fr") == "en"
    with pytest.raises(KeyError):
        t("en", "missing")


@pytest.mark.parametrize("lang", ["en", "ru"])
def test_screens_escape_and_callbacks(lang):
    device = {"id": 7, "name": "<b>x</b>&", "owner": "<alice>", "enabled": True,
              "allowed_ip": "10.0.0.1", "created_at": "now", "rx": 1024, "tx": 2048}
    assert "&lt;b&gt;x&lt;/b&gt;&amp;" in device_card(lang, device).text
    card = device_card(lang, device, can_manage_state=True)
    assert "dev_toggle:7" in callbacks(card) and "dev_del:7" in callbacks(card)
    assert len(callbacks(main_menu(lang, "user"))) > 0
    req = request_admin_screen(lang, {"id": 4, "type": "access", "username": "<x>", "first_name": "<b>"})
    assert "&lt;x&gt;" in req.text
    assert all(len(data.encode()) <= 64 for data in callbacks(card) + callbacks(req))


def test_time_bytes_filters_pagination_and_large_callbacks():
    now = datetime(2026, 1, 3, tzinfo=UTC)
    assert handshake_age(None) == "—"
    assert handshake_age((now - timedelta(minutes=59)).isoformat(), now) == "59m"
    assert handshake_age((now - timedelta(hours=47)).isoformat(), now) == "47h"
    assert handshake_age((now - timedelta(days=2)).isoformat(), now) == "2d"
    assert handshake_age("2026-01-03T00:00:00", now) == "0m"
    assert format_bytes(1024) == "1.0 KiB"
    assert format_bytes(1024**2) == "1.0 MiB"
    assert format_bytes(1024**3) == "1.0 GiB"
    records = [{"id": i, "name": f"d{i}", "active": i == 1, "enabled": i % 2 == 0} for i in range(10)]
    assert len(devices_screen("en", records, "active", 0, 10, -1).buttons) == 3
    assert "pinfo:8" in callbacks(devices_screen("en", records, "all", 999, 10, -1))
    assert "pinfo:0" in callbacks(devices_screen("en", records, "enabled", 0, 10, -1))
    assert "pinfo:1" in callbacks(devices_screen("en", records, "disabled", 0, 10, -1))
    with pytest.raises(ValueError):
        device_card("en", {"id": 10**80, "name": "x"})


@pytest.mark.asyncio
async def test_create_rename_config_permissions_and_limit():
    api = FakeApi()
    alice = Actor("alice", 1, "user")
    created = await cmd_create(alice, api, CFG)
    assert isinstance(created, ShowScreen)
    asked = await handle_callback("create:self", alice, api, CFG)
    assert isinstance(asked, AskInput)
    assert (await handle_input(asked.kind, asked.payload, alice, api, "bad name", CFG)).text
    assert isinstance(await handle_input("create_name", {}, alice, api, "named", CFG), ShowScreen)
    assert isinstance(await handle_input("create_name", {}, alice, api, "named", CFG), Toast)
    await api.create_device("bob", 9, "other")
    for callback in ("cfg:3", "ren:3", "pinfo:3"):
        assert (await handle_callback(callback, alice, api, CFG)).text == t("en", "forbidden")
    assert isinstance(await handle_callback("cfg:3", Actor("root", 2, "admin"), api, CFG), SendDocument)
    api.users["alice"]["config_limit"] = 2
    assert isinstance(await handle_input("create_name", {}, alice, api, "third", CFG), Toast)
    api.users["alice"]["config_limit"] = -1
    assert isinstance(await handle_input("create_name", {}, alice, api, "unlimited", CFG), ShowScreen)


@pytest.mark.asyncio
async def test_rename_authorization_rechecked_and_api_errors_converted():
    api = FakeApi()
    await api.create_device("bob", 9, "other")
    result = await handle_input("rename", {"id": 1}, Actor("alice", 1, "user"), api, "new", CFG)
    assert isinstance(result, Toast) and result.text == t("en", "forbidden")
    result = await handle_input("rename", {"id": 1}, Actor("bob", 3, "user"), api, "renamed", CFG)
    assert isinstance(result, ShowScreen)
    assert (await handle_callback("mystery", Actor("alice", 1, "user"), api, CFG)).text == ""
    assert (await handle_callback("cfg:999", Actor("alice", 1, "user"), api, CFG)).text


@pytest.mark.asyncio
async def test_access_requests_admin_notifications_and_double_decision():
    api = FakeApi()
    deliveries = []

    async def send(tg_id, screen):
        if tg_id == 2:
            deliveries.append((tg_id, screen))
            return 100, 200
        raise RuntimeError("send failed")

    requester = type("User", (), {"id": 44, "username": "new", "first_name": "Name", "last_name": "", "lang": "ru"})()
    result = await cmd_givemepowers(requester, api, send)
    assert result[0].text == t("ru", "request_sent")
    request_id = next(iter(api.requests))
    assert api.refs[request_id] == [[100, 200]]
    admin = Actor("root", 2, "admin")
    decided = await handle_callback(f"req:a:{request_id}", admin, api, CFG)
    assert isinstance(decided, ResultBundle)
    assert isinstance(decided.results[0], EditAdminCopies)
    assert decided.results[0].refs == [[100, 200]]
    assert isinstance(decided.results[1], Notify)
    again = await handle_callback(f"req:a:{request_id}", admin, api, CFG)
    assert isinstance(again, Toast) and again.text == t("en", "already_processed")
    assert isinstance(await handle_callback(f"req:d:{request_id}", Actor("alice", 1, "user"), api, CFG), Toast)


@pytest.mark.asyncio
async def test_limit_request_validation_admin_and_no_admin():
    api = FakeApi()
    actor = Actor("alice", 1, "user")
    assert (await handle_input("limit_req", {}, actor, api, "abc", CFG)).text
    assert (await handle_input("limit_req", {}, actor, api, "2", CFG)).text
    assert isinstance(await handle_input("limit_req", {}, actor, api, "5", CFG), Toast)
    assert (await handle_callback("reqlim", Actor("root", 2, "admin"), api, CFG)).text
    api.admins = [{"username": "ghost", "role": "admin"}]

    async def send(tg_id, screen):
        return None

    result = await cmd_givemepowers(type("User", (), {"id": 55, "username": "fresh", "first_name": "", "last_name": "", "lang": "en"})(), api, send)
    assert result[0].text == t("en", "no_admin")
