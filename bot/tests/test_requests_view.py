import pytest
from fakes import FakeApi

from wgoctopus_bot.i18n import EN, RU
from wgoctopus_bot.router import (
    Actor,
    Config,
    ResultBundle,
    ShowScreen,
    Toast,
    cmd_admin,
    handle_callback,
)
from wgoctopus_bot.screens import requests_screen


@pytest.mark.asyncio
async def test_requests_tabs_pages_and_render():
    api = FakeApi()
    for i in range(25):
        api.requests[i + 1] = {"id": i + 1, "status": "pending", "type": "access", "username": "alice", "tg_id": 1}
    result = await handle_callback("reqs:pending:2", Actor("root", 2, "admin"), api)
    assert isinstance(result, ShowScreen)
    assert "#21" in result.screen.text and "#25" in result.screen.text
    assert [k for k in EN] == [k for k in RU]
    assert "pending" in requests_screen("en", [api.requests[1]], "all", 0, 25, 25).text
    assert (await handle_callback("reqs:all:0", Actor("root", 2, "admin"), api)).screen.buttons[0][0].data == "reqs:all:0"


@pytest.mark.asyncio
@pytest.mark.parametrize("action,status", [("a", "approved"), ("d", "declined")])
async def test_request_decisions_from_view(action, status):
    api = FakeApi()
    api.requests[1] = {"id": 1, "status": "pending", "type": "access", "username": "alice", "tg_id": 1, "notification_refs": []}
    result = await handle_callback(f"req:{action}:1", Actor("root", 2, "admin"), api, Config("", 3))
    assert isinstance(result, ResultBundle) and len(result.results) == 2
    assert api.requests[1]["status"] == status
    again = await handle_callback(f"req:{action}:1", Actor("root", 2, "admin"), api)
    assert isinstance(again, Toast) and again.text


@pytest.mark.asyncio
async def test_requests_non_admin_and_command():
    api = FakeApi()
    denied = await handle_callback("reqs:all:0", Actor("alice", 1, "user"), api)
    assert isinstance(denied, Toast) and denied.alert
    assert isinstance(await cmd_admin("requests", [], Actor("root", 2, "admin"), api, Config("")), ShowScreen)
