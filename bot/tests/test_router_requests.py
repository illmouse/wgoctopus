from types import SimpleNamespace

import httpx
import pytest
from fakes import FakeApi

from wgoctopus_bot.api import ApiError
from wgoctopus_bot.i18n import t
from wgoctopus_bot.router import (
    Actor,
    AskInput,
    EditAdminCopies,
    Notify,
    ResultBundle,
    Toast,
    cmd_givemepowers,
    handle_callback,
    handle_input,
)

CFG = SimpleNamespace(bot_instance="test", default_limit=7)
ADMIN = Actor("root", 2, "admin")
USER = Actor("alice", 1, "user", "ru")
TG_USER = SimpleNamespace(id=44, username="new", first_name="Name", last_name="", lang="ru")


@pytest.mark.asyncio
async def test_access_request_admin_filter_delivery_refs_and_pending():
    api = FakeApi()
    api.admins = [
        {"username": "no-id", "role": "admin", "status": "enabled"},
        {"username": "disabled", "role": "admin", "status": "disabled", "tg_id": 5},
        {"username": "root", "role": "admin", "status": "enabled", "tg_id": 2, "language": "ru"},
        {"username": "second", "role": "admin", "status": "enabled", "tg_id": 6},
    ]
    sent = []

    async def send(tg_id, screen):
        sent.append((tg_id, screen))
        if tg_id == 2:
            raise RuntimeError("Telegram unavailable")
        return (60, 70)

    assert (await cmd_givemepowers(TG_USER, api, send))[0].text == t("ru", "request_sent")
    ident = next(iter(api.requests))
    assert [tg_id for tg_id, _ in sent] == [2, 6]
    assert api.refs[ident] == [[60, 70]]
    assert api.requests[ident]["notification_refs"] == [[60, 70]]

    again = await cmd_givemepowers(TG_USER, api, send)
    assert isinstance(again[0], Toast) and again[0].text == t("ru", "request_pending")


@pytest.mark.asyncio
async def test_access_request_no_admin_and_api_errors():
    api = FakeApi()
    api.admins = [{"username": "ghost", "role": "admin"}]
    assert (await cmd_givemepowers(TG_USER, api, lambda *_: None))[0].text == t("ru", "no_admin")
    api.create_request = _raises(ApiError(422, "bad request"))
    assert (await cmd_givemepowers(TG_USER, api, lambda *_: None))[0].text == t("ru", "api_error")


@pytest.mark.asyncio
async def test_access_approve_default_limit_language_and_forbidden():
    api = FakeApi()
    api.users.pop("alice")
    request = await api.create_request(type="access", tg_id=1, username="fresh", first_name="", last_name="")
    request["language"] = "ru"
    request["notification_refs"] = [[3, 4]]
    api.requests[request["id"]].update(language="ru", notification_refs=[[3, 4]])
    result = await handle_callback(f"req:a:{request['id']}", Actor("stranger", 99, "user"), api, CFG)
    assert isinstance(result, Toast) and result.alert and result.text == t("en", "forbidden")
    assert api.requests[request["id"]]["status"] == "pending"

    approved = await handle_callback(f"req:a:{request['id']}", ADMIN, api, CFG)
    assert isinstance(approved, ResultBundle)
    edit, notify = approved.results
    assert isinstance(edit, EditAdminCopies) and edit.refs == [[3, 4]]
    assert isinstance(notify, Notify) and notify.tg_id == 1
    assert notify.screen == t("ru", "registered", limit=7)
    assert api.users["fresh"]["config_limit"] == 7
    duplicate = await handle_callback(f"req:a:{request['id']}", ADMIN, api, CFG)
    assert isinstance(duplicate, Toast) and duplicate.text == t("en", "already_processed")


@pytest.mark.asyncio
async def test_decline_request_notifies_requester_and_edits_copies():
    api = FakeApi()
    req = await api.create_request(type="access", tg_id=44, username="new", first_name="", last_name="")
    api.requests[req["id"]].update(language="ru", notification_refs=[[8, 9]])
    result = await handle_callback(f"req:d:{req['id']}", ADMIN, api, CFG)
    assert isinstance(result, ResultBundle)
    assert result.results[0].refs == [[8, 9]]
    assert result.results[1] == Notify(44, t("ru", "declined"))


@pytest.mark.asyncio
async def test_limit_request_validation_duplicate_and_admin_copy():
    api = FakeApi()
    for value in ("nope", "-2", "2"):
        result = await handle_input("limit_req", {}, USER, api, value, CFG)
        assert isinstance(result, Toast) and result.text == t("ru", "limit_invalid")
    assert isinstance(await handle_callback("reqlim", USER, api, CFG), AskInput)
    assert (await handle_input("limit_req", {}, ADMIN, api, "4", CFG)).text == t("en", "admin_use_limit_cmd")

    assert (await handle_input("limit_req", {}, USER, api, "-1", CFG)).text == t("ru", "request_sent")
    req = next(iter(api.requests.values()))
    assert req["requested_limit"] == -1 and req["previous_limit"] == 2
    assert "2" in req["username"] or req["username"] == "alice"
    duplicate = await handle_input("limit_req", {}, USER, api, "5", CFG)
    assert duplicate.text == t("ru", "request_pending")


@pytest.mark.asyncio
async def test_limit_approval_notifies_requester_with_new_limit():
    api = FakeApi()
    req = await api.create_request(type="limit", tg_id=1, username="alice", requested_limit=5)
    api.requests[req["id"]]["notification_refs"] = [[10, 20]]
    result = await handle_callback(f"req:a:{req['id']}", ADMIN, api, CFG)
    assert isinstance(result, ResultBundle)
    assert result.results[0].refs == [[10, 20]]
    assert result.results[1] == Notify(1, t("en", "registered", limit=5))


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [ApiError(503, "unavailable"), httpx.ConnectError("offline")])
async def test_request_input_api_errors_become_api_error_toast(error):
    api = FakeApi()
    api.create_request = _raises(error)
    result = await handle_input("limit_req", {}, USER, api, "5", CFG)
    assert isinstance(result, Toast) and result.text == t("ru", "api_error")


def _raises(error):
    async def fail(*args, **kwargs):
        raise error

    return fail
