import httpx
import pytest
from fakes import FakeApi

from wgoctopus_bot.api import ApiError, OrchApi
from wgoctopus_bot.i18n import EN, RU, t
from wgoctopus_bot.router import Actor, ShowScreen, Toast, handle_callback

ADMIN = Actor("root", 2, "admin")
USER = Actor("alice", 1, "user")
RU_ADMIN = Actor("root", 2, "admin", "ru")


@pytest.mark.asyncio
async def test_admin_confirm_and_reject_call_api_with_actor():
    api = FakeApi()
    out = await handle_callback("fo:c:7", ADMIN, api)
    assert isinstance(out, ShowScreen) and out.edit and out.screen.buttons == []
    assert "7" in out.screen.text and "root" in out.screen.text
    out = await handle_callback("fo:r:8", RU_ADMIN, api)
    assert "отклон" in out.screen.text
    assert api.failover_calls == [("confirm", 7, "root"), ("reject", 8, "root")]


@pytest.mark.asyncio
async def test_non_admin_is_refused_without_api_call():
    api = FakeApi()
    out = await handle_callback("fo:c:7", USER, api)
    assert isinstance(out, Toast) and out.alert and out.text == t("en", "forbidden")
    assert not getattr(api, "failover_calls", [])


@pytest.mark.asyncio
@pytest.mark.parametrize("data", ["fo:x:1", "fo:c:abc", "fo:c", "fo:c:1:2"])
async def test_malformed_callbacks_are_ignored(data):
    api = FakeApi()
    out = await handle_callback(data, ADMIN, api)
    assert isinstance(out, Toast)
    assert not getattr(api, "failover_calls", [])


@pytest.mark.asyncio
@pytest.mark.parametrize("status,code,detail,key", [
    (404, "not_found", "not_found", "fo_not_found"),
    (409, "conflict", "not_pending", "fo_not_pending"),
    (409, "conflict", "expired", "fo_expired"),
    (409, "conflict", "stale", "fo_stale"),
    (409, "conflict", "no_candidate", "fo_no_candidate"),
    (500, "error", "boom", "api_error"),
])
async def test_api_errors_map_to_toasts(status, code, detail, key):
    api = FakeApi()
    api.failover_error = ApiError(status, code, detail)
    out = await handle_callback("fo:c:1", ADMIN, api)
    assert isinstance(out, Toast) and out.alert and out.text == t("en", key)


def test_catalogs_have_failover_keys():
    for key in ("fo_confirmed", "fo_rejected", "fo_not_found", "fo_not_pending", "fo_expired", "fo_stale", "fo_no_candidate"):
        assert key in RU and key in EN


@pytest.mark.asyncio
async def test_client_sends_actor_and_parses_string_detail():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.content))
        if request.url.path.endswith("/reject"):
            return httpx.Response(409, json={"error": "conflict", "detail": "not_pending"})
        return httpx.Response(200, json={"id": 3})

    api = OrchApi("http://orch", "tok", httpx.AsyncClient(base_url="http://orch", transport=httpx.MockTransport(handler)))
    assert await api.confirm_failover(3, actor="root") == {"id": 3}
    assert seen[0][0] == "/v1/failovers/3/confirm"
    assert b'"by":"telegram"' in seen[0][1].replace(b" ", b"") and b"root" in seen[0][1]
    with pytest.raises(ApiError) as exc:
        await api.reject_failover(3, actor="root")
    assert exc.value.status == 409 and exc.value.detail == "not_pending"
