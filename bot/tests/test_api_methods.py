import httpx
import pytest

from wgoctopus_bot.api import OrchApi

CASES = [
    ("list_users", ("x",), {"status": "enabled"}, "GET", "/v1/users"),
    ("get_user", ("alice",), {}, "GET", "/v1/users/alice"),
    ("patch_user", ("alice",), {"config_limit": 5}, "PATCH", "/v1/users/alice"),
    ("delete_user", ("alice",), {}, "DELETE", "/v1/users/alice"),
    ("disable_user", ("alice", "root"), {}, "POST", "/v1/users/alice/disable"),
    ("enable_user", ("alice",), {}, "POST", "/v1/users/alice/enable"),
    ("create_request", (), {"type": "access"}, "POST", "/v1/requests"),
    ("list_requests", (), {"status": "pending"}, "GET", "/v1/requests"),
    ("get_request", (4,), {}, "GET", "/v1/requests/4"),
    ("approve_request", (4,), {"admin_tg_id": 1}, "POST", "/v1/requests/4/approve"),
    ("decline_request", (4,), {"admin_tg_id": 1}, "POST", "/v1/requests/4/decline"),
    ("set_request_refs", (4, [[1, 2]]), {}, "PUT", "/v1/requests/4/refs"),
    ("devices", ("alice",), {}, "GET", "/v1/users/alice/devices"),
    ("create_device", ("alice", 3, "ph"), {}, "POST", "/v1/users/alice/devices"),
    ("device", (7,), {}, "GET", "/v1/devices/7"),
    ("patch_device", (7,), {"enabled": False}, "PATCH", "/v1/devices/7"),
    ("delete_device", (7,), {}, "DELETE", "/v1/devices/7"),
    ("instances", (), {}, "GET", "/v1/instances"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "args", "kwargs", "method", "path"), CASES)
async def test_method_routes(name, args, kwargs, method, path):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(base_url="https://example.test", transport=httpx.MockTransport(handler))
    api = OrchApi("https://example.test", "t", client)
    if name == "list_users":
        args = ()
    assert await getattr(api, name)(*args, **kwargs) == {"ok": True}
    assert (seen[0].method, seen[0].url.path) == (method, path)
    await client.aclose()


@pytest.mark.asyncio
async def test_empty_body_and_owned_client_close():
    client = httpx.AsyncClient(base_url="https://example.test", transport=httpx.MockTransport(lambda _: httpx.Response(204)))
    api = OrchApi("https://example.test", "t", client)
    assert await api.delete_device(1) is None
    await api.close()  # injected client is not closed
    assert not client.is_closed
    await client.aclose()
    owned = OrchApi("https://example.test", "t")
    await owned.close()
    assert owned.client.is_closed


@pytest.mark.asyncio
async def test_device_config_non_json_error():
    from wgoctopus_bot.api import ApiError
    client = httpx.AsyncClient(base_url="https://example.test", transport=httpx.MockTransport(lambda _: httpx.Response(500, text="boom")))
    with pytest.raises(ApiError) as e:
        await OrchApi("https://example.test", "t", client).device_config(1)
    assert e.value.code == "request_failed"
    await client.aclose()
