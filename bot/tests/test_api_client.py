import json

import httpx
import pytest

from wgoctopus_bot.api import ApiError, OrchApi


@pytest.mark.asyncio
async def test_auth_bodies_and_instance_cache():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/v1/instances":
            return httpx.Response(200, json=[{"name": "wg", "id": 9}])
        return httpx.Response(200, json={"username": "alice"})

    client = httpx.AsyncClient(base_url="https://example.test", headers={"Authorization": "Bearer secret"}, transport=httpx.MockTransport(handler))
    api = OrchApi("https://example.test", "secret", client)
    await api.resolve(12, "alice", "ru")
    await api.ensure_user("alice", role="admin", config_limit=7)
    assert json.loads(seen[0].content) == {"tg_id": 12, "username": "alice", "language": "ru"}
    assert json.loads(seen[1].content) == {"role": "admin", "config_limit": 7}
    assert all(req.headers["Authorization"] == "Bearer secret" for req in seen)
    assert await api.instance_id("wg") == await api.instance_id("wg") == 9
    assert sum(req.url.path == "/v1/instances" for req in seen) == 1
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "body", "code"), [
    (400, {"detail": {"error": "bad", "detail": "no"}}, "bad"),
    (403, {"error": "denied"}, "denied"),
    (500, "broken", "request_failed"),
])
async def test_error_envelopes_do_not_expose_token(status, body, code):
    client = httpx.AsyncClient(base_url="https://example.test", headers={"Authorization": "Bearer private"}, transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body) if isinstance(body, dict) else httpx.Response(status, text=body)))
    api = OrchApi("https://example.test", "private", client)
    with pytest.raises(ApiError) as error:
        await api.instances()
    assert (error.value.status, error.value.code) == (status, code)
    assert "private" not in str(error.value)
    await client.aclose()


@pytest.mark.asyncio
async def test_device_config_bytes_and_error():
    client = httpx.AsyncClient(base_url="https://example.test", transport=httpx.MockTransport(lambda req: httpx.Response(404, json={"error": "not_found"}) if req.url.path.endswith("/2/config") else httpx.Response(200, content=b"config-bytes")))
    api = OrchApi("https://example.test", "token", client)
    assert await api.device_config(1) == b"config-bytes"
    with pytest.raises(ApiError) as error:
        await api.device_config(2)
    assert error.value.status == 404 and error.value.code == "not_found"
    await client.aclose()
