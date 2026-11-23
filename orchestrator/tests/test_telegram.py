import json
import traceback

import httpx
import pytest

from wgoctopus_orch.alerts import NotifyError, TelegramNotifier

TOKEN = "123456:" + "TEST-TOKEN"
API_BASE = "https://telegram." + "invalid"

@pytest.mark.asyncio
async def test_telegram_request_and_truncation():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        notifier = TelegramNotifier(TOKEN, "chat", api_base=API_BASE, client=client)
        await notifier.send("x" * 5000)
    assert str(requests[0].url) == f"{API_BASE}/bot{TOKEN}/sendMessage"
    assert requests[0].method == "POST"
    assert requests[0].url.path == f"/bot{TOKEN}/sendMessage"
    body = json.loads(requests[0].content)
    assert body == {"chat_id": "chat", "text": "x" * 4000, "disable_web_page_preview": True}
    assert "parse_mode" not in body
    assert TOKEN not in repr(notifier)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "connect", "401", "429", "500", "rejected", "invalid-json"])
async def test_telegram_errors_are_redacted(failure):
    async def handler(request):
        if failure == "timeout":
            raise httpx.ReadTimeout(f"request to {request.url}", request=request)
        if failure == "connect":
            raise httpx.ConnectError(f"failed {request.url}", request=request)
        status = {"401": 401, "429": 429, "500": 500}.get(failure, 200)
        if failure == "invalid-json":
            return httpx.Response(200, text="not json")
        payload = {"ok": False, "parameters": {"retry_after": 8}} if failure == "429" else {"ok": failure != "rejected"}
        return httpx.Response(status, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(NotifyError) as error:
            await TelegramNotifier(TOKEN, "chat", api_base=API_BASE, client=client).send("hello")
    rendered = "\n".join((str(error.value), repr(error.value), "".join(traceback.format_exception(error.type, error.value, error.tb))))
    assert TOKEN not in rendered
    assert API_BASE.removeprefix("https://") not in rendered
    if failure == "429":
        assert error.value.retry_after == 8
