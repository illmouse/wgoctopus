import httpx
import pytest
import pytest_asyncio
from fake_agent import FakeAgent

from wgoctopus_orch.agent_client import AgentClient, ErrorKind
from wgoctopus_orch.transport import AgentSession


@pytest_asyncio.fixture
async def fake_agent():
    agent = FakeAgent()
    await agent.start()
    yield agent
    await agent.stop()


def client(agent, timeout=1, token=None):
    return AgentClient(AgentSession(httpx.AsyncClient(base_url=f"http://127.0.0.1:{agent.port}", headers={"Authorization": f"Bearer {token or agent.token}"})), timeout)


@pytest.mark.asyncio
async def test_put_result_kinds(fake_agent):
    c = client(fake_agent)
    assert (await c.put_state({"revision": 1})).ok
    assert (await c.put_state({"revision": 1})).error_kind == ErrorKind.STALE_REVISION
    changed = {"revision": 2, "interfaces": [{"name": "wg0", "private_key": "key", "listen_port": 1, "obfuscation": {}}]}
    assert (await c.put_state(changed)).ok
    dangerous = {**changed, "revision": 3, "interfaces": [{**changed["interfaces"][0], "private_key": "changed"}]}
    result = await c.put_state(dangerous)
    assert result.error_kind == ErrorKind.DANGEROUS and result.reasons
    assert (await c.put_state(dangerous, allow_dangerous=True)).ok
    assert (await c.put_state({})).error_kind == ErrorKind.INVALID
    unauthorized = AgentClient(AgentSession(httpx.AsyncClient(base_url=f"http://127.0.0.1:{fake_agent.port}", headers={"Authorization": "Bearer wrong"})))
    assert (await unauthorized.put_state({"revision": 9})).error_kind == ErrorKind.UNAUTHORIZED
    await c.session._client.aclose()
    await unauthorized.session._client.aclose()


@pytest.mark.asyncio
async def test_timeout_unreachable_and_other(fake_agent):
    fake_agent.delay = .2
    c = client(fake_agent, .05)
    assert (await c.put_state({"revision": 1})).error_kind == ErrorKind.TIMEOUT
    await c.session._client.aclose()
    fake_agent.delay = 0
    c = client(fake_agent)
    await fake_agent.stop()
    assert (await c.put_state({"revision": 1})).error_kind == ErrorKind.UNREACHABLE
    await c.session._client.aclose()


@pytest.mark.asyncio
async def test_get_health_metrics_and_secret_redaction(fake_agent, caplog):
    c = client(fake_agent)
    assert await c.healthz() == "ok"
    assert (await c.get_state())[0] == 0
    assert "fake 1" in await c.metrics_text()
    assert fake_agent.token not in repr(c) + str(c)
    await c.session._client.aclose()
