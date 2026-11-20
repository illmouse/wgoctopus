import pytest
import pytest_asyncio
from fake_agent import FakeAgent

from wgoctopus_orch.config import Settings
from wgoctopus_orch.models import Event, NodeObserved, NodeRevision
from wgoctopus_orch.push import PushStatus, push_node
from wgoctopus_orch.service import add_peer, create_instance, create_node, place
from wgoctopus_orch.transport import DirectHttpTransport


@pytest_asyncio.fixture
async def fake_agent():
    agent = FakeAgent()
    await agent.start()
    yield agent
    if agent._server:
        await agent.stop()


def setup(session, agent, crypto):
    node = create_node(session, "node", "127.0.0.1", "test", agent_port=agent.port, agent_token=agent.token, crypto=crypto)
    instance = create_instance(session, "wg0", 12345, "10.0.0.1/24", obfuscation={"jc": 1, "jmin": 8, "jmax": 80, "s1": 1, "s2": 2, "s3": 3, "s4": 4, "h1": "1", "h2": "2", "h3": "3", "h4": "4"}, crypto=crypto)
    place(session, instance.id, node.id, crypto=crypto)
    peer = add_peer(session, instance.id, "peer", crypto=crypto)
    session.flush()
    return node, instance, peer


@pytest.mark.asyncio
async def test_push_ok_redaction_and_up_to_date(session, fake_agent, crypto, caplog):
    node, instance, peer = setup(session, fake_agent, crypto)
    transport = DirectHttpTransport(Settings(transport="direct"), crypto=crypto)
    outcome = await push_node(session, node.id, transport=transport, crypto=crypto)
    observed = session.get(NodeObserved, node.id)
    assert outcome.status == PushStatus.OK
    assert observed.last_seen_at and observed.applied_revision and observed.applied_checksum and observed.healthy and observed.last_error is None
    assert session.query(Event).filter_by(kind="push.ok").one().data == {"revision": observed.applied_revision}
    secrets = [crypto.decrypt(instance.private_key_enc), crypto.decrypt(peer.preshared_key_enc), fake_agent.token]
    exposed = repr([e.data for e in session.query(Event).all()]) + repr(observed.last_error) + repr(observed.raw) + caplog.text
    assert all(secret not in exposed for secret in secrets)
    count = sum(request[0] == "PUT" for request in fake_agent.requests)
    current = await push_node(session, node.id, transport=transport, crypto=crypto)
    assert current.status == PushStatus.UP_TO_DATE, (current, fake_agent.requests)
    assert sum(request[0] == "PUT" for request in fake_agent.requests) == count
    session.get(NodeRevision, node.id).desired_revision += 1
    session.flush()
    fake_agent.state["revision"] = 99
    assert (await push_node(session, node.id, transport=transport, crypto=crypto)).status == PushStatus.REVISION_AHEAD
    assert sum(request[0] == "PUT" for request in fake_agent.requests) == count


@pytest.mark.asyncio
async def test_push_dangerous_allowed_disabled_and_errors(session, fake_agent, crypto):
    node, _, _ = setup(session, fake_agent, crypto)
    transport = DirectHttpTransport(Settings(transport="direct"), crypto=crypto)
    assert (await push_node(session, node.id, transport=transport, crypto=crypto)).status == PushStatus.OK
    revision = session.get(NodeRevision, node.id)
    revision.desired_revision += 1
    fake_agent.state["interfaces"][0]["listen_port"] += 1
    blocked = await push_node(session, node.id, transport=transport, crypto=crypto)
    assert blocked.status == PushStatus.BLOCKED_DANGEROUS and blocked.reasons
    assert (await push_node(session, node.id, transport=transport, crypto=crypto, allow_dangerous=True)).status == PushStatus.OK
    node.enabled = False
    assert (await push_node(session, node.id, transport=transport, crypto=crypto)).status == PushStatus.SKIPPED_DISABLED
    node.enabled = True
    fake_agent.token = "other-token"
    assert (await push_node(session, node.id, transport=transport, crypto=crypto)).status == PushStatus.UNAUTHORIZED
    assert "unauthorized" in session.get(NodeObserved, node.id).last_error
    node.enabled = False
    node.enabled = True
    await fake_agent.stop()
    assert (await push_node(session, node.id, transport=transport, crypto=crypto)).status == PushStatus.FAILED
    assert not session.get(NodeObserved, node.id).healthy
