import asyncio
import logging

import pytest
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.config import Settings
from wgoctopus_orch.models import Event
from wgoctopus_orch.push import PushOutcome, PushStatus
from wgoctopus_orch.reconciler import NodeState, NodeStatus, Reconciler, build_reconciler
from wgoctopus_orch.service import add_peer, create_instance, create_node, place
from wgoctopus_orch.transport import DirectHttpTransport


def sessions(session):
    return sessionmaker(bind=session.get_bind(), expire_on_commit=False)


@pytest.mark.asyncio
async def test_converges_and_revision_updates_only_placed_nodes(session, fake_agent_factory, crypto):
    agents = await fake_agent_factory(2)
    nodes = [create_node(session, f"n{i}", "127.0.0.1", "test", agent_port=agent.port,
                         agent_token=agent.token, crypto=crypto) for i, agent in enumerate(agents)]
    instances = [create_instance(session, f"wg{i}", 12000 + i, f"10.{i}.0.1/24", crypto=crypto) for i in range(2)]
    for instance, node in zip(instances, nodes):
        place(session, instance.id, node.id, crypto=crypto)
        add_peer(session, instance.id, "peer", crypto=crypto)
    transport = DirectHttpTransport(Settings(transport="direct"), crypto=crypto)
    reconciler = Reconciler(sessions(session), lambda _: transport, Settings(transport="direct"), crypto=crypto)
    results = await reconciler.reconcile_once()
    assert all(result.status == PushStatus.OK for result in results.values()), results
    puts = [sum(req[0] == "PUT" for req in agent.requests) for agent in agents]
    await reconciler.reconcile_once()
    assert [sum(req[0] == "PUT" for req in agent.requests) for agent in agents] == puts
    add_peer(session, instances[0].id, "new", crypto=crypto)
    # A successful sync is revisited each interval; the other node remains up to date.
    await reconciler.reconcile_once()
    assert [sum(req[0] == "PUT" for req in agent.requests) for agent in agents] == [puts[0] + 1, puts[1]]
    assert all(s.state == NodeState.IN_SYNC for s in reconciler.status().values())


@pytest.mark.asyncio
async def test_disabled_and_status_is_memory_only(session, fake_agent_factory, crypto):
    agent, = await fake_agent_factory()
    node = create_node(session, "disabled", "127.0.0.1", "test", agent_port=agent.port,
                       agent_token=agent.token, enabled=False, crypto=crypto)
    settings = Settings(transport="direct")
    rec = Reconciler(sessions(session), lambda _: DirectHttpTransport(settings, crypto=crypto), settings, crypto=crypto)
    await rec.reconcile_once()
    assert rec.status()[node.id].state == NodeState.DISABLED
    assert Reconciler(lambda: session, lambda _: None, settings).status() == {}


@pytest.mark.asyncio
async def test_blocked_dangerous_requires_explicit_override(session, fake_agent_factory, crypto):
    agent, = await fake_agent_factory()
    node = create_node(session, "blocked", "127.0.0.1", "test", agent_port=agent.port,
                       agent_token=agent.token, crypto=crypto)
    instance = create_instance(session, "wg0", 12345, "10.0.0.1/24", crypto=crypto)
    place(session, instance.id, node.id, crypto=crypto)
    transport = DirectHttpTransport(Settings(transport="direct"), crypto=crypto)
    settings = Settings(transport="direct", reconcile_blocked_recheck=300)
    rec = Reconciler(sessions(session), lambda _: transport, settings, crypto=crypto)
    session.commit()
    assert (await rec.reconcile_once())[node.id].status == PushStatus.OK
    instance.listen_port += 1
    from wgoctopus_orch.service import bump_revision
    session.flush()
    assert bump_revision(session, node.id, crypto)
    session.commit()
    result = await rec.reconcile_once()
    assert result[node.id].status == PushStatus.BLOCKED_DANGEROUS
    assert rec.status()[node.id].state == NodeState.BLOCKED_DANGEROUS
    assert await rec.reconcile_once() == {}
    assert (await rec.apply_dangerous(node.id)).status == PushStatus.OK
    assert session.query(Event).filter_by(kind="reconcile.dangerous_override").count() == 1


@pytest.mark.asyncio
async def test_unreachable_backoff_transitions_and_forced_kick(session, fake_agent_factory, crypto):
    agent, = await fake_agent_factory()
    node = create_node(session, "offline", "127.0.0.1", "test", agent_port=agent.port,
                       agent_token=agent.token, crypto=crypto)
    settings = Settings(transport="direct", reconcile_max_backoff=12)
    now = [100.0]
    rec = Reconciler(sessions(session), lambda _: DirectHttpTransport(settings, crypto=crypto), settings,
                     crypto=crypto, clock=lambda: now[0], random_fn=lambda: 0)
    await agent.stop()
    await rec.reconcile_once()
    assert rec._next[node.id] == 104
    assert rec.status()[node.id].consecutive_failures == 1
    assert await rec.reconcile_once() == {}
    assert rec.status()[node.id].consecutive_failures == 1
    now[0] = 104
    await rec.reconcile_once()
    assert rec._next[node.id] == 112  # 10s base * 0.8
    now[0] = 112
    await rec.reconcile_once()
    assert rec._next[node.id] == 112 + 9.6  # capped base, then lower jitter bound
    rec.kick(node.id, force=True)
    # Connection failure remains a failure, but force bypasses the deadline.
    await rec.reconcile_once({node.id})
    assert rec.status()[node.id].consecutive_failures == 4
    assert session.query(Event).filter_by(kind="node.unreachable").count() == 0


@pytest.mark.asyncio
async def test_recovery_and_exact_transition_events(session, crypto, monkeypatch):
    from wgoctopus_orch import reconciler as module

    node = create_node(session, "recover", "127.0.0.1", "test", crypto=crypto)
    settings = Settings(transport="direct")
    outcomes = iter([PushOutcome(PushStatus.FAILED), PushOutcome(PushStatus.UP_TO_DATE)])

    async def push(*args, **kwargs):
        return next(outcomes)

    monkeypatch.setattr(module, "push_node", push)
    rec = Reconciler(sessions(session), lambda _: None, settings, crypto=crypto, clock=lambda: 0)
    rec._status[node.id] = NodeStatus(state=NodeState.IN_SYNC)
    await rec.reconcile_once()
    assert [e.kind for e in session.query(Event).all()].count("node.unreachable") == 1
    rec.kick(node.id, force=True)
    await rec.reconcile_once({node.id})
    kinds = [e.kind for e in session.query(Event).all()]
    assert kinds.count("node.recovered") == 1
    assert kinds.count("node.in_sync") == 0
    assert rec.status()[node.id].state == NodeState.IN_SYNC


@pytest.mark.asyncio
async def test_revision_ahead_blocked_until_deadline(session, fake_agent_factory, crypto):
    agent, = await fake_agent_factory()
    agent.state["revision"] = 9
    node = create_node(session, "ahead", "127.0.0.1", "test", agent_port=agent.port,
                       agent_token=agent.token, crypto=crypto)
    settings = Settings(transport="direct", reconcile_blocked_recheck=30)
    now = [0.0]
    rec = Reconciler(sessions(session), lambda _: DirectHttpTransport(settings, crypto=crypto), settings,
                     crypto=crypto, clock=lambda: now[0])
    await rec.reconcile_once()
    assert rec.status()[node.id].state == NodeState.BLOCKED_REVISION_AHEAD
    assert not any(req[0] == "PUT" for req in agent.requests)
    assert await rec.reconcile_once() == {}
    now[0] = 30
    await rec.reconcile_once()
    assert len([e for e in session.query(Event).all() if e.kind == "node.blocked"]) == 1


@pytest.mark.asyncio
async def test_concurrency_limit_and_timeout_do_not_block_other_nodes(session, fake_agent_factory, crypto):
    agents = await fake_agent_factory(2, delay=.04)
    nodes = [create_node(session, f"slow{i}", "127.0.0.1", "test", agent_port=a.port,
                         agent_token=a.token, crypto=crypto) for i, a in enumerate(agents)]
    settings = Settings(transport="direct", reconcile_concurrency=1, reconcile_node_timeout=.02)
    rec = Reconciler(sessions(session), lambda _: DirectHttpTransport(settings, crypto=crypto), settings,
                     crypto=crypto)
    results = await rec.reconcile_once()
    assert set(results) == {n.id for n in nodes}
    assert all(result.status == PushStatus.FAILED for result in results.values())
    assert all(rec.status()[n.id].state == NodeState.UNREACHABLE for n in nodes)
    assert all(not any(req[0] == "PUT" for req in a.requests) for a in agents)


@pytest.mark.asyncio
async def test_push_exception_is_contained_and_logs_no_secrets(session, fake_agent_factory, crypto, monkeypatch, caplog):
    from wgoctopus_orch import reconciler as module

    agent, = await fake_agent_factory()
    node = create_node(session, "exception", "127.0.0.1", "test", agent_port=agent.port,
                       agent_token=agent.token, crypto=crypto)
    settings = Settings(transport="direct")
    async def fail(*args, **kwargs):
        raise RuntimeError("test secret and private_key")
    monkeypatch.setattr(module, "push_node", fail)
    rec = Reconciler(sessions(session), lambda _: DirectHttpTransport(settings, crypto=crypto), settings,
                     crypto=crypto)
    with caplog.at_level(logging.WARNING):
        result = await rec.reconcile_once()
    assert result[node.id].status == PushStatus.FAILED
    assert session.query(Event).filter_by(kind="reconcile.error").count() == 1
    assert "test secret" not in caplog.text and "private_key" not in caplog.text


@pytest.mark.asyncio
async def test_run_wakes_for_kick_and_stops_promptly(session):
    settings = Settings(transport="direct", reconcile_interval=60)
    rec = Reconciler(lambda: session, lambda _: None, settings)
    calls = []
    started = asyncio.Event()

    async def reconcile(ids=None):
        calls.append(ids)
        started.set()
        return {}

    rec.reconcile_once = reconcile
    stop = asyncio.Event()
    task = asyncio.create_task(rec.run(stop))
    await asyncio.wait_for(started.wait(), 1)
    rec.kick(42)
    await asyncio.sleep(0)
    while len(calls) < 3:
        await asyncio.sleep(0)
    assert calls == [None, {42}, None]
    stop.set()
    await asyncio.wait_for(task, 1)
    assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and t.get_name().startswith("Task-") and not t.done()]


@pytest.mark.asyncio
async def test_unknown_node_is_disabled_result(session):
    settings = Settings(transport="direct")
    rec = Reconciler(sessions(session), lambda _: None, settings)
    result = await rec._one(999)
    assert result.status == PushStatus.SKIPPED_DISABLED


def test_build_reconciler_smoke():
    rec = build_reconciler(Settings(transport="direct"), session_factory=lambda: None)
    assert isinstance(rec, Reconciler)
