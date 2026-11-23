from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.alerts import RULES, AlertDispatcher, NotifyError
from wgoctopus_orch.db import make_engine, upgrade_to_head
from wgoctopus_orch.models import AlertState, Event, Peer
from wgoctopus_orch.service import create_hop_link, create_instance, create_node, create_probe


class FakeNotifier:
    def __init__(self, failures=0):
        self.texts = []
        self.failures = failures

    async def send(self, text):
        if self.failures:
            self.failures -= 1
            raise NotifyError("delivery failed")
        self.texts.append(text)


class Clock:
    def __init__(self, value=0):
        self.value = value

    def __call__(self):
        return self.value


def factory_for(session):
    return sessionmaker(bind=session.get_bind(), expire_on_commit=False)


def add_events(session, *events):
    session.add_all(Event(kind=kind, subject=str(subject), data=data or {}, ts=ts or datetime.now(UTC))
                    for kind, subject, data, ts in events)
    session.commit()


def cursor(session):
    return int(session.get(AlertState, "last_event_id").value)


@pytest.mark.asyncio
async def test_initial_cursor_skips_history_then_delivers_new_events(session):
    add_events(session, ("node.drift", "old", {}, None))
    notifier = FakeNotifier()
    dispatcher = AlertDispatcher(factory_for(session), notifier)
    await dispatcher.poll_once()
    assert cursor(session) == 1 and notifier.texts == []
    add_events(session, ("node.drift", "new", {}, None))
    await dispatcher.poll_once()
    assert cursor(session) == 2 and len(notifier.texts) == 1


@pytest.mark.asyncio
async def test_empty_initial_table_and_ignored_events_advance_cursor(session):
    dispatcher = AlertDispatcher(factory_for(session), FakeNotifier())
    await dispatcher.poll_once()
    assert cursor(session) == 0
    add_events(session, ("peer.created", "p", {}, None), ("node.in_sync", "n", {}, None),
               ("probe.created", "q", {}, None))
    await dispatcher.poll_once()
    assert cursor(session) == 3 and dispatcher.counters()["sent"] == 0


@pytest.mark.asyncio
async def test_default_rule_messages_resolve_names_and_include_severity(session, crypto):
    inst = create_instance(session, "wg0", 51820, "192.0.2.10/24", crypto=crypto)
    hop = create_node(session, "hop-name", "192.0.2.1", "tester", kind="hop", wan_interface="eth0",
                      hop_ip="198.51.100.1", crypto=crypto)
    node = create_node(session, "node-name", "192.0.2.2", "tester", crypto=crypto)
    runner = create_node(session, "runner-name", "192.0.2.3", "tester", crypto=crypto)
    create_hop_link(session, hop.id, inst.id, crypto)
    probe = create_probe(session, hop.id, inst.id, runner.id, crypto=crypto)
    kinds = ["node.unreachable", "node.recovered", "node.blocked", "node.drift", "probe.down",
             "probe.up", "instance.switched", "reconcile.error"]
    # Start after service-generated history, then exercise every default rule.
    session.add(AlertState(key="last_event_id", value=str(session.scalar(select(Event.id).order_by(Event.id.desc()).limit(1)) or 0)))
    session.commit()
    base = datetime(2024, 1, 1, tzinfo=UTC)
    add_events(session,
               (kinds[0], node.id, {}, base), (kinds[1], node.id, {}, base + timedelta(seconds=1)),
               (kinds[2], node.id, {"kind": "firewall"}, base + timedelta(seconds=2)),
               (kinds[3], node.id, {}, base + timedelta(seconds=3)),
               (kinds[4], probe.id, {}, base + timedelta(seconds=4)),
               (kinds[5], probe.id, {}, base + timedelta(seconds=5)),
               (kinds[6], inst.id, {"from": "old-node", "to": "new-node"}, base + timedelta(seconds=6)),
               (kinds[7], "controller", {}, base + timedelta(seconds=7)))
    clock, notifier = Clock(100), FakeNotifier()
    dispatcher = AlertDispatcher(factory_for(session), notifier, delay_seconds=0, clock=clock)
    await dispatcher.poll_once()
    assert len(notifier.texts) == len(RULES)
    for severity, title in RULES.values():
        assert any(f"[{severity}] {title}:" in message for message in notifier.texts)
    assert any("node-name" in t and "Node unreachable" in t for t in notifier.texts)
    assert any("(firewall)" in t for t in notifier.texts)
    assert sum("hop-name / wg0" in t for t in notifier.texts) == 2
    assert any("wg0 old-node to new-node" in t for t in notifier.texts)


@pytest.mark.asyncio
async def test_cursor_persists_between_dispatcher_instances(session):
    session.add(AlertState(key="last_event_id", value="0"))
    session.commit()
    add_events(session, ("node.drift", "n", {}, None))
    factory, notifier = factory_for(session), FakeNotifier()
    await AlertDispatcher(factory, notifier).poll_once()
    await AlertDispatcher(factory, notifier).poll_once()
    assert cursor(session) == 1 and len(notifier.texts) == 1


@pytest.mark.asyncio
async def test_recovery_window_delay_and_subject_independence(session):
    session.add(AlertState(key="last_event_id", value="0"))
    session.commit()
    base, clock, notifier = datetime(2024, 1, 1, tzinfo=UTC), Clock(), FakeNotifier()
    add_events(session, ("node.unreachable", "same", {}, base),
               ("node.recovered", "same", {}, base + timedelta(seconds=4)))
    dispatcher = AlertDispatcher(factory_for(session), notifier, delay_seconds=5, clock=clock)
    await dispatcher.poll_once()
    assert notifier.texts == [] and dispatcher.counters()["dropped"] == 2
    add_events(session, ("node.unreachable", "solo", {}, base),)
    await dispatcher.poll_once()
    assert not notifier.texts
    clock.value = 6
    await dispatcher.poll_once()
    assert len(notifier.texts) == 1
    add_events(session, ("node.recovered", "solo", {}, base + timedelta(seconds=6)))
    await dispatcher.poll_once()
    assert len(notifier.texts) == 2
    add_events(session, ("node.unreachable", "a", {}, base), ("node.unreachable", "b", {}, base))
    clock.value = 10
    await dispatcher.poll_once()
    assert len(notifier.texts) == 2
    clock.value = 16
    await dispatcher.poll_once()
    assert len(notifier.texts) == 4


@pytest.mark.asyncio
async def test_custom_kinds_restrict_alerting(session):
    session.add(AlertState(key="last_event_id", value="0"))
    session.commit()
    add_events(session, ("node.drift", "n", {}, None), ("reconcile.error", "r", {}, None))
    notifier = FakeNotifier()
    dispatcher = AlertDispatcher(factory_for(session), notifier, kinds={"reconcile.error"})
    await dispatcher.poll_once()
    assert len(notifier.texts) == 1 and "Reconcile error" in notifier.texts[0]
    assert cursor(session) == 2


@pytest.mark.asyncio
async def test_rate_limit_coalesces_and_sends_window_summary(session):
    session.add(AlertState(key="last_event_id", value="0"))
    session.commit()
    add_events(session, *(("node.drift", str(i), {}, None) for i in range(5)))
    clock, notifier = Clock(), FakeNotifier()
    dispatcher = AlertDispatcher(factory_for(session), notifier, max_per_minute=2, clock=clock)
    await dispatcher.poll_once()
    assert len(notifier.texts) == 2
    assert dispatcher.counters() == {"sent": 2, "failed": 0, "dropped": 3, "pending": 0}
    clock.value = 60
    await dispatcher.poll_once()
    assert len(notifier.texts) == 3 and "3 more alerts suppressed" in notifier.texts[-1]
    assert dispatcher.counters()["sent"] == 3 and dispatcher.counters()["dropped"] == 3


@pytest.mark.asyncio
async def test_failure_retries_after_exponential_backoff_without_advancing_cursor(session):
    session.add(AlertState(key="last_event_id", value="0"))
    session.commit()
    add_events(session, ("node.drift", "n", {}, None))
    clock, notifier = Clock(), FakeNotifier(failures=1)
    dispatcher = AlertDispatcher(factory_for(session), notifier, clock=clock)
    await dispatcher.poll_once()
    assert cursor(session) == 0 and dispatcher.counters()["failed"] == 1
    clock.value = 4
    await dispatcher.poll_once()
    assert cursor(session) == 0 and notifier.texts == []
    clock.value = 5
    await dispatcher.poll_once()
    assert cursor(session) == 1 and len(notifier.texts) == 1
    assert dispatcher.counters()["sent"] == 1
    for expected in (5, 10, 20, 40, 80, 160, 300, 300):
        notifier.failures = 1
        clock.value += expected
        await dispatcher._deliver("failure")
        assert dispatcher._retry_at == clock.value + expected
    assert dispatcher.counters()["failed"] == 9


@pytest.mark.asyncio
async def test_alert_text_never_exposes_wireguard_secrets(session, crypto):
    instance = create_instance(session, "wg0", 51820, "192.0.2.10/24", crypto=crypto)
    hop = create_node(session, "secret-hop", "192.0.2.1", "tester", kind="hop",
                      wan_interface="eth0", hop_ip="198.51.100.1", crypto=crypto)
    runner = create_node(session, "secret-runner", "192.0.2.2", "tester", crypto=crypto)
    create_hop_link(session, hop.id, instance.id, crypto)
    probe = create_probe(session, hop.id, instance.id, runner.id, crypto=crypto)
    peer = session.get(Peer, probe.peer_id)
    secrets = [crypto.decrypt(peer.private_key_enc), crypto.decrypt(peer.preshared_key_enc),
               peer.public_key, peer.allowed_ip, f"{peer.allowed_ip}/32"]
    session.add(AlertState(key="last_event_id", value=str(session.scalar(select(Event.id).order_by(Event.id.desc()).limit(1)) or 0)))
    session.commit()
    add_events(session, ("probe.down", probe.id, {}, None), ("probe.up", probe.id, {}, None))
    notifier = FakeNotifier()
    await AlertDispatcher(factory_for(session), notifier, delay_seconds=0, clock=Clock(100)).poll_once()
    assert len(notifier.texts) == 2
    assert all(secret not in message for secret in secrets for message in notifier.texts)


@pytest.mark.asyncio
async def test_send_test_wraps_notifier_failure(session):
    notifier = FakeNotifier()
    await AlertDispatcher(factory_for(session), notifier).send_test()
    assert notifier.texts == ["wgoctopus alert test"]
    notifier.failures = 1
    with pytest.raises(NotifyError):
        await AlertDispatcher(factory_for(session), notifier).send_test()


@pytest.mark.asyncio
async def test_run_polls_and_stops(session):
    session.add(AlertState(key="last_event_id", value="0"))
    session.commit()
    add_events(session, ("node.drift", "n", {}, None))
    notifier = FakeNotifier()
    dispatcher = AlertDispatcher(factory_for(session), notifier, poll_seconds=0.001)
    import asyncio
    stop = asyncio.Event()
    task = asyncio.create_task(dispatcher.run(stop))
    asyncio.get_running_loop().call_later(0.01, stop.set)
    await asyncio.wait_for(task, timeout=1)
    assert len(notifier.texts) == 1


def test_alert_migration_is_idempotent_and_preserves_data(tmp_path):
    url = f"sqlite:///{tmp_path / 'alerts.db'}"
    here = Path(__file__).resolve().parents[1]
    config = Config(str(here / "alembic.ini"))
    config.set_main_option("script_location", str(here / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0003_probes")
    engine = make_engine(url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO nodes (id, name, ssh_host, ssh_port, ssh_user, mgmt_mode, agent_port, agent_token_enc, enabled, kind, created_at) VALUES (1, 'existing', '192.0.2.1', 22, 'tester', 'push', 18080, 'token', 1, 'awg', '2024-01-01 00:00:00')"))
    engine.dispose()
    upgrade_to_head(url)
    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.begin() as connection:
        assert connection.execute(text("SELECT name FROM nodes WHERE id=1")).scalar_one() == "existing"
        connection.execute(text("INSERT INTO alert_state (key, value) VALUES ('last_event_id', '7')"))
        assert connection.execute(text("SELECT value FROM alert_state WHERE key='last_event_id'")).scalar_one() == "7"
    engine.dispose()
