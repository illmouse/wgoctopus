import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from test_api_probes import _api, _create_fixture

from wgoctopus_orch.config import Settings
from wgoctopus_orch.failover import FailoverEngine, FailoverError
from wgoctopus_orch.models import Event, FailoverProposal, NodeRevision, Placement
from wgoctopus_orch.reconciler import NodeState, NodeStatus, Scrape
from wgoctopus_orch.renderer import active_placement


async def _setup(session, fake_agent_factory, crypto, monkeypatch):
    active_agent, runner_agent, hop_agent, standby_agent = await fake_agent_factory(4)
    client, sessions, rec = _api(session, crypto, monkeypatch)
    with client:
        active, runner, hop, instance = _create_fixture(client, active_agent, runner_agent, hop_agent)
        standby = client.post("/v1/nodes", json={"name": "decision-standby", "ssh_host": "127.0.0.1",
            "ssh_user": "test", "agent_port": standby_agent.port, "agent_token": standby_agent.token,
            "backend_ip": "203.0.113.45"}).json()
        client.put(f"/v1/instances/{instance['id']}/placements/{standby['id']}",
                   json={"role": "standby"}).raise_for_status()
        probe = client.post("/v1/probes", json={"hop_id": hop["id"], "instance_id": instance["id"],
            "runner_node_id": runner["id"]}).json()
    now = 1000.0
    rec._status = {ident: NodeStatus(state=NodeState.IN_SYNC)
                   for ident in (active["id"], runner["id"], hop["id"], standby["id"])}
    rec._scrapes = {standby["id"]: Scrape(datetime.now(UTC), True, {instance["name"]: {"up": True}}, {})}
    engine = FailoverEngine(sessions, rec, Settings(), clock=lambda: now)
    return sessions, rec, engine, active, runner, hop, instance, standby, probe, now


async def _proposal(sessions, active, hop, instance, standby, now, state="pending"):
    proposal = FailoverProposal(instance_id=instance["id"], hop_id=hop["id"], from_node_id=active["id"],
        to_node_id=standby["id"], state=state, mode_at_creation="confirm", reason="test",
        created_at=datetime.fromtimestamp(now - 1, UTC), expires_at=datetime.fromtimestamp(now + 100, UTC))
    with sessions.begin() as db:
        db.add(proposal)
    return proposal.id


@pytest.mark.asyncio
async def test_confirm_unknown_id(session, fake_agent_factory, crypto, monkeypatch):
    _, _, engine, *_ = await _setup(session, fake_agent_factory, crypto, monkeypatch)
    with pytest.raises(FailoverError) as error:
        engine.confirm(99999, by="operator")
    assert error.value.code == "not_found"


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["rejected", "executed"])
async def test_confirm_non_pending(session, fake_agent_factory, crypto, monkeypatch, state):
    sessions, _, engine, active, _, hop, instance, standby, _, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    ident = await _proposal(sessions, active, hop, instance, standby, now, state)
    with pytest.raises(FailoverError) as error:
        engine.confirm(ident, by="operator")
    assert error.value.code == "not_pending"
    with sessions() as db:
        assert db.get(FailoverProposal, ident).state == state


@pytest.mark.asyncio
async def test_confirm_expired(session, fake_agent_factory, crypto, monkeypatch):
    sessions, _, engine, active, _, hop, instance, standby, _, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    ident = await _proposal(sessions, active, hop, instance, standby, now)
    with sessions.begin() as db:
        db.get(FailoverProposal, ident).expires_at = datetime.fromtimestamp(now, UTC)
    with pytest.raises(FailoverError, match="expired") as error:
        engine.confirm(ident, by="operator")
    assert error.value.code == "expired"
    with sessions() as db:
        proposal = db.get(FailoverProposal, ident)
        assert (proposal.state, proposal.decided_by) == ("expired", "system")
        assert db.scalar(select(Event).where(Event.kind == "failover.expired"))


@pytest.mark.asyncio
async def test_confirm_stale_active_placement(session, fake_agent_factory, crypto, monkeypatch):
    sessions, _, engine, active, _, hop, instance, standby, _, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    ident = await _proposal(sessions, active, hop, instance, standby, now)
    with sessions.begin() as db:
        placement = db.scalar(select(Placement).where(Placement.instance_id == instance["id"],
                                                   Placement.role == "active"))
        placement.role = "standby"
        db.scalar(select(Placement).where(Placement.instance_id == instance["id"],
                                         Placement.node_id == standby["id"])).role = "active"
    with pytest.raises(FailoverError) as error:
        engine.confirm(ident, by="operator")
    assert error.value.code == "stale"
    with sessions() as db:
        proposal = db.get(FailoverProposal, ident)
        assert (proposal.state, proposal.error) == ("failed", "active placement changed")


@pytest.mark.asyncio
async def test_confirm_candidate_unhealthy(session, fake_agent_factory, crypto, monkeypatch):
    sessions, rec, engine, active, _, hop, instance, standby, _, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    ident = await _proposal(sessions, active, hop, instance, standby, now)
    rec._scrapes[standby["id"]].ok = False
    with pytest.raises(FailoverError) as error:
        engine.confirm(ident, by="operator")
    assert error.value.code == "no_candidate"
    with sessions() as db:
        proposal = db.get(FailoverProposal, ident)
        assert (proposal.state, proposal.error) == ("failed", "candidate is no longer healthy")


@pytest.mark.asyncio
async def test_confirm_success_switches_and_bumps_only_hop_revision(session, fake_agent_factory, crypto, monkeypatch):
    sessions, _, engine, active, _, hop, instance, standby, _, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    calls = []
    engine.on_executed = lambda instance_id, node_id: calls.append((instance_id, node_id))
    ident = await _proposal(sessions, active, hop, instance, standby, now)
    with sessions() as db:
        before = {revision.node_id: revision.desired_revision for revision in db.scalars(select(NodeRevision))}
    proposal = engine.confirm(ident, by="operator")
    with sessions() as db:
        assert proposal.state == "executed" and proposal.decided_by == "operator"
        assert active_placement(db, instance["id"]).node_id == standby["id"]
        executed = db.scalar(select(Event).where(Event.kind == "failover.executed"))
        assert executed.data == {"proposal_id": ident, "instance_id": instance["id"],
                                 "from": active["id"], "to": standby["id"], "by": "operator"}
        assert db.scalar(select(Event).where(Event.kind == "instance.switched"))
        after = {revision.node_id: revision.desired_revision for revision in db.scalars(select(NodeRevision))}
    assert calls == [(instance["id"], standby["id"])]
    assert after[hop["id"]] == before[hop["id"]] + 1
    assert all(after[node_id] == revision for node_id, revision in before.items() if node_id != hop["id"])


@pytest.mark.asyncio
async def test_confirm_switch_failure_is_sanitized(session, fake_agent_factory, crypto, monkeypatch):
    from wgoctopus_orch import failover

    sessions, _, engine, active, _, hop, instance, standby, _, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    ident = await _proposal(sessions, active, hop, instance, standby, now)
    calls = []
    engine.on_executed = lambda *args: calls.append(args)
    def boom(*args, **kwargs):
        raise RuntimeError("boom password=hunter2")
    monkeypatch.setattr(failover, "switch_active", boom)
    with pytest.raises(RuntimeError, match="boom password=hunter2"):
        engine.confirm(ident, by="operator")
    with sessions() as db:
        proposal = db.get(FailoverProposal, ident)
        assert (proposal.state, proposal.error) == ("failed", "switch_active failed")
        assert db.scalar(select(Event).where(Event.kind == "failover.failed"))
    assert calls == []


@pytest.mark.asyncio
async def test_reject_unknown_non_pending_and_success(session, fake_agent_factory, crypto, monkeypatch):
    sessions, _, engine, active, _, hop, instance, standby, _, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    with pytest.raises(FailoverError) as unknown:
        engine.reject(99999, by="operator")
    assert unknown.value.code == "not_found"
    ident = await _proposal(sessions, active, hop, instance, standby, now, "executed")
    with pytest.raises(FailoverError) as non_pending:
        engine.reject(ident, by="operator")
    assert non_pending.value.code == "not_pending"
    with sessions.begin() as db:
        db.get(FailoverProposal, ident).state = "pending"
    assert engine.reject(ident, by="operator").state == "rejected"
    with sessions() as db:
        proposal = db.get(FailoverProposal, ident)
        event = db.scalar(select(Event).where(Event.kind == "failover.rejected"))
        assert proposal.decided_by == "operator"
        assert event.data == {"proposal_id": ident, "by": "operator"}


@pytest.mark.asyncio
async def test_failover_event_data_never_contains_secret_terms(session, fake_agent_factory, crypto, monkeypatch):
    sessions, _, engine, active, _, hop, instance, standby, _, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    expired = await _proposal(sessions, active, hop, instance, standby, now)
    with sessions.begin() as db:
        db.get(FailoverProposal, expired).expires_at = datetime.fromtimestamp(now, UTC)
    with pytest.raises(FailoverError):
        engine.confirm(expired, by="operator")
    rejected = await _proposal(sessions, active, hop, instance, standby, now)
    engine.reject(rejected, by="operator")
    with sessions() as db:
        data = [json.dumps(event.data).lower() for event in db.scalars(select(Event)).all()
                if event.kind.startswith("failover.")]
    assert data
    assert all(not any(secret in item for secret in ("private", "preshared", "token", "password"))
               for item in data)
