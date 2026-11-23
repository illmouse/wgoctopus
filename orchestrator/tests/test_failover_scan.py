"""Direct evaluation-loop coverage for probe-driven failover."""

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from test_failover_decisions import _proposal, _setup

from wgoctopus_orch.models import Event, FailoverProposal
from wgoctopus_orch.renderer import active_placement


@pytest.mark.asyncio
async def test_scan_down_threshold_and_single_pending(session, fake_agent_factory, crypto, monkeypatch):
    sessions, rec, engine, active, _, _, instance, standby, probe, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    engine.settings = replace(engine.settings, failover_down_seconds=10)
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="DOWN")
    engine.evaluate_once()
    now_value = [now]
    engine.clock = lambda: now_value[0]
    now_value[0] += 9
    engine.evaluate_once()
    with sessions() as db:
        assert db.scalar(select(FailoverProposal)) is None
    now_value[0] += 1
    engine.evaluate_once()
    engine.evaluate_once()
    with sessions() as db:
        proposals = db.scalars(select(FailoverProposal)).all()
        event = db.scalar(select(Event).where(Event.kind == "failover.proposed"))
        assert len(proposals) == 1 and proposals[0].state == "pending"
        assert event.data == {"proposal_id": proposals[0].id, "instance_id": instance["id"],
                              "from_node_id": active["id"], "to_node_id": standby["id"],
                              "mode": "confirm", "expires_at": datetime.fromisoformat(
                                  event.data["expires_at"]).isoformat()}
        assert datetime.fromisoformat(event.data["expires_at"]).timestamp() == proposals[0].expires_at.timestamp()


@pytest.mark.asyncio
async def test_scan_up_resets_episode_and_unknown_does_not(session, fake_agent_factory, crypto, monkeypatch):
    sessions, rec, engine, _, _, _, _, _, probe, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    engine.settings = replace(engine.settings, failover_down_seconds=10)
    tick = [now]
    engine.clock = lambda: tick[0]
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="DOWN")
    engine.evaluate_once()
    tick[0] += 8
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="UNKNOWN")
    engine.evaluate_once()
    tick[0] += 8
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="UP")
    engine.evaluate_once()
    tick[0] += 1
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="DOWN")
    engine.evaluate_once()
    tick[0] += 9
    engine.evaluate_once()
    with sessions() as db:
        assert db.scalar(select(FailoverProposal)) is None
    tick[0] += 1
    engine.evaluate_once()
    with sessions() as db:
        assert db.scalar(select(FailoverProposal)).state == "pending"


@pytest.mark.asyncio
async def test_scan_runner_and_hop_must_be_in_sync(session, fake_agent_factory, crypto, monkeypatch):
    sessions, rec, engine, _active, runner, hop, _, _, probe, _ = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    engine.settings = replace(engine.settings, failover_down_seconds=0)
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="DOWN")
    rec._status[runner["id"]] = SimpleNamespace(state="OUT_OF_SYNC")
    engine.evaluate_once()
    rec._status[runner["id"]] = SimpleNamespace(state="IN_SYNC")
    rec._status[hop["id"]] = SimpleNamespace(state="OUT_OF_SYNC")
    engine.evaluate_once()
    with sessions() as db:
        assert db.scalar(select(FailoverProposal)) is None


@pytest.mark.asyncio
async def test_scan_no_candidate_emitted_once_then_up_clears_memory(session, fake_agent_factory, crypto, monkeypatch):
    sessions, rec, engine, _, _, _, _, standby, probe, _ = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    engine.settings = replace(engine.settings, failover_down_seconds=0)
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="DOWN")
    rec._scrapes[standby["id"]].interfaces.clear()
    engine.evaluate_once()
    engine.evaluate_once()
    with sessions() as db:
        assert len(db.scalars(select(Event).where(Event.kind == "failover.no_candidate")).all()) == 1
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="UP")
    engine.evaluate_once()
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="DOWN")
    engine.evaluate_once()
    with sessions() as db:
        assert len(db.scalars(select(Event).where(Event.kind == "failover.no_candidate")).all()) == 2


@pytest.mark.asyncio
async def test_scan_pending_expires_and_cancels_when_condition_clears(session, fake_agent_factory, crypto, monkeypatch):
    sessions, rec, engine, active, _, hop, instance, standby, probe, now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    ident = await _proposal(sessions, active, hop, instance, standby, now)
    with sessions.begin() as db:
        db.get(FailoverProposal, ident).expires_at = datetime.fromtimestamp(now, UTC)
    engine.evaluate_once()
    with sessions() as db:
        p = db.get(FailoverProposal, ident)
        assert (p.state, p.decided_by) == ("expired", "system")
        assert db.scalar(select(Event).where(Event.kind == "failover.expired"))

    ident = await _proposal(sessions, active, hop, instance, standby, now + 100)
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="UP")
    engine.clock = lambda: now + 1
    engine.evaluate_once()
    with sessions() as db:
        assert db.get(FailoverProposal, ident).state == "cancelled"
        event = db.scalar(select(Event).where(Event.kind == "failover.cancelled"))
        assert event.data == {"proposal_id": ident, "reason": "condition_cleared"}


@pytest.mark.asyncio
async def test_scan_off_and_missing_probe_status_create_nothing(session, fake_agent_factory, crypto, monkeypatch):
    sessions, rec, engine, _, _, _, _, _, probe, _ = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    engine.settings = replace(engine.settings, failover_mode="off")
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="DOWN")
    engine.evaluate_once()
    engine.settings = replace(engine.settings, failover_mode="confirm")
    rec._probe_statuses.clear()
    engine.evaluate_once()
    with sessions() as db:
        assert db.scalar(select(FailoverProposal)) is None


@pytest.mark.asyncio
async def test_scan_auto_executes_and_notifies(session, fake_agent_factory, crypto, monkeypatch):
    sessions, rec, engine, _active, _, _, instance, standby, probe, _now = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    engine.settings = replace(engine.settings, failover_mode="auto", failover_down_seconds=0)
    rec._probe_statuses[probe["id"]] = SimpleNamespace(state="DOWN")
    called = []
    engine.on_executed = lambda iid, nid: called.append((iid, nid))
    engine.evaluate_once()
    with sessions() as db:
        proposal = db.scalar(select(FailoverProposal))
        assert (proposal.state, proposal.decided_by) == ("executed", "auto")
        assert active_placement(db, instance["id"]).node_id == standby["id"]
    assert called == [(instance["id"], standby["id"])]
