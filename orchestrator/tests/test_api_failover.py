import asyncio
import re
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_api_probes import _api, _create_fixture

from wgoctopus_orch.api import create_app
from wgoctopus_orch.config import Settings
from wgoctopus_orch.failover import FailoverEngine
from wgoctopus_orch.models import AlertState, Event, FailoverProposal
from wgoctopus_orch.reconciler import NodeState, NodeStatus, Scrape


@pytest.mark.asyncio
async def _setup(session, fake_agent_factory, crypto, monkeypatch, *, mode="confirm"):
    from wgoctopus_orch.config import Settings

    a, b, hop_agent, standby_agent = await fake_agent_factory(4)
    client, sessions, rec = _api(session, crypto, monkeypatch)
    settings = Settings(failover_mode=mode)
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_MODE", mode)
    # The regular reconciler worker is intentionally idle for deterministic API tests.
    with client:
        active, runner, hop, instance = _create_fixture(client, a, b, hop_agent)
        standby = client.post("/v1/nodes", json={"name": "failover-standby", "ssh_host": "127.0.0.1",
            "ssh_user": "test", "agent_port": standby_agent.port, "agent_token": standby_agent.token,
            "backend_ip": "203.0.113.45"}).json()
        client.put(f"/v1/instances/{instance['id']}/placements/{standby['id']}",
                   json={"role": "standby"}).raise_for_status()
        client.put(f"/v1/hops/{hop['id']}/links/{instance['id']}").raise_for_status()
        probe = client.post("/v1/probes", json={"hop_id": hop["id"], "instance_id": instance["id"],
            "runner_node_id": runner["id"]}).json()
    rec._status = {i: NodeStatus(state=NodeState.IN_SYNC)
                   for i in (active["id"], runner["id"], hop["id"], standby["id"])}
    rec._scrapes = {standby["id"]: Scrape(datetime.now(UTC), True, {instance["name"]: {"up": True}}, {})}
    client.app.state.failover = FailoverEngine(sessions, rec, settings)
    client.__enter__()
    return client, sessions, rec, active, runner, hop, instance, standby, probe


def _add_proposal(sessions, active, hop, instance, standby, *, state="pending", expires=None):
    row = FailoverProposal(instance_id=instance["id"], hop_id=hop["id"], from_node_id=active["id"],
        to_node_id=standby["id"], state=state, mode_at_creation="confirm", reason="test",
        created_at=datetime.now(UTC), expires_at=expires or datetime.now(UTC) + timedelta(hours=1))
    with sessions.begin() as db:
        db.add(row)
    return row.id

@pytest.mark.asyncio
async def test_failover_metrics_states_and_modes(session, fake_agent_factory, crypto, monkeypatch):
    client, sessions, _, active, _, hop, instance, standby, _ = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    for state in ("pending", "executed", "rejected", "expired", "cancelled", "failed"):
        _add_proposal(sessions, active, hop, instance, standby, state=state)
    response = client.get("/metrics")
    assert response.status_code == 200
    metrics = response.text
    assert 'wgoctopus_failover_mode{mode="confirm"} 1' in metrics
    assert 'wgoctopus_failover_mode{mode="off"} 0' in metrics
    assert 'wgoctopus_failover_mode{mode="auto"} 0' in metrics
    for state in ("pending", "executed", "rejected", "expired", "cancelled", "failed"):
        assert f'wgoctopus_failover_proposals{{state="{state}"}} 1' in metrics
    assert "wgoctopus_failover_pending 1" in metrics
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_MODE", "off")
    off_metrics = client.get("/metrics").text
    assert 'wgoctopus_failover_mode{mode="off"} 1' in off_metrics

@pytest.mark.asyncio
async def test_failover_invalid_state_filter_envelope(session, fake_agent_factory, crypto, monkeypatch):
    client, *_ = await _setup(session, fake_agent_factory, crypto, monkeypatch)
    response = client.get("/v1/failovers?state=bogus")
    assert response.status_code == 422
    assert "error" in response.json()

@pytest.mark.asyncio
async def test_node_detail_without_last_reconcile_outcome(session, fake_agent_factory, crypto, monkeypatch):
    client, _, _, active, *_ = await _setup(session, fake_agent_factory, crypto, monkeypatch)
    response = client.get(f"/v1/nodes/{active['id']}")
    assert response.status_code == 200
    assert response.json()["reconciler"]["last_outcome"] is None

@pytest.mark.asyncio
async def test_failover_alert_format_and_severities(session, fake_agent_factory, crypto, monkeypatch):
    from test_alerts import FakeNotifier, add_events, factory_for

    from wgoctopus_orch.alerts import DOWN, RULES, AlertDispatcher

    _, sessions, _, active, _, hop, instance, standby, _ = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    ident = _add_proposal(sessions, active, hop, instance, standby)
    session.add(AlertState(key="last_event_id", value=str(session.scalar(select(Event.id).order_by(Event.id.desc()).limit(1)) or 0)))
    session.commit()
    add_events(session, ("failover.proposed", str(ident), {"proposal_id": ident}, None))
    notifier = FakeNotifier()
    await AlertDispatcher(factory_for(session), notifier, delay_seconds=0).poll_once()
    message = next(text for text in notifier.texts if "Failover proposed" in text)
    assert all(value in message for value in (str(ident), instance["name"], "POST /v1/failovers/"))
    assert "confirm" in message and "private" not in message.lower()
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
    assert {kind: RULES[kind][0] for kind in (
        "failover.proposed", "failover.executed", "failover.no_candidate", "failover.failed",
        "failover.expired", "failover.cancelled", "failover.rejected")} == {
        "failover.proposed": "CRITICAL", "failover.executed": "WARNING",
        "failover.no_candidate": "CRITICAL", "failover.failed": "CRITICAL",
        "failover.expired": "WARNING", "failover.cancelled": "INFO", "failover.rejected": "INFO"}
    assert all(not kind.startswith("failover.") for kind in DOWN)


@pytest.mark.asyncio
async def test_failover_auth_and_configuration(session, fake_agent_factory, crypto, monkeypatch):
    client, _, *_ = await _setup(session, fake_agent_factory, crypto, monkeypatch)
    client.headers.pop("Authorization")
    for method, path in [("GET", "/v1/failover"), ("GET", "/v1/failovers"),
                         ("GET", "/v1/failovers/1"), ("POST", "/v1/failovers/1/confirm"),
                         ("POST", "/v1/failovers/1/reject")]:
        assert client.request(method, path).status_code == 401
    client.headers["Authorization"] = "Bearer probe-api-token"
    response = client.get("/v1/failover")
    assert response.status_code == 200
    assert response.json() == {"mode": "confirm", "enabled": True,
        "down_seconds": Settings().failover_down_seconds,
        "proposal_ttl_seconds": Settings().failover_proposal_ttl_seconds,
        "cooldown_seconds": Settings().failover_cooldown_seconds,
        "eval_interval": Settings().failover_eval_interval}


@pytest.mark.asyncio
async def test_failover_list_detail_filters_and_validation(session, fake_agent_factory, crypto, monkeypatch):
    client, sessions, _, a, _, hop, inst, standby, _ = await _setup(session, fake_agent_factory, crypto, monkeypatch)
    ids = [_add_proposal(sessions, a, hop, inst, standby, state=state) for state in ("pending", "rejected", "failed")]
    rows = client.get("/v1/failovers").json()
    assert [r["id"] for r in rows] == list(reversed(ids))
    assert [r["state"] for r in client.get("/v1/failovers?state=pending").json()] == ["pending"]
    assert all(r["instance_id"] == inst["id"] for r in client.get(f"/v1/failovers?instance_id={inst['id']}").json())
    assert [r["id"] for r in client.get("/v1/failovers?limit=1&offset=1").json()] == [ids[-2]]
    assert client.get("/v1/failovers?state=bogus").status_code == 422
    assert client.get("/v1/failovers?limit=0").status_code == 422
    assert client.get(f"/v1/failovers/{ids[0]}").json()["id"] == ids[0]
    assert client.get("/v1/failovers/999999").status_code == 404


@pytest.mark.asyncio
async def test_failover_confirm_reject_and_conflicts(session, fake_agent_factory, crypto, monkeypatch):
    client, sessions, _, a, _, hop, inst, standby, _ = await _setup(session, fake_agent_factory, crypto, monkeypatch)
    proposal = _add_proposal(sessions, a, hop, inst, standby)
    old_hop = client.get(f"/v1/nodes/{hop['id']}").json()["desired_revision"]
    old_awg = client.get(f"/v1/nodes/{a['id']}").json()["desired_revision"]
    response = client.post(f"/v1/failovers/{proposal}/confirm")
    assert response.status_code == 200 and response.json()["state"] == "executed"
    assert response.json()["decided_by"] == "api"
    assert client.get(f"/v1/instances/{inst['id']}").json()["active_node_id"] == standby["id"]
    assert client.get(f"/v1/nodes/{hop['id']}").json()["desired_revision"] > old_hop
    assert client.get(f"/v1/nodes/{a['id']}").json()["desired_revision"] == old_awg
    with sessions() as db:
        kinds = set(db.scalars(select(Event.kind)).all())
    assert {"failover.executed", "instance.switched"} <= kinds

    rejected = _add_proposal(sessions, a, hop, inst, standby)
    assert client.post(f"/v1/failovers/{rejected}/reject").json()["state"] == "rejected"
    assert client.post(f"/v1/failovers/{rejected}/reject").status_code == 409
    assert client.post("/v1/failovers/999999/reject").status_code == 404
    assert client.post("/v1/failovers/999999/confirm").status_code == 404
    expired = _add_proposal(sessions, a, hop, inst, standby, expires=datetime.now(UTC) - timedelta(seconds=1))
    assert client.post(f"/v1/failovers/{expired}/confirm").status_code == 409
    stale = _add_proposal(sessions, a, hop, inst, standby)
    client.post(f"/v1/instances/{inst['id']}/switch", json={"node_id": standby["id"]}).raise_for_status()
    assert client.post(f"/v1/failovers/{stale}/confirm").status_code == 409


@pytest.mark.asyncio
async def test_failover_responses_exclude_secret_material(session, fake_agent_factory, crypto, monkeypatch):
    client, sessions, _, a, _, hop, inst, standby, _ = await _setup(session, fake_agent_factory, crypto, monkeypatch)
    ident = _add_proposal(sessions, a, hop, inst, standby)
    text = client.get("/v1/failovers").text + client.get(f"/v1/failovers/{ident}").text
    assert not re.search(r"private.?key|preshared|agent.?token|peer.?ip", text, re.IGNORECASE)


@pytest.mark.asyncio
async def test_failover_loop_creates_proposal(session, fake_agent_factory, crypto, monkeypatch):
    client, sessions, rec, active, _, _, _, standby, probe = await _setup(
        session, fake_agent_factory, crypto, monkeypatch)
    client.close()
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_DOWN_SECONDS", "0")
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_EVAL_INTERVAL", "0.05")
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_MODE", "confirm")
    settings = Settings.from_env()
    rec._probe_statuses = {probe["id"]: SimpleNamespace(state=SimpleNamespace(value="DOWN"))}
    engine = FailoverEngine(sessions, rec, settings, clock=lambda: time.monotonic())
    app = create_app(session_factory=sessions, reconciler=rec, crypto=crypto, migrate=False, failover=engine)
    with TestClient(app) as running:
        running.headers["Authorization"] = "Bearer probe-api-token"
        deadline = time.monotonic() + 10
        proposals = []
        while time.monotonic() < deadline:
            proposals = running.get("/v1/failovers").json()
            if proposals:
                break
            await asyncio.sleep(0.02)
        assert len(proposals) == 1
        assert proposals[0]["from_node_id"] == active["id"]
        assert proposals[0]["to_node_id"] == standby["id"]
        assert proposals[0]["state"] == "pending"


@pytest.mark.asyncio
async def test_failover_loop_survives_errors_and_stops_cleanly(session, fake_agent_factory, crypto, monkeypatch, caplog):
    client, sessions, rec, *_ = await _setup(session, fake_agent_factory, crypto, monkeypatch)
    client.close()

    class BrokenEngine:
        def __init__(self):
            self.calls = 0

        def evaluate_once(self):
            self.calls += 1
            raise RuntimeError("boom password=hunter2")

    engine = BrokenEngine()
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_EVAL_INTERVAL", "0.05")
    app = create_app(session_factory=sessions, reconciler=rec, crypto=crypto, migrate=False, failover=engine)
    with TestClient(app) as running:
        deadline = time.monotonic() + 10
        while engine.calls < 3 and time.monotonic() < deadline:
            assert running.get("/healthz").status_code == 200
            await asyncio.sleep(0.02)
        assert engine.calls >= 3
    assert "boom password=hunter2" not in caplog.text
