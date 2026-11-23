from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from test_api_probes import _api, _create_fixture

from wgoctopus_orch.config import Settings
from wgoctopus_orch.failover import FailoverEngine, pick_candidate
from wgoctopus_orch.models import Event, FailoverProposal, NodeRevision
from wgoctopus_orch.probe_status import ProbeState
from wgoctopus_orch.reconciler import NodeState, NodeStatus, Scrape


class Session:
    def __init__(self, placements, nodes, instance):
        self.placements, self.nodes, self.instance = placements, nodes, instance

    def scalars(self, _query):
        return SimpleNamespace(all=lambda: self.placements)

    def get(self, model, ident):
        if model.__name__ == "Node":
            return self.nodes.get(ident)
        return self.instance


def test_pick_candidate_orders_healthy_standbys_and_allows_active_runner():
    placements = [SimpleNamespace(node_id=4, weight=10), SimpleNamespace(node_id=3, weight=10)]
    nodes = {3: SimpleNamespace(kind="awg", enabled=True), 4: SimpleNamespace(kind="awg", enabled=True)}
    status = SimpleNamespace(state="IN_SYNC")
    scrapes = {node: SimpleNamespace(ok=True, interfaces={"wg0": {"up": True}}) for node in nodes}
    assert pick_candidate(Session(placements, nodes, SimpleNamespace(name="wg0")), 1, 2,
                          {3: status, 4: status}, scrapes) == 3
    scrapes[3].interfaces["wg0"]["up"] = False
    assert pick_candidate(Session(placements, nodes, SimpleNamespace(name="wg0")), 1, 2,
                          {3: status, 4: status}, scrapes) == 4

def test_pick_candidate_filters_unhealthy_nodes_and_orders_weight_then_id():
    placements = [SimpleNamespace(node_id=i, weight=w) for i, w in [(8, 99), (7, 8), (6, 8), (5, 7)]]
    nodes = {i: SimpleNamespace(kind="awg", enabled=True) for i in range(5, 9)}
    nodes[8].enabled = False
    states = {i: SimpleNamespace(state="IN_SYNC") for i in nodes}
    states[7].state = "OUT_OF_SYNC"
    scrapes = {i: SimpleNamespace(ok=True, interfaces={"wg0": {"up": True}}) for i in nodes}
    scrapes[6].ok = False
    scrapes[5].interfaces["wg0"]["up"] = False
    assert pick_candidate(Session(placements, nodes, SimpleNamespace(name="wg0")), 1, 2,
                          states, scrapes) is None
    scrapes[5].interfaces["wg0"]["up"] = True
    assert pick_candidate(Session(placements, nodes, SimpleNamespace(name="wg0")), 1, 2,
                          states, scrapes) == 5
    placements.append(SimpleNamespace(node_id=4, weight=7))
    nodes[4] = SimpleNamespace(kind="awg", enabled=True)
    states[4] = SimpleNamespace(state="IN_SYNC")
    scrapes[4] = SimpleNamespace(ok=True, interfaces={"wg0": {"up": True}})
    assert pick_candidate(Session(placements, nodes, SimpleNamespace(name="wg0")), 1, 2,
                          states, scrapes) == 4

def test_failover_settings_from_env(monkeypatch):
    from wgoctopus_orch.config import Settings
    assert Settings().failover_mode == "confirm"
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_MODE", "broken")
    with pytest.raises(ValueError):
        Settings.from_env()
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_MODE", "auto")
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_DOWN_SECONDS", "11")
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_PROPOSAL_TTL", "22")
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_COOLDOWN", "33")
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_EVAL_INTERVAL", "44")
    settings = Settings.from_env()
    assert (settings.failover_mode, settings.failover_down_seconds, settings.failover_proposal_ttl_seconds,
            settings.failover_cooldown_seconds, settings.failover_eval_interval) == ("auto", 11, 22, 33, 44)


@pytest.mark.asyncio
async def test_failover_confirm_switches_active_and_records_events(session, fake_agent_factory, crypto, monkeypatch):
    agents = await fake_agent_factory(4)
    client, sessions, rec = _api(session, crypto, monkeypatch)
    with client:
        active, runner, hop, instance = _create_fixture(client, agents[0], agents[1], agents[2])
        standby = client.post("/v1/nodes", json={"name": "failover-standby", "ssh_host": "127.0.0.1",
            "ssh_user": "test", "agent_port": agents[3].port, "agent_token": agents[3].token,
            "backend_ip": "203.0.113.44"}).json()
        client.put(f"/v1/instances/{instance['id']}/placements/{standby['id']}", json={"role": "standby", "weight": 5}).raise_for_status()
        probe = client.post("/v1/probes", json={"hop_id": hop["id"], "instance_id": instance["id"],
            "runner_node_id": runner["id"]}).json()
        await rec.reconcile_once()
        rec._status = {ident: NodeStatus(state=NodeState.IN_SYNC) for ident in
                       (active["id"], runner["id"], hop["id"], standby["id"])}
        rec._scrapes = {standby["id"]: Scrape(datetime.now(UTC), True, {instance["name"]: {"up": True}}, {})}
        rec._probe_statuses = {probe["id"]: SimpleNamespace(state=ProbeState.DOWN)}
        now = [1000.0]
        executed = []
        engine = FailoverEngine(sessions, rec, Settings(failover_down_seconds=10,
            failover_proposal_ttl_seconds=100), clock=lambda: now[0],
            on_executed=lambda instance_id, node_id: executed.append((instance_id, node_id)))
        engine.evaluate_once()
        assert not sessions().query(FailoverProposal).count()
        now[0] += 11
        engine.evaluate_once()
        with sessions() as db:
            proposal = db.scalar(select(FailoverProposal))
            assert proposal.state == "pending"
            proposed = db.scalar(select(Event).where(Event.kind == "failover.proposed"))
            assert set(proposed.data) == {"proposal_id", "instance_id", "from_node_id", "to_node_id", "mode", "expires_at"}
            assert proposed.data == {"proposal_id": proposal.id, "instance_id": instance["id"],
                "from_node_id": active["id"], "to_node_id": standby["id"], "mode": "confirm",
                "expires_at": "1970-01-01T00:18:31+00:00"}
            assert all("secret" not in str(event.data).lower() for event in db.scalars(select(Event)).all())
            revision_before = db.get(NodeRevision, hop["id"]).desired_revision
        engine.confirm(proposal.id, by="api")
        with sessions() as db:
            assert db.get(FailoverProposal, proposal.id).state == "executed"
            assert {e.kind for e in db.scalars(select(Event)).all()} >= {"instance.switched", "failover.executed"}
            assert db.get(NodeRevision, hop["id"]).desired_revision > revision_before
        assert executed == [(instance["id"], standby["id"])]
        placements = client.get(f"/v1/instances/{instance['id']}").json()["placements"]
        assert next(p for p in placements if p["role"] == "active")["node_id"] == standby["id"]


@pytest.mark.asyncio
async def test_failover_unknown_timer_and_pending_recovery_cancellation(session, fake_agent_factory, crypto, monkeypatch):
    agents = await fake_agent_factory(4)
    client, sessions, rec = _api(session, crypto, monkeypatch)
    with client:
        active, runner, hop, instance = _create_fixture(client, agents[0], agents[1], agents[2])
        standby = client.post("/v1/nodes", json={"name": "standby", "ssh_host": "127.0.0.1",
            "ssh_user": "test", "agent_port": agents[3].port, "agent_token": agents[3].token,
            "backend_ip": "203.0.113.45"}).json()
        client.put(f"/v1/instances/{instance['id']}/placements/{standby['id']}",
                   json={"role": "standby"}).raise_for_status()
        probe = client.post("/v1/probes", json={"hop_id": hop["id"], "instance_id": instance["id"],
            "runner_node_id": runner["id"]}).json()
        await rec.reconcile_once()
        rec._status = {i: NodeStatus(state=NodeState.IN_SYNC) for i in
                       (active["id"], runner["id"], hop["id"], standby["id"])}
        rec._scrapes = {standby["id"]: Scrape(datetime.now(UTC), True, {instance["name"]: {"up": True}}, {})}
        rec._probe_statuses = {probe["id"]: SimpleNamespace(state=ProbeState.DOWN)}
        tick = [100.0]
        engine = FailoverEngine(sessions, rec, Settings(failover_down_seconds=10), clock=lambda: tick[0])
        engine.evaluate_once()
        rec._probe_statuses[probe["id"]] = SimpleNamespace(state=ProbeState.UNKNOWN)
        tick[0] += 8
        engine.evaluate_once()
        rec._probe_statuses[probe["id"]] = SimpleNamespace(state=ProbeState.DOWN)
        tick[0] += 2
        engine.evaluate_once()
        with sessions() as db:
            proposal = db.scalar(select(FailoverProposal))
            assert proposal and proposal.state == "pending"
        rec._probe_statuses[probe["id"]] = SimpleNamespace(state=ProbeState.UP)
        engine.evaluate_once()
        with sessions() as db:
            assert db.get(FailoverProposal, proposal.id).state == "cancelled"
            event = db.scalar(select(Event).where(Event.kind == "failover.cancelled"))
            assert event.data == {"proposal_id": proposal.id, "reason": "condition_cleared"}


@pytest.mark.asyncio
async def test_failover_rejects_expired_pending_proposal(session, fake_agent_factory, crypto, monkeypatch):
    agents = await fake_agent_factory(3)
    client, sessions, rec = _api(session, crypto, monkeypatch)
    with client:
        active, runner, hop, instance = _create_fixture(client, agents[0], agents[1], agents[2])
        engine = FailoverEngine(sessions, rec, Settings(), clock=lambda: 1000)
        proposal = FailoverProposal(instance_id=instance["id"], hop_id=hop["id"],
            from_node_id=active["id"], to_node_id=runner["id"], state="pending", mode_at_creation="confirm",
            reason="test", created_at=datetime.fromtimestamp(0, UTC), expires_at=datetime.fromtimestamp(999, UTC))
        with sessions.begin() as db:
            db.add(proposal)
        from wgoctopus_orch.failover import FailoverError
        with pytest.raises(FailoverError) as error:
            engine.confirm(proposal.id, by="api")
        assert error.value.code == "expired"
