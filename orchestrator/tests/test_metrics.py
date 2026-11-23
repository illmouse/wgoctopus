from datetime import UTC, datetime

from fastapi.testclient import TestClient

from wgoctopus_orch.api import create_app
from wgoctopus_orch.metrics import escape_label
from wgoctopus_orch.models import Event, NodeObserved
from wgoctopus_orch.reconciler import NodeState, NodeStatus


def test_metrics_requires_auth_and_is_stable(api):
    client, _sessions, _, _ = api
    client.headers.pop("Authorization")
    assert client.get("/metrics").status_code == 401
    client.headers["Authorization"] = "Bearer test-admin-token"
    first = client.get("/metrics")
    assert first.status_code == 200
    assert first.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert first.text == client.get("/metrics").text
    assert "# HELP wgoctopus_build_info" in first.text


def test_metrics_public_mode(api, monkeypatch):
    _client, sessions, reconciler, crypto = api
    monkeypatch.setenv("WGOCTOPUS_METRICS_PUBLIC", "true")
    app = create_app(session_factory=sessions, reconciler=reconciler, crypto=crypto, migrate=False)
    with TestClient(app) as public_client:
        assert public_client.get("/metrics").status_code == 200


def test_metrics_node_states_escape_and_secret_exclusion(api):
    client, _sessions, _, _ = api
    created = client.post("/v1/nodes", json={"name": "metrics-node", "ssh_host": "192.0.2.10", "ssh_user": "root", "agent_token": "METRICS-TOKEN-SECRET"})
    assert created.status_code == 201
    text = client.get("/metrics").text
    assert 'node="metrics-node",kind="awg",state="UNKNOWN"} 1' in text
    states = [int(line.rsplit(" ", 1)[1]) for line in text.splitlines() if line.startswith("wgoctopus_node_state{")]
    assert len(states) == len(NodeState) and sum(states) == 1
    assert "METRICS-TOKEN-SECRET" not in text
    assert escape_label('a\\b"c\nd') == 'a\\\\b\\"c\\nd'


def test_metrics_without_reconciler(api, monkeypatch):
    _, sessions, _, crypto = api
    monkeypatch.setenv("WGOCTOPUS_RECONCILER_ENABLED", "false")
    app = create_app(session_factory=sessions, reconciler=None, crypto=crypto, migrate=False)
    with TestClient(app) as client:
        response = client.get("/metrics", headers={"Authorization": "Bearer test-admin-token"})
    assert "wgoctopus_reconcile_outcomes_total" not in response.text
    assert "wgoctopus_reconcile_last_duration_seconds" not in response.text


def test_metrics_database_series_and_reconcile_counters(api):
    client, sessions, reconciler, _ = api
    backend = client.post("/v1/nodes", json={"name": "backend", "ssh_host": "192.0.2.20", "ssh_user": "root", "backend_ip": "192.0.2.21", "agent_token": "BACKEND-SECRET"}).json()
    hop = client.post("/v1/nodes", json={"name": "hop", "kind": "hop", "wan_interface": "eth0", "hop_ip": "192.0.2.22", "ssh_host": "192.0.2.23", "ssh_user": "root", "agent_token": "HOP-SECRET"}).json()
    instance = client.post("/v1/instances", json={"name": "metrics-wg", "listen_port": 51820, "address": "10.0.0.1/24"}).json()
    client.put(f"/v1/instances/{instance['id']}/placements/{backend['id']}", json={"role": "active"}).raise_for_status()
    client.put(f"/v1/hops/{hop['id']}/links/{instance['id']}").raise_for_status()
    peer = client.post(f"/v1/instances/{instance['id']}/peers", json={"name": "peer-a"})
    assert peer.status_code == 201
    with sessions() as db:
        observed = db.get(NodeObserved, backend["id"])
        observed.applied_revision = 7
        observed.last_seen_at = datetime.now(UTC)
        db.add(Event(kind="metric.test", subject="1", data={}))
        db.commit()
    class MetricsReconciler:
        def status(self):
            return {backend["id"]: NodeStatus(state=NodeState.IN_SYNC, consecutive_failures=2, last_duration_seconds=0.25)}

        def counters(self):
            return {"OK": 3}

    reconciler.status = MetricsReconciler().status
    reconciler.counters = MetricsReconciler().counters
    text = client.get("/metrics").text
    for expected in (
        'wgoctopus_node_applied_revision{node="backend"} 7',
        'wgoctopus_instance_active_node{instance="metrics-wg",node="backend"} 1',
        'wgoctopus_hop_route{hop="hop",instance="metrics-wg",port="51820"} 1',
        'wgoctopus_events_total{kind="metric.test"} 1',
        'wgoctopus_reconcile_outcomes_total{outcome="OK"} 3',
        'wgoctopus_reconcile_last_duration_seconds{node="backend"} 0.25',
    ):
        assert expected in text
    assert "BACKEND-SECRET" not in text and "HOP-SECRET" not in text
    standby = client.post("/v1/nodes", json={"name": "standby", "ssh_host": "192.0.2.24", "ssh_user": "root", "backend_ip": "192.0.2.25", "agent_token": "STANDBY-SECRET"}).json()
    client.put(f"/v1/instances/{instance['id']}/placements/{standby['id']}", json={"role": "standby"}).raise_for_status()
    client.post(f"/v1/instances/{instance['id']}/switch", json={"node_id": standby["id"]}).raise_for_status()
    assert 'wgoctopus_instance_active_node{instance="metrics-wg",node="standby"} 1' in client.get("/metrics").text
    client.delete(f"/v1/hops/{hop['id']}/links/{instance['id']}").raise_for_status()
    assert "wgoctopus_hop_route{hop=\"hop\"" not in client.get("/metrics").text
