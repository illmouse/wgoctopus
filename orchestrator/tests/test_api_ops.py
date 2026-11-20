import base64
import logging

from sqlalchemy import select

from wgoctopus_orch.models import Instance, Node, NodeObserved, Peer
from wgoctopus_orch.reconciler import NodeState, NodeStatus


def _instance(client, name="wg0", address="10.0.0.1/24", port=51820):
    return client.post("/v1/instances", json={"name": name, "listen_port": port, "address": address})


def _node(client, name="node-a", token="agent-token"):
    return client.post("/v1/nodes", json={"name": name, "ssh_host": "host", "ssh_user": "root", "agent_token": token})


def test_reconcile_and_apply_dangerous(api):
    client, _, reconciler, _ = api
    node = _node(client).json()
    ident = node["id"]
    response = client.post(f"/v1/nodes/{ident}/reconcile")
    assert response.status_code == 202
    assert reconciler.kicks == [(ident, {"force": True})]
    assert client.post("/v1/nodes/999/reconcile").status_code == 404
    for body in (None, {"confirm": False}, {}):
        response = client.post(f"/v1/nodes/{ident}/apply-dangerous", json=body) if body is not None else client.post(f"/v1/nodes/{ident}/apply-dangerous")
        assert response.status_code == 422
    assert reconciler.dangerous == []
    response = client.post(f"/v1/nodes/{ident}/apply-dangerous", json={"confirm": True})
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "error": None}
    assert reconciler.dangerous == [ident]
    assert client.post("/v1/nodes/999/apply-dangerous", json={"confirm": True}).status_code == 404


def test_events_filters_order_and_limits(api):
    client, _, _, _ = api
    first = _instance(client).json()
    _instance(client, "wg1", "10.1.0.1/24", 51821)
    node = _node(client).json()
    assert client.put(f"/v1/instances/{first['id']}/placements/{node['id']}", json={}).status_code == 200
    assert client.post(f"/v1/instances/{first['id']}/peers", json={"name": "phone"}).status_code == 201
    all_events = client.get("/v1/events")
    assert all_events.status_code == 200 and len(all_events.json()) == 7
    events = all_events.json()
    assert [e["id"] for e in events] == sorted((e["id"] for e in events), reverse=True)
    assert client.get("/v1/events", params={"kind": "instance.created"}).json() == [e for e in events if e["kind"] == "instance.created"]
    assert client.get("/v1/events", params={"subject": str(first["id"])}).json()
    assert len(client.get("/v1/events", params={"limit": 1}).json()) == 1
    assert client.get("/v1/events", params={"limit": 1001}).status_code == 422


def test_status_counts(api):
    client, sessions, reconciler, _ = api
    instance = _instance(client).json()
    node1 = _node(client, "node-a").json()
    node2 = _node(client, "node-b").json()
    client.post(f"/v1/instances/{instance['id']}/peers", json={"name": "phone"})
    reconciler.statuses = {
        node1["id"]: NodeStatus(state=NodeState.IN_SYNC),
        node2["id"]: NodeStatus(state=NodeState.UNREACHABLE),
    }
    with sessions() as db:
        db.get(NodeObserved, node1["id"]).healthy = True
        db.get(NodeObserved, node2["id"]).healthy = False
        db.commit()
    counts = client.get("/v1/status").json()
    assert counts["nodes_by_state"]["IN_SYNC"] == counts["nodes_by_state"]["UNREACHABLE"] == 1
    assert counts["nodes_unhealthy"] == 1
    assert counts["instances"] == 1 and counts["peers"] == 1


def test_secrets_never_appear_in_api_responses_or_logs(api, caplog):
    client, sessions, _, crypto = api
    caplog.set_level(logging.DEBUG)
    api_token = "test-admin-token"
    master_key = crypto._fernet._signing_key + crypto._fernet._encryption_key
    secrets = {api_token, base64.urlsafe_b64encode(master_key).decode(), master_key.hex()}
    instance1 = _instance(client, "wg0", "10.0.0.1/24", 51820).json()
    instance2 = _instance(client, "wg1", "10.1.0.1/24", 51821).json()
    nodes = [_node(client, f"node-{i}", f"agent-token-secret-{i}").json() for i in (1, 2)]
    for node in nodes:
        with sessions() as db:
            secrets.add(str(crypto.decrypt(db.get(Node, node["id"]).agent_token_enc)))
    for instance in (instance1, instance2):
        for node in nodes:
            assert client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={}).status_code == 200
    peers = []
    for instance, count in ((instance1, 2), (instance2, 1)):
        for index in range(count):
            peers.append((instance["id"], client.post(f"/v1/instances/{instance['id']}/peers", json={"name": f"peer-{instance['id']}-{index}"}).json()))
    with sessions() as db:
        secrets.update(str(crypto.decrypt(value)) for row in db.scalars(select(Instance)) for value in [row.private_key_enc])
        for row in db.scalars(select(Peer)):
            secrets.add(str(crypto.decrypt(row.private_key_enc)))
            secrets.add(str(crypto.decrypt(row.preshared_key_enc)))
    config_peer = peers[0][1]
    assert client.get(f"/v1/peers/{config_peer['id']}/config", params={"endpoint_host": "203.0.113.1"}).status_code == 200

    requests = [
        ("/v1/instances", {}), (f"/v1/instances/{instance1['id']}", {}),
        ("/v1/nodes", {}), (f"/v1/nodes/{nodes[0]['id']}", {}),
        (f"/v1/instances/{instance1['id']}/peers", {}), (f"/v1/peers/{peers[0][1]['id']}", {}),
        ("/v1/events", {}), ("/v1/status", {}), ("/healthz", {}), ("/readyz", {}),
        ("/v1/instances/99999", {}), ("/v1/events?limit=1001", {}),
        ("/v1/nodes/99999/reconcile", {"method": "POST"}),
        (f"/v1/instances/{instance1['id']}", {"method": "GET", "headers": {"Authorization": "Bearer wrong"}}),
        ("/v1/instances", {"method": "POST", "json": {"bad": True}}),
        ("/v1/instances", {"method": "POST", "json": {"name": "wg0", "listen_port": 51820, "address": "10.0.0.1/24"}}),
    ]
    for path, options in requests:
        response = client.request(options.pop("method", "GET"), path, **options)
        rendered = response.text + repr(dict(response.headers))
        assert not any(secret in rendered for secret in secrets if secret), (path, response.text)
    assert client.get("/openapi.json").status_code == client.get("/docs").status_code == 404
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert not any(secret in log_text for secret in secrets if secret)
