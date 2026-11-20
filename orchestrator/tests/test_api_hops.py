import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.api import create_app
from wgoctopus_orch.config import Settings
from wgoctopus_orch.reconciler import Reconciler
from wgoctopus_orch.transport import DirectHttpTransport


async def _converge(rec, predicate, attempts=30):
    for _ in range(attempts):
        await rec.reconcile_once()
        if predicate():
            return
        await asyncio.sleep(0.1)
    assert predicate(), "agents did not converge"


def test_hop_api_validation_links_switch_and_secrets(api):
    client, _, reconciler, _ = api
    authorization = client.headers.pop("Authorization")
    for response in (
        client.get("/v1/hops/1/links"),
        client.put("/v1/hops/1/links/1"),
        client.delete("/v1/hops/1/links/1"),
        client.post("/v1/instances/1/switch", json={"node_id": 1}),
    ):
        assert response.status_code == 401
    client.headers["Authorization"] = authorization
    base = {"ssh_host": "192.0.2.1", "ssh_user": "root"}
    assert client.post("/v1/nodes", json={"name":"bad-hop", **base, "kind":"hop"}).status_code == 422
    assert client.post("/v1/nodes", json={"name":"bad-ip", **base, "kind":"hop", "wan_interface":"eth0", "hop_ip":"not-ip"}).status_code == 422
    hop = client.post("/v1/nodes", json={"name":"hop0", **base, "kind":"hop", "wan_interface":"eth0", "hop_ip":"198.51.100.1", "agent_token":"sensitive"})
    assert hop.status_code == 201 and "sensitive" not in hop.text and "agent_token" not in hop.text
    hop_id=hop.json()["id"]
    instance=client.post("/v1/instances",json={"name":"wg0","listen_port":51820,"address":"10.0.0.1/24"}).json()
    iid=instance["id"]
    assert client.put(f"/v1/hops/{hop_id}/links/{iid}").status_code == 204
    assert client.put(f"/v1/hops/{hop_id}/links/{iid}").status_code == 204
    result=client.get(f"/v1/hops/{hop_id}/links").json()[0]
    assert result["reason"] == "no_active_placement" and result["backend_ip"] is None
    first=client.post("/v1/nodes",json={"name":"backend0",**base}).json()
    second=client.post("/v1/nodes",json={"name":"backend1",**base,"ssh_host":"192.0.2.2","backend_ip":"192.0.2.22"}).json()
    client.put(f"/v1/instances/{iid}/placements/{first['id']}",json={"role":"active"})
    result=client.get(f"/v1/hops/{hop_id}/links").json()[0]
    assert result["reason"] == "backend_ip_missing"
    client.put(f"/v1/instances/{iid}/placements/{second['id']}",json={"role":"standby"})
    assert client.get(f"/v1/instances/{iid}").json()["active_node_id"] == first["id"]
    switched=client.post(f"/v1/instances/{iid}/switch",json={"node_id":second["id"]})
    assert switched.status_code == 200 and switched.json()["changed"] is True
    assert client.post(f"/v1/instances/{iid}/switch",json={"node_id":second["id"]}).json()["changed"] is False
    route=client.get(f"/v1/hops/{hop_id}/links").json()[0]
    assert route["backend_ip"] == "192.0.2.22" and "reason" not in route
    patched=client.patch(f"/v1/nodes/{second['id']}",json={"backend_ip":"192.0.2.23"})
    assert patched.status_code == 200
    assert client.get(f"/v1/hops/{hop_id}/links").json()[0]["backend_ip"] == "192.0.2.23"
    assert client.post(f"/v1/instances/{iid}/switch",json={"node_id":999}).status_code == 409
    assert client.post("/v1/instances/999/switch",json={"node_id":second["id"]}).status_code == 404
    assert client.get("/v1/hops/999/links").status_code == 404
    assert client.delete(f"/v1/hops/{hop_id}/links/{iid}").status_code == 204
    assert any(ident == hop_id for ident, _ in reconciler.kicks)


@pytest.mark.asyncio
async def test_hop_routes_reconcile_with_active_backend(session, fake_agent_factory, crypto, monkeypatch):
    a, b, h = await fake_agent_factory(3)
    sessions = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    settings = Settings(transport="direct")
    rec = Reconciler(sessions, lambda _: DirectHttpTransport(settings, crypto=crypto), settings, crypto=crypto)
    token = "hop-integration-token"
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", token)
    with TestClient(create_app(session_factory=sessions, reconciler=rec, crypto=crypto, migrate=False)) as client:
        client.headers["Authorization"] = f"Bearer {token}"
        nodes = [client.post("/v1/nodes", json={
            "name": name, "ssh_host": "127.0.0.1", "ssh_user": "test",
            "agent_port": agent.port, "agent_token": agent.token, **extra,
        }).json() for name, agent, extra in (
            ("backend-a", a, {"backend_ip": "192.0.2.10"}),
            ("backend-b", b, {"backend_ip": "192.0.2.11"}),
            ("hop", h, {"kind": "hop", "wan_interface": "eth0", "hop_ip": "198.51.100.5"}),
        )]
        instance = client.post("/v1/instances", json={"name": "wg0", "listen_port": 51820, "address": "10.0.0.1/24"}).json()
        iid = instance["id"]
        for node, role in zip(nodes[:2], ("active", "standby")):
            client.put(f"/v1/instances/{iid}/placements/{node['id']}", json={"role": role}).raise_for_status()
        client.put(f"/v1/hops/{nodes[2]['id']}/links/{iid}").raise_for_status()
        await _converge(rec, lambda: bool(h.state["hop"].get("routes")))
        assert h.state["interfaces"] == []
        assert h.state["hop"] == {"wan_interface": "eth0", "hop_ip": "198.51.100.5", "routes": [{
            "listen_port": 51820, "backend_ip": "192.0.2.10", "backend_port": 51820, "name": "wg0",
        }]}
        assert a.state["interfaces"] and b.state["interfaces"]
        before = {n["id"]: client.get(f"/v1/nodes/{n['id']}").json()["desired_revision"] for n in nodes}
        switched = client.post(f"/v1/instances/{iid}/switch", json={"node_id": nodes[1]["id"]})
        assert switched.json()["changed"] is True
        await _converge(rec, lambda: h.state["hop"]["routes"][0]["backend_ip"] == "192.0.2.11")
        after = {n["id"]: client.get(f"/v1/nodes/{n['id']}").json()["desired_revision"] for n in nodes}
        assert after[nodes[2]["id"]] > before[nodes[2]["id"]]
        assert after[nodes[0]["id"]] == before[nodes[0]["id"]]
        assert after[nodes[1]["id"]] == before[nodes[1]["id"]]
        assert client.post(f"/v1/instances/{iid}/switch", json={"node_id": nodes[1]["id"]}).json()["changed"] is False
        unchanged = {n["id"]: client.get(f"/v1/nodes/{n['id']}").json()["desired_revision"] for n in nodes}
        assert unchanged == after
        client.delete(f"/v1/hops/{nodes[2]['id']}/links/{iid}").raise_for_status()
        await _converge(rec, lambda: h.state["hop"]["routes"] == [])
