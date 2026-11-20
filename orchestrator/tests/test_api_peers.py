from sqlalchemy import select

from wgoctopus_orch.models import Event, Instance, Peer
from wgoctopus_orch.renderer import render_node_state


def test_peer_lifecycle_and_rendering(api):
    client, sessions, reconciler, _ = api
    instance = client.post("/v1/instances", json={"name": "wg0", "listen_port": 51820, "address": "10.0.0.1/29"}).json()
    node = client.post("/v1/nodes", json={"name": "node-a", "ssh_host": "host", "ssh_user": "root"}).json()
    iid, nid = instance["id"], node["id"]
    client.put(f"/v1/instances/{iid}/placements/{nid}", json={"role": "active"})

    first = client.post(f"/v1/instances/{iid}/peers", json={"name": "phone", "owner": "alice"})
    assert first.status_code == 201
    peer = first.json()
    assert {"id", "name", "public_key", "allowed_ip", "enabled", "owner", "created_at"} <= peer.keys()
    assert "private_key" not in peer and "preshared_key" not in peer
    assert peer["allowed_ip"] == "10.0.0.2"
    second = client.post(f"/v1/instances/{iid}/peers", json={"name": "laptop"}).json()
    assert second["allowed_ip"] == "10.0.0.3"
    for index in range(3):
        assert client.post(f"/v1/instances/{iid}/peers", json={"name": f"peer-{index}"}).status_code == 201
    assert client.post(f"/v1/instances/{iid}/peers", json={"name": "full"}).status_code == 409
    assert client.post("/v1/instances/999/peers", json={"name": "x"}).status_code == 404

    assert client.get(f"/v1/instances/{iid}/peers", params={"owner": "alice"}).json()[0]["id"] == peer["id"]
    assert len(client.get(f"/v1/instances/{iid}/peers", params={"enabled": "true", "limit": 1}).json()) == 1
    assert client.get(f"/v1/instances/{iid}/peers", params={"offset": 1, "limit": 1}).json()[0]["id"] == second["id"]
    assert client.get(f"/v1/instances/{iid}/peers", params={"limit": 1001}).status_code == 422
    assert client.get(f"/v1/peers/{peer['id']}").json()["id"] == peer["id"]
    assert client.get("/v1/peers/999").status_code == 404

    rev = client.get(f"/v1/nodes/{nid}").json()["desired_revision"]
    assert client.patch(f"/v1/peers/{peer['id']}", json={"enabled": False, "owner": "bob", "name": "phone2"}).status_code == 200
    assert client.get(f"/v1/nodes/{nid}").json()["desired_revision"] > rev
    assert reconciler.kicks[-1] == (nid, {})
    with sessions() as db:
        assert all(p["public_key"] != peer["public_key"] for p in render_node_state(db, nid, api[3])["interfaces"][0]["peers"])
    assert client.patch(f"/v1/peers/{peer['id']}", json={"unexpected": 1}).status_code == 422
    assert client.patch(f"/v1/peers/{peer['id']}", json={"enabled": "yes"}).status_code == 422
    assert client.patch(f"/v1/peers/{peer['id']}", json={"enabled": True}).status_code == 200
    with sessions() as db:
        assert any(p["public_key"] == peer["public_key"] for p in render_node_state(db, nid, api[3])["interfaces"][0]["peers"])
    assert client.delete(f"/v1/peers/{peer['id']}").status_code == 204
    assert client.get(f"/v1/peers/{peer['id']}").status_code == 404
    with sessions() as db:
        assert all(p["public_key"] != peer["public_key"] for p in render_node_state(db, nid, api[3])["interfaces"][0]["peers"])


def test_peer_client_config(api, monkeypatch):
    client, sessions, _, crypto = api
    instance = client.post("/v1/instances", json={"name": "wg0", "listen_port": 51820, "address": "10.0.0.1/24"}).json()
    ident = client.post(f"/v1/instances/{instance['id']}/peers", json={"name": "phone"}).json()["id"]
    assert client.get(f"/v1/peers/{ident}/config").status_code == 422
    response = client.get(f"/v1/peers/{ident}/config", params={"endpoint_host": "203.0.113.10"})
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/plain")
    assert response.headers["cache-control"] == "no-store"
    with sessions() as db:
        peer = db.get(Peer, ident)
        private = str(crypto.decrypt(peer.private_key_enc))
        instance_row = db.get(Instance, instance["id"])
        psk = str(crypto.decrypt(peer.preshared_key_enc))
        port = instance_row.listen_port
        params = instance_row.obfuscation
        assert db.scalar(select(Event).where(Event.kind == "peer.config_issued")).data == {}
    text = response.text
    assert f"PrivateKey = {private}" in text and "[Interface]" in text and f"Address = {peer.allowed_ip}/32" in text
    assert "[Peer]" in text and f"PublicKey = {instance['public_key']}" in text and f"PresharedKey = {psk}" in text
    assert f"Endpoint = 203.0.113.10:{port}" in text
    for k, label in [("jc", "Jc"), ("jmin", "Jmin"), ("jmax", "Jmax"), *((f"s{i}", f"S{i}") for i in range(1, 5)), *((f"h{i}", f"H{i}") for i in range(1, 5))]:
        assert f"{label} = {params[k]}" in text
    monkeypatch.setenv("WGOCTOPUS_CLIENT_ENDPOINT_HOST", "198.51.100.20")
    assert "Endpoint = 198.51.100.20:" in client.get(f"/v1/peers/{ident}/config").text
    with sessions() as db:
        db.get(Peer, ident).private_key_enc = None
        db.commit()
    missing_key = client.get(f"/v1/peers/{ident}/config", params={"endpoint_host": "203.0.113.10"})
    assert missing_key.status_code == 422 and "private key" in missing_key.text
