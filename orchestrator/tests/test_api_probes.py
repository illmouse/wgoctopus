import re
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.api import create_app
from wgoctopus_orch.config import Settings
from wgoctopus_orch.models import NodeRevision, Peer
from wgoctopus_orch.reconciler import Reconciler
from wgoctopus_orch.service import PROBE_OWNER
from wgoctopus_orch.transport import DirectHttpTransport


def _api(session, crypto, monkeypatch):
    sessions = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    settings = Settings(transport="direct")
    rec = Reconciler(sessions, lambda _: DirectHttpTransport(settings, crypto=crypto), settings, crypto=crypto)

    async def idle(stop_event):
        await stop_event.wait()

    rec.run = idle
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "probe-api-token")
    client = TestClient(create_app(session_factory=sessions, reconciler=rec, crypto=crypto, migrate=False))
    client.headers["Authorization"] = "Bearer probe-api-token"
    return client, sessions, rec


def _create_fixture(client, a, b, hop_agent):
    nodes = []
    for name, agent, extra in (
        ("probe-active", a, {"backend_ip": "192.0.2.10"}),
        ("probe-runner", b, {}),
        ("probe-hop", hop_agent, {"kind": "hop", "wan_interface": "eth0", "hop_ip": "198.51.100.9"}),
    ):
        response = client.post("/v1/nodes", json={"name": name, "ssh_host": "127.0.0.1", "ssh_user": "test",
            "agent_port": agent.port, "agent_token": agent.token, **extra})
        response.raise_for_status()
        nodes.append(response.json())
    active, runner, hop = nodes
    instance = client.post("/v1/instances", json={"name": "wgprobe", "listen_port": 51820,
        "address": "203.0.113.20/24"}).json()
    client.put(f"/v1/instances/{instance['id']}/placements/{active['id']}", json={"role": "active"}).raise_for_status()
    client.put(f"/v1/hops/{hop['id']}/links/{instance['id']}").raise_for_status()
    return active, runner, hop, instance


@pytest.mark.asyncio
async def test_probe_delivery_scrape_and_delete(session, fake_agent_factory, crypto, monkeypatch):
    agent_a, agent_b, hop_agent = await fake_agent_factory(3)
    client, sessions, rec = _api(session, crypto, monkeypatch)
    with client:
        active, runner, hop, instance = _create_fixture(client, agent_a, agent_b, hop_agent)
        hop_revision = client.get(f"/v1/nodes/{hop['id']}").json()["desired_revision"]
        probe = client.post("/v1/probes", json={"hop_id": hop["id"], "instance_id": instance["id"],
            "runner_node_id": runner["id"]})
        probe.raise_for_status()
        probe = probe.json()
        with sessions() as db:
            peer = db.scalar(select(Peer).where(Peer.owner == PROBE_OWNER))
            private_key = crypto.decrypt(peer.private_key_enc)
            psk = crypto.decrypt(peer.preshared_key_enc)
            probe_ip, probe_public_key = peer.allowed_ip, peer.public_key
            hop_revision_db = db.get(NodeRevision, hop["id"]).desired_revision
        rec.kick(active["id"], force=True)
        rec.kick(runner["id"], force=True)
        rec.kick(hop["id"], force=True)
        await rec.reconcile_once({active["id"], runner["id"], hop["id"]})
        interface_name = f"wgp{probe['id']}"
        runner_iface = next(i for i in agent_b.state["interfaces"] if i["name"] == interface_name)
        server_iface = next(i for i in agent_a.state["interfaces"] if i["name"] == "wgprobe")
        client_peer = runner_iface["peers"][0]
        server_peer = next(p for p in server_iface["peers"] if p["public_key"] == probe_public_key)
        assert (runner_iface["mode"], runner_iface["listen_port"], runner_iface["address"]) == ("client", 0, f"{probe_ip}/32")
        assert client_peer["endpoint"] == "198.51.100.9:51820"
        assert client_peer["persistent_keepalive"] == 5
        assert client_peer["preshared_key"] == psk == server_peer["preshared_key"]
        assert client_peer["allowed_ips"] == ["203.0.113.20/32"]
        assert runner_iface["obfuscation"] == instance["obfuscation"]
        assert server_peer["allowed_ips"] == [f"{probe_ip}/32"]
        assert client.get(f"/v1/nodes/{hop['id']}").json()["desired_revision"] == hop_revision
        assert hop_revision_db == hop_revision

        now = datetime.now(UTC).timestamp()
        agent_b.metrics_text = "\n".join((
            f'wg_interface_up{{interface="{interface_name}"}} 1',
            f'wg_peer_last_handshake_timestamp_seconds{{interface="{interface_name}",public_key="{probe_public_key}"}} {now - 10}',
        ))
        await rec.reconcile_once()
        metrics = client.get("/metrics").text
        assert f'wgoctopus_unknown_peers{{node="probe-runner",instance="{interface_name}"}} 0' in metrics or f'wgoctopus_unknown_peers{{node="probe-runner",instance="{interface_name}"}}' not in metrics
        assert 'wgoctopus_peers{instance="wgprobe"} 0' in metrics
        assert f'peer="{probe_public_key}"' not in "\n".join(line for line in metrics.splitlines() if line.startswith("wgoctopus_peer_"))
        responses = [client.get(f"/v1/probes/{probe['id']}"), client.get("/v1/probes"),
            client.get("/v1/probes", params={"runner_node_id": runner["id"]}), client.get("/v1/events"),
            client.get(f"/v1/instances/{instance['id']}/peers"), client.get("/metrics")]
        for response in responses:
            assert response.status_code == 200
            assert private_key not in response.text and psk not in response.text and not re.search(rf"(?<![0-9.]){re.escape(probe_ip)}(?![0-9])", response.text)

        assert client.delete(f"/v1/probes/{probe['id']}").status_code == 204
        await rec.reconcile_once()
        assert all(i["name"] != interface_name for i in agent_b.state["interfaces"])
        assert all(p["public_key"] != probe_public_key for i in agent_a.state["interfaces"] for p in i["peers"])


@pytest.mark.asyncio
async def test_probe_api_rejects_invalid_runner_link_and_duplicate(session, fake_agent_factory, crypto, monkeypatch):
    a, b, h = await fake_agent_factory(3)
    client, _, _ = _api(session, crypto, monkeypatch)
    with client:
        _active, runner, hop, instance = _create_fixture(client, a, b, h)
        payload = {"hop_id": hop["id"], "instance_id": instance["id"], "runner_node_id": hop["id"]}
        assert client.post("/v1/probes", json=payload).status_code == 422
        payload["runner_node_id"] = runner["id"]
        assert client.post("/v1/probes", json=payload).status_code == 201
        assert client.post("/v1/probes", json=payload).status_code == 409
        unlinked = client.post("/v1/nodes", json={"name": "unlinked-hop", "ssh_host": "192.0.2.2",
            "ssh_user": "test", "kind": "hop", "wan_interface": "eth0", "hop_ip": "203.0.113.9"}).json()
        assert client.post("/v1/probes", json={"hop_id": unlinked["id"], "instance_id": instance["id"],
            "runner_node_id": runner["id"]}).status_code in (409, 422)


def test_probe_api_visibility_and_secret_safety(api, crypto):
    client, sessions, _, _ = api
    auth = client.headers.pop("Authorization")
    assert client.post("/v1/probes", json={}).status_code == 401
    client.headers["Authorization"] = auth

    # This fixture's instance/node identifiers are established by the shared API fixture.
    instance = client.post("/v1/instances", json={
        "name": "probe-test", "listen_port": 51821, "address": "192.0.2.10/24",
    }).json()
    hop = client.post("/v1/nodes", json={
        "name": "probe-hop", "ssh_host": "127.0.0.1", "ssh_user": "test",
        "kind": "hop", "wan_interface": "eth0", "hop_ip": "198.51.100.1",
    }).json()
    runner = client.post("/v1/nodes", json={
        "name": "probe-runner", "ssh_host": "192.0.2.2", "ssh_user": "test",
    }).json()
    assert client.put(f"/v1/hops/{hop['id']}/links/{instance['id']}").status_code == 204
    payload = {"hop_id": hop["id"], "instance_id": instance["id"], "runner_node_id": runner["id"]}
    assert client.post("/v1/probes", json={**payload, "extra": 1}).status_code == 422
    response = client.post("/v1/probes", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert set(data) == {"id", "hop_id", "instance_id", "runner_node_id", "interface", "created_at"}
    assert client.get(f"/v1/probes/{data['id']}").json()["id"] == data["id"]
    assert [p["id"] for p in client.get("/v1/probes", params={"runner_node_id": runner["id"]}).json()] == [data["id"]]
    with sessions() as session:
        peer = session.query(Peer).filter_by(owner=PROBE_OWNER).one()
        peer_id = peer.id
    assert client.get(f"/v1/instances/{instance['id']}/peers").json() == []
    assert client.get(f"/v1/peers/{peer_id}").status_code == 404
    assert client.patch(f"/v1/peers/{peer_id}", json={"name": "no"}).status_code == 404
    assert client.delete(f"/v1/peers/{peer_id}").status_code == 404
    assert client.get(f"/v1/peers/{peer_id}/config?endpoint_host=example.invalid").status_code == 404
    assert client.post(f"/v1/instances/{instance['id']}/peers", json={"name": "reserved", "owner": PROBE_OWNER}).status_code == 422
    assert client.delete(f"/v1/probes/{data['id']}").status_code == 204
    assert client.get(f"/v1/probes/{data['id']}").status_code == 404
