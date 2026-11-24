import asyncio

import asyncssh
import pytest
from api_helpers import RecordingReconciler
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.alerts import AlertDispatcher
from wgoctopus_orch.api import create_app
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.metrics import render_metrics
from wgoctopus_orch.models import AlertState, Event


class FakePullServer:
    host_key_fingerprint = "SHA256:public-fingerprint"

    def __init__(self):
        self.counters = {"connections_ok": 2, "connections_denied": 1}

    def connected_node_ids(self):
        return []

    def is_connected(self, node_id):
        return False


def test_pull_node_crud(session, crypto, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_ALLOW_NO_AUTH", "true")
    app = create_app(session_factory=sessionmaker(bind=session.get_bind()), crypto=crypto, migrate=False,
                     reconciler=RecordingReconciler(), pull_server=FakePullServer())
    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    with TestClient(app) as client:
        created = client.post("/v1/nodes", json={"name": "pull-node", "mgmt_mode": "pull"})
        assert created.status_code == 201, created.text
        node = created.json()
        assert (node["ssh_host"], node["ssh_user"]) == ("-", "pull")
        assert client.post("/v1/nodes", json={"name": "push-node"}).status_code == 422
        created = client.post("/v1/nodes", json={"name": "auto-node", "ssh_host": "example", "ssh_user": "agent",
                                                  "mgmt_mode": "auto", "pull_public_key": key + " comment"})
        assert created.status_code == 201, created.text
        ident = created.json()["id"]
        assert created.json()["pull_public_key"] == " ".join(key.split()[:2])
        for invalid in ("garbage-key", asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()):
            response = client.post("/v1/nodes", json={"name": "bad-key", "ssh_host": "host", "ssh_user": "agent",
                                                       "pull_public_key": invalid})
            assert response.status_code == 422
            assert invalid not in response.text
        assert client.patch(f"/v1/nodes/{ident}", json={"pull_public_key": None}).json()["pull_public_key"] is None
        invalid = "not-a-valid-pull-key"
        response = client.patch(f"/v1/nodes/{ident}", json={"pull_public_key": invalid})
        assert response.status_code == 422
        assert invalid not in response.text
        assert client.get("/v1/pull").json()["host_key_fingerprint"] == FakePullServer.host_key_fingerprint


def test_pull_api_disabled(session, crypto, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_ALLOW_NO_AUTH", "true")
    app = create_app(session_factory=sessionmaker(bind=session.get_bind()), crypto=crypto, migrate=False, reconciler=RecordingReconciler())
    with TestClient(app) as client:
        assert client.get("/v1/pull").json()["enabled"] is False


@pytest.mark.asyncio
async def test_pull_lifespan_callbacks_and_api(tmp_path, crypto, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "test-admin-token")
    monkeypatch.setenv("WGOCTOPUS_PULL_LISTEN", "127.0.0.1:0")
    monkeypatch.setenv("WGOCTOPUS_PULL_HOST_KEY_FILE", str(tmp_path / "host-key"))
    url = f"sqlite:///{tmp_path / 'pull-api.db'}"
    upgrade_to_head(url)
    engine = make_engine(url)
    sessions = make_session_factory(engine)
    reconciler = RecordingReconciler()
    app = create_app(session_factory=sessions, reconciler=reconciler, crypto=crypto, migrate=False)
    key = asyncssh.generate_private_key("ssh-ed25519")
    client = TestClient(app)
    client.headers["Authorization"] = "Bearer test-admin-token"
    agent = None
    connection = None
    try:
        with client:
            created = client.post("/v1/nodes", json={"name": "pull-agent", "mgmt_mode": "pull",
                "pull_public_key": key.export_public_key().decode().strip()})
            assert created.status_code == 201, created.text
            node_id = created.json()["id"]
            server = app.state.pull_server
            seen = []

            async def handle(reader, writer):
                seen.append(await reader.readuntil(b"\r\n\r\n"))
                writer.close()

            agent = await asyncio.start_server(handle, "127.0.0.1", 0)
            agent_port = agent.sockets[0].getsockname()[1]
            connection = await asyncssh.connect("127.0.0.1", port=server.port, username="pull-agent",
                client_keys=[key], known_hosts=None)
            await connection.forward_remote_port("127.0.0.1", 0, "127.0.0.1", agent_port)

            async def wait_for(predicate):
                async with asyncio.timeout(5):
                    while not predicate():
                        await asyncio.sleep(.01)

            await wait_for(lambda: server.is_connected(node_id) and any(k == node_id for k, _ in reconciler.kicks))
            events = client.get("/v1/events").json()
            assert any(event["kind"] == "node.pull_connected" for event in events)
            status = client.get("/v1/pull").json()
            assert node_id in status["connected_node_ids"]
            assert status["host_key_fingerprint"].startswith("SHA256:")
            assert client.get(f"/v1/nodes/{node_id}").json()["pull_connected"] is True
            metrics = client.get("/metrics").text
            assert 'wgoctopus_pull_tunnel_up{node="pull-agent"} 1' in metrics
            assert "wgoctopus_pull_server_enabled 1" in metrics
            assert (node_id, {"force": True}) in reconciler.kicks

            connection.close()
            await connection.wait_closed()
            connection = None
            await wait_for(lambda: not server.is_connected(node_id))
            await wait_for(lambda: any(e["kind"] == "node.pull_disconnected" for e in client.get("/v1/events").json()))
            assert 'wgoctopus_pull_tunnel_up{node="pull-agent"} 0' in client.get("/metrics").text
    finally:
        if connection:
            connection.close()
            await connection.wait_closed()
        if agent:
            agent.close()
            await agent.wait_closed()
        engine.dispose()


def test_pull_metrics_without_server_and_connection_counters(session, crypto):
    from wgoctopus_orch.service import create_node

    create_node(session, "push-only", "127.0.0.1", "agent", crypto=crypto)
    text = render_metrics(session, None, pull_server=None)
    assert "wgoctopus_pull_server_enabled 0" in text
    assert "wgoctopus_pull_tunnel_up{" not in text

    server = FakePullServer()
    text = render_metrics(session, None, pull_server=server)
    assert 'wgoctopus_pull_tunnel_up{node="push-only"}' not in text
    assert 'wgoctopus_pull_connections_total{result="ok"} 2' in text
    assert 'wgoctopus_pull_connections_total{result="denied"} 1' in text


@pytest.mark.asyncio
async def test_pull_events_are_ignored_by_alert_dispatcher(session):

    session.add(AlertState(key="last_event_id", value="0"))
    session.add_all([Event(kind=kind, subject="1", data={}) for kind in
                     ("node.pull_connected", "node.pull_disconnected")])
    session.commit()

    class Notifier:
        def __init__(self):
            self.sent = []

        async def send(self, message):
            self.sent.append(message)

    notifier = Notifier()
    dispatcher = AlertDispatcher(sessionmaker(bind=session.get_bind(), expire_on_commit=False), notifier)
    await dispatcher.poll_once()
    assert notifier.sent == []
    assert session.get(AlertState, "last_event_id").value == "2"
