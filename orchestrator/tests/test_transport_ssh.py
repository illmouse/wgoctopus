import asyncio
import os
import socket
from types import SimpleNamespace

import asyncssh
import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fake_agent import FakeAgent
from ssh_server import start_server

from wgoctopus_orch.agent_client import AgentClient
from wgoctopus_orch.config import Settings
from wgoctopus_orch.crypto import Crypto
from wgoctopus_orch.models import NodeObserved
from wgoctopus_orch.push import PushStatus, push_node
from wgoctopus_orch.service import add_peer, create_instance, create_node, place
from wgoctopus_orch.transport import SshTunnelTransport

TEST_CRYPTO = Crypto(Fernet.generate_key())


@pytest_asyncio.fixture
async def fake_agent():
    agent = FakeAgent()
    await agent.start()
    yield agent
    if agent._server:
        await agent.stop()


@pytest.fixture
def ssh_keys(tmp_path):
    host = asyncssh.generate_private_key("ssh-ed25519")
    client = asyncssh.generate_private_key("ssh-ed25519")
    host_file, client_file = tmp_path / "host", tmp_path / "client"
    host_file.write_bytes(host.export_private_key())
    client_file.write_bytes(client.export_private_key())
    return host, client, host_file, client_file


@pytest_asyncio.fixture
async def ssh_server(fake_agent, ssh_keys):
    host, client, _, client_file = ssh_keys
    server = await start_server(0, fake_agent.port, host, client)
    port = server.get_port()
    yield SimpleNamespace(server=server, port=port, host_key=host, client_key=client, client_file=client_file)
    server.close()
    await server.wait_closed()


def node(agent, ssh_server, token=None, client_key=None):
    return SimpleNamespace(ssh_host="127.0.0.1", ssh_port=ssh_server.port,
                           ssh_user="tester", agent_port=agent.port,
                           agent_token_enc=TEST_CRYPTO.encrypt(token or agent.token))


def make_transport(ssh_server, tmp_path, *, tofu=False, key=None, timeout=1, crypto=TEST_CRYPTO):
    return SshTunnelTransport(Settings(
        ssh_key_file=str(key or ssh_server.client_file),
        ssh_known_hosts=str(tmp_path / "known_hosts"), ssh_tofu=tofu,
        ssh_connect_timeout=timeout, agent_request_timeout=timeout), crypto=crypto)


@pytest.mark.asyncio
async def test_strict_host_key_rejects_unknown(ssh_server, fake_agent, tmp_path):
    with pytest.raises(asyncssh.HostKeyNotVerifiable):
        async with make_transport(ssh_server, tmp_path).open(node(fake_agent, ssh_server)):
            pass
    assert not fake_agent.requests


@pytest.mark.asyncio
async def test_known_key_tunnel_get_and_put(ssh_server, fake_agent, tmp_path):
    known = tmp_path / "known_hosts"
    label = f"[127.0.0.1]:{ssh_server.port}"
    known.write_bytes(f"{label} {ssh_server.host_key.export_public_key().decode()}".encode())
    async with make_transport(ssh_server, tmp_path).open(node(fake_agent, ssh_server)) as session:
        assert (await session.request("GET", "/healthz")).text == "ok"
        assert (await session.request("PUT", "/v1/state", json={"revision": 1, "interfaces": []})).status_code == 204
        assert {r[1] for r in fake_agent.requests} >= {"/healthz", "/v1/state"}


async def _tracked_open(monkeypatch, transport, node):
    original = asyncssh.connect
    connections = []

    async def connect(*args, **kwargs):
        conn = await original(*args, **kwargs)
        connections.append(conn)
        return conn

    monkeypatch.setattr(asyncssh, "connect", connect)
    context = transport.open(node)
    session = await context.__aenter__()
    port = int(session._client.base_url.port)
    return context, connections, port


async def _assert_closed(connections, port):
    assert connections and connections[0].is_closed()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        with pytest.raises(OSError):
            await asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", port))
    finally:
        sock.close()


@pytest.mark.asyncio
async def test_context_cleanup_on_exit_and_exception(ssh_server, fake_agent, tmp_path, monkeypatch):
    transport = make_transport(ssh_server, tmp_path, tofu=True)
    context, connections, port = await _tracked_open(monkeypatch, transport, node(fake_agent, ssh_server))
    await context.__aexit__(None, None, None)
    await _assert_closed(connections, port)

    context, connections, port = await _tracked_open(monkeypatch, transport, node(fake_agent, ssh_server))
    assert not await context.__aexit__(RuntimeError, RuntimeError("test"), None)
    await _assert_closed(connections, port)


@pytest.mark.asyncio
async def test_context_cleanup_on_cancel(ssh_server, fake_agent, tmp_path, monkeypatch):
    fake_agent.delay = 30
    baseline = asyncio.all_tasks()
    transport = make_transport(ssh_server, tmp_path, tofu=True)
    original = asyncssh.connect
    connections = []

    async def connect(*args, **kwargs):
        conn = await original(*args, **kwargs)
        connections.append(conn)
        return conn

    monkeypatch.setattr(asyncssh, "connect", connect)
    info = {}

    async def request():
        async with transport.open(node(fake_agent, ssh_server)) as session:
            info["port"] = int(session._client.base_url.port)
            await session.request("GET", "/v1/state", timeout=None)

    task = asyncio.create_task(request())
    while "port" not in info:
        await asyncio.sleep(.01)
    await asyncio.sleep(.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _assert_closed(connections, info["port"])
    await asyncio.sleep(0)
    assert {t for t in asyncio.all_tasks() - baseline if t is not asyncio.current_task()} == set()


@pytest.mark.asyncio
async def test_ssh_server_refuses_unapproved_forward(ssh_server, ssh_keys, tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text(f"[127.0.0.1]:{ssh_server.port} {ssh_server.host_key.export_public_key().decode()}\n")
    conn = await asyncssh.connect("127.0.0.1", port=ssh_server.port, username="tester",
        client_keys=[str(ssh_server.client_file)], known_hosts=str(known))
    try:
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.open_connection("127.0.0.1", 1)
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_tofu_pins_and_rejects_changed_key(ssh_server, fake_agent, tmp_path):
    transport = make_transport(ssh_server, tmp_path, tofu=True)
    async with transport.open(node(fake_agent, ssh_server)):
        pass
    known = tmp_path / "known_hosts"
    assert os.stat(known).st_mode & 0o777 == 0o600
    assert f"[127.0.0.1]:{ssh_server.port}" in known.read_text()
    async with transport.open(node(fake_agent, ssh_server)):
        pass
    ssh_server.server.close()
    await ssh_server.server.wait_closed()
    replacement = await start_server(ssh_server.port, fake_agent.port,
                                     asyncssh.generate_private_key("ssh-ed25519"), ssh_server.client_key)
    try:
        with pytest.raises(asyncssh.HostKeyNotVerifiable):
            async with transport.open(node(fake_agent, ssh_server)):
                pass
    finally:
        replacement.close()
        await replacement.wait_closed()


@pytest.mark.asyncio
async def test_wrong_client_key_rejected(ssh_server, fake_agent, tmp_path):
    wrong = tmp_path / "wrong"
    wrong.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    # Restrict accepted client keys to the fixture's intended public key.
    ssh_server.server.close()
    await ssh_server.server.wait_closed()
    server = await asyncssh.create_server(lambda: __import__("ssh_server").SSHServer(fake_agent.port),
        "127.0.0.1", ssh_server.port, server_host_keys=[ssh_server.host_key],
        authorized_client_keys=asyncssh.import_authorized_keys(ssh_server.client_key.export_public_key().decode()),
        allow_pty=False, encoding=None)
    try:
        with pytest.raises((asyncssh.PermissionDenied, asyncssh.HostKeyNotVerifiable)):
            async with make_transport(ssh_server, tmp_path, key=wrong).open(node(fake_agent, ssh_server)):
                pass
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_closed_ssh_port_fails_quickly(ssh_server, fake_agent, tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]
    missing = SimpleNamespace(**vars(ssh_server))
    missing.port = closed_port
    with pytest.raises(OSError):
        async with make_transport(missing, tmp_path, timeout=1).open(node(fake_agent, missing)):
            pass


@pytest.mark.asyncio
async def test_bearer_auth_timeout_and_closed_agent(ssh_server, fake_agent, tmp_path):
    async with make_transport(ssh_server, tmp_path, tofu=True).open(node(fake_agent, ssh_server, token="wrong")) as session:
        result = await AgentClient(session, timeout=1).healthz()
        assert result  # health endpoint is intentionally unauthenticated
        response = await session.request("GET", "/v1/state")
        assert response.status_code == 401
    fake_agent.delay = .2
    async with make_transport(ssh_server, tmp_path, tofu=True).open(node(fake_agent, ssh_server)) as session:
        result = await AgentClient(session, timeout=.03).put_state({"revision": 1})
        assert result.error_kind.value == "timeout"
    fake_agent.delay = 0
    await fake_agent.stop()
    async with make_transport(ssh_server, tmp_path, tofu=True).open(node(fake_agent, ssh_server)) as session:
        with pytest.raises(httpx.RequestError):
            await session.request("GET", "/healthz")


@pytest.mark.asyncio
async def test_context_closes_forward_and_push_happy_path(ssh_server, fake_agent, tmp_path, session, crypto):
    node_db = create_node(session, "node", "127.0.0.1", "tester", ssh_port=ssh_server.port,
                          agent_port=fake_agent.port, agent_token=fake_agent.token, crypto=crypto)
    instance = create_instance(session, "wg0", 12345, "10.0.0.1/24", crypto=crypto)
    place(session, instance.id, node_db.id, crypto=crypto)
    add_peer(session, instance.id, "peer", crypto=crypto)
    known = tmp_path / "known_hosts"
    known.write_text(f"[127.0.0.1]:{ssh_server.port} {ssh_server.host_key.export_public_key().decode()}")
    transport = make_transport(ssh_server, tmp_path, crypto=crypto)
    outcome = await push_node(session, node_db.id, transport=transport, crypto=crypto)
    assert outcome.status == PushStatus.OK
    assert session.get(NodeObserved, node_db.id).applied_revision == outcome.revision
