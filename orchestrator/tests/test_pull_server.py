import asyncio
import logging

import asyncssh
import pytest
from cryptography.fernet import Fernet

from wgoctopus_orch.config import Settings
from wgoctopus_orch.pull_server import PullServer
from wgoctopus_orch.service import create_instance, create_node, place
from wgoctopus_orch.transport import (
    AutoTransport,
    DirectHttpTransport,
    PullTransport,
    RoutingTransport,
)


@pytest.mark.asyncio
async def test_pull_auth_and_host_key(session, tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    from wgoctopus_orch.crypto import Crypto
    crypto = Crypto(Fernet.generate_key())
    node = create_node(session, "agent", "127.0.0.1", "agent", mgmt_mode="pull", crypto=crypto)
    node.pull_public_key = key.export_public_key().decode().strip()
    session.commit()
    settings = Settings(pull_listen="127.0.0.1:0", pull_host_key_file=str(tmp_path / "host"))
    server = PullServer(lambda: session, settings=settings)
    await server.start()
    fingerprint = server.host_key_fingerprint
    assert (tmp_path / "host").stat().st_mode & 0o777 == 0o600
    conn = await asyncssh.connect("127.0.0.1", port=server.port, username="agent",
                                  client_keys=[key], known_hosts=None)
    assert fingerprint.startswith("SHA256:")
    assert server.counters["connections_ok"] == 1
    conn.close()
    await conn.wait_closed()
    await server.stop()
    restarted = PullServer(lambda: session, settings=settings)
    await restarted.start()
    assert restarted.host_key_fingerprint == fingerprint
    await restarted.stop()


@pytest.mark.asyncio
async def test_pull_rejects_wrong_key(session):
    key = asyncssh.generate_private_key("ssh-ed25519")
    from wgoctopus_orch.crypto import Crypto
    node = create_node(session, "agent", "127.0.0.1", "agent", mgmt_mode="pull", crypto=Crypto(Fernet.generate_key()))
    node.pull_public_key = key.export_public_key().decode().strip()
    session.commit()
    server = PullServer(lambda: session, settings=Settings(pull_listen="127.0.0.1:0"))
    await server.start()
    with pytest.raises(asyncssh.PermissionDenied):
        await asyncssh.connect("127.0.0.1", port=server.port, username="agent",
                               client_keys=[asyncssh.generate_private_key("ssh-ed25519")], known_hosts=None)
    assert server.counters["connections_denied"] > 0
    await server.stop()


@pytest.mark.asyncio
async def test_pull_transport_disconnected():
    class Registry:
        def get_port(self, node_id):
            return None

    with pytest.raises(ConnectionError, match="pull tunnel not connected"):
        from wgoctopus_orch.crypto import Crypto
        async with PullTransport(Registry(), crypto=Crypto(Fernet.generate_key())).open(type("Node", (), {"id": 1})()):
            pass


def test_pull_settings_env(monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_PULL_LISTEN", "127.0.0.1:2222")
    monkeypatch.setenv("WGOCTOPUS_PULL_HOST_KEY_FILE", "/tmp/pull-key")
    monkeypatch.setenv("WGOCTOPUS_PULL_LOGIN_TIMEOUT", "9")
    settings = Settings.from_env()
    assert (settings.pull_listen, settings.pull_host_key_file, settings.pull_login_timeout) == (
        "127.0.0.1:2222", "/tmp/pull-key", 9)
    monkeypatch.setenv("WGOCTOPUS_PULL_LISTEN", "bad")
    with pytest.raises(ValueError):
        Settings.from_env()


@pytest.mark.parametrize("mode,expected", [("push", DirectHttpTransport), ("pull", PullTransport),
                                            ("auto", AutoTransport)])
def test_routing_selects_by_mode(mode, expected):
    settings = Settings(transport="direct")
    from wgoctopus_orch.crypto import Crypto
    routing = RoutingTransport(settings, object(), crypto=Crypto(Fernet.generate_key()))
    node = type("Node", (), {"mgmt_mode": mode})()
    assert routing.open(node).args[0].__class__ is expected


async def _fake_agent(seen):
    async def handle(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        seen.append(head.decode())
        body = b'{"ok":true}'
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                     b"Connection: close\r\n\r\n%s" % (len(body), body))
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _connect_agent(server, node_name, key, agent_port, *, expect_fingerprint=True):
    conn = await asyncssh.connect("127.0.0.1", port=server.port, username=node_name,
                                  client_keys=[key], known_hosts=None)
    listener = await conn.forward_remote_port("127.0.0.1", 0, "127.0.0.1", agent_port)
    return conn, listener


@pytest.mark.asyncio
async def test_pull_forward_roundtrip_with_token(session):
    from wgoctopus_orch.crypto import Crypto
    crypto = Crypto(Fernet.generate_key())
    key = asyncssh.generate_private_key("ssh-ed25519")
    node = create_node(session, "agent", "127.0.0.1", "agent", mgmt_mode="pull",
                       agent_token="synthetic-token", crypto=crypto)
    node.pull_public_key = key.export_public_key().decode().strip()
    session.commit()
    connected = []
    server = PullServer(lambda: session, settings=Settings(pull_listen="127.0.0.1:0"),
                        on_connect=connected.append)
    await server.start()
    seen = []
    agent, agent_port = await _fake_agent(seen)
    conn, listener = await _connect_agent(server, "agent", key, agent_port)
    await _poll(lambda: server.is_connected(node.id))
    assert server.get_port(node.id) == listener.get_port()
    assert connected == [node.id]
    async with PullTransport(server, crypto=crypto).open(node) as agent_session:
        response = await agent_session.request("GET", "/healthz")
    assert response.status_code == 200 and response.json() == {"ok": True}
    assert "authorization: bearer synthetic-token" in seen[0].lower()
    conn.close()
    await conn.wait_closed()
    await _poll(lambda: not server.is_connected(node.id))
    assert not server.is_connected(node.id)
    agent.close()
    await server.stop()


async def _poll(predicate):
    async with asyncio.timeout(3):
        while not predicate():
            await asyncio.sleep(.01)


async def _setup(session, *, name="agent", mode="pull", token="synthetic-token"):
    from wgoctopus_orch.crypto import Crypto
    crypto = Crypto(Fernet.generate_key())
    key = asyncssh.generate_private_key("ssh-ed25519")
    node = create_node(session, name, "127.0.0.1", "agent", mgmt_mode=mode,
                       agent_token=token, crypto=crypto)
    node.pull_public_key = key.export_public_key().decode().strip()
    session.commit()
    server = PullServer(lambda: session, settings=Settings(pull_listen="127.0.0.1:0"))
    await server.start()
    return node, key, crypto, server


def _deny_unknown_user(session, node, key, other):
    return "missing", key


def _deny_wrong_key(session, node, key, other):
    return node.name, asyncssh.generate_private_key("ssh-ed25519")


def _deny_disabled(session, node, key, other):
    node.enabled = False
    return node.name, key


def _deny_push_mode(session, node, key, other):
    node.mgmt_mode = "push"
    return node.name, key


def _deny_no_pubkey(session, node, key, other):
    node.pull_public_key = None
    return node.name, key


def _deny_other_nodes_name(session, node, key, other):
    return other.name, key


@pytest.mark.asyncio
@pytest.mark.parametrize("mutate", [_deny_unknown_user, _deny_wrong_key, _deny_disabled,
                                    _deny_push_mode, _deny_no_pubkey, _deny_other_nodes_name])
async def test_pull_denial_matrix(session, mutate):
    from wgoctopus_orch.crypto import Crypto
    node, key, _, server = await _setup(session)
    other = create_node(session, "other", "127.0.0.1", "agent", mgmt_mode="pull",
                        crypto=Crypto(Fernet.generate_key()))
    other.pull_public_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    username, client_key = mutate(session, node, key, other)
    session.commit()
    try:
        before = server.counters["connections_denied"]
        with pytest.raises(asyncssh.PermissionDenied):
            await asyncssh.connect("127.0.0.1", port=server.port, username=username,
                                   client_keys=[client_key], known_hosts=None)
        assert server.counters["connections_denied"] > before
        assert server.counters["connections_ok"] == 0
        assert not server.connected_node_ids()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_pull_forbidden_channels_and_forwarding(session):
    node, key, _, server = await _setup(session)
    seen = []
    agent, port = await _fake_agent(seen)
    conn, _ = await _connect_agent(server, "agent", key, port)
    await _poll(lambda: server.is_connected(node.id))
    try:
        with pytest.raises(asyncssh.Error):
            await conn.create_process("id")
        # direct-tcpip is refused: the local listener accepts TCP but the channel
        # is rejected, so the peer sees EOF and the fake agent never gets a request.
        listener = await conn.forward_local_port("127.0.0.1", 0, "127.0.0.1", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.get_port())
        writer.write(b"GET / HTTP/1.1\r\n\r\n")
        assert await asyncio.wait_for(reader.read(), 3) == b""
        writer.close()
        listener.close()
        await listener.wait_closed()
        assert seen == []
        with pytest.raises(asyncssh.ChannelListenError):
            await conn.forward_remote_port("0.0.0.0", 0, "127.0.0.1", port)
        with pytest.raises(asyncssh.ChannelListenError):
            await conn.forward_remote_port("127.0.0.1", 0, "127.0.0.1", port)
    finally:
        conn.close()
        await conn.wait_closed()
        agent.close()
        await server.stop()


@pytest.mark.asyncio
async def test_pull_second_connection_replaces_first(session):
    node, key, crypto, server = await _setup(session)
    connected, disconnected = [], []
    server.on_connect, server.on_disconnect = connected.append, disconnected.append
    first_seen, second_seen = [], []
    first_agent, first_port = await _fake_agent(first_seen)
    second_agent, second_port = await _fake_agent(second_seen)
    first, _first_listener = await _connect_agent(server, "agent", key, first_port)
    await _poll(lambda: server.is_connected(node.id))
    old_port = server.get_port(node.id)
    second, second_listener = await _connect_agent(server, "agent", key, second_port)
    await _poll(lambda: server.get_port(node.id) == second_listener.get_port())
    assert server.get_port(node.id) != old_port
    await asyncio.wait_for(first.wait_closed(), 3)
    assert connected == [node.id, node.id]
    # The replaced connection is superseded, not "lost": no disconnect event for it,
    # the node never left service.
    await asyncio.sleep(.1)
    assert disconnected == []
    async with PullTransport(server, crypto=crypto).open(node) as agent_session:
        assert (await agent_session.request("GET", "/healthz")).status_code == 200
    assert second_seen and not first_seen
    second.close()
    await second.wait_closed()
    await _poll(lambda: disconnected == [node.id])
    assert not server.is_connected(node.id)
    first_agent.close()
    second_agent.close()
    await server.stop()


class _FakeSession:
    def __init__(self, label):
        self.label = label


class _FakeTransport:
    def __init__(self, label, fail=None):
        self.label, self.fail, self.entered = label, fail, 0

    def open(self, node):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def manager():
            if self.fail:
                raise self.fail
            self.entered += 1
            yield _FakeSession(self.label)
        return manager()


class _FakeServer:
    def __init__(self, connected):
        self.connected = connected

    def is_connected(self, node_id):
        return self.connected


@pytest.mark.asyncio
async def test_auto_transport_prefers_ssh_and_falls_back():
    from wgoctopus_orch.transport import AutoTransport
    node = type("Node", (), {"id": 1})()
    ssh, pull = _FakeTransport("ssh"), _FakeTransport("pull")
    async with AutoTransport(ssh, pull, _FakeServer(True)).open(node) as got:
        assert got.label == "ssh"
    assert pull.entered == 0

    ssh, pull = _FakeTransport("ssh", fail=OSError("down")), _FakeTransport("pull")
    async with AutoTransport(ssh, pull, _FakeServer(True)).open(node) as got:
        assert got.label == "pull"

    ssh = _FakeTransport("ssh", fail=OSError("down"))
    with pytest.raises(OSError, match="down"):
        async with AutoTransport(ssh, _FakeTransport("pull"), _FakeServer(False)).open(node):
            pass


@pytest.mark.asyncio
async def test_auto_transport_body_errors_do_not_trigger_fallback():
    from wgoctopus_orch.transport import AutoTransport
    node = type("Node", (), {"id": 1})()
    ssh, pull = _FakeTransport("ssh"), _FakeTransport("pull")
    with pytest.raises(OSError, match="inside body"):
        async with AutoTransport(ssh, pull, _FakeServer(True)).open(node):
            raise OSError("inside body")
    assert pull.entered == 0


@pytest.mark.asyncio
async def test_pull_node_without_tunnel_is_unreachable(session, crypto):
    from sqlalchemy.orm import sessionmaker

    from wgoctopus_orch.reconciler import NodeState, Reconciler
    from wgoctopus_orch.transport import RoutingTransport
    node = create_node(session, "lonely", "-", "pull", mgmt_mode="pull", crypto=crypto)
    instance = create_instance(session, "wg0", 12345, "10.0.0.1/24", crypto=crypto)
    place(session, instance.id, node.id, crypto=crypto)
    settings = Settings(transport="direct")
    routing = RoutingTransport(settings, None, crypto=crypto)
    rec = Reconciler(sessionmaker(bind=session.get_bind(), expire_on_commit=False),
                     lambda _node: routing, settings, crypto=crypto)
    await rec.reconcile_once()
    assert rec.status()[node.id].state == NodeState.UNREACHABLE


@pytest.mark.asyncio
async def test_pull_logs_do_not_leak_secrets(session, caplog):
    caplog.set_level(logging.DEBUG)
    node, key, crypto, server = await _setup(session)
    seen = []
    agent, port = await _fake_agent(seen)
    conn, _ = await _connect_agent(server, "agent", key, port)
    await _poll(lambda: server.is_connected(node.id))
    async with PullTransport(server, crypto=crypto).open(node) as agent_session:
        await agent_session.request("GET", "/healthz")
    with pytest.raises(asyncssh.PermissionDenied):
        await asyncssh.connect("127.0.0.1", port=server.port, username="agent",
                               client_keys=[asyncssh.generate_private_key("ssh-ed25519")], known_hosts=None)
    conn.close()
    await conn.wait_closed()
    agent.close()
    await server.stop()
    blob = key.export_public_key().decode().split()[1]
    private = key.export_private_key().decode()
    text = caplog.text
    for secret in (blob, "synthetic-token", private.splitlines()[1] if len(private.splitlines()) > 1 else private):
        assert secret not in text


def _from_env(monkeypatch, value):
    monkeypatch.setenv("WGOCTOPUS_PULL_LISTEN", value)
    return Settings.from_env()


@pytest.mark.parametrize("value", ["bad", ":", "host:99999", "host:abc"])
def test_pull_listen_invalid(monkeypatch, value):
    with pytest.raises(ValueError):
        _from_env(monkeypatch, value)


@pytest.mark.parametrize("value", ["[::1]:2222", "0.0.0.0:2222"])
def test_pull_listen_valid(monkeypatch, value):
    assert _from_env(monkeypatch, value).pull_listen == value


@pytest.mark.asyncio
async def test_pull_disconnect_callback_and_host_fingerprint(session, tmp_path):
    node, key, _, server = await _setup(session)
    await server.stop()
    # Host key persistence is exercised separately with an explicit key path.
    callbacks = []
    server = PullServer(lambda: session, settings=Settings(pull_listen="127.0.0.1:0",
        pull_host_key_file=str(tmp_path / "host")), on_disconnect=callbacks.append)
    await server.start()
    seen=[]; agent, port=await _fake_agent(seen)
    conn, _=await _connect_agent(server, "agent", key, port)
    await _poll(lambda: server.is_connected(node.id))
    public = conn.get_server_host_key().export_public_key("openssh").decode().split()[1]
    import base64
    import hashlib
    assert "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public)).digest()).decode().rstrip("=") == server.host_key_fingerprint
    assert (tmp_path / "host").stat().st_mode & 0o777 == 0o600
    conn.close(); await conn.wait_closed()
    await _poll(lambda: not server.is_connected(node.id))
    await _poll(lambda: callbacks == [node.id])
    await server.stop(); agent.close()


@pytest.mark.asyncio
async def test_host_key_reuse_and_insecure_mode(session, tmp_path):
    _node, _, _, server = await _setup(session)
    await server.stop()
    path=tmp_path / "host"
    first=PullServer(lambda: session, settings=Settings(pull_listen="127.0.0.1:0", pull_host_key_file=str(path)))
    await first.start(); fingerprint=first.host_key_fingerprint; await first.stop()
    second=PullServer(lambda: session, settings=Settings(pull_listen="127.0.0.1:0", pull_host_key_file=str(path)))
    await second.start(); assert second.host_key_fingerprint == fingerprint; await second.stop()
    path.chmod(0o644)
    with pytest.raises(PermissionError): await PullServer(lambda: session, settings=Settings(pull_listen="127.0.0.1:0", pull_host_key_file=str(path))).start()
