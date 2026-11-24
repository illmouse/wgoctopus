"""Agent HTTP sessions over an outbound SSH local-forward tunnel."""

import os
import tempfile
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import asyncssh
import httpx

from .config import Settings
from .crypto import Crypto


class AgentSession:
    def __init__(self, client):
        self._client = client

    async def request(self, method, path, *, json=None, params=None, timeout=30):
        return await self._client.request(method, path, json=json, params=params, timeout=timeout)


class AgentTransport:
    async def open(self, node):
        raise NotImplementedError


class SshTunnelTransport(AgentTransport):
    def __init__(self, settings: Settings | None = None, *, crypto: Crypto | None = None):
        self.settings = settings or Settings.from_env()
        self.crypto = crypto or Crypto()

    @asynccontextmanager
    async def open(self, node):
        settings = self.settings
        if not settings.ssh_key_file:
            raise ValueError("WGOCTOPUS_SSH_KEY_FILE is required")
        passphrase = None
        if settings.ssh_key_passphrase_file:
            passphrase = Path(settings.ssh_key_passphrase_file).read_text().strip()
        known_hosts = settings.ssh_known_hosts or str(Path.home() / ".ssh" / "known_hosts")
        known_path = Path(known_hosts)
        known_path.parent.mkdir(parents=True, exist_ok=True)
        entry_host = node.ssh_host if node.ssh_port == 22 else f"[{node.ssh_host}]:{node.ssh_port}"
        known = known_path.read_text() if known_path.exists() else ""

        def validate_host_public_key(host, addr, port, key):
            public_key = key.export_public_key().decode().strip()
            matching = [line.split() for line in known.splitlines()
                        if line.strip() and not line.lstrip().startswith("#")
                        and entry_host in line.split()[0].split(",")]
            if matching:
                return any(len(fields) >= 3 and fields[1:] == public_key.split()
                           for fields in matching)
            if not settings.ssh_tofu:
                return False
            content = known + ("" if not known or known.endswith("\n") else "\n")
            content += f"{entry_host} {public_key}\n"
            fd, temp_name = tempfile.mkstemp(dir=known_path.parent)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w") as temp_file:
                    temp_file.write(content)
                os.replace(temp_name, known_path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
            return True

        class HostKeyClient(asyncssh.SSHClient):
            def validate_host_public_key(self, host, addr, port, key):
                return validate_host_public_key(host, addr, port, key)

        conn = await asyncssh.connect(
            node.ssh_host, port=node.ssh_port, username=node.ssh_user,
            client_keys=[settings.ssh_key_file], passphrase=passphrase,
            known_hosts=(), client_factory=HostKeyClient,
            connect_timeout=settings.ssh_connect_timeout, keepalive_interval=30,
        )
        listener = None
        client = None
        try:
            listener = await conn.forward_local_port("127.0.0.1", 0, "127.0.0.1", node.agent_port)
            token = self.crypto.decrypt(node.agent_token_enc)
            client = httpx.AsyncClient(base_url=f"http://127.0.0.1:{listener.get_port()}",
                                       headers={"Authorization": f"Bearer {token}"})
            yield AgentSession(client)
        finally:
            if client:
                await client.aclose()
            if listener:
                listener.close()
                await listener.wait_closed()
            conn.close()
            await conn.wait_closed()


class DirectHttpTransport(AgentTransport):
    def __init__(self, settings: Settings | None = None, *, crypto: Crypto | None = None):
        self.settings = settings or Settings.from_env()
        self.crypto = crypto or Crypto()
        if self.settings.transport != "direct":
            raise ValueError("direct transport requires WGOCTOPUS_TRANSPORT=direct")

    @asynccontextmanager
    async def open(self, node):
        token = self.crypto.decrypt(node.agent_token_enc)
        client = httpx.AsyncClient(
            base_url=f"http://{node.ssh_host}:{node.agent_port}",
            headers={"Authorization": f"Bearer {token}"})
        try:
            yield AgentSession(client)
        finally:
            await client.aclose()


class PullTransport(AgentTransport):
    def __init__(self, server, *, settings=None, crypto=None):
        self.server, self.settings = server, settings or Settings.from_env()
        self.crypto = crypto or Crypto()

    @asynccontextmanager
    async def open(self, node):
        port = self.server.get_port(node.id)
        if port is None:
            raise ConnectionError("pull tunnel not connected")
        client = httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", headers={
            "Authorization": f"Bearer {self.crypto.decrypt(node.agent_token_enc)}"})
        try:
            yield AgentSession(client)
        finally:
            await client.aclose()


class AutoTransport(AgentTransport):
    def __init__(self, ssh_transport, pull_transport, server):
        self.ssh_transport, self.pull_transport, self.server = ssh_transport, pull_transport, server

    @asynccontextmanager
    async def open(self, node):
        stack = AsyncExitStack()
        try:
            session = await stack.enter_async_context(self.ssh_transport.open(node))
        except (OSError, asyncssh.Error, TimeoutError, ValueError):
            await stack.aclose()
            if not self.server.is_connected(node.id):
                raise
            async with self.pull_transport.open(node) as session:
                yield session
        else:
            try:
                yield session
            finally:
                await stack.aclose()


class RoutingTransport(AgentTransport):
    def __init__(self, settings, server=None, *, crypto=None):
        self.settings, self.server = settings, server
        self.ssh = DirectHttpTransport(settings, crypto=crypto) if settings.transport == "direct" else SshTunnelTransport(settings, crypto=crypto)
        self.pull = PullTransport(server, settings=settings, crypto=crypto) if server else None

    def open(self, node):
        if node.mgmt_mode == "push":
            return self.ssh.open(node)
        if node.mgmt_mode == "pull":
            return self.pull.open(node) if self.pull else _not_connected()
        if node.mgmt_mode == "auto":
            if self.pull:
                return AutoTransport(self.ssh, self.pull, self.server).open(node)
            return self.ssh.open(node)
        return _not_connected()


@asynccontextmanager
async def _not_connected():
    raise ConnectionError("pull tunnel not connected")
    yield
