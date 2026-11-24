"""Inbound SSH reverse-forward endpoint for pull-mode agents."""

import asyncio
import base64
import hashlib
import logging
import os
import socket
import tempfile
from pathlib import Path

import asyncssh
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from .models import Node

log = logging.getLogger(__name__)


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _public_line(key):
    return " ".join(key.export_public_key("openssh").decode().split()[:2])


class PullServer:
    def __init__(self, session_factory, *, settings, on_connect=None, on_disconnect=None):
        self.session_factory, self.settings = session_factory, settings
        self.on_connect, self.on_disconnect = on_connect, on_disconnect
        self._server = None
        self._connections = {}
        self.counters = {"connections_ok": 0, "connections_denied": 0}
        self._port = None
        self._fingerprint = None

    @property
    def host_key_fingerprint(self):
        return self._fingerprint

    @property
    def port(self):
        return self._port

    def get_port(self, node_id):
        item = self._connections.get(node_id)
        return item[1] if item else None

    def connected_node_ids(self):
        return set(self._connections)

    def is_connected(self, node_id):
        return node_id in self._connections

    def _host_key(self):
        path = Path(self.settings.pull_host_key_file) if self.settings.pull_host_key_file else None
        if path and path.exists():
            if path.stat().st_mode & 0o077:
                raise PermissionError("pull host key file permissions must be 0600")
            key = asyncssh.read_private_key(str(path))
        else:
            key = asyncssh.generate_private_key("ssh-ed25519")
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                fd, temp = tempfile.mkstemp(dir=path.parent)
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "wb") as out:
                        out.write(key.export_private_key("openssh"))
                    os.replace(temp, path)
                finally:
                    if os.path.exists(temp):
                        os.unlink(temp)
        blob = key.export_public_key("openssh").decode().split()[1]
        fingerprint = base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")
        self._fingerprint = "SHA256:" + fingerprint
        return key

    async def start(self):
        if not self.settings.pull_listen:
            raise ValueError("pull listener is disabled")
        host, port = self.settings.pull_listen.rsplit(":", 1)
        host = host.strip("[]")
        owner = self

        class Server(asyncssh.SSHServer):
            _conn = None

            def connection_made(self, conn):
                self._conn = conn

            def begin_auth(self, username):
                self.username = username
                self.node_id = None
                self.forward_registered = False
                return True

            def public_key_auth_supported(self):
                return True

            def auth_completed(self):
                owner.counters["connections_ok"] += 1

            def password_auth_supported(self):
                return False

            def kbdint_auth_supported(self):
                return False

            def validate_public_key(self, username, key):
                try:
                    with owner.session_factory() as session:
                        node = session.scalar(select(Node).where(
                            Node.name == username, Node.enabled.is_(True),
                            Node.pull_public_key.is_not(None),
                            Node.mgmt_mode.in_(("pull", "auto"))))
                        valid = bool(node and _public_line(key) == " ".join(node.pull_public_key.split()[:2]))
                        if valid:
                            self.node_id = node.id
                        else:
                            owner.counters["connections_denied"] += 1
                        return valid
                except (SQLAlchemyError, OSError) as exc:
                    log.warning("Pull authentication lookup failed (%s)", type(exc).__name__)
                    owner.counters["connections_denied"] += 1
                    return False

            def session_requested(self):
                return False

            def connection_requested(self, *args):
                return False

            async def server_requested(self, listen_host, listen_port):
                if listen_host not in ("127.0.0.1", "localhost"):
                    log.info("Pull forward denied for node %s", self.username)
                    return False
                if self.node_id is None or self.forward_registered:
                    return False
                conn = self._conn
                # The client matches forwarded-tcpip channels by the port we
                # report back, so the destination port must be the real one:
                # reserve a free loopback port first when 0 was requested.
                port = listen_port or _free_loopback_port()
                try:
                    listener = await conn.forward_local_port("127.0.0.1", port, "127.0.0.1", port)
                except OSError:
                    return False
                self.forward_registered = True
                previous = owner._connections.pop(self.node_id, None)
                if previous:
                    previous[0].close()
                owner._connections[self.node_id] = (conn, listener.get_port(), listener)
                if owner.on_connect:
                    result = owner.on_connect(self.node_id)
                    if asyncio.iscoroutine(result):
                        asyncio.create_task(result)
                return listener

            def connection_lost(self, exc):
                ident = self.node_id
                if ident is not None:
                    current = owner._connections.get(ident)
                    if current and current[0] is self._conn:
                        owner._connections.pop(ident, None)
                        if owner.on_disconnect:
                            result = owner.on_disconnect(ident)
                            if asyncio.iscoroutine(result):
                                asyncio.create_task(result)

        self._server = await asyncssh.create_server(
            Server, host, int(port), server_host_keys=[self._host_key()],
            login_timeout=self.settings.pull_login_timeout,
            keepalive_interval=30, keepalive_count_max=3)
        self._port = self._server.get_port()
        return self

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._port = None
