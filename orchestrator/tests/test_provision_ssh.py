"""SshExecutor against an in-process asyncssh server that executes scripted commands."""
from types import SimpleNamespace

import asyncssh
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet

from wgoctopus_orch.config import Settings
from wgoctopus_orch.crypto import Crypto
from wgoctopus_orch.provision import ProvisionError, SshExecutor, _text, open_executor

RECEIVED: list[str] = []
FAIL_SUDO = False


class Srv(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == "bootstrap-password"

    def public_key_auth_supported(self):
        return True


async def handle(process):
    cmd = process.command
    RECEIVED.append(cmd)
    if cmd == "sudo -n true" and FAIL_SUDO:
        process.exit(1)
        return
    if "fail" in cmd:
        process.stderr.write("boom")
        process.exit(3)
        return
    if "echo-stdin" in cmd:
        data = await process.stdin.read()
        process.stdout.write(f"got {len(data)}")
        process.exit(0)
        return
    if "sleep" in cmd:
        import asyncio
        await asyncio.sleep(5)
    process.stdout.write("hello")
    process.exit(0)


@pytest_asyncio.fixture
async def server(tmp_path):
    RECEIVED.clear()
    host = asyncssh.generate_private_key("ssh-ed25519")
    client = asyncssh.generate_private_key("ssh-ed25519")
    client_file = tmp_path / "client"
    client_file.write_bytes(client.export_private_key())
    srv = await asyncssh.create_server(
        Srv, "127.0.0.1", 0, server_host_keys=[host], process_factory=handle, encoding="utf-8",
        authorized_client_keys=asyncssh.import_authorized_keys(client.export_public_key().decode()))
    yield SimpleNamespace(port=srv.sockets[0].getsockname()[1], client_file=client_file, host=host, client=client)
    srv.close()
    await srv.wait_closed()


def settings(server, tmp_path, tofu=True):
    return Settings(ssh_key_file=str(server.client_file), ssh_known_hosts=str(tmp_path / "kh"),
                    ssh_tofu=tofu, ssh_connect_timeout=5)


def node(server, user="root"):
    return SimpleNamespace(ssh_host="127.0.0.1", ssh_port=server.port, ssh_user=user)


@pytest.mark.asyncio
async def test_rejects_unknown_host_in_strict_mode(server, tmp_path):
    with pytest.raises(asyncssh.HostKeyNotVerifiable):
        await open_executor(node(server), settings(server, tmp_path, tofu=False))


@pytest.mark.asyncio
async def test_run_stdin_failure_sudo_and_timeout(server, tmp_path, monkeypatch):
    ex = await open_executor(node(server), settings(server, tmp_path))
    try:
        assert ex.use_sudo is False
        res = await ex.run("say hi")
        assert (res.rc, res.out) == (0, "hello")
        assert (await ex.run("echo-stdin", stdin=b"abcd")).out == "got 4"
        big = tmp_path / "big"
        big.write_bytes(b"x" * 300_000)
        assert (await ex.run("echo-stdin", stdin_path=big)).out == "got 300000"
        with pytest.raises(ProvisionError, match=r"rc=3.*boom"):
            await ex.run("fail now")
        res = await ex.run("fail now", check=False)
        assert res.rc == 3 and res.err == "boom"
        with pytest.raises(TimeoutError):
            await ex.run("sleep", timeout=0.2)
        ex.use_sudo = True
        await ex.run("say hi")
        assert RECEIVED[-1] == "sudo -n sh -c 'say hi'"
    finally:
        await ex.close()


@pytest.mark.asyncio
async def test_non_root_uses_sudo_and_missing_key(server, tmp_path):
    ex = await open_executor(node(server, "tester"), settings(server, tmp_path))
    try:
        assert ex.use_sudo is True
    finally:
        await ex.close()
    with pytest.raises(ProvisionError, match="credentials"):
        await open_executor(node(server), Settings())


@pytest.mark.asyncio
async def test_executor_uses_encrypted_node_key(server, tmp_path):
    crypto = Crypto(Fernet.generate_key())
    target = node(server)
    target.ssh_private_key_enc = crypto.encrypt(server.client.export_private_key().decode())
    ex = await open_executor(target, settings(server, tmp_path), crypto)
    assert ex.crypto is crypto
    await ex.close()


@pytest.mark.asyncio
async def test_executor_uses_master_key_environment(server, tmp_path, monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("WGOCTOPUS_MASTER_KEY", key.decode())
    crypto = Crypto(key)
    target = node(server)
    target.ssh_private_key_enc = crypto.encrypt(server.client.export_private_key().decode())
    ex = await open_executor(target, settings(server, tmp_path))
    await ex.close()


def test_text_none_is_empty():
    assert _text(None) == ""


@pytest.mark.asyncio
async def test_executor_accepts_encrypted_bootstrap_password(server, tmp_path):
    crypto = Crypto(Fernet.generate_key())
    target = node(server)
    target.ssh_password_enc = crypto.encrypt("bootstrap-password")
    cfg = Settings(ssh_key_file=None, ssh_known_hosts=str(tmp_path / "kh"),
                   ssh_tofu=True, ssh_connect_timeout=5)
    ex = await open_executor(target, cfg, crypto)
    await ex.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_management_key_verification_checks_sudo(server, tmp_path, fail):
    global FAIL_SUDO
    FAIL_SUDO = fail
    crypto = Crypto(Fernet.generate_key())
    target = node(server)
    target.ssh_private_key_enc = crypto.encrypt(server.client.export_private_key().decode())
    cfg = Settings(ssh_known_hosts=str(tmp_path / "kh"), ssh_tofu=True, ssh_connect_timeout=5)
    executor = SshExecutor(None, crypto=crypto)
    try:
        if fail:
            with pytest.raises(ProvisionError, match="passwordless sudo"):
                await executor.verify_management(target, cfg)
        else:
            await executor.verify_management(target, cfg)
    finally:
        FAIL_SUDO = False
