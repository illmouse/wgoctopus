"""Provisioning steps against a stateful fake host (records commands and stdin)."""

import asyncssh
import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.config import Settings
from wgoctopus_orch.models import Node
from wgoctopus_orch.provision import ExecResult, ProvisionError, ProvisionRunner
from wgoctopus_orch.provision_steps import STEPS
from wgoctopus_orch.service import create_node

TOKEN = "tok-0123456789abcdef"


class FakeHost:
    def __init__(self, *, os_line="debian bookworm x86_64", uid="0", sudo=False):
        self.use_sudo = sudo
        self.os_line, self.uid = os_line, uid
        self.files, self.cmds, self.stdins = {}, [], []
        self.packages_missing = "curl openssh-client"
        self.docker_ok, self.image_ok, self.container = False, False, None
        self.health = True
        self.sudo_ok = True

    async def close(self):
        pass

    async def run(self, cmd, *, stdin=None, stdin_path=None, timeout=120, check=True):
        self.cmds.append(cmd)
        if stdin_path is not None:
            stdin = stdin_path.read_bytes()
        if stdin is not None:
            self.stdins.append(stdin)
        rc, out = 0, ""
        if "/etc/os-release" in cmd:
            out = self.os_line
        elif cmd == "id -u":
            out = self.uid
        elif cmd == "true":
            rc = 0 if self.sudo_ok else 1
        elif cmd.startswith("for p in"):
            out = self.packages_missing
        elif "apt-get install" in cmd and "docker-ce" in cmd:
            self.docker_ok = True
        elif "apt-get install" in cmd:
            self.packages_missing = ""
        elif cmd.startswith("cat /etc/sysctl.d"):
            out = self.files.get("sysctl", "")
        elif cmd == "cat /proc/sys/net/ipv4/ip_forward":
            out = "1" if "sysctl" in self.files and not self.packages_missing else "0"
        elif cmd.startswith("tee /etc/sysctl.d"):
            self.files["sysctl"] = stdin.decode()
        elif cmd.startswith("docker version"):
            rc = 0 if self.docker_ok else 1
        elif cmd.startswith("tee /etc/apt/sources.list.d/docker.sources"):
            self.files["docker.sources"] = stdin.decode()
        elif cmd.startswith("cat /etc/wgoctopus/token"):
            out = self.files.get("token", "")
        elif "token.new" in cmd:
            self.files["token"] = stdin.decode()
        elif cmd.startswith("cat /etc/wgoctopus/nodekey.pub"):
            out = "ssh-ed25519 AAAAnodekey wgoctopus-x\n"
        elif "ssh-keygen" in cmd:
            self.files["nodekey"] = "x"
        elif cmd.startswith("docker image inspect"):
            rc = 0 if self.image_ok else 1
        elif cmd == "docker load" or cmd.startswith("docker pull"):
            self.image_ok = True
        elif cmd.startswith("docker inspect"):
            out = f"true {self.container}" if self.container else ""
            rc = 0 if self.container else 1
        elif cmd.startswith("docker rm -f"):
            self.container = None
        elif cmd.startswith("docker run"):
            self.container = cmd.split("wgoctopus.spec=")[1].split()[0]
        elif cmd.startswith("curl -fsS"):
            rc = 0 if self.health else 22
        elif cmd.startswith("tee /home/"):
            self.files["authorized_keys"] = stdin.decode()
        if check and rc:
            raise ProvisionError(f"command failed (rc={rc})")
        return ExecResult(rc, out, "")


def factory_for(session):
    return sessionmaker(bind=session.get_bind(), expire_on_commit=False)


def make_runner(session, crypto, host, settings=None):
    async def opener(node, st):
        return host
    return ProvisionRunner(factory_for(session), crypto, settings or Settings(), opener, STEPS)


async def run(runner, node_id, **opts):
    opts.setdefault("health_interval", 0)
    job = runner.create_job(node_id, opts)
    await runner.run_job(job)
    return runner.job_view(job)


def states(view):
    return [s["state"] for s in view["steps"]]


@pytest.mark.asyncio
async def test_full_run_then_idempotent_rerun(session, crypto):
    node = create_node(session, "n1", "127.0.0.1", "root", agent_token=TOKEN, crypto=crypto)
    host = FakeHost()
    runner = make_runner(session, crypto, host)
    view = await run(runner, node.id)
    assert view["state"] == "succeeded", view
    assert states(view) == ["ok", "ok", "ok", "skipped", "ok", "skipped", "ok", "ok", "ok"]
    assert host.files["token"] == TOKEN + "\n" and host.files["sysctl"].startswith("net.ipv4.ip_forward")
    assert "download.docker.com/linux/debian" in host.files["docker.sources"]
    # the token never appears in a command line or a persisted log
    assert not any(TOKEN in c for c in host.cmds)
    assert TOKEN not in str(view)
    run_cmd = next(c for c in host.cmds if c.startswith("docker run"))
    assert "--network host" in run_cmd and "--cap-add NET_ADMIN" in run_cmd and "--hop-enabled" not in run_cmd
    again = await run(runner, node.id)
    assert again["state"] == "succeeded"
    assert states(again) == ["ok", "skipped", "skipped", "skipped", "skipped", "skipped", "skipped", "skipped", "ok"]


@pytest.mark.asyncio
@pytest.mark.parametrize("host_kwargs,msg", [
    ({"os_line": "centos stream x86_64"}, "unsupported OS"),
    ({"os_line": "debian bookworm armv7l"}, "unsupported architecture"),
    ({"uid": "1000"}, "root or use a sudo"),
    ({"sudo": True},  "sudo is required"),
])
async def test_detect_rejects(session, crypto, host_kwargs, msg):
    node = create_node(session, "n2", "127.0.0.1", "root", crypto=crypto)
    host = FakeHost(**host_kwargs)
    if host_kwargs.get("sudo"):
        host.sudo_ok = False
    view = await run(make_runner(session, crypto, host), node.id)
    assert view["state"] == "failed" and msg in view["error"]
    assert states(view)[1] == "pending"


@pytest.mark.asyncio
async def test_hop_flag_and_ubuntu_repo(session, crypto):
    node = create_node(session, "hop1", "127.0.0.1", "root", crypto=crypto, kind="hop",
                       wan_interface="eth0", hop_ip="203.0.113.5")
    host = FakeHost(os_line="ubuntu noble aarch64")
    view = await run(make_runner(session, crypto, host), node.id)
    assert view["state"] == "succeeded", view
    assert "linux/ubuntu" in host.files["docker.sources"] and "Architectures: arm64" in host.files["docker.sources"]
    assert "--hop-enabled" in next(c for c in host.cmds if c.startswith("docker run"))


@pytest.mark.asyncio
async def test_mgmt_user_and_pull_mode_persist_on_node(session, crypto, tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    key_file = tmp_path / "id"
    key_file.write_bytes(key.export_private_key())
    node = create_node(session, "pull1", "127.0.0.1", "root", crypto=crypto, mgmt_mode="pull")
    host = FakeHost()
    runner = make_runner(session, crypto, host, Settings(ssh_key_file=str(key_file)))
    view = await run(runner, node.id, mgmt_user="wgoctopus", pull_server="198.51.100.9:2222",
                     pull_host_key="SHA256:" + "A" * 43)
    assert view["state"] == "succeeded", view
    line = host.files["authorized_keys"]
    assert line.startswith('restrict,port-forwarding,permitopen="127.0.0.1:18080" ssh-ed25519 ')
    run_cmd = next(c for c in host.cmds if c.startswith("docker run"))
    assert "--pull-server 198.51.100.9:2222" in run_cmd and "--pull-user pull1" in run_cmd
    session.expire_all()
    row = session.scalar(select(Node).where(Node.name == "pull1"))
    assert row.ssh_user == "wgoctopus" and row.pull_public_key == "ssh-ed25519 AAAAnodekey"
    assert row.provision_options["login_user"] == "root"

    # Re-provisioning must log in as the original user, not the restricted management user.
    seen = []

    async def opener(node, st):
        seen.append(node.ssh_user)
        return host

    again = ProvisionRunner(factory_for(session), crypto, Settings(ssh_key_file=str(key_file)), opener, STEPS)
    opts = {"health_interval": 0, "mgmt_user": "wgoctopus", "pull_server": "198.51.100.9:2222",
            "pull_host_key": "SHA256:" + "A" * 43, "login_user": "root"}
    job = again.create_job(node.id, opts)
    await again.run_job(job)
    assert again.job_view(job)["state"] == "succeeded" and seen == ["root"]


@pytest.mark.asyncio
async def test_pull_requires_server_and_host_key_and_bad_mgmt_user(session, crypto, tmp_path):
    node = create_node(session, "pull2", "127.0.0.1", "root", crypto=crypto, mgmt_mode="pull")
    view = await run(make_runner(session, crypto, FakeHost()), node.id)
    assert view["state"] == "failed" and "pull_server" in view["error"]
    view = await run(make_runner(session, crypto, FakeHost()), node.id, pull_server="x:1")
    assert view["state"] == "failed" and "pull_host_key" in view["error"]
    view = await run(make_runner(session, crypto, FakeHost()), node.id, mgmt_user="bad name;rm")
    assert view["state"] == "failed" and "invalid mgmt_user" in view["error"]
    ok = create_node(session, "pull3", "127.0.0.1", "root", crypto=crypto)
    view = await run(make_runner(session, crypto, FakeHost()), ok.id, mgmt_user="wgoctopus")
    assert view["state"] == "failed" and "key file" in view["error"]


@pytest.mark.asyncio
async def test_image_archive_upload_and_missing_archive(session, crypto, tmp_path):
    node = create_node(session, "img1", "127.0.0.1", "root", crypto=crypto)
    archive = tmp_path / "agent.tar"
    archive.write_bytes(b"tar-bytes")
    host = FakeHost()
    view = await run(make_runner(session, crypto, host), node.id, image_archive=str(archive), image="agent:test")
    assert view["state"] == "succeeded" and b"tar-bytes" in host.stdins
    assert "docker load" in host.cmds and any("agent:test" in c for c in host.cmds if c.startswith("docker run"))
    view = await run(make_runner(session, crypto, FakeHost()), node.id, image_archive=str(tmp_path / "nope"))
    assert view["state"] == "failed" and "archive not found" in view["error"]
    host2 = FakeHost()
    host2.image_ok = True
    view = await run(make_runner(session, crypto, host2), node.id, force_image=True)
    assert "docker pull ghcr.io/illmouse/wgoctopus-agent:latest" in host2.cmds


@pytest.mark.asyncio
async def test_container_recreated_when_spec_changes_and_unhealthy_fails(session, crypto):
    node = create_node(session, "spec1", "127.0.0.1", "root", crypto=crypto)
    host = FakeHost()
    runner = make_runner(session, crypto, host)
    await run(runner, node.id)
    old = host.container
    view = await run(runner, node.id, image="other:tag")
    assert view["state"] == "succeeded" and host.container != old
    assert any(c.startswith("docker rm -f") for c in host.cmds)
    host.health = False
    view = await run(runner, node.id, health_attempts=2)
    assert view["state"] == "failed" and "healthy" in view["error"]
