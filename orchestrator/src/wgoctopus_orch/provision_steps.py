"""Idempotent host provisioning steps executed over SSH (Debian/Ubuntu)."""
import asyncio
import hashlib
import shlex
from pathlib import Path

import asyncssh

from .provision import ProvisionError, Step

AGENT_DIR = "/etc/wgoctopus"
CONTAINER = "wgoctopus-agent"
STATE_VOLUME = "wgoctopus-agent-state"
BASE_PACKAGES = "ca-certificates curl gnupg iproute2 iptables openssh-client"


def sh(script):
    """Wrap a multi-line script so it runs under POSIX sh with errexit."""
    return f"sh -ec {shlex.quote(script)}"


async def detect(ctx):
    ex = ctx.executor
    res = await ex.run(". /etc/os-release; echo \"$ID $VERSION_CODENAME $(uname -m)\"")
    distro, codename, arch = (res.out.split() + ["", "", ""])[:3]
    if distro not in {"debian", "ubuntu"}:
        raise ProvisionError(f"unsupported OS: {distro or 'unknown'} (Debian/Ubuntu only)")
    if arch not in {"x86_64", "aarch64"}:
        raise ProvisionError(f"unsupported architecture: {arch}")
    if not ex.use_sudo:
        who = (await ex.run("id -u")).out.strip()
        if who != "0":
            raise ProvisionError("connect as root or use a sudo-capable user")
    else:
        if (await ex.run("true", check=False)).rc:
            raise ProvisionError("passwordless sudo is required")
    ctx.extra.update(distro=distro, codename=codename, arch=arch)
    ctx.log(f"{distro} {codename} {arch}")


async def packages(ctx):
    ex = ctx.executor
    missing = (await ex.run(
        f"for p in {BASE_PACKAGES}; do dpkg -s $p >/dev/null 2>&1 || echo $p; done")).out.split()
    if missing:
        ctx.log("installing: " + " ".join(missing))
        await ex.run(sh("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; "
                        f"apt-get install -y -qq {' '.join(missing)}"), timeout=600)
    conf = "net.ipv4.ip_forward = 1\n"
    cur = (await ex.run("cat /etc/sysctl.d/99-wgoctopus.conf 2>/dev/null", check=False)).out
    fwd = (await ex.run("cat /proc/sys/net/ipv4/ip_forward")).out.strip()
    if cur == conf and fwd == "1" and not missing:
        return "skipped"
    await ex.run("tee /etc/sysctl.d/99-wgoctopus.conf >/dev/null", stdin=conf.encode())
    await ex.run("sysctl -q -w net.ipv4.ip_forward=1")
    ctx.log("ip_forward enabled")


async def docker(ctx):
    ex = ctx.executor
    if (await ex.run("docker version --format '{{.Server.Version}}'", check=False)).rc == 0:
        ctx.log("docker already installed")
        return "skipped"
    distro, codename = ctx.extra["distro"], ctx.extra["codename"]
    arch = "amd64" if ctx.extra["arch"] == "x86_64" else "arm64"
    repo = (f"Types: deb\nURIs: https://download.docker.com/linux/{distro}\nSuites: {codename}\n"
            f"Components: stable\nArchitectures: {arch}\nSigned-By: /etc/apt/keyrings/docker.asc\n")
    await ex.run(sh(f"install -m 0755 -d /etc/apt/keyrings; curl -fsSL -o /etc/apt/keyrings/docker.asc "
                    f"https://download.docker.com/linux/{distro}/gpg; chmod 0644 /etc/apt/keyrings/docker.asc"),
                 timeout=120)
    await ex.run("tee /etc/apt/sources.list.d/docker.sources >/dev/null", stdin=repo.encode())
    await ex.run(sh("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; "
                    "apt-get install -y -qq docker-ce docker-ce-cli containerd.io; "
                    "systemctl enable --now docker"), timeout=900)
    ctx.log("docker installed")


async def mgmt_user(ctx):
    name = ctx.options.get("mgmt_user")
    if not name:
        return "skipped"
    if not name.replace("-", "").replace("_", "").isalnum() or len(name) > 32:
        raise ProvisionError("invalid mgmt_user")
    key_file = ctx.settings.ssh_key_file
    if not key_file:
        raise ProvisionError("SSH key file is required")
    pub = asyncssh.read_private_key(key_file, ctx.settings.ssh_key_passphrase_file and
                                    Path(ctx.settings.ssh_key_passphrase_file).read_text().strip()
                                    ).export_public_key().decode().strip()
    port = ctx.node.agent_port
    line = f'restrict,port-forwarding,permitopen="127.0.0.1:{port}" {pub}\n'
    await _install_user(ctx, name, line)
    ctx.extra["new_ssh_user"] = name
    ctx.log(f"management user {name} ready")


async def _install_user(ctx, name, line):
    ex = ctx.executor
    q = shlex.quote(name)
    await ex.run(sh(f"id {q} >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin {q}; "
                    f"install -d -m 0700 -o {q} -g {q} /home/{q}/.ssh"))
    await ex.run(f"tee /home/{q}/.ssh/authorized_keys >/dev/null", stdin=line.encode())
    await ex.run(f"chown {q}:{q} /home/{q}/.ssh/authorized_keys; chmod 0600 /home/{q}/.ssh/authorized_keys")


async def token(ctx):
    ex = ctx.executor
    await ex.run(f"install -d -m 0700 {AGENT_DIR}")
    want = ctx.token + "\n"
    cur = (await ex.run(f"cat {AGENT_DIR}/token 2>/dev/null", check=False)).out
    if cur == want:
        return "skipped"
    await ex.run(sh(f"umask 077; cat > {AGENT_DIR}/token.new; mv {AGENT_DIR}/token.new {AGENT_DIR}/token"),
                 stdin=want.encode())
    ctx.log("agent token installed")


async def pull_key(ctx):
    if ctx.node.mgmt_mode not in {"pull", "auto"}:
        return "skipped"
    ex = ctx.executor
    await ex.run(sh(f"test -f {AGENT_DIR}/nodekey || ssh-keygen -q -t ed25519 -N '' -C wgoctopus-{ctx.node.name} "
                    f"-f {AGENT_DIR}/nodekey; chmod 0600 {AGENT_DIR}/nodekey"))
    pub = (await ex.run(f"cat {AGENT_DIR}/nodekey.pub")).out.strip()
    ctx.extra["pull_public_key"] = " ".join(pub.split()[:2])
    ctx.log("node key ready")


async def image(ctx):
    ex = ctx.executor
    ref = ctx.options.get("image") or ctx.settings.agent_image
    ctx.extra["image"] = ref
    present = (await ex.run(f"docker image inspect {shlex.quote(ref)} >/dev/null 2>&1", check=False)).rc == 0
    archive = ctx.options.get("image_archive")
    if present and not ctx.options.get("force_image"):
        return "skipped"
    if archive:
        if not Path(archive).is_file():
            raise ProvisionError("image archive not found on the orchestrator")
        await ex.run("docker load", stdin_path=Path(archive), timeout=1800)
        ctx.log("image uploaded")
    else:
        await ex.run(f"docker pull {shlex.quote(ref)}", timeout=900)
        ctx.log("image pulled")


def agent_command(ctx):
    cmd = ["--listen", f"127.0.0.1:{ctx.node.agent_port}", "--token-file", "/run/token"]
    if ctx.node.kind == "hop":
        cmd.append("--hop-enabled")
    mounts = [f"{STATE_VOLUME}:/var/lib/wgoctopus", f"{AGENT_DIR}/token:/run/token:ro"]
    if ctx.node.mgmt_mode in {"pull", "auto"} and ctx.options.get("pull_server"):
        host_key = ctx.options.get("pull_host_key")
        if not host_key:
            raise ProvisionError("pull_host_key is required with pull_server")
        cmd += ["--pull-server", ctx.options["pull_server"], "--pull-user", ctx.node.name,
                "--pull-key-file", "/run/nodekey", "--pull-host-key", host_key]
        mounts.append(f"{AGENT_DIR}/nodekey:/run/nodekey:ro")
    elif ctx.node.mgmt_mode == "pull":
        raise ProvisionError("mgmt_mode pull requires the pull_server and pull_host_key options")
    return cmd, mounts


async def run_agent(ctx):
    ex = ctx.executor
    ref = ctx.extra["image"]
    cmd, mounts = agent_command(ctx)
    spec = hashlib.sha256(repr((ref, cmd, mounts, hashlib.sha256(ctx.token.encode()).hexdigest())).encode()).hexdigest()
    cur = (await ex.run(f"docker inspect -f '{{{{.State.Running}}}} {{{{index .Config.Labels \"wgoctopus.spec\"}}}}' "
                        f"{CONTAINER} 2>/dev/null", check=False)).out.split()
    if cur == ["true", spec]:
        return "skipped"
    args = ["docker", "run", "-d", "--name", CONTAINER, "--restart", "unless-stopped", "--network", "host",
            "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--label", f"wgoctopus.spec={spec}"]
    for m in mounts:
        args += ["-v", m]
    args += [ref, *cmd]
    await ex.run(f"docker rm -f {CONTAINER} >/dev/null 2>&1 || true")
    await ex.run(" ".join(shlex.quote(a) for a in args))
    ctx.log("agent container started")


async def wait_healthy(ctx):
    ex = ctx.executor
    url = f"http://127.0.0.1:{ctx.node.agent_port}/healthz"
    for _ in range(int(ctx.options.get("health_attempts", 30))):
        if (await ex.run(f"curl -fsS -m 3 {url}", check=False)).rc == 0:
            ctx.log("agent healthy")
            return
        await asyncio.sleep(ctx.options.get("health_interval", 1))
    raise ProvisionError("agent did not become healthy")


STEPS = [Step("detect", detect), Step("packages", packages), Step("docker", docker),
         Step("management user", mgmt_user), Step("agent token", token), Step("node key", pull_key),
         Step("agent image", image), Step("agent container", run_agent), Step("health check", wait_healthy)]
