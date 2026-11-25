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
    if ctx.extra["distro"] not in {"debian", "ubuntu"}:
        ctx.log(f"package setup skipped on unsupported distribution: {ctx.extra['distro']}")
        return "skipped"
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
    if ctx.extra["distro"] not in {"debian", "ubuntu"}:
        raise ProvisionError("Docker must be installed before provisioning on this distribution")
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
    name = ctx.options.get("mgmt_user", "wgoctopus")
    if not name.replace("-", "").replace("_", "").isalnum() or len(name) > 32:
        raise ProvisionError("invalid mgmt_user")
    private_key = (ctx.node.ssh_private_key_enc and
                   ctx.extra.get("ssh_private_key"))
    if not private_key:
        key = asyncssh.generate_private_key("ssh-ed25519")
        private_key = key.export_private_key().decode()
        pub = key.export_public_key().decode().strip()
        if ctx.save_ssh_key:
            ctx.save_ssh_key(private_key, pub)
        ctx.extra["ssh_private_key"] = private_key
        ctx.secrets.append(private_key)
        ctx.node.ssh_public_key = pub
    else:
        pub = getattr(ctx.node, "ssh_public_key", None)
        if not pub:
            raise ProvisionError("stored management SSH key has no public key")
    await _install_user(ctx, name, pub + "\n")
    verifier = getattr(ctx.executor, "verify_management", None)
    if verifier:
        original_user = ctx.node.ssh_user
        ctx.node.ssh_user = name
        try:
            await verifier(ctx.node, ctx.settings)
        finally:
            ctx.node.ssh_user = original_user
    ctx.extra["new_ssh_user"] = name
    # Keep bootstrap access until the per-node key has been proven usable.
    if ctx.settings.ssh_key_file:
        bootstrap_key = asyncssh.import_private_key(
            Path(ctx.settings.ssh_key_file).read_bytes(),
            passphrase=(Path(ctx.settings.ssh_key_passphrase_file).read_text().strip()
                        if ctx.settings.ssh_key_passphrase_file else None),
        )
        keypart = bootstrap_key.export_public_key().decode().split()[1]
        user = shlex.quote(ctx.node.ssh_user)
        key = shlex.quote(keypart)
        await ctx.executor.run(sh(
            "home=$(getent passwd " + user + " | cut -d: -f6); "
            "[ -n \"$home\" ] && [ -f \"$home/.ssh/authorized_keys\" ] || exit 0; "
            "tmp=$(mktemp); "
            "awk -v key=" + key + " '{for (i=1;i<=NF;i++) if ($i==key) next; print}' "
            "\"$home/.ssh/authorized_keys\" > \"$tmp\"; "
            "cat \"$tmp\" > \"$home/.ssh/authorized_keys\"; rm -f \"$tmp\""
        ))
    ctx.log(f"management user {name} ready")


async def harden(ctx):
    """Apply idempotent baseline SSH, brute-force, firewall and PAM safeguards."""
    if ctx.options.get("harden", True) is False:
        ctx.log("security hardening disabled")
        return "skipped"
    if ctx.extra.get("distro") not in {"debian", "ubuntu"}:
        ctx.log("security hardening skipped: unsupported distribution")
        return "skipped"
    ex = ctx.executor
    ssh_port = int(ctx.node.ssh_port)
    user = ctx.options.get("mgmt_user", "wgoctopus")
    config = (
        f"AllowUsers {user}\n"
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PubkeyAuthentication yes\n"
        "X11Forwarding no\n"
        "MaxAuthTries 3\n"
        "LoginGraceTime 30\n"
    )
    await ex.run("install -d -m 0755 /etc/ssh/sshd_config.d")
    await ex.run("cp -p /etc/ssh/sshd_config /tmp/wgoctopus-sshd_config.bak")
    await ex.run("cp -p /etc/ssh/sshd_config.d/99-wgoctopus-hardening.conf /tmp/wgoctopus-sshd.conf.bak 2>/dev/null || true")
    await ex.run("tee /etc/ssh/sshd_config.d/99-wgoctopus-hardening.conf >/dev/null", stdin=config.encode())
    if (await ex.run("grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\\*\\.conf' /etc/ssh/sshd_config",
                     check=False)).rc:
        await ex.run("printf '\\nInclude /etc/ssh/sshd_config.d/*.conf\\n' >> /etc/ssh/sshd_config")
    if (await ex.run("sshd -t", check=False)).rc:
        await ex.run("cp -p /tmp/wgoctopus-sshd_config.bak /etc/ssh/sshd_config; if [ -f /tmp/wgoctopus-sshd.conf.bak ]; then cp -p /tmp/wgoctopus-sshd.conf.bak /etc/ssh/sshd_config.d/99-wgoctopus-hardening.conf; else rm -f /etc/ssh/sshd_config.d/99-wgoctopus-hardening.conf; fi; rm -f /tmp/wgoctopus-sshd_config.bak /tmp/wgoctopus-sshd.conf.bak")
        raise ProvisionError("sshd configuration validation failed")
    await ex.run("rm -f /tmp/wgoctopus-sshd_config.bak /tmp/wgoctopus-sshd.conf.bak; systemctl reload ssh 2>/dev/null || systemctl reload sshd")
    await ex.run("DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban iptables-persistent libpam-pwquality")
    jail = "[sshd]\nenabled = true\nmaxretry = 5\nbantime = 1h\nfindtime = 10m\nbackend = systemd\n"
    await ex.run("install -d -m 0755 /etc/fail2ban/jail.d")
    await ex.run("tee /etc/fail2ban/jail.d/wgoctopus.conf >/dev/null", stdin=jail.encode())
    await ex.run("systemctl enable --now fail2ban")
    firewall = (
        "#!/bin/sh\n"
        "iptables -N WGOCTOPUS-INPUT 2>/dev/null || true\n"
        "iptables -F WGOCTOPUS-INPUT\n"
        f"iptables -A WGOCTOPUS-INPUT -p tcp --dport {ssh_port} -m conntrack --ctstate NEW "
        "-m hashlimit --hashlimit-above 6/minute --hashlimit-burst 10 "
        "--hashlimit-mode srcip --hashlimit-name wgoctopus_ssh -j DROP\n"
        f"iptables -A WGOCTOPUS-INPUT -p tcp --dport {ctx.node.agent_port} ! -i lo -j DROP\n"
        "iptables -A WGOCTOPUS-INPUT -j RETURN\n"
        "iptables -C INPUT -j WGOCTOPUS-INPUT 2>/dev/null || iptables -I INPUT 1 -j WGOCTOPUS-INPUT\n"
    )
    await ex.run("install -d -m 0755 /usr/local/sbin")
    await ex.run("tee /usr/local/sbin/wgoctopus-iptables >/dev/null", stdin=firewall.encode())
    await ex.run("chmod 0755 /usr/local/sbin/wgoctopus-iptables; /usr/local/sbin/wgoctopus-iptables")
    await ex.run("tee /etc/systemd/system/wgoctopus-iptables.service >/dev/null", stdin=(
        b"[Unit]\nDescription=WGoctopus input firewall rules\nAfter=network-pre.target\n"
        b"Before=network.target\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/wgoctopus-iptables\n"
        b"RemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n"))
    await ex.run("systemctl daemon-reload; systemctl enable wgoctopus-iptables")
    await ex.run("tee /etc/security/faillock.conf >/dev/null",
                 stdin=b"deny = 5\nunlock_time = 900\nfail_interval = 900\n")
    await ex.run("tee /etc/security/pwquality.conf >/dev/null", stdin=b"minlen = 14\n")
    await ex.run("grep -q 'pam_wheel.so.*group=sudo' /etc/pam.d/su || "
                 "printf '\\nauth required pam_wheel.so use_uid group=sudo\\n' >> /etc/pam.d/su")
    verifier = getattr(ex, "verify_management", None)
    if verifier:
        original_user = ctx.node.ssh_user
        ctx.node.ssh_user = ctx.extra.get("new_ssh_user", user)
        try:
            await verifier(ctx.node, ctx.settings)
        finally:
            ctx.node.ssh_user = original_user
    ctx.log("SSH, fail2ban, persistent firewall and PAM safeguards configured")


async def _install_user(ctx, name, line):
    ex = ctx.executor
    q = shlex.quote(name)
    await ex.run(sh(f"id {q} >/dev/null 2>&1 || useradd -m -s /bin/bash {q}; usermod -s /bin/bash {q}; "
                    f"install -d -m 0700 -o {q} -g {q} /home/{q}/.ssh"))
    await ex.run(f"tee /home/{q}/.ssh/authorized_keys >/dev/null", stdin=line.encode())
    await ex.run(f"chown {q}:{q} /home/{q}/.ssh/authorized_keys; chmod 0600 /home/{q}/.ssh/authorized_keys")
    await ex.run(f"printf '%s\\n' '{name} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{q}; chmod 0440 /etc/sudoers.d/{q}; visudo -cf /etc/sudoers.d/{q}")


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
         Step("management user", mgmt_user), Step("host security", harden),
         Step("agent token", token), Step("node key", pull_key),
         Step("agent image", image), Step("agent container", run_agent), Step("health check", wait_healthy)]
