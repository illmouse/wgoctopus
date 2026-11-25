"""Persisted, restart-safe host provisioning jobs."""
import asyncio
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import asyncssh
from sqlalchemy import select

from .models import Event, Node, ProvisionJob, ProvisionStep, now_utc
from .transport import host_key_client


class ProvisionError(Exception):
    """Safe-to-persist provisioning failure."""


@dataclass
class ExecResult:
    rc: int
    out: str
    err: str


class Executor(Protocol):
    use_sudo: bool
    async def run(self, cmd: str, *, stdin: bytes | None = None, stdin_path: Path | None = None,
                  timeout: float = 120, check: bool = True) -> ExecResult: ...
    async def close(self): ...


def _text(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data or ""


class SshExecutor:
    def __init__(self, conn, use_sudo=False, crypto=None):
        self.conn, self.use_sudo = conn, use_sudo
        self.crypto = crypto

    async def run(self, cmd, *, stdin=None, stdin_path=None, timeout=120, check=True):
        safe_cmd = f"sudo -n sh -c {shlex.quote(cmd)}" if self.use_sudo else cmd
        process = await self.conn.create_process(safe_cmd, encoding=None)
        try:
            if stdin is not None:
                process.stdin.write(stdin)
                process.stdin.write_eof()
            elif stdin_path is not None:
                with Path(stdin_path).open("rb") as source:  # noqa: ASYNC230
                    while chunk := await asyncio.to_thread(source.read, 65536):
                        process.stdin.write(chunk)
                        await process.stdin.drain()
                process.stdin.write_eof()
            result = await asyncio.wait_for(process.wait(), timeout)
        except BaseException:
            process.close()
            raise
        out, err = (_text(result.stdout), _text(result.stderr))
        rc = result.exit_status if result.exit_status is not None else 255
        if check and rc:
            raise ProvisionError(f"command failed (rc={rc}): {err[-500:]}")
        return ExecResult(rc, out, err)

    async def close(self):
        self.conn.close()
        await self.conn.wait_closed()

    async def verify_management(self, node, settings):
        key = asyncssh.import_private_key(self.crypto.decrypt(node.ssh_private_key_enc))
        conn = await asyncssh.connect(node.ssh_host, port=node.ssh_port,
            username=node.ssh_user, client_keys=[key], known_hosts=(),
            client_factory=host_key_client(node, settings),
            connect_timeout=settings.ssh_connect_timeout)
        try:
            result = await conn.run("sudo -n true", check=False)
            if result.exit_status:
                raise ProvisionError("management SSH key lacks passwordless sudo")
        finally:
            conn.close()
            await conn.wait_closed()


async def open_executor(node, settings, crypto=None):
    passphrase = Path(settings.ssh_key_passphrase_file).read_text().strip() if settings.ssh_key_passphrase_file else None
    node_key = getattr(node, "ssh_private_key_enc", None)
    password_enc = getattr(node, "ssh_password_enc", None)
    if node_key or password_enc:
        if crypto is None:
            from .crypto import Crypto
            crypto = Crypto()
    client_keys = [asyncssh.import_private_key(crypto.decrypt(node_key))] if node_key else settings.ssh_key_file
    if not client_keys and not getattr(node, "ssh_password_enc", None):
        raise ProvisionError("node SSH credentials are required")
    conn = await asyncssh.connect(node.ssh_host, port=node.ssh_port, username=node.ssh_user,
        client_keys=client_keys, password=(crypto.decrypt(password_enc) if password_enc else None),
        passphrase=passphrase, known_hosts=(),
        client_factory=host_key_client(node, settings), connect_timeout=settings.ssh_connect_timeout)
    return SshExecutor(conn, node.ssh_user != "root", crypto)


@dataclass
class StepContext:
    node: object
    settings: object
    executor: Executor
    options: dict
    token: str = field(repr=False, default="")
    secrets: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    _lines: list[str] = field(default_factory=list, repr=False)
    save_ssh_key: object | None = field(default=None, repr=False)

    def log(self, msg):
        self._lines.append(redact(str(msg), self.secrets))


@dataclass
class Step:
    name: str
    fn: object


def redact(text, secrets):
    for secret in secrets:
        if secret and len(secret) >= 6:
            text = text.replace(secret, "***")
    return text


OPTION_TYPES = {"mgmt_user": str, "image": str, "image_archive": str, "force_image": bool, "pull_server": str,
                "pull_host_key": str, "health_attempts": int, "health_interval": (int, float), "auto": bool,
                "login_user": str, "harden": bool}


def validate_options(options):
    """Reject unknown option names and wrong types; returns a plain dict."""
    if options is None:
        return {}
    if not isinstance(options, dict):
        raise ProvisionError("options must be an object")
    for key, value in options.items():
        types = OPTION_TYPES.get(key)
        if types is None:
            raise ProvisionError(f"unknown option: {key}")
        if not isinstance(value, types) or (types is int and isinstance(value, bool)):
            raise ProvisionError(f"invalid option type: {key}")
    return dict(options)


class ProvisionRunner:
    def __init__(self, session_factory, crypto, settings, executor_factory=open_executor, steps=None):
        self.session_factory, self.crypto, self.settings = session_factory, crypto, settings
        if steps is None:
            from .provision_steps import STEPS
            steps = STEPS
        self.executor_factory, self.steps = executor_factory, list(steps)
        self.is_protected = lambda node: bool(getattr(node, "protected", False))
        self._tasks = {}

    def create_job(self, node_id, options=None, confirm_protected=False):
        with self.session_factory.begin() as s:
            node = s.get(Node, node_id)
            if node is None:
                raise ProvisionError("node not found")
            if self.is_protected(node) and not confirm_protected:
                raise ProvisionError("confirmation required")
            active = s.scalar(select(ProvisionJob).where(ProvisionJob.node_id == node_id,
                ProvisionJob.state.in_(("queued", "running"))).limit(1))
            if active:
                raise ProvisionError("provisioning already in progress")
            job = ProvisionJob(node_id=node_id, state="queued", options=options or {})
            s.add(job)
            s.flush()
            s.add_all(ProvisionStep(job_id=job.id, seq=i, name=step.name, state="pending") for i, step in enumerate(self.steps))
            job_id = job.id
        return job_id

    async def run_job(self, job_id):
        executor, token = None, ""
        with self.session_factory.begin() as s:
            job = s.get(ProvisionJob, job_id)
            if not job or job.state != "queued":
                return
            node = s.get(Node, job.node_id)
            snapshot = {k: getattr(node, k) for k in ("id", "name", "kind", "ssh_host", "ssh_port", "ssh_user", "mgmt_mode", "agent_port", "agent_token_enc", "ssh_private_key_enc", "ssh_public_key", "ssh_password_enc")}
            job.state, job.started_at = "running", now_utc()
            options = dict(job.options or {})
            node_po = dict(node.provision_options or {})
            login = None if node.ssh_private_key_enc else (options.get("login_user") or node_po.get("login_user"))
            if login:
                snapshot["ssh_user"] = login
        subject = snapshot["name"]
        self._event("provision.started", subject, {"job_id": job_id})
        try:
            snapshot["agent_token_enc"] = None
            from types import SimpleNamespace
            node_obj = SimpleNamespace(**snapshot)
            with self.session_factory() as s:
                token = self.crypto.decrypt(s.get(Node, snapshot["id"]).agent_token_enc)
            executor = (self.executor_factory(node_obj, self.settings, self.crypto)
                        if self.executor_factory is open_executor
                        else self.executor_factory(node_obj, self.settings))
            if asyncio.iscoroutine(executor) or isinstance(executor, asyncio.Future):
                executor = await executor
            def save_ssh_key(private_key, public_key):
                encrypted = self.crypto.encrypt(private_key)
                with self.session_factory.begin() as s:
                    row = s.get(Node, snapshot["id"])
                    row.ssh_private_key_enc = encrypted
                    row.ssh_public_key = public_key
                node_obj.ssh_private_key_enc = encrypted
                node_obj.ssh_public_key = public_key
            extra = {}
            if snapshot.get("ssh_private_key_enc"):
                extra["ssh_private_key"] = self.crypto.decrypt(snapshot["ssh_private_key_enc"])
            if snapshot.get("ssh_password_enc"):
                extra["ssh_password"] = self.crypto.decrypt(snapshot["ssh_password_enc"])
            ctx = StepContext(node_obj, self.settings, executor, options, token,
                              [token, extra.get("ssh_private_key", ""), extra.get("ssh_password", "")], extra,
                              save_ssh_key=save_ssh_key)
            for seq, step in enumerate(self.steps):
                with self.session_factory.begin() as s:
                    row = s.scalar(select(ProvisionStep).where(ProvisionStep.job_id == job_id, ProvisionStep.seq == seq))
                    row.state, row.started_at, row.log = "running", now_utc(), ""
                try:
                    outcome = await step.fn(ctx)
                    state = "skipped" if outcome == "skipped" else "ok"
                except asyncio.CancelledError:
                    ctx.log("cancelled")
                    with self.session_factory.begin() as s:
                        row = s.scalar(select(ProvisionStep).where(ProvisionStep.job_id == job_id, ProvisionStep.seq == seq))
                        row.state, row.log, row.finished_at = "failed", "\n".join(ctx._lines), now_utc()
                    raise
                except Exception as exc:  # noqa: BLE001
                    msg = redact(str(exc)[:500], ctx.secrets)
                    ctx.log(msg)
                    with self.session_factory.begin() as s:
                        row = s.scalar(select(ProvisionStep).where(ProvisionStep.job_id == job_id, ProvisionStep.seq == seq))
                        row.state, row.log, row.finished_at = "failed", "\n".join(ctx._lines), now_utc()
                        job = s.get(ProvisionJob, job_id)
                        job.state, job.error, job.finished_at = "failed", msg, now_utc()
                    self._event("provision.failed", subject, {"job_id": job_id})
                    return
                with self.session_factory.begin() as s:
                    row = s.scalar(select(ProvisionStep).where(ProvisionStep.job_id == job_id, ProvisionStep.seq == seq))
                    row.state, row.log, row.finished_at = state, "\n".join(ctx._lines), now_utc()
            with self.session_factory.begin() as s:
                job = s.get(ProvisionJob, job_id)
                job.state, job.finished_at = "succeeded", now_utc()
                node_row = s.get(Node, snapshot["id"])
                if node_row is not None:
                    if ctx.extra.get("new_ssh_user"):
                        node_row.ssh_user = ctx.extra["new_ssh_user"]
                        node_row.ssh_password_enc = None
                    if ctx.extra.get("pull_public_key"):
                        node_row.pull_public_key = ctx.extra["pull_public_key"]
            self._event("provision.succeeded", subject, {"job_id": job_id})
        except asyncio.CancelledError:
            with self.session_factory.begin() as s:
                job = s.get(ProvisionJob, job_id)
                if job:
                    job.state, job.error, job.finished_at = "cancelled", "cancelled", now_utc()
            self._event("provision.failed", subject, {"job_id": job_id})
            raise
        except Exception as exc:  # noqa: BLE001
            msg = (redact(str(exc)[:500], [token]) if isinstance(exc, ProvisionError)
                   else f"provisioning failed ({type(exc).__name__})")
            with self.session_factory.begin() as s:
                job = s.get(ProvisionJob, job_id)
                if job:
                    job.state, job.error, job.finished_at = "failed", msg, now_utc()
            self._event("provision.failed", subject, {"job_id": job_id})
        finally:
            if executor:
                await executor.close()

    def _event(self, kind, subject, data):
        with self.session_factory.begin() as s:
            s.add(Event(kind=kind, subject=subject, data=data))

    def run_in_background(self, job_id):
        task = asyncio.create_task(self.run_job(job_id))
        self._tasks[job_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(job_id, None))
        return task

    def cancel(self, job_id):
        task = self._tasks.get(job_id)
        if task is None:
            return False
        task.cancel()
        return True

    async def shutdown(self):
        for task in list(self._tasks.values()):
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    def auto_provision(self):
        """Start jobs for nodes flagged auto that never succeeded; protected nodes are skipped."""
        started = []
        with self.session_factory() as s:
            nodes = [(n.id, dict(n.provision_options or {})) for n in s.scalars(select(Node)) if
                     (n.provision_options or {}).get("auto") and not n.protected and n.enabled]
            done = set(s.scalars(select(ProvisionJob.node_id).where(ProvisionJob.state == "succeeded")))
        for node_id, options in nodes:
            if node_id in done:
                continue
            try:
                job_id = self.create_job(node_id, {k: v for k, v in options.items() if k != "auto"})
            except ProvisionError:
                continue
            self.run_in_background(job_id)
            started.append(job_id)
        return started

    def active_jobs(self):
        return list(self._tasks)

    def job_view(self, job_id):
        with self.session_factory() as s:
            job = s.get(ProvisionJob, job_id)
            if not job:
                return None
            return {"id": job.id, "node_id": job.node_id, "state": job.state, "options": job.options,
                "error": job.error, "created_at": job.created_at, "started_at": job.started_at, "finished_at": job.finished_at,
                "steps": [{"name": r.name, "state": r.state, "log": r.log, "started_at": r.started_at, "finished_at": r.finished_at}
                    for r in s.scalars(select(ProvisionStep).where(ProvisionStep.job_id == job_id).order_by(ProvisionStep.seq))]}

    def list_jobs(self, node_id=None, limit=100):
        with self.session_factory() as s:
            query = select(ProvisionJob).order_by(ProvisionJob.id.desc()).limit(limit)
            if node_id is not None:
                query = query.where(ProvisionJob.node_id == node_id)
            return [{"id": j.id, "node_id": j.node_id, "state": j.state, "error": j.error,
                     "created_at": j.created_at, "started_at": j.started_at, "finished_at": j.finished_at} for j in s.scalars(query)]

    def recover_interrupted(self):
        with self.session_factory.begin() as s:
            jobs = list(s.scalars(select(ProvisionJob).where(ProvisionJob.state == "running")))
            for job in jobs:
                job.state, job.error, job.finished_at = "failed", "interrupted by restart", now_utc()
