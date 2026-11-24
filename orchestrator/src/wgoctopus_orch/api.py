"""HTTP API for the orchestrator service."""
# ruff: noqa: B008, C408, BLE001
import asyncio
import hmac
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import asyncssh
import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import bootstrap, service, webauth
from . import service_users as users
from .alerts import AlertDispatcher, NotifyError, TelegramNotifier
from .config import Settings, database_url
from .crypto import Crypto
from .db import make_engine, make_session_factory, upgrade_to_head
from .device_stats import device_stats
from .failover import FailoverError, build_failover
from .metrics import render_metrics
from .models import (
    Event,
    FailoverProposal,
    HopLink,
    Instance,
    Node,
    NodeObserved,
    NodeRevision,
    Peer,
    Placement,
    Probe,
    UserRequest,
    WebAccount,
)
from .provision import ProvisionError, ProvisionRunner, validate_options
from .pull_server import PullServer
from .reconciler import build_reconciler
from .renderer import active_placement, probe_iface_name

log = logging.getLogger(__name__)


def _token():
    token = os.getenv("WGOCTOPUS_API_TOKEN")
    path = os.getenv("WGOCTOPUS_API_TOKEN_FILE")
    if token is None and path:
        try:
            token = Path(path).read_text().strip()
        except OSError as exc:
            raise RuntimeError("cannot read WGOCTOPUS_API_TOKEN_FILE") from exc
    return token


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")

class ResolveUserIn(Strict):
    tg_id: int
    username: str | None
    language: str | None

class UserEnsureIn(Strict):
    role: str = Field(default="user", pattern="^(admin|user)$")
    config_limit: int = Field(default=3, ge=-1)

class UserPatchIn(Strict):
    role: str | None = Field(default=None, pattern="^(admin|user)$")
    config_limit: int | None = Field(default=None, ge=-1)

class DisableIn(Strict):
    by: str

class RequestIn(Strict):
    type: str = Field(pattern="^(access|limit)$")
    tg_id: int
    username: str | None
    first_name: str | None
    last_name: str | None
    requested_limit: int | None = Field(default=None, ge=-1)

class DecisionIn(Strict):
    admin_tg_id: int
    admin_username: str | None

class ApproveIn(DecisionIn):
    default_limit: int = Field(default=3, ge=-1)

class RefsIn(Strict):
    refs: list[tuple[int, int]]


class InstanceIn(Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,14}$")
    listen_port: int = Field(ge=1, le=65535)
    address: str
    obfuscation: dict | None = None
    cps_profile: str | None = Field(default=None, pattern="^(none|quic_initial|tls_client_hello|dns_query|wireguard_noise|sip|random)$")
    intensity: str = Field(default="medium", pattern="^(low|medium|high)$")
    awg_version: str = Field(default="2.0", pattern="^(2.0|3.0|3.1)$")
    mtu: int | None = Field(default=None, ge=576, le=9000)
    egress_interface: str | None = None
    snat_ip: str | None = None
    endpoint_host: str | None = None
    client_dns: str | None = None
    client_keepalive: int | None = Field(default=None, ge=0, le=65535)
    client_allowed_ips: str | None = None


class InstancePatch(Strict):
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    mtu: int | None = Field(default=None, ge=576, le=9000)
    egress_interface: str | None = None
    snat_ip: str | None = None
    endpoint_host: str | None = None
    client_dns: str | None = None
    client_keepalive: int | None = Field(default=None, ge=0, le=65535)
    client_allowed_ips: str | None = None


class PlacementIn(Strict):
    role: str = Field(default="active", pattern="^(active|standby)$")
    weight: int = Field(default=1, ge=1)


class ProvisionIn(Strict):
    options: dict | None = None
    confirm_protected: bool = False


class NodeIn(Strict):
    name: str
    ssh_host: str | None = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str | None = None
    mgmt_mode: str = Field(default="push", pattern="^(push|pull|auto)$")
    pull_public_key: str | None = None
    agent_port: int = Field(default=18080, ge=1, le=65535)
    agent_token: str | None = None
    egress_interface: str | None = None
    snat_ip: str | None = None
    enabled: bool = True
    kind: str = Field(default="awg", pattern="^(awg|hop)$")
    wan_interface: str | None = None
    hop_ip: str | None = None
    backend_ip: str | None = None
    protected: bool = False
    provision: dict | None = None

    @field_validator("hop_ip", "backend_ip")
    @classmethod
    def ipv4(cls, value):
        if value is not None and ipaddress.ip_address(value).version != 4:
            raise ValueError("must be an IPv4 address")
        return value

    @model_validator(mode="after")
    def valid_kind_fields(self):
        if self.mgmt_mode == "pull":
            self.ssh_host = self.ssh_host or "-"
            self.ssh_user = self.ssh_user or "pull"
        elif not self.ssh_host or not self.ssh_user:
            raise ValueError("ssh_host and ssh_user are required unless mgmt_mode is pull")
        if self.kind == "hop" and (not self.wan_interface or not self.hop_ip):
            raise ValueError("hop nodes require wan_interface and hop_ip")
        if self.kind == "awg" and (self.wan_interface is not None or self.hop_ip is not None):
            raise ValueError("awg nodes cannot set wan_interface or hop_ip")
        return self

    @field_validator("pull_public_key")
    @classmethod
    def public_key(cls, value):
        return _normalize_pull_key(value)


class PeerIn(Strict):
    name: str
    owner: str | None = None


class PeerPatch(Strict):
    enabled: StrictBool | None = None
    owner: str | None = None
    name: str | None = None


class NodePatch(Strict):
    name: str | None = Field(default=None, min_length=1)
    ssh_host: str | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_user: str | None = None
    mgmt_mode: str | None = Field(default=None, pattern="^(push|pull|auto)$")
    pull_public_key: str | None = None
    agent_port: int | None = Field(default=None, ge=1, le=65535)
    agent_token: str | None = None
    egress_interface: str | None = None
    snat_ip: str | None = None
    enabled: bool | None = None
    protected: bool | None = None
    provision: dict | None = None
    kind: str | None = Field(default=None, pattern="^(awg|hop)$")
    wan_interface: str | None = None
    hop_ip: str | None = None
    backend_ip: str | None = None

    @field_validator("hop_ip", "backend_ip")
    @classmethod
    def ipv4(cls, value):
        if value is not None and ipaddress.ip_address(value).version != 4:
            raise ValueError("must be an IPv4 address")
        return value

    @field_validator("pull_public_key")
    @classmethod
    def public_key(cls, value):
        return _normalize_pull_key(value)


def _normalize_pull_key(value):
    if value is None:
        return None
    try:
        if not value.startswith(("ssh-", "ecdsa-", "sk-")) or "\n" in value or "\r" in value:
            raise ValueError
        key = asyncssh.import_public_key(value)
        normalized = key.export_public_key("openssh").decode().split()
        return " ".join(normalized[:2])
    except (ValueError, asyncssh.Error, TypeError):
        raise ValueError("invalid OpenSSH public key") from None


class DeviceIn(Strict):
    instance_id: int
    name: str | None = None
    admin_bypass: StrictBool = False


class DevicePatchIn(Strict):
    name: str | None = None
    enabled: StrictBool | None = None


class SwitchIn(Strict):
    node_id: int


class ProbeIn(Strict):
    hop_id: int
    instance_id: int
    runner_node_id: int


def create_app(*, session_factory=None, reconciler=None, crypto=None, migrate=None, alerts=None, notifier=None, failover=None, bot=None, pull_server=None, provision=None):
    engine = make_engine(database_url()) if session_factory is None else None
    sessions = session_factory or make_session_factory(engine)
    cipher = crypto or Crypto()
    enabled = os.getenv("WGOCTOPUS_RECONCILER_ENABLED", "true").lower() == "true"
    alert_settings = Settings.from_env()
    if alert_settings.web_enabled:
        app_web_sessions = webauth.SessionStore(sessions, ttl_seconds=alert_settings.web_session_ttl, idle_seconds=alert_settings.web_session_idle)
        app_web_throttle = webauth.LoginThrottle()

    def pull_event(kind, node_id):
        try:
            with sessions() as session:
                service._event(session, kind, str(node_id), {})
                session.commit()
            if kind == "node.pull_connected" and app.state.reconciler:
                app.state.reconciler.kick(node_id, force=True)
        except Exception as exc:
            log.error("Pull callback failed (%s)", type(exc).__name__)

    @asynccontextmanager
    async def lifespan(app):
        owned_pull_server = None
        try:
            if migrate if migrate is not None else os.getenv("WGOCTOPUS_AUTO_MIGRATE", "true").lower() == "true":
                try:
                    upgrade_to_head()
                except Exception:
                    log.exception("Database migration failed")
                    raise
            app.state.bootstrap_last_apply = None
            if alert_settings.bootstrap_file and alert_settings.bootstrap_apply:
                try:
                    doc = bootstrap.load_yaml(Path(alert_settings.bootstrap_file).read_text())
                    result = bootstrap.apply_bootstrap(sessions, doc, crypto=cipher)
                    app.state.bootstrap_last_apply = {"at": time.time(), "ok": True, "summary": {k: sum(map(len, getattr(result, k).values())) for k in ("created", "updated", "unchanged", "pruned")}}
                except Exception as exc:
                    paths = exc.errors if isinstance(exc, bootstrap.BootstrapError) else ["/"]
                    log.error("Bootstrap failed at paths: %s", ", ".join(paths))
                    raise
            app.state.provision = provision or ProvisionRunner(sessions, cipher, alert_settings)
            try:
                app.state.provision.recover_interrupted()
                if enabled:
                    app.state.provision.auto_provision()
            except Exception as exc:
                log.error("Provisioning startup failed (%s)", type(exc).__name__)
            if pull_server is not None:
                app.state.pull_server = pull_server
            elif alert_settings.pull_listen:
                owned_pull_server = PullServer(sessions, settings=alert_settings,
                    on_connect=lambda node_id: asyncio.create_task(asyncio.to_thread(pull_event, "node.pull_connected", node_id)),
                    on_disconnect=lambda node_id: asyncio.create_task(asyncio.to_thread(pull_event, "node.pull_disconnected", node_id)))
                app.state.pull_server = owned_pull_server
                await owned_pull_server.start()
            else:
                app.state.pull_server = None
            app.state.reconciler = (build_reconciler(alert_settings, sessions, pull_server=app.state.pull_server)
                                    if reconciler is None and enabled else reconciler)
            if alerts is not None:
                app.state.alerts = alerts
            elif alert_settings.alerts_enabled:
                app.state.alerts = AlertDispatcher(sessions, notifier or TelegramNotifier(
                    alert_settings.telegram_token, alert_settings.telegram_chat_id,
                    api_base=alert_settings.telegram_api_base), delay_seconds=alert_settings.alert_delay_seconds,
                    max_per_minute=alert_settings.alert_max_per_minute, poll_seconds=alert_settings.alert_poll_seconds,
                    kinds=alert_settings.alert_kinds, buttons_enabled=(alert_settings.telegram_buttons_enabled or alert_settings.telegram_failover_buttons) and alert_settings.alerts_enabled)
            else:
                app.state.alerts = None
            stop = asyncio.Event()
            task = asyncio.create_task(app.state.reconciler.run(stop)) if app.state.reconciler else None
            alert_task = asyncio.create_task(app.state.alerts.run(stop)) if app.state.alerts else None
            app.state.failover = failover
            if app.state.failover is None and alert_settings.failover_mode != "off" and app.state.reconciler:
                app.state.failover = build_failover(sessions, app.state.reconciler, alert_settings,
                    on_executed=lambda instance_id, node_id: kick_for_failover(instance_id, node_id))
            async def failover_loop():
                while not stop.is_set():
                    try:
                        await asyncio.to_thread(app.state.failover.evaluate_once)
                    except Exception as exc:
                        log.error("Failover evaluation failed (%s)", type(exc).__name__)
                    try:
                        await asyncio.wait_for(stop.wait(), timeout=alert_settings.failover_eval_interval)
                    except TimeoutError:
                        pass
            failover_task = asyncio.create_task(failover_loop()) if app.state.failover else None
            if bot is not None:
                app.state.telegram_bot = bot
            elif alert_settings.telegram_buttons_enabled and app.state.failover:
                from .telegram_bot import TelegramBot
                app.state.telegram_bot = TelegramBot(alert_settings.telegram_token, alert_settings.telegram_chat_id,
                    alert_settings.telegram_api_base, httpx.AsyncClient(timeout=alert_settings.telegram_poll_timeout + 5),
                    app.state.failover, sessions, alert_settings.telegram_allowed_user_ids, alert_settings.telegram_poll_timeout)
            else:
                app.state.telegram_bot = None
            bot_task = asyncio.create_task(app.state.telegram_bot.run()) if app.state.telegram_bot else None
            yield
        finally:
            if 'stop' in locals():
                stop.set()
            if 'bot_task' in locals() and bot_task:
                bot_task.cancel()
                try:
                    await bot_task
                except asyncio.CancelledError:
                    pass
                await app.state.telegram_bot.client.aclose()
            if 'failover_task' in locals() and failover_task:
                await failover_task
            if 'task' in locals() and task:
                app.state.reconciler._kick.set()
                await task
            if 'alert_task' in locals() and alert_task:
                await alert_task
            if owned_pull_server:
                await owned_pull_server.stop()
            if app.state.provision is not None:
                await app.state.provision.shutdown()
            if engine:
                engine.dispose()

    docs = os.getenv("WGOCTOPUS_API_DOCS", "false").lower() == "true"
    app = FastAPI(lifespan=lifespan, openapi_url="/openapi.json" if docs else None,
                  docs_url="/docs" if docs else None)
    app.state.sessions = sessions
    app.state.crypto = cipher
    app.state.reconciler = reconciler
    app.state.alerts = alerts
    app.state.telegram_bot = bot
    app.state.pull_server = pull_server
    app.state.provision = provision
    app.state.bootstrap_last_apply = None
    token = _token()
    allow_no_auth = os.getenv("WGOCTOPUS_API_ALLOW_NO_AUTH", "false").lower() == "true"
    if not token and not allow_no_auth:
        raise RuntimeError("WGOCTOPUS_API_TOKEN or WGOCTOPUS_API_TOKEN_FILE is required")
    if not token:
        log.warning("API authentication disabled; development mode only")

    def db():
        with sessions() as session:
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def auth(authorization: str | None = Header(default=None)):
        if token and (not authorization or not authorization.startswith("Bearer ") or
                      not hmac.compare_digest(authorization[7:], token)):
            raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})

    if alert_settings.web_enabled:
        app.state.web_sessions, app.state.web_throttle = app_web_sessions, app_web_throttle

        def web_actor(min_role="viewer", request: Request = None):
            info = app_web_sessions.lookup(request.cookies.get("wgoctopus_session") if request else None)
            if not info or not webauth.has_role(info.role, min_role):
                raise HTTPException(401 if not info else 403, detail={"error": "authentication_required" if not info else "forbidden"})
            return info

        def require_web(min_role="viewer"):
            def dependency(request: Request, x_csrf_token: str | None = Header(default=None)):
                info = web_actor(min_role, request)
                if request.method != "GET" and not webauth.check_csrf(info, x_csrf_token):
                    raise HTTPException(403, detail={"error": "csrf"})
                return info
            return dependency

        def web_error(exc):
            status = {"invalid": 422, "weak_password": 422, "conflict": 409, "not_found": 404, "last_admin": 409}[exc.code]
            raise HTTPException(status, detail={"error": exc.code}) from None

        def account_json(a):
            return {"username": a.username, "role": a.role, "source": a.source, "enabled": a.enabled,
                    "created_at": a.created_at, "last_login_at": a.last_login_at}

        if alert_settings.web_admin_password:
            with sessions.begin() as session:
                if session.scalar(select(WebAccount.id).limit(1)) is None:
                    webauth.create_account(session, alert_settings.web_admin_username, alert_settings.web_admin_password, "admin")

        @app.post("/auth/login")
        def web_login(body: dict, request: Request, response: Response, s: Session = Depends(db)):
            ip = request.client.host if request.client else ""
            username = body.get("username", "")
            if not isinstance(username, str) or not isinstance(body.get("password"), str):
                raise HTTPException(401, detail={"error": "invalid_credentials"})
            try:
                account = webauth.authenticate_local(s, username, body["password"], app_web_throttle, ip)
            except webauth.WebAuthError as exc:
                if exc.code == "throttled":
                    raise HTTPException(429, detail={"error": "throttled"}, headers={"Retry-After": str(app_web_throttle.lockout)}) from None
                raise HTTPException(401, detail={"error": "invalid_credentials"}) from None
            token, csrf = app_web_sessions.create(account.id, ip)
            response.set_cookie("wgoctopus_session", token, httponly=True, samesite="lax", path="/", secure=alert_settings.web_cookie_secure, max_age=alert_settings.web_session_ttl)
            return {"username": account.username, "role": account.role, "csrf_token": csrf}

        @app.get("/auth/me")
        def web_me(request: Request):
            info = web_actor("viewer", request)
            return {"username": info.username, "role": info.role, "csrf_token": info.csrf, "source": info.source}

        @app.post("/auth/logout", status_code=204)
        def web_logout(request: Request, response: Response, info=Depends(require_web("viewer"))):
            app_web_sessions.revoke(request.cookies.get("wgoctopus_session"))
            with sessions.begin() as session:
                service._event(session, "web.logout", info.username, {})
            response.delete_cookie("wgoctopus_session", path="/", secure=alert_settings.web_cookie_secure, httponly=True, samesite="lax")
            return Response(status_code=204)

        def account_admin(request: Request, authorization: str | None = Header(default=None), x_csrf_token: str | None = Header(default=None)):
            if token and authorization and authorization.startswith("Bearer ") and hmac.compare_digest(authorization[7:], token):
                return None
            info = web_actor("admin", request)
            if request.method != "GET" and not webauth.check_csrf(info, x_csrf_token):
                raise HTTPException(403, detail={"error": "csrf"})
            return info

        @app.get("/v1/web-accounts", dependencies=[Depends(account_admin)])
        def web_accounts(s: Session = Depends(db)):
            return [account_json(a) for a in webauth.list_accounts(s)]

        @app.post("/v1/web-accounts", dependencies=[Depends(account_admin)], status_code=201)
        def web_account_create(body: dict, s: Session = Depends(db)):
            try:
                return account_json(webauth.create_account(s, body.get("username"), body.get("password"), body.get("role"), body.get("source", "local")))
            except webauth.WebAuthError as exc: web_error(exc)

        @app.patch("/v1/web-accounts/{username}", dependencies=[Depends(account_admin)])
        def web_account_patch(username: str, body: dict, s: Session = Depends(db)):
            account = s.scalar(select(WebAccount).where(WebAccount.username == username.lower()))
            if not account: raise HTTPException(404, detail={"error": "not_found"})
            try:
                if body.get("password") is not None: webauth.set_password(s, account, body["password"])
                if body.get("role") is not None: webauth.set_role(s, account, body["role"])
                if body.get("enabled") is not None: webauth.set_enabled(s, account, body["enabled"])
                if body.get("enabled") is False: app_web_sessions.revoke_account(account.id)
                return account_json(account)
            except webauth.WebAuthError as exc: web_error(exc)

        @app.delete("/v1/web-accounts/{username}", dependencies=[Depends(account_admin)], status_code=204)
        def web_account_delete(username: str, s: Session = Depends(db)):
            account = s.scalar(select(WebAccount).where(WebAccount.username == username.lower()))
            if not account: raise HTTPException(404, detail={"error": "not_found"})
            try: webauth.delete_account(s, account)
            except webauth.WebAuthError as exc: web_error(exc)

    else:
        app.state.web_sessions = app.state.web_throttle = None
        @app.api_route("/auth/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
        @app.api_route("/auth", methods=["GET", "POST", "PATCH", "DELETE"])
        @app.api_route("/v1/web-accounts/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
        @app.api_route("/v1/web-accounts", methods=["GET", "POST", "PATCH", "DELETE"])
        def web_disabled():
            raise HTTPException(404, detail={"error": "not_found"})

    @app.get("/v1/bootstrap", dependencies=[Depends(auth)])
    def bootstrap_status():
        return {"configured": bool(alert_settings.bootstrap_file),
                "file": Path(alert_settings.bootstrap_file).name if alert_settings.bootstrap_file else None,
                "last_apply": app.state.bootstrap_last_apply}

    @app.post("/v1/bootstrap/apply", dependencies=[Depends(auth)])
    def bootstrap_apply(body: dict = Body(default={})):
        configured = alert_settings.bootstrap_file
        if body.keys() - {"dry_run", "document"} or not isinstance(body.get("dry_run", False), bool):
            raise HTTPException(422, detail={"error": "validation_error", "detail": ["/"]})
        if "document" in body:
            document = body["document"]
        elif configured:
            try: document = bootstrap.load_yaml(Path(configured).read_text())
            except OSError: raise HTTPException(422, detail={"error": "validation_error", "detail": ["/"]}) from None
        else:
            raise HTTPException(404, "bootstrap not configured")
        try:
            result = bootstrap.apply_bootstrap(sessions, document, crypto=cipher, dry_run=body.get("dry_run", False))
        except bootstrap.BootstrapError as exc:
            return JSONResponse(status_code=422, content={"error": "validation_error", "detail": exc.errors})
        report = {key: getattr(result, key) for key in ("created", "updated", "unchanged", "pruned", "warnings")}
        if not body.get("dry_run", False):
            affected = []
            with sessions() as session:
                affected = session.scalars(select(Node.id).where(Node.name.in_([*{r.get("node") for r in document.get("placements", [])}, *{r.get("hop") for r in document.get("hop_links", [])}]))).all()
                kick(session, affected)
            app.state.bootstrap_last_apply = {"at": time.time(), "ok": True, "summary": {k: sum(map(len, report[k].values())) for k in ("created", "updated", "unchanged", "pruned")}}
        return report

    @app.get("/metrics", response_class=Response)
    def metrics(s: Session = Depends(db), _auth=Depends(auth) if not Settings.from_env().metrics_public else None):
        return Response(render_metrics(s, app.state.reconciler, alerts=app.state.alerts, bot=app.state.telegram_bot, pull_server=app.state.pull_server), media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/v1/alerts", dependencies=[Depends(auth)])
    def alerts_status():
        dispatcher = app.state.alerts
        return {"enabled": dispatcher is not None, "buttons_enabled": alert_settings.telegram_buttons_enabled, "failover_buttons": alert_settings.telegram_failover_buttons and alert_settings.alerts_enabled, "counters": dispatcher.counters() if dispatcher else {"sent": 0, "failed": 0, "dropped": 0, "pending": 0}}

    @app.get("/v1/pull", dependencies=[Depends(auth)])
    def pull_status():
        server = app.state.pull_server
        return {"enabled": bool(server), "listen": alert_settings.pull_listen or None if server else None,
                "host_key_fingerprint": server.host_key_fingerprint if server else None,
                "connected_node_ids": server.connected_node_ids() if server else [],
                "counters": server.counters if server else {"connections_ok": 0, "connections_denied": 0}}

    @app.post("/v1/alerts/test", status_code=202, dependencies=[Depends(auth)])
    async def alert_test():
        if app.state.alerts is None:
            raise HTTPException(409, "alerts disabled")
        try:
            await app.state.alerts.send_test()
        except NotifyError:
            raise HTTPException(502, "notification failed") from None
        return {"sent": True}

    def kick(session, node_ids):
        reconciler_obj = app.state.reconciler
        if reconciler_obj:
            for ident in set(node_ids):
                reconciler_obj.kick(ident)

    def kick_for_failover(instance_id, node_id):
        with sessions() as session:
            hop_ids = session.scalars(select(HopLink.hop_id).where(HopLink.instance_id == instance_id)).all()
            kick(session, [node_id, *hop_ids])

    def proposal_json(p):
        return {key: getattr(p, key) for key in ("id", "instance_id", "hop_id", "from_node_id", "to_node_id", "state", "mode_at_creation", "reason", "created_at", "expires_at", "decided_at", "decided_by", "error")}

    @app.get("/v1/failover", dependencies=[Depends(auth)])
    def failover_settings():
        return {"mode": alert_settings.failover_mode, "enabled": alert_settings.failover_mode != "off", "down_seconds": alert_settings.failover_down_seconds, "proposal_ttl_seconds": alert_settings.failover_proposal_ttl_seconds, "cooldown_seconds": alert_settings.failover_cooldown_seconds, "eval_interval": alert_settings.failover_eval_interval}

    @app.get("/v1/failovers", dependencies=[Depends(auth)])
    def list_failovers(state: str | None = Query(None, pattern="^(pending|executed|rejected|expired|cancelled|failed)$"), instance_id: int | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), s: Session = Depends(db)):
        query = select(FailoverProposal)
        if state is not None: query = query.where(FailoverProposal.state == state)
        if instance_id is not None: query = query.where(FailoverProposal.instance_id == instance_id)
        return [proposal_json(p) for p in s.scalars(query.order_by(FailoverProposal.id.desc()).limit(limit).offset(offset)).all()]

    @app.get("/v1/failovers/{ident}", dependencies=[Depends(auth)])
    def get_failover(ident: int, s: Session = Depends(db)):
        p = s.get(FailoverProposal, ident)
        if not p: raise HTTPException(404, "not_found")
        return proposal_json(p)

    def decide(ident, action, decision):
        if not app.state.failover: raise HTTPException(409, "disabled")
        by, actor = decision.get("by", "api"), decision.get("actor")
        if by not in {"api", "telegram"} or (actor is not None and (not isinstance(actor, str) or len(actor) > 64)):
            raise HTTPException(422, "invalid decision")
        try: return proposal_json(getattr(app.state.failover, action)(ident, by=by, actor=actor))
        except FailoverError as exc:
            code = "not_found" if exc.code == "not_found" else exc.code
            raise HTTPException(404 if code == "not_found" else 409, code) from None

    @app.post("/v1/failovers/{ident}/confirm", dependencies=[Depends(auth)])
    def confirm_failover(ident: int, decision: dict | None = Body(None)): return decide(ident, "confirm", decision or {})

    @app.post("/v1/failovers/{ident}/reject", dependencies=[Depends(auth)])
    def reject_failover(ident: int, decision: dict | None = Body(None)): return decide(ident, "reject", decision or {})

    def placed_nodes(session, instance_id):
        return session.scalars(select(Placement.node_id).where(Placement.instance_id == instance_id)).all()

    def inst(i, session):
        peers = session.scalar(select(__import__("sqlalchemy").func.count(Peer.id)).where(Peer.instance_id == i.id, or_(Peer.owner.is_(None), Peer.owner != service.PROBE_OWNER)))
        placements = session.scalars(select(Placement).where(Placement.instance_id == i.id)).all()
        return dict(id=i.id, name=i.name, listen_port=i.listen_port, address=i.address, public_key=i.public_key,
                    obfuscation={**{k:v for k,v in i.obfuscation.items() if k != "header_protection_key"},
                                 **({"header_protection_key_set": True} if i.obfuscation.get("header_protection_key") else {})},
                    mtu=i.mtu, egress_interface=i.egress_interface, snat_ip=i.snat_ip,
                    endpoint_host=i.endpoint_host, client_dns=i.client_dns,
                    client_keepalive=i.client_keepalive, client_allowed_ips=i.client_allowed_ips,
                     placements=[dict(node_id=p.node_id, role=p.role, weight=p.weight) for p in placements],
                     active_node_id=next((p.node_id for p in placements if p.role == "active"), None), peer_count=peers,
                    created_at=i.created_at)

    def node(n, session):
        rev=session.get(NodeRevision,n.id); obs=session.get(NodeObserved,n.id)
        status=(app.state.reconciler.status().get(n.id) if app.state.reconciler else None)
        return dict(id=n.id,name=n.name,ssh_host=n.ssh_host,ssh_port=n.ssh_port,ssh_user=n.ssh_user,
                    mgmt_mode=n.mgmt_mode,agent_port=n.agent_port,egress_interface=n.egress_interface,snat_ip=n.snat_ip,
                    protected=n.protected, provision=n.provision_options,
                    pull_public_key=n.pull_public_key, pull_connected=bool(app.state.pull_server and app.state.pull_server.is_connected(n.id)),
                    enabled=n.enabled,kind=n.kind,wan_interface=n.wan_interface,hop_ip=n.hop_ip,backend_ip=n.backend_ip,
                    desired_revision=rev.desired_revision if rev else None,
                    observed=dict(last_seen_at=obs.last_seen_at,applied_revision=obs.applied_revision,healthy=obs.healthy,last_error=obs.last_error) if obs else None,
                    reconciler=dict(state=status.state.value,last_attempt_at=status.last_attempt_at,next_attempt_at=status.next_attempt_at,
                                    consecutive_failures=status.consecutive_failures,last_outcome=status.last_outcome.status.value if status.last_outcome else None) if status else None)

    def peer(p):
        return dict(id=p.id,instance_id=p.instance_id,name=p.name,public_key=p.public_key,allowed_ip=p.allowed_ip,
                    enabled=p.enabled,owner=p.owner,created_at=p.created_at)

    @app.exception_handler(ValueError)
    async def value_error(_, exc):
        detail = str(exc)
        unknown = detail.startswith("unknown ")
        conflict = "no placement" in detail
        return JSONResponse(status_code=404 if unknown else 409 if conflict else 422,
                            content={"error":"not_found" if unknown else "conflict" if conflict else "validation_error","detail":detail})

    @app.exception_handler(HTTPException)
    async def http_error(_, exc):
        code = "not_found" if exc.status_code == 404 else "conflict" if exc.status_code == 409 else "unauthorized" if exc.status_code == 401 else "error"
        return JSONResponse(status_code=exc.status_code, content={"error":code,"detail":exc.detail}, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(_: Request, exc: RequestValidationError):
        errors = exc.errors()
        for error in errors:
            if "pull_public_key" in error.get("loc", ()):
                error.pop("input", None)
        return JSONResponse(status_code=422, content={"error":"validation_error","detail":jsonable_encoder(errors)})

    @app.exception_handler(IntegrityError)
    async def integrity_error(_, exc):
        return JSONResponse(status_code=409,content={"error":"conflict","detail":"resource conflicts with existing state"})

    @app.get("/healthz")
    def health(): return {"status":"ok"}

    @app.get("/readyz")
    def ready():
        try:
            with sessions() as s: s.execute(select(1))
            cipher.decrypt(cipher.encrypt("ready"))
            return {"status":"ready"}
        except Exception: raise HTTPException(503,"not ready")

    @app.post("/v1/instances", dependencies=[Depends(auth)], status_code=201)
    def create_instance(body: InstanceIn, s: Session=Depends(db)):
        try:
            instance = service.create_instance(s, body.name, body.listen_port, body.address,
                obfuscation=body.obfuscation, mtu=body.mtu, cps_profile=body.cps_profile,
                intensity=body.intensity, egress_interface=body.egress_interface,
                snat_ip=body.snat_ip, endpoint_host=body.endpoint_host, client_dns=body.client_dns,
                client_keepalive=body.client_keepalive, client_allowed_ips=body.client_allowed_ips,
                crypto=cipher, awg_version=body.awg_version)
        except ValueError:
            raise HTTPException(422, "invalid instance parameters") from None
        return inst(instance, s)

    @app.get("/v1/instances", dependencies=[Depends(auth)])
    def list_instances(s: Session=Depends(db)): return [inst(i,s) for i in s.scalars(select(Instance)).all()]

    @app.get("/v1/instances/{ident}", dependencies=[Depends(auth)])
    def get_instance(ident:int,s:Session=Depends(db)):
        i=s.get(Instance,ident)
        if not i: raise HTTPException(404,"unknown instance")
        return inst(i,s)

    @app.patch("/v1/instances/{ident}",dependencies=[Depends(auth)])
    def patch_instance(ident:int, body:InstancePatch, s:Session=Depends(db)):
        i=s.get(Instance,ident)
        if not i: raise HTTPException(404,"unknown instance")
        changes = body.model_dump(exclude_unset=True)
        for key, validator in (("endpoint_host", service.validate_endpoint_host),
                               ("client_dns", service.validate_client_dns),
                               ("client_allowed_ips", service.validate_client_allowed_ips)):
            if key in changes:
                changes[key] = validator(changes[key])
        for k,v in changes.items(): setattr(i,k,v)
        nodes=placed_nodes(s,ident); s.flush()
        if {"listen_port", "mtu", "egress_interface", "snat_ip"} & changes.keys():
            for n in nodes: service.bump_revision(s,n,cipher)
        if "listen_port" in changes: service._bump_hops(s,ident,cipher)
        if {"listen_port", "mtu"} & changes.keys(): service._bump_probe_runners(s,instance_id=ident,crypto=cipher)
        kick(s,nodes); return inst(i,s)

    @app.delete("/v1/instances/{ident}",dependencies=[Depends(auth)],status_code=204)
    def delete_instance(ident:int,s:Session=Depends(db)):
        i=s.get(Instance,ident)
        if not i: raise HTTPException(404,"unknown instance")
        if s.scalar(select(Peer.id).where(Peer.instance_id==ident)) or s.scalar(select(Placement.id).where(Placement.instance_id==ident)): raise HTTPException(409,"instance has peers or placements")
        s.delete(i); return Response(status_code=204)

    @app.put("/v1/instances/{ident}/placements/{node_id}",dependencies=[Depends(auth)])
    def put_placement(ident:int,node_id:int,body:PlacementIn,s:Session=Depends(db)):
        body=body.model_dump()
        if not s.get(Instance, ident): raise HTTPException(404,"unknown instance")
        if not s.get(Node, node_id): raise HTTPException(404,"unknown node")
        p=s.scalar(select(Placement).where(Placement.instance_id==ident,Placement.node_id==node_id))
        if p: p.role=body.get("role","active"); p.weight=body.get("weight",1); s.flush(); service.bump_revision(s,node_id,cipher)
        else: p=service.place(s,ident,node_id,body.get("role","active"),body.get("weight",1),cipher)
        kick(s,[node_id]); return dict(instance_id=ident,node_id=node_id,role=p.role,weight=p.weight)

    @app.delete("/v1/instances/{ident}/placements/{node_id}",dependencies=[Depends(auth)],status_code=204)
    def del_placement(ident:int,node_id:int,s:Session=Depends(db)):
        p=s.scalar(select(Placement).where(Placement.instance_id==ident,Placement.node_id==node_id))
        if not p: raise HTTPException(404,"unknown placement")
        instance_id=p.instance_id
        s.delete(p); s.flush(); service.bump_revision(s,node_id,cipher)
        service._bump_hops(s,instance_id,cipher)
        kick(s,[node_id]); return Response(status_code=204)

    def valid_options(options):
        try:
            return validate_options(options)
        except ProvisionError as exc:
            raise HTTPException(422, {"error": "validation_error", "detail": str(exc)}) from None

    def job_or_404(ident):
        view = app.state.provision.job_view(ident)
        if view is None: raise HTTPException(404, "unknown job")
        return view

    @app.post("/v1/nodes/{ident}/provision",dependencies=[Depends(auth)],status_code=202)
    async def start_provision(ident:int,body:ProvisionIn=Body(default=ProvisionIn()),s:Session=Depends(db)):
        n=s.get(Node,ident)
        if not n: raise HTTPException(404,"unknown node")
        options={**(n.provision_options or {}),**valid_options(body.options)}
        options.pop("auto",None)
        try:
            job_id=app.state.provision.create_job(ident,options,confirm_protected=body.confirm_protected)
        except ProvisionError as exc:
            message=str(exc)
            code="confirmation_required" if "confirmation" in message else "conflict"
            raise HTTPException(409,{"error":code,"detail":message}) from None
        app.state.provision.run_in_background(job_id)
        return {"job_id":job_id}

    @app.get("/v1/provision/jobs",dependencies=[Depends(auth)])
    def list_provision_jobs(node_id:int|None=None,limit:int=Query(default=50,ge=1,le=500)):
        return app.state.provision.list_jobs(node_id,limit)

    @app.get("/v1/provision/jobs/{ident}",dependencies=[Depends(auth)])
    def get_provision_job(ident:int): return job_or_404(ident)

    @app.post("/v1/provision/jobs/{ident}/cancel",dependencies=[Depends(auth)],status_code=202)
    def cancel_provision_job(ident:int):
        job_or_404(ident)
        if not app.state.provision.cancel(ident): raise HTTPException(409,{"error":"not_running","detail":"job is not running"})
        return {"cancelled":True}

    @app.post("/v1/nodes",dependencies=[Depends(auth)],status_code=201)
    def create_node(body:NodeIn,s:Session=Depends(db)):
        n=service.create_node(s,body.name,body.ssh_host or "-",body.ssh_user or "pull",ssh_port=body.ssh_port,mgmt_mode=body.mgmt_mode,agent_port=body.agent_port,agent_token=body.agent_token,egress_interface=body.egress_interface,snat_ip=body.snat_ip,enabled=body.enabled,kind=body.kind,wan_interface=body.wan_interface,hop_ip=body.hop_ip,backend_ip=body.backend_ip,pull_public_key=body.pull_public_key,protected=body.protected,provision_options=valid_options(body.provision) if body.provision is not None else None,crypto=cipher)
        return node(n,s)

    @app.get("/v1/nodes",dependencies=[Depends(auth)])
    def list_nodes(s:Session=Depends(db)): return [node(n,s) for n in s.scalars(select(Node)).all()]

    @app.get("/v1/nodes/{ident}",dependencies=[Depends(auth)])
    def get_node(ident:int,s:Session=Depends(db)):
        n=s.get(Node,ident)
        if not n: raise HTTPException(404,"unknown node")
        return node(n,s)

    @app.patch("/v1/nodes/{ident}",dependencies=[Depends(auth)])
    def patch_node(ident:int,body:NodePatch,s:Session=Depends(db)):
        n=s.get(Node,ident)
        if not n: raise HTTPException(404,"unknown node")
        body=body.model_dump(exclude_unset=True)
        proposed = {"kind": n.kind, "wan_interface": n.wan_interface, "hop_ip": n.hop_ip, **body}
        mode = body.get("mgmt_mode", n.mgmt_mode)
        if mode != "pull" and (not body.get("ssh_host", n.ssh_host) or not body.get("ssh_user", n.ssh_user)):
            raise HTTPException(422, "ssh_host and ssh_user are required unless mgmt_mode is pull")
        if mode == "pull" and n.mgmt_mode != "pull":
            if "ssh_host" not in body: n.ssh_host = "-"
            if "ssh_user" not in body: n.ssh_user = "pull"
        if proposed["kind"] == "hop" and (not proposed["wan_interface"] or not proposed["hop_ip"]):
            raise HTTPException(422, "hop nodes require wan_interface and hop_ip")
        if proposed["kind"] == "awg" and (proposed["wan_interface"] is not None or proposed["hop_ip"] is not None):
            raise HTTPException(422, "awg nodes cannot set wan_interface or hop_ip")
        for k,v in body.items():
            if k == "agent_token":
                n.agent_token_enc = cipher.encrypt(v)
            elif k == "provision":
                n.provision_options = valid_options(v) if v is not None else None
            else:
                setattr(n, k, v)
        hop_ids = []
        if body:
            service.bump_revision(s,ident,cipher)
            if n.kind == "hop" and {"hop_ip", "wan_interface"} & body.keys():
                service._bump_probe_runners(s,hop_id=ident,crypto=cipher)
            if n.kind == "awg":
                service._bump_probe_runners(s,runner_node_id=ident,crypto=cipher)
            if "backend_ip" in body:
                hop_ids = s.scalars(select(HopLink.hop_id).join(Placement, Placement.instance_id == HopLink.instance_id)
                                    .where(Placement.node_id == ident)).all()
                for hop_id in hop_ids:
                    service.bump_revision(s,hop_id,cipher)
        kick(s,[ident, *hop_ids]); return node(n,s)

    @app.get("/v1/hops/{hop_id}/links", dependencies=[Depends(auth)])
    def list_hop_links(hop_id: int, s: Session=Depends(db)):
        hop=s.get(Node,hop_id)
        if not hop or hop.kind != "hop": raise HTTPException(404,"unknown hop")
        result=[]
        for link in s.scalars(select(HopLink).where(HopLink.hop_id==hop_id)).all():
            instance=s.get(Instance,link.instance_id)
            active=active_placement(s, instance.id)
            backend=s.get(Node,active.node_id) if active else None
            row=dict(instance_id=instance.id,name=instance.name,listen_port=instance.listen_port,
                     active_node_id=active.node_id if active else None,active_node_name=backend.name if backend else None,
                     backend_ip=backend.backend_ip if backend and backend.backend_ip else None)
            if not active: row["reason"]="no_active_placement"
            elif not backend.backend_ip: row["reason"]="backend_ip_missing"
            result.append(row)
        return result

    @app.put("/v1/hops/{hop_id}/links/{instance_id}",dependencies=[Depends(auth)],status_code=204)
    def put_hop_link(hop_id:int,instance_id:int,s:Session=Depends(db)):
        hop,instance=s.get(Node,hop_id),s.get(Instance,instance_id)
        if not hop or hop.kind!="hop": raise HTTPException(404,"unknown hop")
        if not instance: raise HTTPException(404,"unknown instance")
        if not s.scalar(select(HopLink).where(HopLink.hop_id==hop_id,HopLink.instance_id==instance_id)):
            service.create_hop_link(s,hop_id,instance_id,cipher)
        kick(s,[hop_id]); return Response(status_code=204)

    @app.delete("/v1/hops/{hop_id}/links/{instance_id}",dependencies=[Depends(auth)],status_code=204)
    def delete_hop_link(hop_id:int,instance_id:int,s:Session=Depends(db)):
        hop=s.get(Node,hop_id)
        if not hop or hop.kind!="hop": raise HTTPException(404,"unknown hop")
        if not s.get(Instance,instance_id): raise HTTPException(404,"unknown instance")
        if not service.delete_hop_link(s,hop_id,instance_id,cipher): raise HTTPException(404,"unknown hop link")
        kick(s,[hop_id]); return Response(status_code=204)

    @app.post("/v1/instances/{ident}/switch",dependencies=[Depends(auth)])
    def switch_instance(ident:int,body:SwitchIn,s:Session=Depends(db)):
        if not s.get(Instance,ident): raise HTTPException(404,"unknown instance")
        old=s.scalar(select(Placement).where(Placement.instance_id==ident,Placement.role=="active").order_by(Placement.weight.desc(),Placement.node_id))
        target=s.scalar(select(Placement).where(Placement.instance_id==ident,Placement.node_id==body.node_id))
        if not target: raise HTTPException(409,"node has no placement for instance")
        old_id=old.node_id if old else None
        service.switch_active(s,ident,body.node_id,cipher)
        placements=s.scalars(select(Placement).where(Placement.instance_id==ident)).all()
        hops=s.scalars(select(HopLink.hop_id).where(HopLink.instance_id==ident)).all()
        kick(s,[p.node_id for p in placements]+hops)
        return dict(instance_id=ident,from_node_id=old_id,to_node_id=body.node_id,changed=old_id!=body.node_id)

    @app.delete("/v1/nodes/{ident}",dependencies=[Depends(auth)],status_code=204)
    def delete_node(ident:int,s:Session=Depends(db)):
        n=s.get(Node,ident)
        if not n: raise HTTPException(404,"unknown node")
        if s.scalar(select(Placement.id).where(Placement.node_id==ident)): raise HTTPException(409,"node has placements")
        s.delete(n); return Response(status_code=204)

    @app.post("/v1/instances/{ident}/peers",dependencies=[Depends(auth)],status_code=201)
    def create_peer(ident:int,body:PeerIn,s:Session=Depends(db)):
        if body.owner == service.PROBE_OWNER:
            raise HTTPException(422, "owner is reserved")
        try:
            p=service.add_peer(s,ident,body.name,owner=body.owner,crypto=cipher)
        except ValueError as exc:
            if "no free peer IPs" in str(exc):
                raise HTTPException(409, "instance subnet has no free peer address") from exc
            raise
        kick(s,placed_nodes(s,ident)); return peer(p)

    @app.get("/v1/instances/{ident}/peers",dependencies=[Depends(auth)])
    def list_peers(ident:int,owner:str|None=None,enabled:bool|None=None,limit:int=Query(100,ge=1,le=1000),offset:int=Query(0,ge=0),s:Session=Depends(db)):
        q=select(Peer).where(Peer.instance_id==ident, or_(Peer.owner.is_(None), Peer.owner != service.PROBE_OWNER))
        if owner is not None:q=q.where(Peer.owner==owner)
        if enabled is not None:q=q.where(Peer.enabled==enabled)
        return [peer(p) for p in s.scalars(q.offset(offset).limit(limit)).all()]

    @app.get("/v1/peers/{ident}",dependencies=[Depends(auth)])
    def get_peer(ident:int,s:Session=Depends(db)):
        p=s.get(Peer,ident)
        if not p or p.owner == service.PROBE_OWNER: raise HTTPException(404,"unknown peer")
        return peer(p)

    @app.patch("/v1/peers/{ident}",dependencies=[Depends(auth)])
    def patch_peer(ident:int,body:PeerPatch,s:Session=Depends(db)):
        p=s.get(Peer,ident)
        if not p or p.owner == service.PROBE_OWNER: raise HTTPException(404,"unknown peer")
        body=body.model_dump(exclude_unset=True)
        nodes=placed_nodes(s,p.instance_id)
        if "enabled" in body: service.set_peer_enabled(s,ident,body.pop("enabled"),cipher)
        for k,v in body.items():setattr(p,k,v)
        if body:
            s.flush()
            for n in nodes:service.bump_revision(s,n,cipher)
        kick(s,nodes); return peer(p)

    @app.delete("/v1/peers/{ident}",dependencies=[Depends(auth)],status_code=204)
    def delete_peer(ident:int,s:Session=Depends(db)):
        p=s.get(Peer, ident)
        if not p or p.owner == service.PROBE_OWNER: raise HTTPException(404,"unknown peer")
        nodes=placed_nodes(s,p.instance_id)
        if not service.remove_peer(s,ident,cipher): raise HTTPException(404,"unknown peer")
        kick(s,nodes); return Response(status_code=204)

    @app.get("/v1/peers/{ident}/config",dependencies=[Depends(auth)])
    def peer_config(ident:int,endpoint_host:str|None=None,s:Session=Depends(db)):
        p=s.get(Peer, ident)
        if not p or p.owner == service.PROBE_OWNER: raise HTTPException(404,"unknown peer")
        instance=s.get(Instance,p.instance_id)
        endpoint_host=instance.endpoint_host or endpoint_host or os.getenv("WGOCTOPUS_CLIENT_ENDPOINT_HOST")
        if not endpoint_host: raise HTTPException(422,"endpoint_host is required")
        text=service.render_client_config(s,ident,endpoint_host,crypto=cipher)
        s.add(Event(kind="peer.config_issued",subject=str(ident),data={}))
        return Response(text,media_type="text/plain",headers={"Cache-Control":"no-store"})

    def probe_dict(p):
        result = app.state.reconciler.probe_statuses().get(p.id) if app.state.reconciler and callable(getattr(app.state.reconciler, "probe_statuses", None)) else None
        return dict(id=p.id, hop_id=p.hop_id, instance_id=p.instance_id,
                    runner_node_id=p.runner_node_id, interface=probe_iface_name(p.id), created_at=p.created_at,
                    status=result.state.value if result else "UNKNOWN",
                    handshake_age_seconds=int(result.age_seconds) if result and result.age_seconds is not None else None)

    @app.post("/v1/probes", dependencies=[Depends(auth)], status_code=201)
    def create_probe(body: ProbeIn, s: Session = Depends(db)):
        try:
            p = service.create_probe(s, body.hop_id, body.instance_id, body.runner_node_id, crypto=cipher)
        except ValueError as exc:
            if "already exists" in str(exc):
                raise HTTPException(409, str(exc)) from exc
            raise
        kick(s, [p.runner_node_id, *placed_nodes(s, p.instance_id)])
        return probe_dict(p)

    @app.get("/v1/probes", dependencies=[Depends(auth)])
    def get_probes(hop_id: int | None = None, instance_id: int | None = None,
                   runner_node_id: int | None = None, s: Session = Depends(db)):
        query = select(Probe).order_by(Probe.id)
        for field, value in ((Probe.hop_id, hop_id), (Probe.instance_id, instance_id),
                             (Probe.runner_node_id, runner_node_id)):
            if value is not None:
                query = query.where(field == value)
        return [probe_dict(p) for p in s.scalars(query).all()]

    @app.get("/v1/probes/{ident}", dependencies=[Depends(auth)])
    def get_probe(ident: int, s: Session = Depends(db)):
        p = s.get(Probe, ident)
        if not p: raise HTTPException(404, "unknown probe")
        return probe_dict(p)

    @app.delete("/v1/probes/{ident}", dependencies=[Depends(auth)], status_code=204)
    def remove_probe(ident: int, s: Session = Depends(db)):
        p = s.get(Probe, ident)
        if not p: raise HTTPException(404, "unknown probe")
        runner = p.runner_node_id
        instance_id = p.instance_id
        service.delete_probe(s, ident, cipher)
        if app.state.reconciler and callable(getattr(app.state.reconciler, "forget_probe", None)):
            app.state.reconciler.forget_probe(ident)
        kick(s, [runner, *placed_nodes(s, instance_id)])
        return Response(status_code=204)

    @app.post("/v1/nodes/{ident}/reconcile",dependencies=[Depends(auth)],status_code=202)
    def reconcile(ident:int, s: Session=Depends(db)):
        if not s.get(Node, ident): raise HTTPException(404,"unknown node")
        r=app.state.reconciler
        if not r: raise HTTPException(503,"reconciler disabled")
        r.kick(ident,force=True); return {"status":"accepted"}

    @app.post("/v1/nodes/{ident}/apply-dangerous",dependencies=[Depends(auth)])
    async def apply_dangerous(ident:int,body:dict,s:Session=Depends(db)):
        if body!={"confirm":True}: raise HTTPException(422,"confirm must be true")
        if not s.get(Node, ident): raise HTTPException(404,"unknown node")
        r=app.state.reconciler
        if not r: raise HTTPException(503,"reconciler disabled")
        outcome=await r.apply_dangerous(ident)
        return {"status":outcome.status.value,"error":outcome.error}

    @app.get("/v1/events",dependencies=[Depends(auth)])
    def events(limit:int=Query(100,ge=1,le=1000),kind:str|None=None,subject:str|None=None,s:Session=Depends(db)):
        q=select(Event).order_by(Event.id.desc())
        if kind:q=q.where(Event.kind==kind)
        if subject:q=q.where(Event.subject==subject)
        return [dict(id=e.id,ts=e.ts,kind=e.kind,subject=e.subject,data=e.data) for e in s.scalars(q.limit(limit)).all()]

    @app.get("/v1/status",dependencies=[Depends(auth)])
    def status(s:Session=Depends(db)):
        states={k:0 for k in ["IN_SYNC","SYNCING","UNREACHABLE","BLOCKED_DANGEROUS","BLOCKED_REVISION_AHEAD","BLOCKED_INVALID","BLOCKED_AUTH","DISABLED","UNKNOWN"]}
        statuses=app.state.reconciler.status().values() if app.state.reconciler else []
        for st in statuses: states[st.state.value]+=1
        return {"nodes_by_state":states,"nodes_unhealthy":s.scalar(select(__import__("sqlalchemy").func.count(NodeObserved.node_id)).where(NodeObserved.healthy.is_(False))),
                "instances":s.scalar(select(__import__("sqlalchemy").func.count(Instance.id))),"peers":s.scalar(select(__import__("sqlalchemy").func.count(Peer.id)).where(or_(Peer.owner.is_(None), Peer.owner != service.PROBE_OWNER)))}

    def user_json(u, s):
        return dict(username=u.username, tg_id=u.tg_id, role=u.role, config_limit=u.config_limit,
                    status=u.status, created_at=u.created_at, disabled_at=u.disabled_at,
                    disabled_by=u.disabled_by, language=u.language,
                    device_count=users.count_user_devices(s, u.username))

    def user_call(fn, *args, **kwargs):
        try: return fn(*args, **kwargs)
        except users.UserError as exc:
            status = {"not_found":404,"conflict":409,"forbidden":403,"not_allowed":409,"invalid":422}[exc.code]
            raise HTTPException(status, detail={"error":exc.code,"detail":str(exc)}) from None

    @app.post("/v1/users/resolve", dependencies=[Depends(auth)])
    def resolve_user(body: ResolveUserIn, s: Session = Depends(db)):
        u = user_call(users.resolve_user, s, body.tg_id, body.username, language=body.language)
        if not u: raise HTTPException(404, detail={"error":"not_found","detail":"user not found"})
        return user_json(u, s)

    @app.put("/v1/users/{username}", dependencies=[Depends(auth)])
    def put_user(username: str, body: UserEnsureIn, s: Session = Depends(db)):
        existed = user_call(users.get_user, s, username)
        u = user_call(users.ensure_admin, s, username) if body.role == "admin" else user_call(users.ensure_user, s, username, config_limit=body.config_limit)
        return JSONResponse(status_code=200 if existed else 201, content=jsonable_encoder(user_json(u, s)))

    @app.get("/v1/users", dependencies=[Depends(auth)])
    def list_users(status: str | None = None, role: str | None = None, s: Session = Depends(db)):
        return [user_json(u, s) for u in users.list_users(s, status, role)]

    @app.get("/v1/users/{username}", dependencies=[Depends(auth)])
    def get_user(username: str, s: Session = Depends(db)):
        u = user_call(users.get_user, s, username)
        if not u: raise HTTPException(404, detail={"error": "not_found", "detail": "user not found"})
        return user_json(u, s)

    @app.patch("/v1/users/{username}", dependencies=[Depends(auth)])
    def patch_user(username: str, body: UserPatchIn, s: Session = Depends(db)):
        u = user_call(users.get_user, s, username)
        if body.config_limit is not None: u = user_call(users.set_limit, s, username, body.config_limit)
        if body.role is not None: u = user_call(users.set_role, s, username, body.role)
        return user_json(u, s)

    @app.post("/v1/users/{username}/disable", dependencies=[Depends(auth)])
    def disable_user(username: str, body: DisableIn, s: Session = Depends(db)):
        ids = s.scalars(select(Peer.instance_id).where(Peer.owner == users.normalize_username(username))).all()
        u = user_call(users.disable_user, s, username, body.by, crypto=cipher)
        for iid in ids: kick(s, placed_nodes(s, iid))
        return user_json(u, s)

    @app.post("/v1/users/{username}/enable", dependencies=[Depends(auth)])
    def enable_user(username: str, s: Session = Depends(db)):
        ids = s.scalars(select(Peer.instance_id).where(Peer.owner == users.normalize_username(username))).all()
        u = user_call(users.enable_user, s, username, crypto=cipher)
        for iid in ids: kick(s, placed_nodes(s, iid))
        return user_json(u, s)

    @app.delete("/v1/users/{username}", dependencies=[Depends(auth)], status_code=204)
    def delete_user(username: str, s: Session = Depends(db)):
        ids = s.scalars(select(Peer.instance_id).where(Peer.owner == users.normalize_username(username))).all()
        user_call(users.delete_user, s, username, crypto=cipher)
        for iid in ids: kick(s, placed_nodes(s, iid))
        return Response(status_code=204)

    def device_json(p, s):
        instance = s.get(Instance, p.instance_id)
        scrapes = app.state.reconciler.scrapes() if app.state.reconciler and callable(getattr(app.state.reconciler, "scrapes", None)) else {}
        stats = device_stats(scrapes, instance.name, p.public_key, time.time())
        return {**peer(p), "instance": instance.name, **stats}

    def get_device(s, ident):
        p = s.get(Peer, ident)
        if not p or p.owner == service.PROBE_OWNER:
            raise HTTPException(404, detail={"error": "not_found", "detail": "device not found"})
        return p

    @app.get("/v1/users/{username}/devices", dependencies=[Depends(auth)])
    def user_devices(username: str, s: Session = Depends(db)):
        u = user_call(users.get_user, s, username)
        peers = s.scalars(select(Peer).where(Peer.owner == u.username).order_by(Peer.id)).all()
        return [device_json(p, s) for p in peers]

    @app.get("/v1/devices", dependencies=[Depends(auth)])
    def list_devices(owner: str | None = None, enabled: bool | None = None, active: bool | None = None,
                     limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
                     s: Session = Depends(db)):
        query = select(Peer).where(Peer.owner != service.PROBE_OWNER).order_by(Peer.id)
        if owner is not None:
            query = query.where(Peer.owner == users.normalize_username(owner))
        if enabled is not None:
            query = query.where(Peer.enabled.is_(enabled))
        items = [device_json(p, s) for p in s.scalars(query).all()]
        if active is not None:
            items = [item for item in items if item["active"] is active]
        return {"total": len(items), "items": items[offset:offset + limit]}

    @app.post("/v1/users/{username}/devices", dependencies=[Depends(auth)], status_code=201)
    def create_user_device(username: str, body: DeviceIn, s: Session = Depends(db)):
        if not s.get(Instance, body.instance_id):
            raise HTTPException(404, detail={"error": "not_found", "detail": "instance not found"})
        p = user_call(users.create_device, s, username, body.name, body.instance_id, crypto=cipher, admin_bypass=body.admin_bypass)
        kick(s, placed_nodes(s, body.instance_id))
        return device_json(p, s)

    @app.get("/v1/devices/{ident}", dependencies=[Depends(auth)])
    def read_device(ident: int, s: Session = Depends(db)):
        return device_json(get_device(s, ident), s)

    @app.patch("/v1/devices/{ident}", dependencies=[Depends(auth)])
    def patch_device(ident: int, body: DevicePatchIn, s: Session = Depends(db)):
        p = get_device(s, ident)
        data = body.model_dump(exclude_unset=True)
        if data.get("name") is not None:
            user_call(users.rename_device, s, ident, data["name"])
        if data.get("enabled") is not None:
            service.set_peer_enabled(s, ident, data["enabled"], cipher)
            kick(s, placed_nodes(s, p.instance_id))
        s.refresh(p)
        return device_json(p, s)

    @app.delete("/v1/devices/{ident}", dependencies=[Depends(auth)], status_code=204)
    def delete_device(ident: int, s: Session = Depends(db)):
        p = get_device(s, ident)
        nodes = placed_nodes(s, p.instance_id)
        service.remove_peer(s, ident, cipher)
        kick(s, nodes)
        return Response(status_code=204)

    @app.post("/v1/requests", dependencies=[Depends(auth)], status_code=201)
    def create_request(body: RequestIn, s: Session = Depends(db)):
        r = user_call(users.create_request, s, body.type, body.tg_id, body.username, body.first_name, body.last_name, body.requested_limit)
        return request_json(r)

    def request_json(r):
        return dict(id=r.id,type=r.type,status=r.status,tg_id=r.tg_id,username=r.username,first_name=r.first_name,last_name=r.last_name,requested_limit=r.requested_limit,previous_limit=r.previous_limit,admin_id=r.admin_id,admin_username=r.admin_username,requested_at=r.requested_at,decided_at=r.decided_at,notification_refs=r.notification_refs)

    @app.get("/v1/requests", dependencies=[Depends(auth)])
    def get_requests(status: str | None = None, type: str | None = None, username: str | None = None, limit: int = Query(100,ge=1,le=500), offset: int = Query(0,ge=0), s: Session = Depends(db)):
        return [request_json(r) for r in users.list_requests(s,status,type,username,limit,offset)]

    @app.get("/v1/requests/{ident}", dependencies=[Depends(auth)])
    def get_request(ident: int, s: Session = Depends(db)):
        r=s.get(UserRequest,ident)
        if not r: raise HTTPException(404,detail={"error":"not_found","detail":"request not found"})
        return request_json(r)

    @app.post("/v1/requests/{ident}/approve", dependencies=[Depends(auth)])
    def approve_request(ident: int, body: ApproveIn, s: Session = Depends(db)):
        r=user_call(users.approve_request,s,ident,body.admin_tg_id,body.admin_username,body.default_limit)
        return request_json(r)

    @app.post("/v1/requests/{ident}/decline", dependencies=[Depends(auth)])
    def decline_request(ident: int, body: DecisionIn, s: Session = Depends(db)):
        return request_json(user_call(users.decline_request,s,ident,body.admin_tg_id,body.admin_username))

    @app.put("/v1/requests/{ident}/refs", dependencies=[Depends(auth)])
    def request_refs(ident: int, body: RefsIn, s: Session = Depends(db)):
        return request_json(user_call(users.set_request_refs,s,ident,body.refs))

    return app
