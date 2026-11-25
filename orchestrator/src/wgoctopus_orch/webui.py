"""Server-rendered admin UI: Jinja2 pages with HTMX fragments.

Pages authenticate with the session cookie only (never the static bearer token) and
never expose /v1 to cookie sessions; they call the same service functions as the API.
"""
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from . import awgcps, awgparams, service, service_users, webauth
from .models import Event, HopLink, Instance, Node, Peer, Placement, Probe, UserRequest, WebAccount
from .provision import ProvisionError

HERE = Path(__file__).parent
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}
NAV = [("/ui/", "Dashboard"), ("/ui/nodes", "Nodes"), ("/ui/instances", "Instances"), ("/ui/failover", "Failover"),
       ("/ui/requests", "Requests"), ("/ui/bootstrap", "Bootstrap")]
PEER_PAGE = 50
FAILOVER_ERRORS = {
    "not_pending": "This proposal was already decided.", "expired": "This proposal has expired.",
    "stale": "The fleet changed since this proposal was made; wait for a new one.",
    "no_candidate": "No healthy candidate node is available right now.", "not_found": "Proposal not found.",
}
LIST_PAGE = 50
FAILOVER_STATES = ("pending", "executed", "rejected", "expired", "cancelled", "failed")
REQUEST_STATES = ("pending", "approved", "declined")
STATE_CLASS = {"IN_SYNC": "ok", "SYNCING": "warn", "DISABLED": "muted", "UNKNOWN": "muted",
               "succeeded": "ok", "running": "warn", "queued": "warn", "failed": "bad", "cancelled": "muted",
               "ok": "ok", "pending": "muted", "skipped": "muted",
               "executed": "ok", "rejected": "muted", "expired": "muted", "approved": "ok", "declined": "muted"}
ACTIVE_JOB = ("queued", "running")


def fmt_ts(value):
    return value.strftime("%Y-%m-%d %H:%M:%S") if hasattr(value, "strftime") else "-"


def build_env():
    env = Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
    env.filters["ts"] = fmt_ts
    return env


def mount(app, *, sessions, lookup, status, nodes, node_view, provision, instances, instance_view, peers_page, ops,
          failovers, failover_info, requests, bootstrap_info, save_failover_settings=None, crypto=None, kick=None,
          revoke_account=None):
    """Register UI routes.

    `lookup(cookie)` returns a session info or None; `status(session)` is the fleet summary;
    `nodes(session)` lists node views, `node_view(session, id)` returns one or None;
    `provision()` returns the provisioning runner; `instances(session)`, `instance_view(session, id)` and
    `peers_page(session, id, limit, offset)` read instances and peers; `ops` holds the operations shared with
    the API (add_peer, set_enabled, remove_peer, config, switch, failover, approve, decline, bootstrap).
    `failovers(session, state, limit, offset)`, `failover_info()`, `requests(session, status, limit, offset)`
    and `bootstrap_info()` feed the failover, requests and bootstrap pages.
    """
    env = build_env()
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def render(template, request, info=None, status_code=200, **ctx):
        nav = NAV + ([("/ui/users", "Users"), ("/ui/accounts", "Accounts"), ("/ui/devices", "Devices")]
                     if info and webauth.has_role(info.role, "operator") else [])
        body = env.get_template(template).render(info=info, nav=nav, path=request.url.path, state_class=STATE_CLASS, **ctx)
        return HTMLResponse(body, status_code=status_code, headers=SECURITY_HEADERS)

    def message(request, info, status_code, text):
        return render("message.html", request, info, status_code=status_code, message=text)

    @app.get("/ui/users", include_in_schema=False)
    def users_page(request: Request):
        info, denied = check(request, "operator")
        if denied: return denied
        with sessions() as s: users = service_users.list_users(s)
        return render("users.html", request, info, users=users, editable=info.role == "admin")

    @app.post("/ui/users/create", include_in_schema=False)
    async def users_create(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            with sessions.begin() as s:
                role = form.get("role", "user")
                if role not in {"admin", "user"}:
                    raise service_users.UserError("invalid", "invalid role")
                if service_users.get_user(s, form.get("username", "")):
                    raise service_users.UserError("conflict", "user already exists")
                tg_id = int(form["tg_id"]) if form.get("tg_id") else None
                if role == "admin" and not tg_id:
                    raise service_users.UserError("invalid", "admin requires Telegram id")
                user = service_users.ensure_user(s, form.get("username", ""), role="user",
                                                 tg_id=tg_id, config_limit=int(form.get("config_limit", "3")))
                if tg_id is not None:
                    user.tg_id = tg_id
                if role == "admin" and user.role != "admin":
                    service_users.set_role(s, user.username, "admin")
            return RedirectResponse("/ui/users", status_code=303, headers=SECURITY_HEADERS)
        except (ValueError, service_users.UserError, IntegrityError):
            return message(request, info, 400, "Invalid user details.")

    @app.post("/ui/users/{username}/update", include_in_schema=False)
    async def users_update(username: str, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            kick_ids = []
            with sessions.begin() as s:
                user = service_users.get_user(s, username)
                if not user: return message(request, info, 404, "User not found.")
                if form.get("tg_id", ""):
                    user.tg_id = int(form["tg_id"])
                new_username = service_users.normalize_username(form.get("username", user.username))
                if new_username != user.username:
                    old_username = user.username
                    if user.tg_id is not None:
                        service_users.resolve_user(s, user.tg_id, new_username)
                    else:
                        if service_users.get_user(s, new_username):
                            raise service_users.UserError("conflict", "username already exists")
                        user.username = new_username
                        s.query(Peer).filter(Peer.owner == old_username).update({Peer.owner: new_username})
                        s.query(UserRequest).filter(UserRequest.username == old_username).update({UserRequest.username: new_username})
                        service._event(s, "user.renamed", old_username, {"username": new_username})
                role = form.get("role", user.role)
                if role != user.role: service_users.set_role(s, user.username, role)
                service_users.set_limit(s, user.username, int(form.get("config_limit", str(user.config_limit))))
                status = form.get("status", user.status)
                if status != user.status:
                    kick_ids = s.scalars(select(Peer.instance_id).where(Peer.owner == user.username)).all()
                    if status == "disabled": service_users.disable_user(s, user.username, info.username, crypto=crypto)
                    elif status == "enabled": service_users.enable_user(s, user.username, crypto=crypto)
                    else: raise service_users.UserError("invalid", "invalid status")
            if kick and kick_ids: kick(list(set(kick_ids)))
            return RedirectResponse("/ui/users", status_code=303, headers=SECURITY_HEADERS)
        except (ValueError, service_users.UserError, IntegrityError):
            return message(request, info, 400, "Invalid user details.")

    @app.post("/ui/users/{username}/delete", include_in_schema=False)
    async def users_delete(username: str, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            with sessions.begin() as s:
                user = service_users.get_user(s, username)
                if not user: raise service_users.UserError("not_found", "user not found")
                kick_ids = s.scalars(select(Peer.instance_id).where(Peer.owner == user.username)).all()
                service_users.delete_user(s, username, crypto=crypto)
            if kick and kick_ids: kick(list(set(kick_ids)))
            return RedirectResponse("/ui/users", status_code=303, headers=SECURITY_HEADERS)
        except service_users.UserError:
            return message(request, info, 400, "User cannot be deleted.")

    @app.get("/ui/accounts", include_in_schema=False)
    def accounts_page(request: Request):
        info, denied = check(request, "operator")
        if denied: return denied
        with sessions() as s: accounts = webauth.list_accounts(s)
        return render("accounts.html", request, info, accounts=accounts, editable=info.role == "admin")

    @app.post("/ui/accounts/{account_id}/update", include_in_schema=False)
    async def account_update(account_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        if account_id == info.account_id and (form.get("role") != "admin" or form.get("enabled") != "on"):
            return message(request, info, 400, "You cannot disable or demote your own account.")
        try:
            with sessions.begin() as s:
                account = s.get(WebAccount, account_id)
                if not account: return message(request, info, 404, "Account not found.")
                webauth.set_role(s, account, form.get("role", account.role))
                webauth.set_enabled(s, account, form.get("enabled") == "on")
            if revoke_account and form.get("enabled") != "on":
                revoke_account(account_id)
            return RedirectResponse("/ui/accounts", status_code=303, headers=SECURITY_HEADERS)
        except webauth.WebAuthError:
            return message(request, info, 400, "Account change denied.")
    @app.post("/ui/accounts/create", include_in_schema=False)
    async def account_create(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            with sessions.begin() as s:
                webauth.create_account(s, form.get("username", ""), form.get("password", ""),
                                       form.get("role", "viewer"))
            return RedirectResponse("/ui/accounts", status_code=303, headers=SECURITY_HEADERS)
        except webauth.WebAuthError:
            return message(request, info, 400, "Invalid account details.")
    @app.post("/ui/accounts/{account_id}/password", include_in_schema=False)
    async def account_password(account_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            with sessions.begin() as s:
                account = s.get(WebAccount, account_id)
                if not account: return message(request, info, 404, "Account not found.")
                webauth.set_password(s, account, form.get("password", ""))
            if revoke_account: revoke_account(account_id)
            return RedirectResponse("/ui/accounts", status_code=303, headers=SECURITY_HEADERS)
        except webauth.WebAuthError:
            return message(request, info, 400, "Password reset denied.")

    @app.post("/ui/accounts/{account_id}/delete", include_in_schema=False)
    async def account_delete(account_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        if account_id == info.account_id: return message(request, info, 400, "You cannot delete your own account.")
        try:
            with sessions.begin() as s:
                account = s.get(WebAccount, account_id)
                if not account: return message(request, info, 404, "Account not found.")
                webauth.delete_account(s, account)
            if revoke_account: revoke_account(account_id)
            return RedirectResponse("/ui/accounts", status_code=303, headers=SECURITY_HEADERS)
        except webauth.WebAuthError:
            return message(request, info, 400, "Account deletion denied.")

    @app.get("/ui/devices", include_in_schema=False)
    def devices_page(request: Request):
        info, denied = check(request, "operator")
        if denied: return denied
        with sessions() as s:
            devices = s.execute(select(Peer, Instance.name).join(Instance, Peer.instance_id == Instance.id)
                                 .where(or_(Peer.owner.is_(None), Peer.owner != service.PROBE_OWNER))
                                 .order_by(Peer.id).limit(500)).all()
            users = service_users.list_users(s)
            available_instances = instances(s)
        return render("devices.html", request, info, devices=devices, users=users, instances=available_instances)

    @app.post("/ui/devices/{peer_id}/owner", include_in_schema=False)
    async def device_owner(peer_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            with sessions.begin() as s:
                peer = s.get(Peer, peer_id)
                if not peer: raise service_users.UserError("not_found", "peer not found")
                if peer.owner == service.PROBE_OWNER: raise service_users.UserError("forbidden", "reserved peer")
                owner = form.get("owner", "")
                user = service_users.get_user(s, owner) if owner else None
                if owner and not user: raise service_users.UserError("not_found", "owner not found")
                old_owner = peer.owner
                peer.owner = user.username if user else None
                s.add(Event(kind="device.owner_changed", subject=str(peer.id),
                            data={"from": old_owner, "to": peer.owner, "actor": info.username}))
                instance_id = peer.instance_id
            if kick: kick([instance_id])
            return RedirectResponse("/ui/devices", status_code=303, headers=SECURITY_HEADERS)
        except service_users.UserError:
            return message(request, info, 400, "Invalid device owner.")
    @app.post("/ui/devices/create", include_in_schema=False)
    async def device_create(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            with sessions.begin() as s:
                peer = service_users.create_device(s, form.get("owner", ""), form.get("name", ""),
                                                   int(form.get("instance_id", "")), crypto=crypto)
                instance_id = peer.instance_id
            if kick: kick([instance_id])
            return RedirectResponse("/ui/devices", status_code=303, headers=SECURITY_HEADERS)
        except (ValueError, service_users.UserError):
            return message(request, info, 400, "Invalid device details.")
    @app.post("/ui/devices/{peer_id}/revoke", include_in_schema=False)
    async def device_revoke(peer_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied: return denied
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")): return Response(status_code=403, headers=SECURITY_HEADERS)
        with sessions.begin() as s:
            peer = s.get(Peer, peer_id)
            if not peer or peer.owner == service.PROBE_OWNER: return message(request, info, 404, "Device not found.")
            ops.remove_peer(s, peer_id)
        return RedirectResponse("/ui/devices", status_code=303, headers=SECURITY_HEADERS)

    def actor(request):
        return lookup(request.cookies.get("wgoctopus_session"))

    def check(request, min_role="viewer", *, write=False, page=True):
        """Return (info, None) when allowed, else (None, response). Pages redirect/render, fragments use bare statuses."""
        info = actor(request)
        if not info:
            return None, RedirectResponse("/login", status_code=303, headers=SECURITY_HEADERS) if page else Response(status_code=401, headers=SECURITY_HEADERS)
        if not webauth.has_role(info.role, min_role):
            return None, message(request, info, 403, f"Your role ({info.role}) cannot open this page.") if page else Response(status_code=403, headers=SECURITY_HEADERS)
        if write and not webauth.check_csrf(info, request.headers.get("x-csrf-token")):
            return None, Response(status_code=403, headers=SECURITY_HEADERS)
        return info, None

    @app.get("/", include_in_schema=False)
    def index(request: Request):
        return RedirectResponse("/ui/" if actor(request) else "/login", status_code=303, headers=SECURITY_HEADERS)

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request):
        if actor(request):
            return RedirectResponse("/ui/", status_code=303, headers=SECURITY_HEADERS)
        return render("login.html", request, oidc=app.state.oidc is not None)

    # dashboard
    def dashboard_data():
        with sessions() as s:
            events = [{"ts": e.ts, "kind": e.kind, "subject": e.subject} for e in s.scalars(select(Event).order_by(Event.id.desc()).limit(10))]
            return {"summary": status(s), "events": events}

    @app.get("/ui/", include_in_schema=False)
    def dashboard(request: Request):
        info, denied = check(request)
        return denied or render("dashboard.html", request, info, **dashboard_data())

    @app.get("/ui/fragments/status", include_in_schema=False)
    def status_fragment(request: Request):
        info, denied = check(request, page=False)
        return denied or render("_status.html", request, info, **dashboard_data())

    # nodes
    def nodes_data():
        with sessions() as s:
            return {"nodes": nodes(s)}

    @app.get("/ui/nodes", include_in_schema=False)
    def nodes_page(request: Request):
        info, denied = check(request)
        return denied or render("nodes.html", request, info, can_create=webauth.has_role(info.role, "admin"), **nodes_data())
    @app.post("/ui/nodes/create", include_in_schema=False)
    async def node_create(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = {key: values[0] for key, values in parse_qs(
            (await request.body()).decode("utf-8", "replace")
        ).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        def val(key, default=None):
            value = str(form.get(key, "")).strip()
            return value or default
        try:
            name = val("name")
            ssh_port = int(val("ssh_port", "22"))
            agent_port = int(val("agent_port", "18080"))
            mode, kind = val("mgmt_mode", "push"), val("kind", "awg")
            if not name or len(name) > 64 or not 1 <= ssh_port <= 65535 or not 1 <= agent_port <= 65535 \
                    or mode not in {"push", "pull", "auto"} or kind not in {"awg", "hop"}:
                raise ValueError
            with sessions.begin() as s:
                node = service.create_node(
                    s, name, val("ssh_host", "-"), val("ssh_user", "pull"),
                    ssh_port=ssh_port, mgmt_mode=mode,
                    ssh_private_key=val("ssh_private_key"), ssh_public_key=val("ssh_public_key"),
                    ssh_password=val("ssh_password"),
                    agent_port=agent_port, enabled=val("enabled") == "on",
                    kind=kind, crypto=crypto,
                    provision_options={"harden": form.get("harden") == "on"},
                )
                ident = node.id
            return Response(status_code=303, headers={**SECURITY_HEADERS, "Location": f"/ui/nodes/{ident}"})
        except (ValueError, TypeError):
            return render("_error.html", request, info, text="Invalid node details.")

    @app.get("/ui/fragments/nodes", include_in_schema=False)
    def nodes_fragment(request: Request):
        info, denied = check(request, page=False)
        return denied or render("_nodes.html", request, info, **nodes_data())

    @app.get("/ui/nodes/{node_id}", include_in_schema=False)
    def node_page(node_id: int, request: Request):
        info, denied = check(request)
        if denied:
            return denied
        with sessions() as s:
            node = node_view(s, node_id)
        if node is None:
            return message(request, info, 404, "Node not found.")
        jobs = provision().list_jobs(node_id, 10)
        return render("node.html", request, info, node=node, jobs=jobs, can_provision=webauth.has_role(info.role, "admin"))

    @app.post("/ui/nodes/{node_id}/provision", include_in_schema=False)
    async def provision_start(node_id: int, request: Request, confirm: bool = False):
        info, denied = check(request, "admin", write=True, page=False)
        if denied:
            return denied
        with sessions() as s:
            node = node_view(s, node_id)
        if node is None:
            return Response(status_code=404, headers=SECURITY_HEADERS)
        options = {k: v for k, v in (node["provision"] or {}).items() if k != "auto"}
        runner = provision()
        try:
            job_id = runner.create_job(node_id, options, confirm_protected=confirm)
        except ProvisionError as exc:
            return render("_error.html", request, info, text=str(exc))
        runner.run_in_background(job_id)
        with sessions.begin() as s:
            service._event(s, "web.provision_start", info.username, {"node_id": node_id, "job_id": job_id})
        return Response(status_code=204, headers={**SECURITY_HEADERS, "HX-Redirect": f"/ui/jobs/{job_id}"})

    # provisioning jobs (logs are admin-only)
    @app.get("/ui/jobs/{job_id}", include_in_schema=False)
    def job_page(job_id: int, request: Request):
        info, denied = check(request, "admin")
        if denied:
            return denied
        job = provision().job_view(job_id)
        if job is None:
            return message(request, info, 404, "Job not found.")
        return render("job.html", request, info, job=job, active=ACTIVE_JOB)

    @app.get("/ui/fragments/jobs/{job_id}", include_in_schema=False)
    def job_fragment(job_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        job = provision().job_view(job_id)
        if job is None:
            return Response(status_code=404, headers=SECURITY_HEADERS)
        return render("_job.html", request, info, job=job, active=ACTIVE_JOB)

    @app.post("/ui/jobs/{job_id}/cancel", include_in_schema=False)
    def job_cancel(job_id: int, request: Request):
        info, denied = check(request, "admin", write=True, page=False)
        if denied:
            return denied
        runner = provision()
        if runner.job_view(job_id) is None:
            return Response(status_code=404, headers=SECURITY_HEADERS)
        if not runner.cancel(job_id):
            return render("_error.html", request, info, text="Job is not running.")
        with sessions.begin() as s:
            service._event(s, "web.provision_cancel", info.username, {"job_id": job_id})
        return Response(status_code=204, headers=SECURITY_HEADERS)

    # instances and peers
    def audit(kind, info, data):
        with sessions.begin() as s:
            service._event(s, kind, info.username, data)

    def run(op, *args, **kwargs):
        """Run an API operation in its own transaction; returns (result, error text)."""
        with sessions() as s:
            try:
                result = op(s, *args, **kwargs)
                s.commit()
                return result, None
            except HTTPException as exc:
                s.rollback()
                detail = exc.detail
                return None, str(detail.get("detail", detail.get("error")) if isinstance(detail, dict) else detail)
            except ValueError as exc:
                s.rollback()
                return None, str(exc)

    def refreshed(request, info, error):
        if error:
            return render("_error.html", request, info, text=error)
        return Response(status_code=204, headers={**SECURITY_HEADERS, "HX-Refresh": "true"})

    @app.get("/ui/instances", include_in_schema=False)
    def instances_page(request: Request):
        info, denied = check(request)
        if denied:
            return denied
        with sessions() as s:
            return render("instances.html", request, info, instances=instances(s), node_names={n["id"]: n["name"] for n in nodes(s)},
                          can_create=webauth.has_role(info.role, "admin"))
    @app.post("/ui/instances/create", include_in_schema=False)
    async def instance_create(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = {key: values[0] for key, values in parse_qs(
            (await request.body()).decode("utf-8", "replace")
        ).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            name = str(form.get("name", "")).strip()
            port = int(form.get("listen_port", ""))
            if not 1 <= port <= 65535:
                raise ValueError
            version = form.get("awg_version", "3.1")
            mtu = int(form.get("mtu", "1280" if version in ("3.0", "3.1") else "1500"))
            obfuscation = json.loads(form["obfuscation_json"]) if form.get("obfuscation_json") else None
            if obfuscation is not None and any(f["severity"] == "error" for f in _awg_findings(obfuscation, version, mtu)):
                raise ValueError
            with sessions.begin() as s:
                instance = service.create_instance(
                    s, name, port,
                    str(form.get("address", "")).strip(),
                    obfuscation=obfuscation, mtu=mtu, awg_version=version,
                    endpoint_host=str(form.get("endpoint_host", "")).strip() or None,
                    crypto=crypto,
                )
                ident = instance.id
            return Response(status_code=303, headers={**SECURITY_HEADERS, "Location": f"/ui/instances/{ident}"})
        except (ValueError, TypeError, json.JSONDecodeError):
            return render("_error.html", request, info, text="Invalid instance details.")

    @app.post("/ui/instances/generate", include_in_schema=False)
    async def instance_generate(request: Request):
        _info, denied = check(request, "admin", write=True, page=False)
        if denied:
            return denied
        try:
            from .api import AwgGenerateIn
            payload = AwgGenerateIn.model_validate(await request.json()).model_dump()
            version = payload.pop("awg_version")
            mtu = payload.pop("mtu") or (1280 if version in ("3.0", "3.1") else 1500)
            mimic_profile, mimic_host = payload.pop("mimic_profile"), payload.pop("mimic_host")
            payload.pop("version", None)
            fixed_s = {}
            for i in range(1, 5):
                value = payload.pop(f"s{i}")
                if value is not None:
                    fixed_s[f"s{i}"] = value
            payload["fixed_s"] = fixed_s
            values = awgparams.generate_obfuscation(version, mtu, **payload)
            if mimic_profile != "none":
                values.update(awgcps.generate_cps(mimic_profile, mtu=mtu, intensity=payload["intensity"], host=mimic_host))
            findings = _awg_findings(values, version, mtu)
            return JSONResponse({"obfuscation": values, "findings": findings}, headers=SECURITY_HEADERS)
        except (ValueError, TypeError, json.JSONDecodeError):
            return JSONResponse({"findings": [{"severity": "error", "field": "", "message": "Invalid AWG generation options."}]},
                                status_code=422, headers=SECURITY_HEADERS)

    @app.post("/ui/instances/validate", include_in_schema=False)
    async def instance_validate(request: Request):
        _info, denied = check(request, "admin", write=True, page=False)
        if denied:
            return denied
        try:
            from .api import AwgValidateIn
            payload = AwgValidateIn.model_validate(await request.json())
            findings = _awg_findings(payload.obfuscation, payload.awg_version, payload.mtu)
            return JSONResponse({"findings": findings}, headers=SECURITY_HEADERS)
        except (ValueError, TypeError):
            return JSONResponse({"findings": [{"severity": "error", "field": "", "message": "Invalid validation request."}]},
                                status_code=422, headers=SECURITY_HEADERS)

    def _awg_findings(values, version, mtu):
        if not isinstance(values, dict) or any(not isinstance(k, str) or not isinstance(v, (str, int, bool))
                                               for k, v in values.items()):
            return [{"severity": "error", "field": "obfuscation", "message": "Parameters must be scalar values."}]
        errors = awgparams.validate_obfuscation(values, mtu=mtu, version=version)
        errors += awgcps.validate_cps_chain({f"i{i}": values.get(f"i{i}", "") for i in range(1, 6)})
        collisions = [error for error in errors if "S collision" in error or "padded S sizes overlap" in error]
        errors = [error for error in errors if error not in collisions]
        warnings = (["s1-s4: S values collide; adjust them to avoid packet size collisions"] if collisions else [])
        if values.get("random_trailers") and version != "3.1":
            warnings.append(f"random_trailers: not supported by AWG {version}; requested setting was omitted")
        if values.get("random_trailers"):
            for i in range(1, 4):
                parts = str(values.get(f"h{i}", "")).split("-")
                if len(parts) == 2 and all(part.isdigit() for part in parts) and int(parts[1]) - int(parts[0]) > 10_000:
                    warnings.append("random_trailers: h1-h3 ranges wider than 10000 may cause packet loss; use narrow H ranges")
                    break
        if ("random_trailers" in values and "disable_cookies" in values
                and values["random_trailers"] != values["disable_cookies"]):
            warnings.append("random_trailers and disable_cookies are usually enabled together")
        findings = [{"severity": "error", "field": error.split(":", 1)[0] if ":" in error else "", "message": error}
                    for error in errors]
        findings.extend({"severity": "warning", "field": warning.split(":", 1)[0], "message": warning}
                        for warning in warnings)
        return findings

    @app.post("/ui/instances/import", include_in_schema=False)
    async def instance_import(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        try:
            from starlette.formparsers import MultiPartException, MultiPartParser

            max_body = 262_144 + 16_384
            if int(request.headers.get("content-length", "0") or 0) > max_body:
                return message(request, info, 413, "Configuration file exceeds 256 KiB.")
            received = 0

            async def bounded_stream():
                nonlocal received
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > max_body:
                        raise MultiPartException("request body exceeds the upload limit")
                    yield chunk

            try:
                form = await MultiPartParser(request.headers, bounded_stream(), max_files=1, max_fields=8).parse()
            except MultiPartException:
                return message(request, info, 413, "Configuration file exceeds 256 KiB.")
            try:
                return await _import_instance_form(request, info, form)
            finally:
                await form.close()
        except (ValueError, TypeError, UnicodeDecodeError, IntegrityError):
            return message(request, info, 422, "Invalid server configuration or conflicting instance.")

    async def _import_instance_form(request, info, form):
        try:
            if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or str(form.get("_csrf", ""))):
                return Response(status_code=403, headers=SECURITY_HEADERS)
            upload = form.get("file") or form.get("config")
            raw = await upload.read(262_145) if hasattr(upload, "read") else b""
            if len(raw) > 262_144:
                return message(request, info, 413, "Configuration file exceeds 256 KiB.")
            from .importer import ImportFailure, parse_server_conf, validate_parsed
            parsed = parse_server_conf(raw.decode("utf-8"))
            if validate_parsed(parsed):
                raise ImportFailure("INVALID_CONFIG")
            parsed.obfuscation = service.complete_import_obfuscation(parsed.obfuscation, parsed.mtu, parsed.awg_version)
            with sessions.begin() as s:
                instance = service.create_instance(
                    s, str(form.get("name", "")).strip(), parsed.listen_port, parsed.address,
                    private_key=parsed.private_key, obfuscation=parsed.obfuscation or None,
                    mtu=parsed.mtu, awg_version=parsed.awg_version,
                    endpoint_host=str(form.get("endpoint_host", "")).strip() or parsed.endpoint_host,
                    client_dns=", ".join(parsed.client_dns) if parsed.client_dns else None,
                    client_keepalive=parsed.client_keepalive,
                    client_allowed_ips=", ".join(parsed.client_allowed_ips) if parsed.client_allowed_ips else None,
                    crypto=crypto,
                )
                for peer in parsed.peers:
                    service.import_peer(s, instance.id, peer.name, public_key=peer.public_key,
                                        private_key=peer.private_key, preshared_key=peer.preshared_key,
                                        allowed_ip=peer.allowed_ip, enabled=peer.enabled, owner=peer.owner, crypto=crypto)
                ident = instance.id
            warnings = ", ".join(f"{w.code} ({w.count})" for w in parsed.warnings) or "none"
            return message(request, info, 201, f'Imported instance <a href="/ui/instances/{ident}">{ident}</a>. Parser warnings: {warnings}.')
        except (ValueError, TypeError, UnicodeDecodeError, IntegrityError):
            return message(request, info, 422, "Invalid server configuration or conflicting instance.")

    def update_obfuscation(instance_id, request, info, payload, *, regenerate=False):
        if payload.get("confirm_break_clients") not in (True, "on", "true", "1"):
            return message(request, info, 409, "Confirmation is required: clients will lose connectivity.")
        try:
            with sessions.begin() as s:
                instance = s.get(Instance, instance_id)
                if instance is None:
                    return Response(status_code=404, headers=SECURITY_HEADERS)
                version = str(payload.get("awg_version") or instance.awg_version)
                mtu = int(payload.get("mtu") or instance.mtu or 1280)
                if version not in ("2.0", "3.0", "3.1") or not 576 <= mtu <= 9000:
                    raise ValueError
                if regenerate:
                    values = awgparams.generate_obfuscation(version, mtu, str(payload.get("intensity", "medium")))
                else:
                    values = json.loads(payload.get("obfuscation_json", ""))
                    if (isinstance(values, dict) and "header_protection_key" not in values
                            and instance.obfuscation.get("header_protection_key")):
                        values["header_protection_key"] = instance.obfuscation["header_protection_key"]
                if any(f["severity"] == "error" for f in _awg_findings(values, version, mtu)):
                    raise ValueError
                mtu_changed = mtu != instance.mtu
                instance.obfuscation, instance.awg_version, instance.mtu = values, version, mtu
                node_ids = s.scalars(select(Placement.node_id).where(Placement.instance_id == instance_id)).all()
                for node_id in node_ids:
                    service.bump_revision(s, node_id, crypto)
                if mtu_changed:
                    service._bump_probe_runners(s, instance_id=instance_id, crypto=crypto)
                service._event(s, "instance.obfuscation.updated", str(instance_id), {"awg_version": version})
            if kick:
                kick(node_ids)
            return Response(status_code=303, headers={**SECURITY_HEADERS, "Location": f"/ui/instances/{instance_id}"})
        except (ValueError, TypeError, json.JSONDecodeError):
            return message(request, info, 422, "Invalid obfuscation parameters.")

    @app.post("/ui/instances/{instance_id}/obfuscation", include_in_schema=False)
    async def instance_obfuscation(instance_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = {key: values[0] for key, values in parse_qs((await request.body()).decode("utf-8", "replace")).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        return update_obfuscation(instance_id, request, info, form)

    @app.post("/ui/instances/{instance_id}/obfuscation/regenerate", include_in_schema=False)
    async def instance_obfuscation_regenerate(instance_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = {key: values[0] for key, values in parse_qs((await request.body()).decode("utf-8", "replace")).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        return update_obfuscation(instance_id, request, info, form, regenerate=True)
    @app.post("/ui/instances/{instance_id}/placements", include_in_schema=False)
    async def placement_create(instance_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = {key: values[0] for key, values in parse_qs(
            (await request.body()).decode("utf-8", "replace")
        ).items()}
        if not webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf")):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            node_id = int(form.get("node_id", ""))
            role = str(form.get("role", "active"))
            weight = int(form.get("weight", "1"))
            if role not in {"active", "standby"} or weight < 1:
                raise ValueError
            with sessions.begin() as s:
                placement = service.place(s, instance_id, node_id, role, weight, crypto)
                target_ids = [placement.node_id]
                if kick:
                    kick(target_ids)
            return Response(status_code=303, headers={**SECURITY_HEADERS, "Location": f"/ui/instances/{instance_id}"})
        except (ValueError, TypeError):
            return render("_error.html", request, info, text="Invalid placement details.")

    @app.get("/ui/instances/{instance_id}", include_in_schema=False)
    def instance_page(instance_id: int, request: Request, offset: int = 0):
        info, denied = check(request)
        if denied:
            return denied
        offset = max(offset, 0)
        with sessions() as s:
            instance = instance_view(s, instance_id)
            if instance is None:
                return message(request, info, 404, "Instance not found.")
            peers, total = peers_page(s, instance_id, PEER_PAGE, offset)
            all_nodes = nodes(s)
            node_names = {n["id"]: n["name"] for n in all_nodes}
        return render("instance.html", request, info, instance=instance, peers=peers, total=total, offset=offset, page_size=PEER_PAGE,
                      node_names=node_names, can_operate=webauth.has_role(info.role, "operator"),
                      can_create=webauth.has_role(info.role, "admin"), available_nodes=all_nodes,
                      obfuscation_json=json.dumps({k: v for k, v in instance["obfuscation"].items()
                                                   if k != "header_protection_key_set"}, indent=2))

    @app.post("/ui/instances/{instance_id}/switch", include_in_schema=False)
    def instance_switch(instance_id: int, node_id: int, request: Request):
        info, denied = check(request, "operator", write=True, page=False)
        if denied:
            return denied
        _, error = run(ops.switch, instance_id, node_id)
        if not error:
            audit("web.switch", info, {"instance_id": instance_id, "to_node_id": node_id})
        return refreshed(request, info, error)

    @app.post("/ui/instances/{instance_id}/peers", include_in_schema=False)
    async def peer_add(instance_id: int, request: Request):
        info, denied = check(request, "operator", write=True, page=False)
        if denied:
            return denied
        form = parse_qs((await request.body()).decode("utf-8", "replace"))
        name = (form.get("name") or [""])[0].strip()
        owner = (form.get("owner") or [""])[0].strip() or None
        if not name:
            return render("_error.html", request, info, text="Peer name is required.")
        result, error = run(ops.add_peer, instance_id, name, owner)
        if not error:
            audit("web.peer_add", info, {"instance_id": instance_id, "peer_id": result["id"]})
        return refreshed(request, info, error)

    @app.post("/ui/peers/{peer_id}/enabled", include_in_schema=False)
    def peer_enabled(peer_id: int, value: bool, request: Request):
        info, denied = check(request, "operator", write=True, page=False)
        if denied:
            return denied
        _, error = run(ops.set_enabled, peer_id, value)
        if not error:
            audit("web.peer_enabled", info, {"peer_id": peer_id, "enabled": value})
        return refreshed(request, info, error)

    @app.post("/ui/peers/{peer_id}/delete", include_in_schema=False)
    def peer_delete(peer_id: int, request: Request):
        info, denied = check(request, "operator", write=True, page=False)
        if denied:
            return denied
        _, error = run(ops.remove_peer, peer_id)
        if not error:
            audit("web.peer_delete", info, {"peer_id": peer_id})
        return refreshed(request, info, error)

    @app.get("/ui/peers/{peer_id}/config", include_in_schema=False)
    def peer_config(peer_id: int, request: Request):
        info, denied = check(request, "operator")
        if denied:
            return denied
        text, error = run(ops.config, peer_id, actor=info.username)
        if error:
            return message(request, info, 404 if "unknown" in error else 409, error)
        return Response(text, media_type="text/plain", headers={**SECURITY_HEADERS, "Content-Disposition": f'attachment; filename="peer-{peer_id}.conf"'})

    # failover proposals
    def pending_proposals():
        with sessions() as s:
            return failovers(s, "pending", 100, 0)[0]

    @app.get("/ui/failover", include_in_schema=False)
    def failover_page(request: Request, state: str = "", offset: int = 0):
        info, denied = check(request)
        if denied:
            return denied
        state, offset = (state if state in FAILOVER_STATES else ""), max(offset, 0)
        with sessions() as s:
            history, total = failovers(s, state or None, LIST_PAGE, offset)
            node_names = {n.id: n.name for n in s.scalars(select(Node)).all()}
            instance_names = {i.id: i.name for i in s.scalars(select(Instance)).all()}
            probes = s.scalars(select(Probe).order_by(Probe.id)).all()
            links = s.scalars(select(HopLink).order_by(HopLink.hop_id, HopLink.instance_id)).all()
            node_rows, instance_rows = nodes(s), instances(s)
            probe_states = (app.state.reconciler.probe_statuses()
                            if app.state.reconciler and callable(getattr(app.state.reconciler, "probe_statuses", None))
                            else {})
        return render("failover.html", request, info, settings=failover_info(), proposals=pending_proposals(), history=history, total=total,
                      state=state, states=FAILOVER_STATES, offset=offset, page_size=LIST_PAGE,
                      can_operate=webauth.has_role(info.role, "operator"),
                      can_admin=webauth.has_role(info.role, "admin"), nodes=node_rows, instances=instance_rows,
                      probes=[{"id": p.id, "hop": node_names.get(p.hop_id, p.hop_id),
                               "instance": instance_names.get(p.instance_id, p.instance_id),
                               "runner": node_names.get(p.runner_node_id, p.runner_node_id),
                               "status": getattr(getattr(probe_states.get(p.id), "state", "UNKNOWN"), "value",
                                                 getattr(probe_states.get(p.id), "state", "UNKNOWN"))} for p in probes],
                      links=[{"hop_id": p.hop_id, "instance_id": p.instance_id,
                              "hop": node_names.get(p.hop_id, p.hop_id),
                              "instance": instance_names.get(p.instance_id, p.instance_id)} for p in links])

    @app.get("/ui/fragments/failover", include_in_schema=False)
    def failover_fragment(request: Request):
        info, denied = check(request, page=False)
        return denied or render("_failover_pending.html", request, info, proposals=pending_proposals(), can_operate=webauth.has_role(info.role, "operator"))

    def decide_failover(request, info, proposal_id, action):
        _, error = run(ops.failover, proposal_id, action, "web", info.username[:64])
        if not error:
            audit(f"web.failover_{action}", info, {"proposal_id": proposal_id})
        return refreshed(request, info, FAILOVER_ERRORS.get(error, error))

    async def form_data(request):
        return {key: values[0] for key, values in parse_qs((await request.body()).decode("utf-8", "replace")).items()}

    def valid_csrf(request, info, form):
        return webauth.check_csrf(info, request.headers.get("x-csrf-token") or form.get("_csrf"))

    @app.post("/ui/failover/settings", include_in_schema=False)
    async def failover_settings_update(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = await form_data(request)
        if not valid_csrf(request, info, form):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        limits = {"down_seconds": (1, 86400), "proposal_ttl_seconds": (1, 604800),
                  "cooldown_seconds": (0, 86400), "eval_interval": (1, 3600)}
        current = failover_info()
        values = {"mode": form.get("mode", current["mode"])}
        try:
            for key, (minimum, maximum) in limits.items():
                value = float(form.get(key, current[key]))
                if not minimum <= value <= maximum:
                    raise ValueError
                values[key] = value
            if values["mode"] not in {"off", "confirm", "auto"}:
                raise ValueError
            save_failover_settings(values)
            audit("web.failover_settings", info, values)
            return RedirectResponse("/ui/failover", status_code=303, headers=SECURITY_HEADERS)
        except (ValueError, TypeError):
            return message(request, info, 400, "Invalid failover settings.")

    @app.post("/ui/failover/links", include_in_schema=False)
    async def failover_link_create(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = await form_data(request)
        if not valid_csrf(request, info, form):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            hop_id, instance_id = int(form["hop_id"]), int(form["instance_id"])
            with sessions.begin() as s:
                service.create_hop_link(s, hop_id, instance_id, crypto)
            if kick:
                kick([hop_id])
            return RedirectResponse("/ui/failover", status_code=303, headers=SECURITY_HEADERS)
        except (KeyError, ValueError, IntegrityError):
            return message(request, info, 400, "Invalid or duplicate hop link.")

    @app.post("/ui/failover/links/{hop_id}/{instance_id}/delete", include_in_schema=False)
    async def failover_link_delete(hop_id: int, instance_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = await form_data(request)
        if not valid_csrf(request, info, form):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        if form.get("confirm") != "yes":
            return message(request, info, 400, "Confirm the deletion first.")
        with sessions.begin() as s:
            if not service.delete_hop_link(s, hop_id, instance_id, crypto):
                return message(request, info, 404, "Hop link not found.")
        if kick:
            kick([hop_id])
        return RedirectResponse("/ui/failover", status_code=303, headers=SECURITY_HEADERS)

    @app.post("/ui/failover/probes", include_in_schema=False)
    async def failover_probe_create(request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = await form_data(request)
        if not valid_csrf(request, info, form):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        try:
            hop_id, instance_id, runner_id = int(form["hop_id"]), int(form["instance_id"]), int(form["runner_node_id"])
            with sessions.begin() as s:
                probe = service.create_probe(s, hop_id, instance_id, runner_id, crypto=crypto)
                runner_id, instance_id = probe.runner_node_id, probe.instance_id
                placed = s.scalars(select(Placement.node_id).where(Placement.instance_id == instance_id)).all()
            if kick:
                kick([runner_id, *placed])
            return RedirectResponse("/ui/failover", status_code=303, headers=SECURITY_HEADERS)
        except (KeyError, ValueError, IntegrityError):
            return message(request, info, 400, "Invalid probe configuration.")

    @app.post("/ui/failover/probes/{probe_id}/delete", include_in_schema=False)
    async def failover_probe_delete(probe_id: int, request: Request):
        info, denied = check(request, "admin", page=False)
        if denied:
            return denied
        form = await form_data(request)
        if not valid_csrf(request, info, form):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        if form.get("confirm") != "yes":
            return message(request, info, 400, "Confirm the deletion first.")
        with sessions.begin() as s:
            probe = s.get(Probe, probe_id)
            if not probe:
                return message(request, info, 404, "Probe not found.")
            runner_id, instance_id = probe.runner_node_id, probe.instance_id
            placed = s.scalars(select(Placement.node_id).where(Placement.instance_id == instance_id)).all()
            service.delete_probe(s, probe_id, crypto)
        if kick:
            kick([runner_id, *placed])
        return RedirectResponse("/ui/failover", status_code=303, headers=SECURITY_HEADERS)

    @app.post("/ui/failover/manual", include_in_schema=False)
    async def failover_manual(request: Request):
        info, denied = check(request, "operator", page=False)
        if denied:
            return denied
        form = await form_data(request)
        if not valid_csrf(request, info, form):
            return Response(status_code=403, headers=SECURITY_HEADERS)
        if form.get("confirm") != "yes":
            return message(request, info, 400, "Confirm the manual failover first.")
        try:
            instance_id, node_id = int(form["instance_id"]), int(form["node_id"])
        except (KeyError, ValueError):
            return message(request, info, 400, "Select an instance and target node.")
        _, error = run(ops.switch, instance_id, node_id)
        if error:
            return message(request, info, 409, error)
        audit("web.failover_manual", info, {"instance_id": instance_id, "node_id": node_id})
        return RedirectResponse("/ui/failover", status_code=303, headers=SECURITY_HEADERS)

    @app.post("/ui/failovers/{proposal_id}/confirm", include_in_schema=False)
    def failover_confirm(proposal_id: int, request: Request):
        info, denied = check(request, "operator", write=True, page=False)
        return denied or decide_failover(request, info, proposal_id, "confirm")

    @app.post("/ui/failovers/{proposal_id}/reject", include_in_schema=False)
    def failover_reject(proposal_id: int, request: Request):
        info, denied = check(request, "operator", write=True, page=False)
        return denied or decide_failover(request, info, proposal_id, "reject")

    # access and limit requests (approving creates or changes users, so deciding is admin-only)
    @app.get("/ui/requests", include_in_schema=False)
    def requests_page(request: Request, status: str = "pending", offset: int = 0):
        info, denied = check(request)
        if denied:
            return denied
        status, offset = (status if status in REQUEST_STATES else "all"), max(offset, 0)
        with sessions() as s:
            rows, total = requests(s, None if status == "all" else status, LIST_PAGE, offset)
        return render("requests.html", request, info, requests=rows, total=total, status=status, states=REQUEST_STATES, offset=offset,
                      page_size=LIST_PAGE, can_decide=webauth.has_role(info.role, "admin"))

    @app.post("/ui/requests/{request_id}/approve", include_in_schema=False)
    async def request_approve(request_id: int, request: Request):
        info, denied = check(request, "admin", write=True, page=False)
        if denied:
            return denied
        form = parse_qs((await request.body()).decode("utf-8", "replace"))
        try:
            limit = int((form.get("default_limit") or ["3"])[0])
        except ValueError:
            limit = -2
        if limit < -1:
            return render("_error.html", request, info, text="Device limit must be a number, -1 for unlimited.")
        _, error = run(ops.approve, request_id, limit)
        if not error:
            audit("web.request_approve", info, {"request_id": request_id, "default_limit": limit})
        return refreshed(request, info, error)

    @app.post("/ui/requests/{request_id}/decline", include_in_schema=False)
    def request_decline(request_id: int, request: Request):
        info, denied = check(request, "admin", write=True, page=False)
        if denied:
            return denied
        _, error = run(ops.decline, request_id)
        if not error:
            audit("web.request_decline", info, {"request_id": request_id})
        return refreshed(request, info, error)

    # bootstrap (status for everyone, apply is admin-only and always uses the configured file)
    @app.get("/ui/bootstrap", include_in_schema=False)
    def bootstrap_page(request: Request):
        info, denied = check(request)
        if denied:
            return denied
        data = bootstrap_info()
        last = data.get("last_apply")
        if last:
            last = dict(last, at=datetime.fromtimestamp(last["at"], UTC))
        return render("bootstrap.html", request, info, boot=dict(data, last_apply=last), can_apply=webauth.has_role(info.role, "admin"))

    @app.post("/ui/bootstrap/apply", include_in_schema=False)
    def bootstrap_apply(request: Request, dry_run: bool = True):
        info, denied = check(request, "admin", write=True, page=False)
        if denied:
            return denied
        report, error = run(ops.bootstrap, dry_run)
        if error:
            return render("_error.html", request, info, text=error)
        audit("web.bootstrap_apply", info, {"dry_run": dry_run})
        return render("_bootstrap_result.html", request, info, report=report, dry_run=dry_run)
