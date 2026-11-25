"""Server-rendered admin UI: Jinja2 pages with HTMX fragments.

Pages authenticate with the session cookie only (never the static bearer token) and
never expose /v1 to cookie sessions; they call the same service functions as the API.
"""
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

from . import service, webauth
from .models import Event
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
          failovers, failover_info, requests, bootstrap_info, crypto=None, kick=None):
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
        body = env.get_template(template).render(info=info, nav=NAV, path=request.url.path, state_class=STATE_CLASS, **ctx)
        return HTMLResponse(body, status_code=status_code, headers=SECURITY_HEADERS)

    def message(request, info, status_code, text):
        return render("message.html", request, info, status_code=status_code, message=text)

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
            with sessions.begin() as s:
                instance = service.create_instance(
                    s, name, port,
                    str(form.get("address", "")).strip(),
                    endpoint_host=str(form.get("endpoint_host", "")).strip() or None,
                    crypto=crypto,
                )
                ident = instance.id
            return Response(status_code=303, headers={**SECURITY_HEADERS, "Location": f"/ui/instances/{ident}"})
        except (ValueError, TypeError):
            return render("_error.html", request, info, text="Invalid instance details.")
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
                      can_create=webauth.has_role(info.role, "admin"), available_nodes=all_nodes)

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
        return render("failover.html", request, info, settings=failover_info(), proposals=pending_proposals(), history=history, total=total,
                      state=state, states=FAILOVER_STATES, offset=offset, page_size=LIST_PAGE, can_operate=webauth.has_role(info.role, "operator"))

    @app.get("/ui/fragments/failover", include_in_schema=False)
    def failover_fragment(request: Request):
        info, denied = check(request, page=False)
        return denied or render("_failover_pending.html", request, info, proposals=pending_proposals(), can_operate=webauth.has_role(info.role, "operator"))

    def decide_failover(request, info, proposal_id, action):
        _, error = run(ops.failover, proposal_id, action, "web", info.username[:64])
        if not error:
            audit(f"web.failover_{action}", info, {"proposal_id": proposal_id})
        return refreshed(request, info, FAILOVER_ERRORS.get(error, error))

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
