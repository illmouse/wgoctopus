"""Server-rendered admin UI: Jinja2 pages with HTMX fragments.

Pages authenticate with the session cookie only (never the static bearer token) and
never expose /v1 to cookie sessions; they call the same service functions as the API.
"""
from pathlib import Path

from fastapi import Request
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
NAV = [("/ui/", "Dashboard"), ("/ui/nodes", "Nodes")]
STATE_CLASS = {"IN_SYNC": "ok", "SYNCING": "warn", "DISABLED": "muted", "UNKNOWN": "muted",
               "succeeded": "ok", "running": "warn", "queued": "warn", "failed": "bad", "cancelled": "muted",
               "ok": "ok", "pending": "muted", "skipped": "muted"}
ACTIVE_JOB = ("queued", "running")


def fmt_ts(value):
    return value.strftime("%Y-%m-%d %H:%M:%S") if hasattr(value, "strftime") else "-"


def build_env():
    env = Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
    env.filters["ts"] = fmt_ts
    return env


def mount(app, *, sessions, lookup, status, nodes, node_view, provision):
    """Register UI routes.

    `lookup(cookie)` returns a session info or None; `status(session)` is the fleet summary;
    `nodes(session)` lists node views, `node_view(session, id)` returns one or None;
    `provision()` returns the provisioning runner.
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
        return denied or render("nodes.html", request, info, **nodes_data())

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
