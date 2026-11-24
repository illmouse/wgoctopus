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

from .models import Event

HERE = Path(__file__).parent
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}
NAV = [("/ui/", "Dashboard")]
STATE_CLASS = {"IN_SYNC": "ok", "SYNCING": "warn", "DISABLED": "muted", "UNKNOWN": "muted"}


def build_env():
    return Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)


def mount(app, *, sessions, lookup, status):
    """Register UI routes. `lookup(cookie)` returns a session info or None; `status(session)` the fleet summary."""
    env = build_env()
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def render(template, request, info=None, status_code=200, **ctx):
        body = env.get_template(template).render(info=info, nav=NAV, path=request.url.path, **ctx)
        return HTMLResponse(body, status_code=status_code, headers=SECURITY_HEADERS)

    def actor(request):
        return lookup(request.cookies.get("wgoctopus_session"))

    @app.get("/", include_in_schema=False)
    def index(request: Request):
        return RedirectResponse("/ui/" if actor(request) else "/login", status_code=303, headers=SECURITY_HEADERS)

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request):
        if actor(request):
            return RedirectResponse("/ui/", status_code=303, headers=SECURITY_HEADERS)
        return render("login.html", request, oidc=app.state.oidc is not None)

    def dashboard_data():
        with sessions() as s:
            events = [{"ts": e.ts, "kind": e.kind, "subject": e.subject} for e in s.scalars(select(Event).order_by(Event.id.desc()).limit(10))]
            return {"summary": status(s), "events": events, "state_class": STATE_CLASS}

    @app.get("/ui/", include_in_schema=False)
    def dashboard(request: Request):
        info = actor(request)
        if not info:
            return RedirectResponse("/login", status_code=303, headers=SECURITY_HEADERS)
        return render("dashboard.html", request, info, **dashboard_data())

    @app.get("/ui/fragments/status", include_in_schema=False)
    def status_fragment(request: Request):
        info = actor(request)
        if not info:
            return Response(status_code=401, headers=SECURITY_HEADERS)
        return render("_status.html", request, info, **dashboard_data())
