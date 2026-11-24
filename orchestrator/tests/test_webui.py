import pytest
from fastapi.testclient import TestClient
from test_api_web_auth import BEARER, PW, build, login

from wgoctopus_orch import service, webauth
from wgoctopus_orch.models import Event

OIDC_ENV = {
    "WGOCTOPUS_OIDC_ISSUER": "https://idp.example",
    "WGOCTOPUS_OIDC_CLIENT_ID": "wgoctopus",
    "WGOCTOPUS_OIDC_REDIRECT_URL": "https://wg.example/auth/oidc/callback",
    "WGOCTOPUS_OIDC_ROLE_MAP": "admins=admin",
}


@pytest.fixture
def ui(tmp_path, crypto, monkeypatch):
    app, sessions, engine = build(tmp_path, crypto, monkeypatch)
    with sessions.begin() as s:
        webauth.create_account(s, "admin", PW, "admin")
        webauth.create_account(s, "view", PW, "viewer")
    with TestClient(app, follow_redirects=False) as client:
        yield client, sessions
    engine.dispose()


def test_anonymous_is_sent_to_login(ui):
    client, _ = ui
    for path in ("/", "/ui/"):
        r = client.get(path)
        assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/ui/fragments/status").status_code == 401


def test_login_page_is_hardened_and_offers_only_enabled_methods(ui, tmp_path, crypto, monkeypatch):
    client, _ = ui
    r = client.get("/login")
    assert r.status_code == 200 and 'id="login-form"' in r.text and "/auth/oidc/login" not in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"] and "'unsafe-inline'" not in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert "<script>" not in r.text.replace('<script src=', "")  # no inline scripts

    app, _, engine = build(tmp_path, crypto, monkeypatch, **OIDC_ENV)
    with TestClient(app) as oidc_client:
        assert "/auth/oidc/login" in oidc_client.get("/login").text
    engine.dispose()


def test_dashboard_after_login(ui):
    client, sessions = ui
    with sessions.begin() as s:
        service._event(s, "demo.event", "<script>alert(1)</script>", {})
    me = login(client)
    assert me.status_code == 200
    assert client.get("/").headers["location"] == "/ui/"
    assert client.get("/login").headers["location"] == "/ui/"
    page = client.get("/ui/")
    assert page.status_code == 200
    csrf = client.get("/auth/me").json()["csrf_token"]
    assert f'name="csrf-token" content="{csrf}"' in page.text
    assert "admin" in page.text and "Dashboard" in page.text and "instances" in page.text and "IN_SYNC" in page.text
    assert "demo.event" in page.text
    assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    fragment = client.get("/ui/fragments/status")
    assert fragment.status_code == 200 and "<html" not in fragment.text and "Recent events" in fragment.text


def test_viewer_may_read_dashboard(ui):
    client, _ = ui
    login(client, "view")
    assert client.get("/ui/").status_code == 200


def test_empty_events_row(ui):
    client, sessions = ui
    login(client)
    with sessions.begin() as s:
        s.query(Event).delete()
    assert "No events yet" in client.get("/ui/").text


def test_static_assets_served(ui):
    client, _ = ui
    for name in ("htmx.min.js", "app.js", "app.css"):
        r = client.get(f"/static/{name}")
        assert r.status_code == 200 and r.content
    assert client.get("/static/../api.py").status_code in (404, 400)
    assert client.get("/static/nope.js").status_code == 404


def test_cookie_session_does_not_open_v1_and_bearer_does_not_open_ui(ui):
    client, _ = ui
    login(client)
    assert client.get("/v1/status").status_code == 401
    client.cookies.clear()
    r = client.get("/ui/", headers=BEARER)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/ui/fragments/status", headers=BEARER).status_code == 401


def test_logout_ends_ui_access(ui):
    client, _ = ui
    csrf = login(client).json()["csrf_token"]
    assert client.get("/ui/").status_code == 200
    assert client.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert client.get("/ui/").status_code == 303


def test_ui_absent_when_web_disabled(tmp_path, crypto, monkeypatch):
    app, _, engine = build(tmp_path, crypto, monkeypatch, WGOCTOPUS_WEB_ENABLED="false")
    with TestClient(app, follow_redirects=False) as client:
        for path in ("/", "/login", "/ui/", "/static/app.js"):
            assert client.get(path).status_code == 404
    engine.dispose()
