import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_api_provision import swap
from test_api_web_auth import BEARER, PW, build, login
from test_provision_steps import FakeHost

from wgoctopus_orch import service, webauth
from wgoctopus_orch.models import Event
from wgoctopus_orch.provision import Step

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
        webauth.create_account(s, "ops", PW, "operator")
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


TOKEN = "tok-0123456789abcdef"


def add_node(client, name="n1", **extra):
    body = {"name": name, "ssh_host": "127.0.0.1", "ssh_user": "root", "agent_token": TOKEN, **extra}
    r = client.post("/v1/nodes", json=body, headers=BEARER)
    assert r.status_code == 201, r.text
    return r.json()


def csrf_of(client):
    return {"X-CSRF-Token": client.get("/auth/me").json()["csrf_token"]}


def wait_fragment(client, job_id, needle, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/ui/fragments/jobs/{job_id}")
        if needle in r.text:
            return r
        time.sleep(0.05)
    raise AssertionError(r.text)


def test_nodes_pages_render_without_secrets(ui):
    client, _ = ui
    node = add_node(client, provision={"health_interval": 0})
    assert client.get("/ui/nodes").status_code == 303
    assert client.get("/ui/fragments/nodes").status_code == 401
    assert client.get(f"/ui/nodes/{node['id']}").status_code == 303
    login(client)
    page = client.get("/ui/nodes")
    assert page.status_code == 200 and "n1" in page.text and f"/ui/nodes/{node['id']}" in page.text
    assert "No nodes yet" not in client.get("/ui/fragments/nodes").text and "<html" not in client.get("/ui/fragments/nodes").text
    detail = client.get(f"/ui/nodes/{node['id']}")
    assert detail.status_code == 200 and "root@127.0.0.1:22" in detail.text and "Never provisioned" in detail.text
    assert TOKEN not in detail.text and TOKEN not in page.text
    missing = client.get("/ui/nodes/999")
    assert missing.status_code == 404 and "Node not found" in missing.text


def test_empty_nodes_and_pull_node_has_no_provision_button(ui):
    client, _ = ui
    login(client)
    assert "No nodes yet" in client.get("/ui/nodes").text
    node = add_node(client, "pulled", mgmt_mode="pull", ssh_host=None, ssh_user=None)
    detail = client.get(f"/ui/nodes/{node['id']}")
    assert detail.status_code == 200 and "hx-post" not in detail.text


def test_provision_from_ui_runs_and_streams_log(ui):
    client, sessions = ui
    swap(client, FakeHost())
    node = add_node(client, provision={"health_interval": 0})
    login(client)
    assert f'hx-post="/ui/nodes/{node["id"]}/provision"' in client.get(f"/ui/nodes/{node['id']}").text
    r = client.post(f"/ui/nodes/{node['id']}/provision", headers=csrf_of(client))
    assert r.status_code == 204
    location = r.headers["hx-redirect"]
    job_id = int(location.rsplit("/", 1)[1])
    done = wait_fragment(client, job_id, "succeeded")
    assert 'hx-trigger' not in done.text and "Cancel" not in done.text and TOKEN not in done.text
    page = client.get(location)
    assert page.status_code == 200 and f"#{job_id}" in page.text and "<ol" in page.text
    assert f"/ui/jobs/{job_id}" in client.get(f"/ui/nodes/{node['id']}").text
    with sessions() as s:
        event = s.scalars(select(Event).where(Event.kind == "web.provision_start")).one()
        assert event.subject == "admin" and event.data == {"node_id": node["id"], "job_id": job_id}
    assert client.get("/ui/jobs/999").status_code == 404
    assert client.get("/ui/fragments/jobs/999").status_code == 404


def test_provision_requires_admin_and_csrf(ui):
    client, sessions = ui
    swap(client, FakeHost())
    node = add_node(client)
    url = f"/ui/nodes/{node['id']}/provision"
    assert client.post(url).status_code == 401
    login(client)
    assert client.post(url).status_code == 403  # no CSRF token
    assert client.post(url, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.post("/ui/nodes/999/provision", headers=csrf_of(client)).status_code == 404
    with sessions() as s:
        assert s.scalars(select(Event).where(Event.kind == "web.provision_start")).first() is None
    for user in ("ops", "view"):
        client.cookies.clear()
        login(client, user)
        assert client.post(url, headers=csrf_of(client)).status_code == 403
        detail = client.get(f"/ui/nodes/{node['id']}")
        assert detail.status_code == 200 and "hx-post" not in detail.text
        denied = client.get("/ui/jobs/1")
        assert denied.status_code == 403 and "cannot open" in denied.text
        assert client.get("/ui/fragments/jobs/1").status_code == 403
        assert client.post("/ui/jobs/1/cancel", headers=csrf_of(client)).status_code == 403


def test_protected_node_needs_confirmation_and_jobs_can_be_cancelled(ui):
    client, _ = ui
    gate = {}

    async def block(ctx):
        gate["ev"] = asyncio.Event()
        await gate["ev"].wait()

    swap(client, FakeHost(), [Step("block", block)])
    node = add_node(client, protected=True)
    login(client)
    headers = csrf_of(client)
    assert "hx-confirm" in client.get(f"/ui/nodes/{node['id']}").text
    refused = client.post(f"/ui/nodes/{node['id']}/provision", headers=headers)
    assert refused.status_code == 200 and "confirmation required" in refused.text and "hx-redirect" not in refused.headers
    started = client.post(f"/ui/nodes/{node['id']}/provision?confirm=true", headers=headers)
    assert started.status_code == 204
    job_id = int(started.headers["hx-redirect"].rsplit("/", 1)[1])
    running = wait_fragment(client, job_id, "running")
    assert 'hx-trigger="every 2s"' in running.text and "Cancel" in running.text
    busy = client.post(f"/ui/nodes/{node['id']}/provision?confirm=true", headers=headers)
    assert busy.status_code == 200 and "already in progress" in busy.text
    assert client.post(f"/ui/jobs/{job_id}/cancel", headers=headers).status_code == 204
    wait_fragment(client, job_id, "cancelled")
    again = client.post(f"/ui/jobs/{job_id}/cancel", headers=headers)
    assert again.status_code == 200 and "not running" in again.text
    assert client.post("/ui/jobs/999/cancel", headers=headers).status_code == 404
    assert client.post(f"/ui/jobs/{job_id}/cancel").status_code == 403
