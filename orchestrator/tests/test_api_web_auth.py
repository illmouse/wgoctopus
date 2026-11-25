import logging

import pytest
from api_helpers import RecordingReconciler
from fastapi.testclient import TestClient
from sqlalchemy import select

from wgoctopus_orch import webauth
from wgoctopus_orch.api import create_app
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.models import Event, WebAccount

PW = "long-enough-password"
BEARER = {"Authorization": "Bearer test-admin-token"}


def build(tmp_path, crypto, monkeypatch, **env):
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "test-admin-token")
    monkeypatch.setenv("WGOCTOPUS_WEB_COOKIE_SECURE", env.pop("secure", "false"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    url = f"sqlite:///{tmp_path / 'web.db'}"
    upgrade_to_head(url)
    engine = make_engine(url)
    sessions = make_session_factory(engine)
    app = create_app(session_factory=sessions, reconciler=RecordingReconciler(), crypto=crypto, migrate=False)
    return app, sessions, engine


@pytest.fixture
def web(tmp_path, crypto, monkeypatch):
    app, sessions, engine = build(tmp_path, crypto, monkeypatch)
    with sessions.begin() as s:
        webauth.create_account(s, "admin", PW, "admin")
        webauth.create_account(s, "ops", PW, "operator")
        webauth.create_account(s, "view", PW, "viewer")
    with TestClient(app) as client:
        yield client, sessions
    engine.dispose()


def login(client, user="admin", password=PW):
    return client.post("/auth/login", json={"username": user, "password": password})


def test_login_sets_hardened_cookie(tmp_path, crypto, monkeypatch):
    app, sessions, engine = build(tmp_path, crypto, monkeypatch, secure="true")
    with sessions.begin() as s:
        webauth.create_account(s, "admin", PW, "admin")
    with TestClient(app) as client:
        r = login(client)
        assert r.status_code == 200 and r.json()["role"] == "admin" and r.json()["csrf_token"]
        cookie = r.headers["set-cookie"].lower()
        assert "wgoctopus_session=" in cookie and "httponly" in cookie and "samesite=lax" in cookie and "secure" in cookie
        assert "max-age=28800" in cookie and "path=/" in cookie
    engine.dispose()


def test_failed_logins_are_indistinguishable_and_audited(web):
    client, sessions = web
    wrong = login(client, "admin", "wrong-password-1")
    unknown = login(client, "nobody", "wrong-password-1")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": {"error": "invalid_credentials"}} or wrong.json() == unknown.json()
    for bad in ({"username": 1, "password": PW}, {"username": "admin"}, {"username": "admin", "password": 5}):
        assert client.post("/auth/login", json=bad).status_code == 401
    with sessions() as s:
        kinds = [e.kind for e in s.scalars(select(Event))]
        assert kinds.count("web.login_failed") >= 2
        assert PW not in repr([e.data for e in s.scalars(select(Event))])


def test_throttle_after_repeated_failures(web):
    client, _ = web
    for _ in range(5):
        assert login(client, "admin", "wrong-password-1").status_code == 401
    locked = login(client, "admin", PW)
    assert locked.status_code == 429 and locked.headers["retry-after"] == "300"
    assert login(client, "ops", PW).status_code == 200  # other account unaffected


def test_me_logout_and_csrf(web):
    client, _ = web
    assert client.get("/auth/me").status_code == 401
    csrf = login(client).json()["csrf_token"]
    me = client.get("/auth/me").json()
    assert me == {"username": "admin", "role": "admin", "csrf_token": csrf, "source": "local"}
    assert client.post("/auth/logout").status_code == 403
    assert client.post("/auth/logout", headers={"X-CSRF-Token": "nope"}).status_code == 403
    assert client.get("/auth/me").status_code == 200  # still alive after failed logout
    assert client.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert client.get("/auth/me").status_code == 401


def test_cookie_does_not_grant_v1_access(web):
    client, _ = web
    login(client)
    assert client.get("/v1/instances").status_code == 401
    assert client.get("/v1/instances", headers=BEARER).status_code == 200
    assert client.get("/healthz").status_code == 200


def test_account_management_with_bearer_token(web):
    client, sessions = web
    r = client.get("/v1/web-accounts", headers=BEARER)
    assert r.status_code == 200 and {a["username"] for a in r.json()} == {"admin", "ops", "view"}
    created = client.post("/v1/web-accounts", headers=BEARER, json={"username": "new", "password": PW, "role": "viewer"})
    assert created.status_code == 201 and "password" not in created.text and "hash" not in created.text
    assert client.post("/v1/web-accounts", headers=BEARER, json={"username": "new", "password": PW, "role": "viewer"}).status_code == 409
    assert client.post("/v1/web-accounts", headers=BEARER, json={"username": "n2", "password": "short", "role": "viewer"}).status_code == 422
    assert client.post("/v1/web-accounts", headers=BEARER, json={"username": "n3", "password": PW, "role": "root"}).status_code == 422
    assert client.post("/v1/web-accounts", headers=BEARER, json={"username": "n4", "role": "viewer"}).status_code == 422
    patched = client.patch("/v1/web-accounts/NEW", headers=BEARER, json={"role": "operator", "password": "another-long-password"})
    assert patched.status_code == 200 and patched.json()["role"] == "operator"
    assert login(client, "new", "another-long-password").status_code == 200
    # disabling kills the live session
    assert client.patch("/v1/web-accounts/new", headers=BEARER, json={"enabled": False}).status_code == 200
    assert client.get("/auth/me").status_code == 401
    assert login(client, "new", "another-long-password").status_code == 401
    assert client.patch("/v1/web-accounts/ghost", headers=BEARER, json={"role": "viewer"}).status_code == 404
    assert client.delete("/v1/web-accounts/ghost", headers=BEARER).status_code == 404
    assert client.delete("/v1/web-accounts/new", headers=BEARER).status_code == 204
    # last admin protected
    assert client.patch("/v1/web-accounts/admin", headers=BEARER, json={"role": "viewer"}).status_code == 409
    assert client.patch("/v1/web-accounts/admin", headers=BEARER, json={"enabled": False}).status_code == 409
    assert client.delete("/v1/web-accounts/admin", headers=BEARER).status_code == 409
    with sessions() as s:
        text = repr([(e.kind, e.subject, e.data) for e in s.scalars(select(Event))])
        assert PW not in text and "another-long-password" not in text


def test_account_management_with_sessions(web):
    client, _ = web
    csrf = login(client, "admin").json()["csrf_token"]
    assert client.get("/v1/web-accounts").status_code == 200
    body = {"username": "s1", "password": PW, "role": "viewer"}
    assert client.post("/v1/web-accounts", json=body).status_code == 403  # csrf required
    assert client.post("/v1/web-accounts", json=body, headers={"X-CSRF-Token": csrf}).status_code == 201
    client.post("/auth/logout", headers={"X-CSRF-Token": csrf})
    ops_csrf = login(client, "ops").json()["csrf_token"]
    assert client.get("/v1/web-accounts").status_code == 403
    assert client.post("/v1/web-accounts", json=body, headers={"X-CSRF-Token": ops_csrf}).status_code == 403
    client.post("/auth/logout", headers={"X-CSRF-Token": ops_csrf})
    login(client, "view")
    assert client.delete("/v1/web-accounts/s1").status_code == 403
    client.cookies.clear()
    assert client.get("/v1/web-accounts").status_code == 401


def test_password_hash_never_leaks(web, caplog):
    client, sessions = web
    caplog.set_level(logging.DEBUG)
    texts = [client.get("/v1/web-accounts", headers=BEARER).text, login(client).text, client.get("/auth/me").text]
    with sessions() as s:
        stored = s.scalar(select(WebAccount.password_hash).where(WebAccount.username == "admin"))
    assert all("scrypt" not in t and stored not in t for t in texts)
    assert stored not in caplog.text and PW not in caplog.text


def test_first_admin_from_env(tmp_path, crypto, monkeypatch):
    pwfile = tmp_path / "pw"
    pwfile.write_text("file-password-123456\n")
    app, sessions, engine = build(tmp_path, crypto, monkeypatch, WGOCTOPUS_WEB_ADMIN_USERNAME="root1",
                                  WGOCTOPUS_WEB_ADMIN_PASSWORD="env-password-123456",
                                  WGOCTOPUS_WEB_ADMIN_PASSWORD_FILE=str(pwfile))
    with TestClient(app) as client:
        assert login(client, "root1", "env-password-123456").status_code == 401  # file wins
        assert login(client, "root1", "file-password-123456").status_code == 200
    # second start must not override or add accounts
    pwfile.write_text("different-password-123\n")
    with TestClient(create_app(session_factory=sessions, reconciler=RecordingReconciler(), crypto=crypto, migrate=False)) as client:
        assert login(client, "root1", "file-password-123456").status_code == 200
        assert login(client, "root1", "different-password-123").status_code == 401
    with sessions() as s:
        assert len(s.scalars(select(WebAccount)).all()) == 1
    engine.dispose()


def test_first_admin_created_after_automatic_migration(tmp_path, crypto, monkeypatch):
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "test-admin-token")
    monkeypatch.setenv("WGOCTOPUS_DATABASE_URL", url)
    monkeypatch.setenv("WGOCTOPUS_AUTO_MIGRATE", "true")
    monkeypatch.setenv("WGOCTOPUS_WEB_ADMIN_USERNAME", "fresh-admin")
    monkeypatch.setenv("WGOCTOPUS_WEB_ADMIN_PASSWORD", PW)
    engine = make_engine(url)
    sessions = make_session_factory(engine)
    app = create_app(session_factory=sessions, crypto=crypto)

    with TestClient(app) as client:
        assert login(client, "fresh-admin", PW).status_code == 200

    engine.dispose()


def test_no_first_admin_without_password(tmp_path, crypto, monkeypatch):
    app, sessions, engine = build(tmp_path, crypto, monkeypatch)
    with TestClient(app):
        pass
    with sessions() as s:
        assert s.scalars(select(WebAccount)).all() == []
    engine.dispose()


def test_web_disabled_returns_404(tmp_path, crypto, monkeypatch):
    app, _, engine = build(tmp_path, crypto, monkeypatch, WGOCTOPUS_WEB_ENABLED="false")
    with TestClient(app) as client:
        assert login(client).status_code == 404
        assert client.get("/auth/me").status_code == 404
        assert client.get("/v1/web-accounts", headers=BEARER).status_code == 404
        assert client.post("/v1/web-accounts", headers=BEARER, json={}).status_code == 404
        assert client.get("/v1/instances", headers=BEARER).status_code == 200
    engine.dispose()


def test_invalid_web_settings(monkeypatch):
    from wgoctopus_orch.config import Settings
    monkeypatch.setenv("WGOCTOPUS_WEB_ENABLED", "maybe")
    with pytest.raises(ValueError):
        Settings.from_env()
    monkeypatch.setenv("WGOCTOPUS_WEB_ENABLED", "true")
    monkeypatch.setenv("WGOCTOPUS_WEB_ADMIN_PASSWORD_FILE", "/nonexistent/pw")
    with pytest.raises(ValueError):
        Settings.from_env()
