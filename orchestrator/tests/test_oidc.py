"""OIDC login against an in-process fake identity provider (httpx MockTransport)."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from api_helpers import RecordingReconciler
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from wgoctopus_orch import oidc, webauth
from wgoctopus_orch.api import create_app
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.models import Event, WebAccount

ISSUER = "https://idp.example.org/realms/main"
CLIENT_ID = "wgoctopus"
SECRET = "client-secret-value"
REDIRECT = "https://orch.example.org/auth/oidc/callback"
ROLE_MAP = "wg-admins=admin,wg-ops=operator,wg-view=viewer"


class FakeIdp:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "k1"
        self.codes = {}
        self.requests = []
        self.fail_token = False
        self.fail_discovery = False
        self.discovery_issuer = ISSUER
        self.alg = "RS256"
        self.signing_key = self.key

    def jwks(self):
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}

    def handler(self, request):
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            if self.fail_discovery:
                return httpx.Response(500)
            return httpx.Response(200, json={
                "issuer": self.discovery_issuer, "authorization_endpoint": f"{ISSUER}/auth",
                "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/certs"})
        if path.endswith("/certs"):
            return httpx.Response(200, json=self.jwks())
        if path.endswith("/token"):
            if self.fail_token:
                return httpx.Response(400, json={"error": "invalid_grant"})
            form = parse_qs(request.content.decode())
            code = form["code"][0]
            entry = self.codes.pop(code, None)
            assert form["client_secret"] == [SECRET] and form["client_id"] == [CLIENT_ID]
            if entry is None:
                return httpx.Response(400, json={"error": "invalid_grant"})
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()).rstrip(b"=").decode()
            if challenge != entry["challenge"]:
                return httpx.Response(400, json={"error": "pkce_failed"})
            return httpx.Response(200, json={"id_token": entry["token"], "access_token": "opaque"})
        return httpx.Response(404)

    def authorize(self, location, claims=None, **overrides):
        """Plays the user's browser at the IdP: returns (code, state) for the callback."""
        query = {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}
        assert query["code_challenge_method"] == "S256" and query["response_type"] == "code"
        assert query["client_id"] == CLIENT_ID and query["redirect_uri"] == REDIRECT
        body = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u-1", "iat": int(time.time()), "exp": int(time.time()) + 300,
                "nonce": query["nonce"], "preferred_username": "Alice", "groups": ["wg-ops"]}
        body.update(claims or {})
        for key, value in overrides.items():
            if value is None:
                body.pop(key, None)
            else:
                body[key] = value
        token = jwt.encode(body, self.signing_key, algorithm=self.alg, headers={"kid": self.kid})
        code = f"code-{len(self.codes)}-{query['state'][:6]}"
        self.codes[code] = {"challenge": query["code_challenge"], "token": token}
        return code, query["state"]


@pytest.fixture
def idp():
    return FakeIdp()


@pytest.fixture
def env(tmp_path, crypto, monkeypatch, idp):
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "test-admin-token")
    monkeypatch.setenv("WGOCTOPUS_WEB_COOKIE_SECURE", "false")
    monkeypatch.setenv("WGOCTOPUS_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("WGOCTOPUS_OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("WGOCTOPUS_OIDC_CLIENT_SECRET", SECRET)
    monkeypatch.setenv("WGOCTOPUS_OIDC_REDIRECT_URL", REDIRECT)
    monkeypatch.setenv("WGOCTOPUS_OIDC_ROLE_MAP", ROLE_MAP)
    url = f"sqlite:///{tmp_path / 'oidc.db'}"
    upgrade_to_head(url)
    engine = make_engine(url)
    sessions = make_session_factory(engine)
    app = create_app(session_factory=sessions, reconciler=RecordingReconciler(), crypto=crypto, migrate=False,
                     oidc_transport=httpx.MockTransport(idp.handler))
    with TestClient(app, follow_redirects=False) as client:
        yield client, sessions
    engine.dispose()


def sign_in(client, idp, claims=None, **overrides):
    start = client.get("/auth/oidc/login")
    assert start.status_code == 303
    code, state = idp.authorize(start.headers["location"], claims, **overrides)
    return client.get("/auth/oidc/callback", params={"code": code, "state": state})


def test_role_mapping_helpers():
    assert oidc.parse_role_map("a=admin, b = viewer ,") == {"a": "admin", "b": "viewer"}
    assert oidc.parse_role_map("") == {}
    for bad in ("a", "a=root", "=admin", "a=admin,b"):
        with pytest.raises(ValueError):
            oidc.parse_role_map(bad)
    mapping = {"a": "admin", "b": "viewer", "c": "operator"}
    assert oidc.role_for_groups(["b", "c", "zzz"], mapping) == "operator"
    assert oidc.role_for_groups(["b", "a"], mapping) == "admin"
    assert oidc.role_for_groups("b", mapping) == "viewer"
    assert oidc.role_for_groups(["zzz", 5, None], mapping) is None
    assert oidc.role_for_groups(None, mapping) is None and oidc.role_for_groups({"a": 1}, mapping) is None


def test_login_flow_creates_account_and_session(env, idp):
    client, sessions = env
    start = client.get("/auth/oidc/login")
    location = start.headers["location"]
    assert location.startswith(f"{ISSUER}/auth?") and start.headers["cache-control"] == "no-store"
    cookie = start.headers["set-cookie"].lower()
    assert "wgoctopus_oidc=" in cookie and "httponly" in cookie and "samesite=lax" in cookie and "path=/auth/oidc" in cookie
    query = parse_qs(urlparse(location).query)
    assert query["scope"] == ["openid profile email groups"] and query["nonce"] and query["state"]
    code, state = idp.authorize(location)
    done = client.get("/auth/oidc/callback", params={"code": code, "state": state})
    assert done.status_code == 303 and done.headers["location"] == "/"
    assert "wgoctopus_session=" in done.headers["set-cookie"]
    me = client.get("/auth/me").json()
    assert (me["username"], me["role"], me["source"]) == ("alice", "operator", "oidc")
    with sessions() as s:
        acc = s.scalar(select(WebAccount).where(WebAccount.username == "alice"))
        assert acc.source == "oidc" and acc.subject == "u-1" and acc.password_hash is None and acc.last_login_at
        kinds = [e.kind for e in s.scalars(select(Event))]
        assert "web.login" in kinds and "web_account.created" in kinds
        dump = repr([e.data for e in s.scalars(select(Event))])
        assert SECRET not in dump and code not in dump


def test_role_follows_groups_on_every_login(env, idp):
    client, sessions = env
    assert sign_in(client, idp).status_code == 303
    assert client.get("/auth/me").json()["role"] == "operator"
    client.cookies.clear()
    assert sign_in(client, idp, groups=["wg-admins", "wg-view"]).status_code == 303
    assert client.get("/auth/me").json()["role"] == "admin"
    client.cookies.clear()
    assert sign_in(client, idp, groups=["wg-view"]).status_code == 303
    assert client.get("/auth/me").json()["role"] == "viewer"
    with sessions() as s:
        assert len(s.scalars(select(WebAccount)).all()) == 1


def test_no_matching_group_is_denied_and_creates_nothing(env, idp):
    client, sessions = env
    r = sign_in(client, idp, groups=["random"])
    assert r.status_code == 403 and "oidc_denied" in r.text and "random" not in r.text
    assert "wgoctopus_session" not in r.headers.get("set-cookie", "")
    assert sign_in(client, idp, groups=None).status_code == 403
    with sessions() as s:
        assert s.scalars(select(WebAccount)).all() == []
        assert any(e.kind == "web.login_denied" and e.data.get("reason") == "no_role" for e in s.scalars(select(Event)))


def test_disabled_and_conflicting_accounts_denied(env, idp):
    client, sessions = env
    with sessions.begin() as s:
        webauth.create_account(s, "taken", "long-enough-password", "admin")
    assert sign_in(client, idp, preferred_username="taken").status_code == 403  # username owned by a local account
    assert sign_in(client, idp).status_code == 303
    client.cookies.clear()
    with sessions.begin() as s:
        s.scalar(select(WebAccount).where(WebAccount.username == "alice")).enabled = False
    assert sign_in(client, idp).status_code == 403
    assert client.get("/auth/me").status_code == 401


def test_username_claim_fallbacks(env, idp):
    client, _ = env
    assert sign_in(client, idp, claims={"sub": "u-2"}, preferred_username=None, email="Bob@Example.org").status_code == 303
    assert client.get("/auth/me").json()["username"] == "bob@example.org"
    client.cookies.clear()
    assert sign_in(client, idp, claims={"sub": "u-3"}, preferred_username=None, email=None).status_code == 303
    assert client.get("/auth/me").json()["username"] == "u-3"


@pytest.mark.parametrize("override", [
    {"iss": "https://evil.example.org"}, {"aud": "someone-else"}, {"exp": 1}, {"nonce": "wrong"}, {"nonce": None},
    {"sub": None}, {"iat": None},
])
def test_invalid_id_token_claims_rejected(env, idp, override):
    client, sessions = env
    r = sign_in(client, idp, **override)
    assert r.status_code == 403 and "wgoctopus_session" not in r.headers.get("set-cookie", "")
    with sessions() as s:
        assert s.scalars(select(WebAccount)).all() == []


def test_token_signed_by_unknown_key_or_weak_alg_rejected(env, idp):
    client, _ = env
    idp.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert sign_in(client, idp).status_code == 403
    idp.signing_key = idp.key
    idp.alg = "HS256"
    idp.signing_key = "a-shared-secret-that-is-long-enough-for-hmac"
    assert sign_in(client, idp).status_code == 403
    idp.alg, idp.signing_key = "RS256", idp.key
    other = ec.generate_private_key(ec.SECP256R1())
    idp.alg, idp.signing_key = "ES256", other
    assert sign_in(client, idp).status_code == 403
    assert client.get("/auth/me").status_code == 401


def test_jwks_refetched_once_after_key_rotation(env, idp):
    client, _ = env
    assert sign_in(client, idp).status_code == 303
    client.cookies.clear()
    idp.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp.signing_key, idp.kid = idp.key, "k2"
    assert sign_in(client, idp).status_code == 303
    assert sum(1 for r in idp.requests if r.url.path.endswith("/certs")) == 2


def test_state_binding_and_replay(env, idp):
    client, _ = env
    start = client.get("/auth/oidc/login")
    code, state = idp.authorize(start.headers["location"])
    # a different browser (no state cookie) cannot complete someone else's flow
    stranger = TestClient(client.app, follow_redirects=False)
    assert stranger.get("/auth/oidc/callback", params={"code": code, "state": state}).status_code == 403
    assert client.get("/auth/oidc/callback", params={"code": code, "state": "other"}).status_code == 403
    assert client.get("/auth/oidc/callback", params={"state": state}).status_code == 403
    assert client.get("/auth/oidc/callback", params={"code": code}).status_code == 403
    ok = client.get("/auth/oidc/callback", params={"code": code, "state": state})
    assert ok.status_code == 303
    client.cookies.set("wgoctopus_oidc", state, path="/auth/oidc")
    code2, _ = idp.authorize(start.headers["location"])
    replay = client.get("/auth/oidc/callback", params={"code": code2, "state": state})
    assert replay.status_code == 403  # state is single use


def test_pkce_verifier_is_sent(env, idp):
    client, _ = env
    start = client.get("/auth/oidc/login")
    code, state = idp.authorize(start.headers["location"])
    idp.codes[code]["challenge"] = "tampered"
    r = client.get("/auth/oidc/callback", params={"code": code, "state": state})
    assert r.status_code == 502  # IdP rejected the verifier


def test_idp_failures_are_generic(env, idp):
    client, _ = env
    idp.fail_token = True
    assert sign_in(client, idp).status_code == 502
    idp.fail_token = False
    assert client.get("/auth/oidc/callback", params={"error": "access_denied", "state": "x"}).status_code == 403
    client.app.state.oidc._discovery = (0.0, None)
    idp.fail_discovery = True
    assert client.get("/auth/oidc/login").status_code == 502
    idp.fail_discovery = False
    idp.discovery_issuer = "https://other.example.org"
    client.app.state.oidc._discovery = (0.0, None)
    assert client.get("/auth/oidc/login").status_code == 502


def test_methods_and_disabled_when_unconfigured(tmp_path, crypto, monkeypatch, env):
    client, _ = env
    assert client.get("/auth/methods").json() == {"local": True, "oidc": True}
    for key in ("ISSUER", "CLIENT_ID", "REDIRECT_URL", "ROLE_MAP", "CLIENT_SECRET"):
        monkeypatch.delenv(f"WGOCTOPUS_OIDC_{key}")
    url = f"sqlite:///{tmp_path / 'plain.db'}"
    upgrade_to_head(url)
    sessions = make_session_factory(make_engine(url))
    app = create_app(session_factory=sessions, reconciler=RecordingReconciler(), crypto=crypto, migrate=False)
    with TestClient(app, follow_redirects=False) as plain:
        assert plain.get("/auth/methods").json() == {"local": True, "oidc": False}
        assert plain.get("/auth/oidc/login").status_code == 404
        assert plain.get("/auth/oidc/callback", params={"code": "x", "state": "y"}).status_code == 404


def test_pending_states_are_bounded_and_expire(idp):
    from wgoctopus_orch.config import Settings
    clock = [1000.0]
    settings = Settings(oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_redirect_url=REDIRECT, oidc_role_map=ROLE_MAP)
    provider = oidc.OidcProvider(settings, transport=httpx.MockTransport(idp.handler), clock=lambda: clock[0])
    import asyncio

    async def run():
        _, first = await provider.start()
        clock[0] += oidc.PENDING_TTL + 1
        await provider.start()
        assert first not in provider._pending
        for _ in range(oidc.PENDING_MAX + 5):
            await provider.start()
        assert len(provider._pending) <= oidc.PENDING_MAX
    asyncio.run(run())


def test_settings_validation(monkeypatch, tmp_path):
    from wgoctopus_orch.config import Settings
    monkeypatch.setenv("WGOCTOPUS_OIDC_ROLE_MAP", "group=superuser")
    with pytest.raises(ValueError):
        Settings.from_env()
    monkeypatch.setenv("WGOCTOPUS_OIDC_ROLE_MAP", "group=admin")
    secret = tmp_path / "s"
    secret.write_text("from-file\n")
    monkeypatch.setenv("WGOCTOPUS_OIDC_CLIENT_SECRET", "from-env")
    monkeypatch.setenv("WGOCTOPUS_OIDC_CLIENT_SECRET_FILE", str(secret))
    settings = Settings.from_env()
    assert settings.oidc_client_secret == "from-file" and "from-file" not in repr(settings)
    assert not settings.oidc_enabled
    monkeypatch.setenv("WGOCTOPUS_OIDC_CLIENT_SECRET_FILE", str(tmp_path / "missing"))
    with pytest.raises(ValueError):
        Settings.from_env()
