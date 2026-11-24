import pytest
from sqlalchemy import select

from wgoctopus_orch import webauth
from wgoctopus_orch.db import make_session_factory
from wgoctopus_orch.models import Event, WebAccount, WebSession

PW = "long-enough-password"


class Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def factory(session):
    return make_session_factory(session.get_bind())


def test_password_hashing_and_validation():
    hashed = webauth.hash_password(PW)
    assert hashed.startswith("scrypt$32768$8$1$") and PW not in hashed
    assert webauth.hash_password(PW) != hashed  # random salt
    assert webauth.verify_password(PW, hashed)
    assert not webauth.verify_password("wrong-password-1", hashed)
    for garbage in ("garbage", None, "", "md5$1$2$3$a$b", "scrypt$x$8$1$AA==$AA==", "scrypt$32768$8$1$!!$!!"):
        assert not webauth.verify_password(PW, garbage)
    for weak in ("short", None, 12345):
        with pytest.raises(webauth.WebAuthError, match="weak_password"):
            webauth.hash_password(weak)


def test_role_ranks():
    assert webauth.has_role("admin", "operator") and webauth.has_role("operator", "operator")
    assert not webauth.has_role("viewer", "operator") and not webauth.has_role("viewer", "admin")
    assert not webauth.has_role("nonsense", "viewer") and not webauth.has_role("admin", "nonsense")


def test_account_lifecycle_and_last_admin_guards(session):
    admin = webauth.create_account(session, " Admin ", PW, "admin")
    assert admin.username == "admin" and admin.source == "local"
    with pytest.raises(webauth.WebAuthError, match="conflict"):
        webauth.create_account(session, "ADMIN", PW, "viewer")
    for args in (("", PW, "admin"), ("x" * 65, PW, "admin"), (None, PW, "admin"), ("bob", PW, "root")):
        with pytest.raises(webauth.WebAuthError, match="invalid"):
            webauth.create_account(session, *args)
    with pytest.raises(webauth.WebAuthError, match="weak_password"):
        webauth.create_account(session, "nopass", None, "viewer")
    for action in (lambda: webauth.set_role(session, admin, "viewer"),
                   lambda: webauth.set_enabled(session, admin, False),
                   lambda: webauth.delete_account(session, admin)):
        with pytest.raises(webauth.WebAuthError, match="last_admin"):
            action()
    second = webauth.create_account(session, "second", PW, "admin")
    webauth.set_role(session, admin, "operator")
    assert admin.role == "operator"
    with pytest.raises(webauth.WebAuthError, match="invalid"):
        webauth.set_role(session, second, "root")
    webauth.set_enabled(session, admin, False)
    webauth.set_password(session, admin, "another-long-password")
    assert webauth.verify_password("another-long-password", admin.password_hash)
    webauth.delete_account(session, admin)
    assert [a.username for a in webauth.list_accounts(session)] == ["second"]
    oidc = webauth.create_account(session, "idp-user", None, "viewer", source="oidc")
    assert oidc.password_hash is None
    with pytest.raises(webauth.WebAuthError, match="invalid"):
        webauth.set_password(session, oidc, PW)
    # OIDC admins never count as the last local admin
    webauth.delete_account(session, oidc)
    kinds = {e.kind for e in session.scalars(select(Event))}
    assert {"web_account.created", "web_account.updated", "web_account.deleted"} <= kinds


def test_events_never_contain_secrets(session):
    webauth.create_account(session, "admin", PW, "admin")
    throttle = webauth.LoginThrottle()
    with pytest.raises(webauth.WebAuthError):
        webauth.authenticate_local(session, "admin", "bad-password-xx", throttle, "192.0.2.1")
    webauth.authenticate_local(session, "admin", PW, throttle, "192.0.2.1")
    dump = repr([(e.kind, e.subject, e.data) for e in session.scalars(select(Event))])
    assert "web.login_failed" in dump and "web.login" in dump
    assert PW not in dump and "bad-password" not in dump and "192.0.2.1" not in dump and "scrypt" not in dump


def test_authenticate_local_is_uniform(session):
    webauth.create_account(session, "admin", PW, "admin")
    webauth.create_account(session, "off", PW, "viewer")
    webauth.create_account(session, "sso", None, "viewer", source="oidc")
    session.get(WebAccount, 2).enabled = False
    session.commit()
    throttle = webauth.LoginThrottle(max_failures=100)
    for user, pw in (("nobody", PW), ("admin", "wrong-password-1"), ("off", PW), ("sso", PW)):
        with pytest.raises(webauth.WebAuthError) as err:
            webauth.authenticate_local(session, user, pw, throttle, "192.0.2.1")
        assert err.value.code == "invalid_credentials"
    account = webauth.authenticate_local(session, "ADMIN", PW, throttle, "192.0.2.1")
    assert account.last_login_at is not None


def test_session_store_lifecycle(session):
    account = webauth.create_account(session, "admin", PW, "admin")
    session.commit()
    clock = Clock()
    store = webauth.SessionStore(factory(session), ttl_seconds=100, idle_seconds=40, clock=clock)
    assert store.lookup(None) is None and store.lookup("unknown") is None
    token, csrf = store.create(account.id, "192.0.2.1")
    stored = session.scalars(select(WebSession)).all()
    assert len(stored) == 1 and stored[0].id != token and token not in repr(stored[0].__dict__)
    info = store.lookup(token)
    assert (info.username, info.role, info.csrf, info.source) == ("admin", "admin", csrf, "local")
    clock.now += 30
    assert store.lookup(token)  # activity slides the idle window
    clock.now += 30
    assert store.lookup(token)
    clock.now += 41
    assert store.lookup(token) is None  # idle
    token, _ = store.create(account.id, "")
    clock.now += 39
    assert store.lookup(token)
    clock.now += 39
    assert store.lookup(token)
    clock.now += 39
    assert store.lookup(token) is None  # absolute ttl (117s > 100s)
    token, _ = store.create(account.id, "")
    store.revoke(token)
    assert store.lookup(token) is None
    store.revoke(None)
    t1, _ = store.create(account.id, "")
    t2, _ = store.create(account.id, "")
    store.revoke_account(account.id)
    assert store.lookup(t1) is None and store.lookup(t2) is None


def test_session_dies_when_account_disabled_or_deleted(session):
    account = webauth.create_account(session, "admin", PW, "admin")
    other = webauth.create_account(session, "other", PW, "admin")
    session.commit()
    store = webauth.SessionStore(factory(session), ttl_seconds=100, idle_seconds=100, clock=Clock())
    token, _ = store.create(account.id, "")
    gone, _ = store.create(other.id, "")
    session.get(WebAccount, account.id).enabled = False
    session.commit()
    assert store.lookup(token) is None
    session.delete(session.get(WebAccount, other.id))
    session.commit()
    assert store.lookup(gone) is None


def test_purge_expired(session):
    account = webauth.create_account(session, "admin", PW, "admin")
    session.commit()
    clock = Clock()
    store = webauth.SessionStore(factory(session), ttl_seconds=10, idle_seconds=100, clock=clock)
    store.create(account.id, "")
    store.create(account.id, "")
    clock.now += 11
    store.create(account.id, "")
    assert store.purge_expired() == 2


def test_throttle_locks_and_unlocks():
    clock = Clock()
    throttle = webauth.LoginThrottle(max_failures=3, window=60, lockout=120, clock=clock)
    for _ in range(2):
        throttle.record_failure("Bob", "192.0.2.1")
        throttle.check("bob", "192.0.2.1")
    throttle.check("bob", "192.0.2.2")  # other ip unaffected
    throttle.record_failure("bob", "192.0.2.1")
    with pytest.raises(webauth.WebAuthError, match="throttled"):
        throttle.check("bob", "192.0.2.1")
    clock.now += 121
    throttle.check("bob", "192.0.2.1")
    throttle.record_failure("bob", "192.0.2.1")
    throttle.record_success("bob", "192.0.2.1")
    assert ("bob", "192.0.2.1") not in throttle.failures
    # failures outside the window are forgotten
    throttle.record_failure("eve", "x")
    throttle.record_failure("eve", "x")
    clock.now += 61
    throttle.record_failure("eve", "x")
    throttle.check("eve", "x")


def test_csrf_compare():
    info = webauth.SessionInfo(1, "a", "admin", "tok", "local")
    assert webauth.check_csrf(info, "tok")
    assert not webauth.check_csrf(info, "bad") and not webauth.check_csrf(info, None) and not webauth.check_csrf(info, "")
