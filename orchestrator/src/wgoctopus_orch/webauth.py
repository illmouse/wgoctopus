"""Local web authentication primitives and account management."""

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, select

from .models import Event, WebAccount, WebSession

ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}


class WebAuthError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def validate_password(pw):
    if not isinstance(pw, str) or len(pw) < 12:
        raise WebAuthError("weak_password")


def hash_password(pw):
    validate_password(pw)
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(pw.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=128 * 1024 * 1024)
    return f"scrypt$32768$8$1${base64.b64encode(salt).decode()}${base64.b64encode(hashed).decode()}"


def verify_password(pw, stored):
    try:
        algorithm, n, r, p, salt, expected = stored.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt, validate=True), n=int(n), r=int(r), p=int(p), maxmem=128 * 1024 * 1024)
        return hmac.compare_digest(actual, base64.b64decode(expected, validate=True))
    except (AttributeError, ValueError, TypeError, UnicodeError):
        return False


def has_role(actor_role, needed):
    return ROLE_RANK.get(actor_role, 0) >= ROLE_RANK.get(needed, 99)


@dataclass(frozen=True)
class SessionInfo:
    account_id: int
    username: str
    role: str
    csrf: str
    source: str


class SessionStore:
    def __init__(self, session_factory, *, ttl_seconds, idle_seconds, clock=time.time):
        self.session_factory, self.ttl_seconds, self.idle_seconds, self.clock = session_factory, ttl_seconds, idle_seconds, clock

    def create(self, account_id, ip):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = datetime.fromtimestamp(self.clock(), UTC)
        with self.session_factory.begin() as session:
            session.add(WebSession(id=hashlib.sha256(token.encode()).hexdigest(), account_id=account_id, csrf_token=csrf,
                                   created_at=now, last_seen_at=now, expires_at=datetime.fromtimestamp(self.clock() + self.ttl_seconds, UTC), ip=ip))
        return token, csrf

    def lookup(self, token):
        if not token:
            return None
        sid = hashlib.sha256(token.encode()).hexdigest()
        now = datetime.fromtimestamp(self.clock(), UTC)
        with self.session_factory.begin() as session:
            row = session.get(WebSession, sid)
            if not row:
                return None
            account = session.get(WebAccount, row.account_id)
            idle_age = now.timestamp() - row.last_seen_at.replace(tzinfo=UTC).timestamp()
            if row.expires_at.replace(tzinfo=UTC) <= now or idle_age >= self.idle_seconds or not account or not account.enabled:
                session.delete(row)
                return None
            row.last_seen_at = now
            return SessionInfo(account.id, account.username, account.role, row.csrf_token, account.source)

    def revoke(self, token):
        if token:
            with self.session_factory.begin() as session:
                session.execute(delete(WebSession).where(WebSession.id == hashlib.sha256(token.encode()).hexdigest()))

    def revoke_account(self, account_id):
        with self.session_factory.begin() as session:
            session.execute(delete(WebSession).where(WebSession.account_id == account_id))

    def purge_expired(self):
        now = datetime.fromtimestamp(self.clock(), UTC)
        with self.session_factory.begin() as session:
            return session.execute(delete(WebSession).where(WebSession.expires_at <= now)).rowcount


class LoginThrottle:
    def __init__(self, max_failures=5, window=300, lockout=300, clock=time.time):
        self.max_failures, self.window, self.lockout, self.clock = max_failures, window, lockout, clock
        self.failures = {}

    def check(self, username, ip):
        if self.failures.get((username.lower(), ip), ([], 0))[1] > self.clock():
            raise WebAuthError("throttled")

    def record_failure(self, username, ip):
        key = (username.lower(), ip)
        attempts, locked = self.failures.get(key, ([], 0))
        attempts = [t for t in attempts if t > self.clock() - self.window] + [self.clock()]
        self.failures[key] = (attempts, self.clock() + self.lockout if len(attempts) >= self.max_failures else locked)

    def record_success(self, username, ip):
        self.failures.pop((username.lower(), ip), None)


def check_csrf(session_info, supplied):
    return bool(supplied) and hmac.compare_digest(session_info.csrf, supplied)


def authenticate_local(session, username, password, throttle, ip):
    throttle.check(username, ip)
    account = session.scalar(select(WebAccount).where(WebAccount.username == username.lower()))
    valid = verify_password(password, account.password_hash) if account and account.password_hash else verify_password(password, _DUMMY_HASH)
    if not valid or not account or not account.enabled or account.source != "local":
        throttle.record_failure(username, ip)
        _event(session, "web.login_failed", username, {})
        session.commit()  # keep the audit event although the request fails
        raise WebAuthError("invalid_credentials")
    account.last_login_at = datetime.now(UTC)
    throttle.record_success(username, ip)
    _event(session, "web.login", username, {"source": "local"})
    return account


_DUMMY_HASH = "scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def _event(session, kind, subject, data=None):
    session.add(Event(kind=kind, subject=subject, data=data or {}))


def _username(username):
    name = username.strip().lower() if isinstance(username, str) else ""
    if not name or len(name) > 64:
        raise WebAuthError("invalid")
    return name


def _last_admin(session, account, role=None, enabled=None):
    removes = account.source == "local" and account.role == "admin" and account.enabled and (role not in (None, "admin") or enabled is False)
    if removes and session.scalar(select(WebAccount.id).where(WebAccount.source == "local", WebAccount.role == "admin", WebAccount.enabled.is_(True), WebAccount.id != account.id).limit(1)) is None:
        raise WebAuthError("last_admin")


def create_account(session, username, password, role, source="local"):
    username = _username(username)
    if role not in ROLE_RANK or source not in {"local", "oidc"}:
        raise WebAuthError("invalid")
    if session.scalar(select(WebAccount.id).where(WebAccount.username == username)):
        raise WebAuthError("conflict")
    account = WebAccount(username=username, password_hash=hash_password(password) if source == "local" else None, role=role, source=source)
    session.add(account)
    session.flush()
    _event(session, "web_account.created", username)
    return account


def set_password(session, account, password):
    if account.source != "local":
        raise WebAuthError("invalid")
    account.password_hash = hash_password(password)
    _event(session, "web_account.updated", account.username)
    return account


def set_role(session, account, role):
    if role not in ROLE_RANK:
        raise WebAuthError("invalid")
    _last_admin(session, account, role=role)
    account.role = role
    _event(session, "web_account.updated", account.username)
    return account


def set_enabled(session, account, enabled):
    _last_admin(session, account, enabled=enabled)
    account.enabled = enabled
    _event(session, "web_account.updated", account.username)
    return account


def delete_account(session, account):
    _last_admin(session, account, role="viewer", enabled=False)
    username = account.username
    session.delete(account)
    _event(session, "web_account.deleted", username)


def list_accounts(session):
    return session.scalars(select(WebAccount).order_by(WebAccount.username)).all()


def login_oidc(session, identity):
    """Create or refresh the account behind an OIDC identity; the role follows the groups on every login."""
    account = session.scalar(select(WebAccount).where(WebAccount.source == "oidc", WebAccount.subject == identity.subject))
    if account is None:
        if session.scalar(select(WebAccount.id).where(WebAccount.username == identity.username)):
            _event(session, "web.login_denied", identity.username, {"reason": "username_taken"})
            session.commit()
            raise WebAuthError("conflict")
        account = WebAccount(username=identity.username, role=identity.role, source="oidc", subject=identity.subject)
        session.add(account)
        session.flush()
        _event(session, "web_account.created", account.username, {"source": "oidc"})
    elif not account.enabled:
        _event(session, "web.login_denied", account.username, {"reason": "disabled"})
        session.commit()
        raise WebAuthError("disabled")
    if account.role != identity.role:
        account.role = identity.role
        _event(session, "web_account.updated", account.username, {"source": "oidc"})
    account.last_login_at = datetime.now(UTC)
    _event(session, "web.login", account.username, {"source": "oidc"})
    return account
