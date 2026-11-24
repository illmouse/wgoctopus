import re
import secrets

from sqlalchemy import func, select

from . import service
from .models import AdminUsernameHistory, BotUser, Peer, UserRequest, now_utc


class UserError(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def normalize_username(value):
    value = str(value).strip().lstrip("@").lower()
    if not re.fullmatch(r"[a-z0-9_]{1,64}", value):
        raise UserError("invalid", "invalid username")
    return value


def _history(session, username):
    session.merge(AdminUsernameHistory(username=username))


def ensure_user(session, username, *, role="user", config_limit=3, tg_id=None):
    username = normalize_username(username)
    if role not in {"admin", "user"} or config_limit < -1:
        raise UserError("invalid", "invalid role or limit")
    with service._transaction(session):
        user = session.scalar(select(BotUser).where(BotUser.username == username))
        if user:
            if role == "admin" and user.role != "admin" and session.get(AdminUsernameHistory, username):
                raise UserError("forbidden", "admin username is reserved")
            return user
        if role == "admin" and session.get(AdminUsernameHistory, username):
            raise UserError("forbidden", "admin username is reserved")
        user = BotUser(username=username, role=role, config_limit=config_limit, tg_id=tg_id)
        session.add(user)
        if role == "admin":
            _history(session, username)
        session.flush()
        service._event(session, "user.created", user.username)
        return user


def ensure_admin(session, username):
    user = ensure_user(session, username, role="admin", config_limit=-1)
    with service._transaction(session):
        _history(session, user.username)
    return user


def get_user(session, username):
    return session.scalar(select(BotUser).where(BotUser.username == normalize_username(username)))


def list_users(session, status=None, role=None):
    q = select(BotUser)
    if status: q = q.where(BotUser.status == status)
    if role: q = q.where(BotUser.role == role)
    return session.scalars(q.order_by(BotUser.username)).all()


def resolve_user(session, tg_id, username, *, language=None):
    username = normalize_username(username) if username else None
    with service._transaction(session):
        user = session.scalar(select(BotUser).where(BotUser.tg_id == tg_id))
        if user:
            if username and username != user.username:
                old = user.username
                if session.scalar(select(BotUser.id).where(BotUser.username == username)):
                    raise UserError("conflict", "username already exists")
                if user.role == "admin": _history(session, old)
                user.username = username
                session.query(Peer).filter(Peer.owner == old).update({Peer.owner: username})
                session.query(UserRequest).filter(UserRequest.username == old).update({UserRequest.username: username})
            if language is not None: user.language = language
            return user
        user = session.scalar(select(BotUser).where(BotUser.username == username)) if username else None
        if user:
            if user.tg_id is not None and user.tg_id != tg_id: return None
            user.tg_id = tg_id
            if language is not None: user.language = language
        return user


def set_limit(session, username, limit):
    if limit < -1: raise UserError("invalid", "invalid limit")
    with service._transaction(session):
        user = get_user(session, username)
        if not user: raise UserError("not_found", "user not found")
        user.config_limit = limit
        return user


def set_role(session, username, role):
    if role not in {"admin", "user"}: raise UserError("invalid", "invalid role")
    with service._transaction(session):
        user = get_user(session, username)
        if not user: raise UserError("not_found", "user not found")
        if role == "admin" and user.tg_id is None: raise UserError("not_allowed", "admin requires Telegram id")
        if user.role == "admin" and role == "user" and session.scalar(select(func.count()).select_from(BotUser).where(BotUser.role == "admin")) < 2:
            raise UserError("forbidden", "cannot demote last admin")
        user.role = role
        if role == "admin": _history(session, user.username)
        return user


def _peer_rows(session, username):
    return session.scalars(select(Peer).where(Peer.owner == username, Peer.owner != service.PROBE_OWNER)).all()


def disable_user(session, username, by, *, crypto=None):
    user = get_user(session, username)
    if not user: raise UserError("not_found", "user not found")
    if user.role == "admin": raise UserError("forbidden", "cannot disable admin")
    with service._transaction(session):
        user.status, user.disabled_at, user.disabled_by = "disabled", now_utc(), by
        service._event(session, "user.disabled", user.username)
    for peer in _peer_rows(session, user.username): service.set_peer_enabled(session, peer.id, False, crypto)
    return user


def enable_user(session, username, *, crypto=None):
    user = get_user(session, username)
    if not user: raise UserError("not_found", "user not found")
    if user.role == "admin": raise UserError("forbidden", "cannot enable admin")
    with service._transaction(session):
        user.status, user.disabled_at, user.disabled_by = "enabled", None, None
        service._event(session, "user.enabled", user.username)
    for peer in _peer_rows(session, user.username): service.set_peer_enabled(session, peer.id, True, crypto)
    return user


def delete_user(session, username, *, crypto=None):
    user = get_user(session, username)
    if not user: raise UserError("not_found", "user not found")
    if user.role == "admin" and session.scalar(select(func.count()).select_from(BotUser).where(BotUser.role == "admin")) < 2:
        raise UserError("forbidden", "cannot delete last admin")
    for peer in _peer_rows(session, user.username): service.remove_peer(session, peer.id, crypto)
    with service._transaction(session):
        service._event(session, "user.deleted", user.username)
        session.delete(user)
    return True


def count_user_devices(session, username):
    return session.scalar(select(func.count()).select_from(Peer).where(Peer.owner == normalize_username(username), Peer.owner != service.PROBE_OWNER))


def create_request(session, kind, tg_id, username, first_name, last_name, requested_limit=None, notification_refs=None):
    username = normalize_username(username) if username else None
    if kind not in {"access", "limit"}: raise UserError("invalid", "invalid request type")
    with service._transaction(session):
        if kind == "access":
            if session.scalar(select(UserRequest.id).where(UserRequest.type == kind, UserRequest.tg_id == tg_id, UserRequest.status == "pending")): raise UserError("conflict", "pending request exists")
            previous = None
        else:
            user = session.scalar(select(BotUser).where(BotUser.tg_id == tg_id))
            if not user: raise UserError("not_found", "user not found")
            if requested_limit is None or requested_limit < -1 or requested_limit == user.config_limit: raise UserError("invalid", "invalid requested limit")
            if session.scalar(select(UserRequest.id).where(UserRequest.type == kind, UserRequest.tg_id == tg_id, UserRequest.status == "pending")): raise UserError("conflict", "pending request exists")
            previous = user.config_limit
        row = UserRequest(type=kind, tg_id=tg_id, username=username, first_name=first_name, last_name=last_name, requested_limit=requested_limit, previous_limit=previous, notification_refs=notification_refs or [])
        session.add(row); session.flush()
        service._event(session, "request.created", str(row.id))
        return row


def list_requests(session, status=None, type=None, username=None, limit=100, offset=0):
    q = select(UserRequest)
    if status: q = q.where(UserRequest.status == status)
    if type: q = q.where(UserRequest.type == type)
    if username: q = q.where(UserRequest.username == normalize_username(username))
    return session.scalars(q.order_by(UserRequest.id.desc()).limit(limit).offset(offset)).all()


def set_request_refs(session, id, refs):
    with service._transaction(session):
        row = session.get(UserRequest, id)
        if not row: raise UserError("not_found", "request not found")
        row.notification_refs = refs
        return row


def _decide(session, id, status, admin_tg_id, admin_username, default_limit=3):
    with service._transaction(session):
        row = session.get(UserRequest, id)
        if not row: raise UserError("not_found", "request not found")
        if row.status != "pending": raise UserError("conflict", "request already processed")
        if status == "approved":
            if row.type == "access":
                username = row.username or f"user{row.tg_id}"
                existing = session.scalar(select(BotUser).where(BotUser.username == username))
                if existing and existing.tg_id not in (None, row.tg_id): raise UserError("conflict", "username belongs to another user")
                created = not existing
                if not existing: existing = BotUser(username=username, tg_id=row.tg_id, config_limit=default_limit)
                else: existing.tg_id = row.tg_id
                session.add(existing)
                if created: service._event(session, "user.created", existing.username)
            else:
                user = session.scalar(select(BotUser).where(BotUser.tg_id == row.tg_id))
                if not user: raise UserError("not_found", "user not found")
                user.config_limit = row.requested_limit
        row.status, row.admin_id, row.admin_username, row.decided_at = status, admin_tg_id, normalize_username(admin_username) if admin_username else None, now_utc()
        service._event(session, "request." + status, str(row.id))
        return row


def approve_request(session, id, admin_tg_id, admin_username, default_limit=3):
    return _decide(session, id, "approved", admin_tg_id, admin_username, default_limit)


def decline_request(session, id, admin_tg_id, admin_username):
    return _decide(session, id, "declined", admin_tg_id, admin_username)


def create_device(session, username, name, instance_id, *, crypto=None, admin_bypass=False):
    user = get_user(session, username)
    if not user: raise UserError("not_found", "user not found")
    if user.status != "enabled": raise UserError("forbidden", "user disabled")
    if name is None: name = secrets.token_hex(4)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", name): raise UserError("invalid", "invalid device name")
    if session.scalar(select(Peer.id).where(Peer.instance_id == instance_id, func.lower(Peer.name) == name.lower())): raise UserError("conflict", "device name exists")
    if not admin_bypass and user.config_limit != -1 and count_user_devices(session, user.username) >= user.config_limit: raise UserError("forbidden", "device limit reached")
    return service.add_peer(session, instance_id, name, owner=user.username, crypto=crypto)


def rename_device(session, peer_id, new_name):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", new_name or ""): raise UserError("invalid", "invalid device name")
    with service._transaction(session):
        peer = session.get(Peer, peer_id)
        if not peer: raise UserError("not_found", "peer not found")
        if session.scalar(select(Peer.id).where(Peer.instance_id == peer.instance_id, Peer.id != peer_id, func.lower(Peer.name) == new_name.lower())): raise UserError("conflict", "device name exists")
        peer.name = new_name
        return peer
