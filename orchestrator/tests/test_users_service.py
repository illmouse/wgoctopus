import pytest
from test_probes import setup

from wgoctopus_orch.models import AdminUsernameHistory, NodeRevision, Peer
from wgoctopus_orch.service import create_instance
from wgoctopus_orch.service_users import (
    UserError,
    count_user_devices,
    create_device,
    delete_user,
    disable_user,
    enable_user,
    ensure_admin,
    ensure_user,
    get_user,
    normalize_username,
    resolve_user,
    set_limit,
    set_role,
)


def test_user_validation_events_and_role_rules(session):
    from wgoctopus_orch.models import Event

    assert normalize_username(" @Name ") == "name"
    for invalid in ("", "bad-name", "x" * 65):
        with pytest.raises(UserError): normalize_username(invalid)
    admin = ensure_admin(session, "root")
    assert ensure_admin(session, "root") is admin
    resolve_user(session, 1, "root_old")
    session.delete(admin); session.flush()
    with pytest.raises(UserError): ensure_user(session, "root", role="admin")
    user = ensure_user(session, "alice", tg_id=3)
    assert ensure_user(session, "alice") is user
    ensure_user(session, "carol")
    with pytest.raises(UserError, match="admin requires"):
        set_role(session, "carol", "admin")
    with pytest.raises(UserError): set_limit(session, "alice", -2)
    assert set_limit(session, "alice", -1).config_limit == -1
    with pytest.raises(UserError): set_limit(session, "missing", 2)
    assert set_role(session, "alice", "admin")
    assert session.get(AdminUsernameHistory, "alice")
    with pytest.raises(UserError): set_role(session, "alice", "user")
    assert ensure_user(session, "bob", tg_id=2)
    set_role(session, "bob", "admin")
    set_role(session, "alice", "user")
    events = session.query(Event).all()
    assert any(e.kind == "user.created" and e.subject == "alice" and e.data == {} for e in events)


def test_resolve_rename_cascade_conflict_and_bound_rows(session):
    from wgoctopus_orch.models import BotUser, UserRequest
    alice = ensure_user(session, "alice", tg_id=12)
    ensure_user(session, "taken")
    req = UserRequest(type="access", tg_id=30, username="alice", status="pending")
    session.add(req); session.flush()
    with pytest.raises(UserError): resolve_user(session, 12, "taken")
    assert resolve_user(session, 12, "renamed", language="fr") is alice
    assert alice.language == "fr" and req.username == "renamed"
    assert resolve_user(session, 13, "renamed") is None
    unbound = ensure_user(session, "bound")
    assert resolve_user(session, 14, "bound") is unbound and unbound.tg_id == 14
    assert resolve_user(session, 99, "unknown") is None
    assert session.get(BotUser, alice.id)


def test_user_resolution_rename_bind_and_admin_history(session):
    admin = ensure_admin(session, "@Root")
    assert admin.username == "root"
    assert resolve_user(session, 5, "root").tg_id == 5
    resolve_user(session, 5, "newroot")
    assert session.get(AdminUsernameHistory, "root")
    assert ensure_user(session, "root")
    user = ensure_user(session, "alice")
    assert resolve_user(session, 9, "alice") is user
    assert resolve_user(session, 10, "alice") is None
    assert set_role(session, "alice", "admin").role == "admin"


def test_device_limits_cascade_revisions_and_rename(session, crypto):
    instance, _, _, server, _ = setup(session, crypto)
    user = ensure_user(session, "alice", tg_id=1, config_limit=1)
    peer = create_device(session, user.username, "phone", instance.id, crypto=crypto)
    with pytest.raises(UserError, match="device limit reached"):
        create_device(session, "alice", "tablet", instance.id, crypto=crypto)
    revision = session.get(NodeRevision, server.id).desired_revision
    disable_user(session, "alice", "root", crypto=crypto)
    assert not session.get(Peer, peer.id).enabled
    assert session.get(NodeRevision, server.id).desired_revision == revision + 1
    with pytest.raises(UserError): create_device(session, "alice", "other", instance.id, crypto=crypto)
    enable_user(session, "alice", crypto=crypto)
    assert session.get(Peer, peer.id).enabled
    assert count_user_devices(session, "alice") == 1
    create_device(session, "alice", "tablet", instance.id, crypto=crypto, admin_bypass=True)


def test_delete_peer_cascade_and_last_admin(session, crypto):
    instance = create_instance(session, "wg0", 51820, "192.0.2.10/24", crypto=crypto)
    ensure_admin(session, "root")
    with pytest.raises(UserError): set_role(session, "root", "user")
    ensure_user(session, "alice")
    peer = create_device(session, "alice", "phone", instance.id, crypto=crypto)
    delete_user(session, "alice", crypto=crypto)
    assert session.get(Peer, peer.id) is None and get_user(session, "alice") is None
