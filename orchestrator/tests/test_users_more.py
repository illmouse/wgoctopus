import re

import pytest
from test_probes import setup

from wgoctopus_orch.models import NodeRevision, Peer
from wgoctopus_orch.service_users import (
    UserError,
    approve_request,
    create_device,
    create_request,
    decline_request,
    delete_user,
    disable_user,
    enable_user,
    ensure_admin,
    ensure_user,
    rename_device,
    set_role,
)


def test_admin_role_guards_and_peer_delete_revision(session, crypto):
    _, _, _, server, _ = setup(session, crypto)
    ensure_admin(session, "root")
    with pytest.raises(UserError, match="last admin"):
        set_role(session, "root", "user")
    second = ensure_user(session, "second", tg_id=2)
    set_role(session, second.username, "admin")
    assert set_role(session, "root", "user").role == "user"
    user = ensure_user(session, "alice")
    peers = [create_device(session, "alice", f"p{i}", 1, crypto=crypto) for i in range(2)]
    before = session.get(NodeRevision, server.id).desired_revision
    delete_user(session, user.username, crypto=crypto)
    assert all(session.get(Peer, peer.id) is None for peer in peers)
    assert session.get(NodeRevision, server.id).desired_revision > before


def test_disable_enable_peer_revisions(session, crypto):
    instance, _, _, server, _ = setup(session, crypto)
    ensure_user(session, "alice")
    peer = create_device(session, "alice", "phone", instance.id, crypto=crypto)
    before = session.get(NodeRevision, server.id).desired_revision
    disable_user(session, "alice", "root", crypto=crypto)
    assert not session.get(Peer, peer.id).enabled
    disabled_revision = session.get(NodeRevision, server.id).desired_revision
    assert disabled_revision == before + 1
    enable_user(session, "alice", crypto=crypto)
    assert session.get(Peer, peer.id).enabled
    assert session.get(NodeRevision, server.id).desired_revision == disabled_revision + 1


def test_rename_device_validation_conflict_and_missing(session, crypto):
    instance, *_ = setup(session, crypto)
    ensure_user(session, "alice")
    one = create_device(session, "alice", "phone", instance.id, crypto=crypto)
    two = create_device(session, "alice", "tablet", instance.id, crypto=crypto)
    assert rename_device(session, one.id, "new-name").name == "new-name"
    for name, code in (("!bad", "invalid"), ("TABLET", "conflict")):
        with pytest.raises(UserError) as exc:
            rename_device(session, one.id, name)
        assert exc.value.code == code
    with pytest.raises(UserError) as exc:
        rename_device(session, 99999, "valid")
    assert exc.value.code == "not_found" and two.name == "tablet"


def test_request_limit_and_decision_branches(session):
    with pytest.raises(UserError) as exc:
        create_request(session, "limit", 90, "alice", None, None, 4)
    assert exc.value.code == "not_found"
    user = ensure_user(session, "alice", tg_id=10)
    for value in (3, -2):
        with pytest.raises(UserError) as exc:
            create_request(session, "limit", 10, "alice", None, None, value)
        assert exc.value.code == "invalid"
    request = create_request(session, "limit", 10, "alice", None, None, 5)
    assert request.previous_limit == 3
    with pytest.raises(UserError) as exc:
        create_request(session, "limit", 10, "alice", None, None, 6)
    assert exc.value.code == "conflict"
    access = create_request(session, "access", 20, "alice", None, None)
    with pytest.raises(UserError) as exc:
        approve_request(session, access.id, 1, "root")
    assert exc.value.code == "conflict" and access.status == "pending"
    approve_request(session, request.id, 1, "root")
    assert user.config_limit == 5
    fallback = create_request(session, "access", 30, None, None, None)
    approve_request(session, fallback.id, 1, "root")
    assert fallback.status == "approved"
    from wgoctopus_orch.service_users import get_user
    assert get_user(session, "user30").tg_id == 30
    decline = create_request(session, "access", 31, None, None, None)
    assert decline_request(session, decline.id, 1, "root").status == "declined"


def test_create_device_branches(session, crypto):
    instance, *_ = setup(session, crypto)
    user = ensure_user(session, "alice", config_limit=1)
    with pytest.raises(UserError) as exc:
        create_device(session, "missing", "phone", instance.id, crypto=crypto)
    assert exc.value.code == "not_found"
    disable_user(session, user.username, "root", crypto=crypto)
    with pytest.raises(UserError) as exc:
        create_device(session, "alice", "phone", instance.id, crypto=crypto)
    assert exc.value.code == "forbidden"
    enable_user(session, "alice", crypto=crypto)
    for name, code in (("!bad", "invalid"),):
        with pytest.raises(UserError) as exc:
            create_device(session, "alice", name, instance.id, crypto=crypto)
        assert exc.value.code == code
    peer = create_device(session, "alice", "Phone", instance.id, crypto=crypto)
    with pytest.raises(UserError) as exc:
        create_device(session, "alice", "phone", instance.id, crypto=crypto)
    assert exc.value.code == "conflict"
    with pytest.raises(UserError) as exc:
        create_device(session, "alice", "tablet", instance.id, crypto=crypto)
    assert exc.value.code == "forbidden"
    bypass = create_device(session, "alice", "tablet", instance.id, crypto=crypto, admin_bypass=True)
    unlimited = ensure_user(session, "unlimited", config_limit=-1)
    assert create_device(session, unlimited.username, "tab2", instance.id, crypto=crypto)
    auto = create_device(session, "unlimited", None, instance.id, crypto=crypto)
    assert re.fullmatch(r"[0-9a-f]{8}", auto.name)
    assert peer.name == "Phone" and bypass.name == "tablet"
