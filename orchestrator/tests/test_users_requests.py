import pytest

from wgoctopus_orch.service_users import (
    UserError,
    approve_request,
    create_request,
    decline_request,
    ensure_user,
    get_user,
    list_requests,
)


def test_access_request_approve_once_and_duplicate_pending(session):
    req = create_request(session, "access", 44, None, "First", None)
    with pytest.raises(UserError): create_request(session, "access", 44, None, None, None)
    approve_request(session, req.id, 1, "admin")
    assert get_user(session, "user44").tg_id == 44
    with pytest.raises(UserError): approve_request(session, req.id, 1, "admin")


def test_limit_request_flow_and_decline(session):
    ensure_user(session, "alice", tg_id=11)
    req = create_request(session, "limit", 11, "alice", "A", None, 5)
    assert req.previous_limit == 3
    assert list_requests(session, status="pending", type="limit") == [req]
    approve_request(session, req.id, 1, "root")
    assert get_user(session, "alice").config_limit == 5
    other = create_request(session, "access", 22, "bob", "B", None)
    decline_request(session, other.id, 1, "root")
    with pytest.raises(UserError): decline_request(session, other.id, 1, "root")
