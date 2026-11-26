import asyncio
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_api_provision import swap
from test_api_web_auth import BEARER, PW, build, login
from test_bootstrap import DOC
from test_provision_steps import FakeHost

from wgoctopus_orch import service, service_users, webauth, webui
from wgoctopus_orch.failover import FailoverError
from wgoctopus_orch.models import (
    BotUser,
    Event,
    FailoverProposal,
    FailoverSettings,
    HopLink,
    Instance,
    Node,
    Peer,
    Probe,
    UserRequest,
    WebAccount,
)
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


def test_management_pages_role_access_and_csrf(ui):
    client, _ = ui
    paths = ("/ui/users", "/ui/accounts", "/ui/devices")
    for path in paths:
        assert client.get(path).status_code == 303
    for username in ("view", "ops"):
        client.cookies.clear()
        login(client, username)
        expected = [403, 403, 403] if username == "view" else [200, 200, 200]
        assert [client.get(path).status_code for path in paths] == expected
        assert client.post("/ui/users/create", data={"username": "blocked"}).status_code == 403
    client.cookies.clear()
    login(client)
    assert all(client.get(path).status_code == 200 for path in paths)
    assert client.post("/ui/users/create", data={"username": "blocked"}).status_code == 403
    assert client.post("/ui/accounts/create", data={"username": "blocked"}).status_code == 403
    assert client.post("/ui/devices/create", data={"owner": "blocked"}).status_code == 403


def test_user_admin_creation_requires_telegram_id(ui):
    client, sessions = ui
    login(client)
    headers = csrf_of(client)
    assert client.post("/ui/users/create", data={"username": "botadmin", "role": "admin"}, headers=headers).status_code == 400
    with sessions() as s:
        assert service_users.get_user(s, "botadmin") is None
    response = client.post("/ui/users/create", data={"username": "botadmin", "role": "admin", "tg_id": "123"}, headers=headers)
    assert response.status_code == 303, response.text
    with sessions() as s:
        user = s.query(BotUser).filter_by(username="botadmin").one()
        assert user.role == "admin" and user.tg_id == 123


def test_user_rename_and_promote_in_one_update(ui):
    client, sessions = ui
    with sessions.begin() as s:
        service_users.ensure_user(s, "botuser")
    login(client)
    response = client.post(
        "/ui/users/botuser/update",
        data={"_csrf": csrf_of(client)["X-CSRF-Token"], "username": "renamed", "tg_id": "456",
              "role": "admin", "config_limit": "-1", "status": "enabled"},
    )
    assert response.status_code == 303
    with sessions() as s:
        user = service_users.get_user(s, "renamed")
        assert user and user.tg_id == 456 and user.role == "admin" and user.config_limit == -1


def test_accounts_create_password_reset_and_safeguards(ui):
    client, sessions = ui
    login(client)
    headers = csrf_of(client)
    with sessions() as s:
        accounts = {a.username: a.id for a in s.query(WebAccount).all()}
    invalid_htmx = client.post("/ui/accounts/create", data={
        "username": "admin", "password": PW, "role": "viewer",
    }, headers={**headers, "HX-Request": "true"})
    assert invalid_htmx.status_code == 400 and "Invalid account details" in invalid_htmx.text
    assert client.post("/ui/accounts/create", data={"username": "newui", "password": PW, "role": "viewer"}, headers=headers).status_code == 303
    assert "newui" in client.get("/ui/accounts").text
    with sessions() as s:
        new_id = s.query(WebAccount).filter_by(username="newui").one().id
    assert client.post(f"/ui/accounts/{new_id}/password", data={"password": "reset-password-123"}, headers=headers).status_code == 303
    client.cookies.clear()
    assert login(client, "newui", "reset-password-123").status_code == 200
    client.cookies.clear()
    login(client)
    headers = csrf_of(client)
    admin_id = accounts["admin"]
    assert client.post(f"/ui/accounts/{admin_id}/update", data={"role": "viewer", "enabled": "on"}, headers=headers).status_code == 400
    assert "cannot disable or demote" in client.post(f"/ui/accounts/{admin_id}/update", data={"role": "admin"}, headers=headers).text
    assert "cannot delete your own" in client.post(f"/ui/accounts/{admin_id}/delete", headers=headers).text
    assert client.post(f"/ui/accounts/{admin_id}/delete").status_code == 403
    with sessions.begin() as s:
        webauth.create_account(s, "admin2", PW, "admin")
        second_id = s.query(WebAccount).filter_by(username="admin2").one().id
    assert client.post(f"/ui/accounts/{second_id}/update", data={"role": "viewer", "enabled": "on"}, headers=headers).status_code == 303
    assert client.post(f"/ui/accounts/{admin_id}/update", data={"role": "viewer", "enabled": "on"}, headers=headers).status_code == 400

def test_devices_create_reassign_revoke_and_probe_protection(ui):
    client, sessions = ui
    instance, _, _ = make_instance(client)
    with sessions.begin() as s:
        service_users.ensure_user(s, "device_owner")
        probe = Peer(instance_id=instance["id"], name="probe", public_key="A" * 43 + "=", allowed_ip="10.255.255.1", owner="__probe__")
        s.add(probe)
        s.flush()
        probe_id = probe.id
    login(client)
    headers = csrf_of(client)
    data = {"owner": "device_owner", "name": "phone", "instance_id": str(instance["id"])}
    assert client.post("/ui/devices/create", data=data).status_code == 403
    assert client.post("/ui/devices/create", data=data, headers=headers).status_code == 303
    with sessions() as s:
        peer = s.query(Peer).filter_by(name="phone").one()
        peer_id = peer.id
    assert client.post(f"/ui/devices/{peer_id}/owner", data={"owner": ""}, headers=headers).status_code == 303
    assert client.post(f"/ui/devices/{peer_id}/owner", data={"owner": "device_owner"}).status_code == 403
    assert client.post(f"/ui/devices/{peer_id}/revoke", headers=headers).status_code == 303
    assert client.post(f"/ui/devices/{probe_id}/revoke").status_code == 403
    assert client.post(f"/ui/devices/{probe_id}/owner", data={"owner": ""}, headers=headers).status_code == 400
    assert client.post(f"/ui/devices/{probe_id}/revoke", headers=headers).status_code == 404


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


def test_node_new_page_and_inline_validation(ui):
    client, _ = ui
    login(client)
    page = client.get("/ui/nodes/new")
    assert page.status_code == 200 and 'action="/ui/nodes/create"' in page.text
    assert client.post("/ui/nodes/create", data={
        "name": "", "_csrf": csrf_of(client)["X-CSRF-Token"],
    }).status_code == 422
    client.cookies.clear()
    login(client, "view")
    assert client.get("/ui/nodes/new").status_code == 403


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


def make_instance(client, name="wg0", endpoint="vpn.example.org", index=0):
    body = {"name": name, "listen_port": 51820 + index, "address": f"10.0.{index}.1/29"}
    if endpoint:
        body["endpoint_host"] = endpoint
    instance = client.post("/v1/instances", json=body, headers=BEARER).json()
    node_a, node_b = add_node(client, f"{name}-a"), add_node(client, f"{name}-b")
    for node, role in ((node_a, "active"), (node_b, "standby")):
        assert client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role": role}, headers=BEARER).status_code == 200
    return instance, node_a, node_b


def add_peer(client, iid, name, owner=None):
    r = client.post(f"/v1/instances/{iid}/peers", json={"name": name, "owner": owner}, headers=BEARER)
    assert r.status_code == 201, r.text
    return r.json()


def test_instances_pages_and_pagination(ui, monkeypatch):
    client, _ = ui
    instance, _, _ = make_instance(client)
    iid = instance["id"]
    for index in range(3):
        add_peer(client, iid, f"peer-{index}")
    assert client.get("/ui/instances").status_code == 303
    assert client.get(f"/ui/instances/{iid}").status_code == 303
    login(client, "view")
    listing = client.get("/ui/instances")
    assert listing.status_code == 200 and f"/ui/instances/{iid}" in listing.text and "wg0-a" in listing.text
    detail = client.get(f"/ui/instances/{iid}")
    assert detail.status_code == 200 and "10.0.0.1/29" in detail.text and instance["public_key"] in detail.text
    assert "peer-0" in detail.text and "wg0-b" in detail.text and "Peers (3)" in detail.text
    assert "PrivateKey" not in detail.text and "private_key" not in detail.text
    assert "hx-post" not in detail.text and "Config" not in detail.text  # viewer: read-only
    missing = client.get("/ui/instances/999")
    assert missing.status_code == 404 and "Instance not found" in missing.text
    monkeypatch.setattr(webui, "PEER_PAGE", 2)
    first = client.get(f"/ui/instances/{iid}")
    assert "peer-1" in first.text and "peer-2" not in first.text and "Next" in first.text and "Previous" not in first.text
    second = client.get(f"/ui/instances/{iid}?offset=2")
    assert "peer-2" in second.text and "peer-0" not in second.text and "Previous" in second.text and "Next" not in second.text
    assert "peer-0" in client.get(f"/ui/instances/{iid}?offset=-5").text


def test_empty_instances(ui):
    client, _ = ui
    login(client)
    assert "No instances yet" in client.get("/ui/instances").text


def test_instance_new_page_role_and_create_csrf(ui):
    client, _ = ui
    login(client)
    page = client.get("/ui/instances/new")
    assert page.status_code == 200
    assert 'id="awg-generator"' in page.text and 'id="instance-create"' in page.text
    assert client.post("/ui/instances/create", data={"name": "bad"}).status_code == 403
    invalid = client.post("/ui/instances/create", data={
        "name": "invalid name", "address": "bad", "listen_port": "0",
        "_csrf": csrf_of(client)["X-CSRF-Token"],
    })
    assert invalid.status_code == 422 and "Check the instance name" in invalid.text
    client.cookies.clear()
    login(client, "view")
    assert client.get("/ui/instances/new").status_code == 403


def test_admin_can_create_instance_node_and_placement(ui):
    client, sessions = ui
    login(client)
    token = {"_csrf": client.get("/auth/me").json()["csrf_token"]}
    assert client.post("/ui/nodes/create", data={"name": "node1", **token}).status_code == 303
    node_page = client.get("/ui/nodes")
    assert "node1" in node_page.text
    assert client.post("/ui/instances/create", data={"name": "wgnew", "address": "10.9.0.1/24",
        "listen_port": "51820", **token}).status_code == 303
    with sessions() as s:
        instance = s.scalars(select(Instance).where(Instance.name == "wgnew")).one()
        node = s.scalars(select(Node).where(Node.name == "node1")).one()
        iid, nid = instance.id, node.id
    assert client.post(f"/ui/instances/{iid}/placements",
        data={"node_id": str(nid), "role": "active", "weight": "1", **token}).status_code == 303
    assert "node1" in client.get(f"/ui/instances/{iid}").text
    client.cookies.clear()
    login(client, "ops")
    assert client.post("/ui/nodes/create", data={"name": "blocked", **csrf_of(client)}).status_code == 403
    login(client, "admin")
    assert client.post("/ui/nodes/create", data={"name": "blocked"}).status_code == 403


def test_node_and_instance_delete_require_admin_csrf_and_confirmation(ui):
    client, sessions = ui
    login(client)
    csrf = csrf_of(client)
    token = {"_csrf": csrf["X-CSRF-Token"]}
    assert client.post("/ui/nodes/create", data={"name": "removable-node", **token}).status_code == 303
    assert client.post("/ui/instances/create", data={
        "name": "removable", "address": "10.50.0.1/24", "listen_port": "52000", **token,
    }).status_code == 303
    with sessions() as s:
        nid = s.scalar(select(Node.id).where(Node.name == "removable-node"))
        iid = s.scalar(select(Instance.id).where(Instance.name == "removable"))
    assert client.post(f"/ui/nodes/{nid}/delete", data={"confirm": "yes"}).status_code == 403
    assert client.post(f"/ui/instances/{iid}/delete", data={"confirm": "yes"}).status_code == 403
    client.cookies.clear()
    login(client, "view")
    viewer_form = {"confirm": "yes", "_csrf": csrf_of(client)["X-CSRF-Token"]}
    assert client.post(f"/ui/nodes/{nid}/delete", data=viewer_form).status_code == 403
    client.cookies.clear()
    login(client)
    token = {"_csrf": csrf_of(client)["X-CSRF-Token"]}
    assert client.post(f"/ui/nodes/{nid}/delete", data={**token}).status_code == 400
    assert client.post(f"/ui/instances/{iid}/delete", data={**token}).status_code == 400
    assert client.post(f"/ui/nodes/{nid}/delete", data={"confirm": "yes", **token}).status_code == 303
    assert client.post(f"/ui/instances/{iid}/delete", data={"confirm": "yes", **token}).status_code == 303


def test_operator_manages_peers(ui):
    client, sessions = ui
    instance, _, _ = make_instance(client)
    iid = instance["id"]
    login(client, "ops")
    headers = csrf_of(client)
    detail = client.get(f"/ui/instances/{iid}")
    assert "Add peer" in detail.text and "Make active" in detail.text
    kicks = len(client.app.state.reconciler.kicks)
    added = client.post(f"/ui/instances/{iid}/peers", content="name=phone&owner=alice", headers=headers)
    assert added.status_code == 200 and added.headers["hx-retarget"] == "#peer-rows"
    assert added.headers["hx-reswap"] == "afterbegin" and "<tr>" in added.text
    peers = client.get(f"/v1/instances/{iid}/peers", headers=BEARER).json()
    assert [(p["name"], p["owner"]) for p in peers] == [("phone", "alice")]
    assert len(client.app.state.reconciler.kicks) > kicks
    pid = peers[0]["id"]
    page = client.get(f"/ui/instances/{iid}")
    assert "phone" in page.text and "Disable" in page.text and f"/ui/peers/{pid}/config" in page.text

    invalid = client.post(f"/ui/instances/{iid}/peers", content="name=+&owner=",
                          headers={**headers, "HX-Request": "true"})
    assert invalid.status_code == 200 and "required" in invalid.text
    assert "reserved" in client.post(f"/ui/instances/{iid}/peers", content=f"name=x&owner={service.PROBE_OWNER}", headers=headers).text
    assert "unknown instance" in client.post("/ui/instances/999/peers", content="name=x", headers=headers).text
    for index in range(4):
        assert client.post(f"/ui/instances/{iid}/peers", content=f"name=p{index}", headers=headers).status_code == 200
    assert "no free peer address" in client.post(f"/ui/instances/{iid}/peers", content="name=full", headers=headers).text

    off = client.post(f"/ui/peers/{pid}/enabled?value=false", headers=headers)
    assert off.status_code == 204 and client.get(f"/v1/peers/{pid}", headers=BEARER).json()["enabled"] is False
    assert "Enable" in client.get(f"/ui/instances/{iid}").text
    assert client.post(f"/ui/peers/{pid}/enabled?value=true", headers=headers).status_code == 204
    assert client.get(f"/v1/peers/{pid}", headers=BEARER).json()["enabled"] is True
    assert "unknown peer" in client.post("/ui/peers/999/enabled?value=true", headers=headers).text

    assert client.post(f"/ui/peers/{pid}/delete", headers=headers).status_code == 204
    assert client.get(f"/v1/peers/{pid}", headers=BEARER).status_code == 404
    assert "unknown peer" in client.post(f"/ui/peers/{pid}/delete", headers=headers).text

    with sessions() as s:
        kinds = [e.kind for e in s.scalars(select(Event).order_by(Event.id))]
        for kind in ("web.peer_add", "web.peer_enabled", "web.peer_delete"):
            assert kind in kinds
        added_event = s.scalars(select(Event).where(Event.kind == "web.peer_add")).first()
        assert added_event.subject == "ops" and added_event.data["instance_id"] == iid


def test_peer_config_download_is_audited(ui):
    client, sessions = ui
    instance, *_ = make_instance(client)
    bare, *_ = make_instance(client, "bare", endpoint=None, index=1)
    pid = add_peer(client, instance["id"], "phone")["id"]
    bare_pid = add_peer(client, bare["id"], "tablet")["id"]
    assert client.get(f"/ui/peers/{pid}/config").status_code == 303
    login(client, "view")
    assert client.get(f"/ui/peers/{pid}/config").status_code == 403
    client.cookies.clear()
    login(client, "ops")
    r = client.get(f"/ui/peers/{pid}/config")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert r.headers["content-disposition"] == f'attachment; filename="peer-{pid}.conf"' and r.headers["cache-control"] == "no-store"
    assert "[Interface]" in r.text and "vpn.example.org" in r.text
    with sessions() as s:
        event = s.scalars(select(Event).where(Event.kind == "peer.config_issued")).one()
        assert event.subject == str(pid) and event.data == {"by": "ops"}
    no_host = client.get(f"/ui/peers/{bare_pid}/config")
    assert no_host.status_code == 409 and "endpoint_host is required" in no_host.text
    assert client.get("/ui/peers/999/config").status_code == 404


def test_peer_qr_is_operator_only_and_served_locally(ui):
    client, _ = ui
    instance, *_ = make_instance(client)
    peer_id = add_peer(client, instance["id"], "qr-phone")["id"]
    login(client, "view")
    assert client.get(f"/ui/peers/{peer_id}/qr").status_code == 403
    client.cookies.clear()
    login(client, "ops")
    response = client.get(f"/ui/peers/{peer_id}/qr")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in response.text


def test_switch_active_node_from_ui(ui):
    client, sessions = ui
    instance, _, node_b = make_instance(client)
    other = add_node(client, "elsewhere")
    iid = instance["id"]
    url = f"/ui/instances/{iid}/switch"
    assert client.post(f"{url}?node_id={node_b['id']}").status_code == 401
    login(client, "ops")
    assert client.post(f"{url}?node_id={node_b['id']}").status_code == 403  # no CSRF
    headers = csrf_of(client)
    assert "no placement" in client.post(f"{url}?node_id={other['id']}", headers=headers).text
    assert "unknown instance" in client.post(f"/ui/instances/999/switch?node_id={node_b['id']}", headers=headers).text
    moved = client.post(f"{url}?node_id={node_b['id']}", headers=headers)
    assert moved.status_code == 204 and moved.headers["hx-refresh"] == "true"
    assert client.get(f"/v1/instances/{iid}", headers=BEARER).json()["active_node_id"] == node_b["id"]
    with sessions() as s:
        event = s.scalars(select(Event).where(Event.kind == "web.switch")).one()
        assert event.data == {"instance_id": iid, "to_node_id": node_b["id"]}


def test_viewer_cannot_mutate_peers_or_switch(ui):
    client, _ = ui
    instance, _, node_b = make_instance(client)
    pid = add_peer(client, instance["id"], "phone")["id"]
    login(client, "view")
    headers = csrf_of(client)
    for url in (f"/ui/instances/{instance['id']}/peers", f"/ui/peers/{pid}/enabled?value=false", f"/ui/peers/{pid}/delete",
                f"/ui/instances/{instance['id']}/switch?node_id={node_b['id']}"):
        assert client.post(url, headers=headers).status_code == 403
    assert client.get(f"/v1/peers/{pid}", headers=BEARER).json()["enabled"] is True


# failover, requests and bootstrap pages (7.4d)
class StubFailover:
    KEYS = ("id", "instance_id", "hop_id", "from_node_id", "to_node_id", "state", "mode_at_creation", "reason",
            "created_at", "expires_at", "decided_at", "decided_by", "error")

    def __init__(self):
        self.calls, self.error = [], None

    def _decide(self, action, ident, by, actor):
        self.calls.append((action, ident, by, actor))
        if self.error:
            raise FailoverError(self.error)
        return SimpleNamespace(**dict.fromkeys(self.KEYS))

    def confirm(self, ident, *, by, actor=None):
        return self._decide("confirm", ident, by, actor)

    def reject(self, ident, *, by, actor=None):
        return self._decide("reject", ident, by, actor)


def add_proposal(sessions, instance, hop, source, target, state="pending", reason="probe_down"):
    now = datetime.now(UTC)
    with sessions.begin() as s:
        row = FailoverProposal(instance_id=instance["id"], hop_id=hop["id"], from_node_id=source["id"], to_node_id=target["id"],
                               state=state, mode_at_creation="confirm", reason=reason, created_at=now, expires_at=now + timedelta(hours=1))
        s.add(row)
        s.flush()
        return row.id


def failover_fixture(client, sessions):
    instance, node_a, node_b = make_instance(client)
    hop = add_node(client, "hop-1")
    return instance, hop, node_a, node_b


def test_failover_page_roles_and_history(ui, monkeypatch):
    client, sessions = ui
    instance, hop, node_a, node_b = failover_fixture(client, sessions)
    pending = add_proposal(sessions, instance, hop, node_a, node_b, reason="<b>probe</b>")
    add_proposal(sessions, instance, hop, node_a, node_b, state="executed")
    add_proposal(sessions, instance, hop, node_a, node_b, state="failed")
    assert client.get("/ui/failover").status_code == 303
    assert client.get("/ui/fragments/failover").status_code == 401
    login(client, "view")
    page = client.get("/ui/failover")
    assert page.status_code == 200 and "Pending proposals" in page.text and "wg0-a" in page.text and "hop-1" in page.text
    assert "evaluator not running" not in page.text and "confirm" in page.text
    client.app.state.failover = None
    assert "evaluator not running" in client.get("/ui/failover").text
    assert "&lt;b&gt;probe&lt;/b&gt;" in page.text and "<b>probe</b>" not in page.text
    assert "hx-post" not in page.text.replace('hx-post="/auth', "") and f"/ui/failovers/{pending}/confirm" not in page.text
    only = client.get("/ui/failover?state=executed")
    assert "History (1)" in only.text and "executed" in only.text
    assert "History (3)" in client.get("/ui/failover?state=bogus").text
    monkeypatch.setattr(webui, "LIST_PAGE", 1)
    first = client.get("/ui/failover")
    assert "Older" in first.text and "Newer" not in first.text
    second = client.get("/ui/failover?offset=1")
    assert "Newer" in second.text and "Older" in second.text
    assert "Newer" not in client.get("/ui/failover?offset=-4").text
    client.cookies.clear()
    login(client, "ops")
    assert f"/ui/failovers/{pending}/confirm" in client.get("/ui/failover").text
    fragment = client.get("/ui/fragments/failover")
    assert fragment.status_code == 200 and "<html" not in fragment.text and f"/ui/failovers/{pending}/reject" in fragment.text


def test_failover_empty_state(ui):
    client, _ = ui
    login(client)
    page = client.get("/ui/failover")
    assert "No pending proposals" in page.text and "No proposals" in page.text


def test_failover_settings_env_priority_roles_and_csrf(tmp_path, crypto, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_FAILOVER_MODE", "auto")
    app, sessions, engine = build(tmp_path, crypto, monkeypatch)
    with sessions.begin() as s:
        for username, role in (("admin", "admin"), ("ops", "operator"), ("view", "viewer")):
            webauth.create_account(s, username, PW, role)
    with TestClient(app, follow_redirects=False) as client:
        login(client)
        page = client.get("/ui/failover")
        assert page.status_code == 200 and 'name="mode" disabled' in page.text and "set via env" in page.text
        payload = {"mode": "confirm", "down_seconds": "80", "proposal_ttl_seconds": "700",
                   "cooldown_seconds": "30", "eval_interval": "5"}
        assert client.post("/ui/failover/settings", data=payload).status_code == 403
        assert client.post("/ui/failover/settings", data=payload | {"_csrf": csrf_of(client)["X-CSRF-Token"]}).status_code == 303
        with sessions() as s:
            row = s.get(FailoverSettings, 1)
            assert row.mode == "confirm" and row.down_seconds == 80 and row.eval_interval == 5
        assert "auto" in client.get("/ui/failover").text
        assert client.post("/ui/failover/settings", data=payload | {"down_seconds": "0", "_csrf": csrf_of(client)["X-CSRF-Token"]}).status_code == 400
        client.cookies.clear()
        login(client, "ops")
        assert client.post("/ui/failover/settings", data=payload | {"_csrf": csrf_of(client)["X-CSRF-Token"]}).status_code == 403
        client.cookies.clear()
        login(client, "view")
        assert client.post("/ui/failover/settings", data=payload | {"_csrf": csrf_of(client)["X-CSRF-Token"]}).status_code == 403
    engine.dispose()


def test_failover_ui_probe_and_link_crud(ui):
    client, sessions = ui
    instance, node_a, _node_b = make_instance(client)
    hop = add_node(client, "hop-ui", kind="hop", hop_ip="10.0.0.1", wan_interface="eth0")
    assert client.post("/ui/failover/links", data={"hop_id": hop["id"], "instance_id": instance["id"]}).status_code == 401
    login(client, "view")
    assert client.post("/ui/failover/links", data={"hop_id": hop["id"], "instance_id": instance["id"]}).status_code == 403
    client.cookies.clear()
    login(client)
    csrf = {"_csrf": csrf_of(client)["X-CSRF-Token"]}
    link = {"hop_id": str(hop["id"]), "instance_id": str(instance["id"]), **csrf}
    assert client.post("/ui/failover/links", data={k: v for k, v in link.items() if k != "_csrf"}).status_code == 403
    assert client.post("/ui/failover/links", data=link).status_code == 303
    with sessions() as s:
        assert s.scalar(select(HopLink).where(HopLink.hop_id == hop["id"])) is not None
    probe = link | {"runner_node_id": str(node_a["id"])}
    assert client.post("/ui/failover/probes", data=probe).status_code == 303
    with sessions() as s:
        probe_id = s.scalar(select(Probe.id).where(Probe.hop_id == hop["id"]))
    assert client.post(f"/ui/failover/probes/{probe_id}/delete", data=csrf).status_code == 400
    assert client.post(f"/ui/failover/probes/{probe_id}/delete", data=csrf | {"confirm": "yes"}).status_code == 303
    assert client.post(f"/ui/failover/links/{hop['id']}/{instance['id']}/delete", data=csrf).status_code == 400
    assert client.post(f"/ui/failover/links/{hop['id']}/{instance['id']}/delete", data=csrf | {"confirm": "yes"}).status_code == 303
    with sessions() as s:
        assert s.scalar(select(Probe.id).where(Probe.id == probe_id)) is None
        assert s.scalar(select(HopLink.id).where(HopLink.hop_id == hop["id"])) is None


def test_operator_manual_failover_requires_confirmation_and_csrf(ui):
    client, _sessions = ui
    instance, _source, target = make_instance(client)
    login(client, "ops")
    form = {"instance_id": str(instance["id"]), "node_id": str(target["id"]), "confirm": "yes"}
    assert client.post("/ui/failover/manual", data=form).status_code == 403
    csrf = {"_csrf": csrf_of(client)["X-CSRF-Token"]}
    assert client.post("/ui/failover/manual", data=form | csrf | {"confirm": "no"}).status_code == 400
    assert client.post("/ui/failover/manual", data=form | csrf).status_code == 303


def test_operator_confirms_and_rejects_failover(ui):
    client, sessions = ui
    instance, hop, node_a, node_b = failover_fixture(client, sessions)
    proposal = add_proposal(sessions, instance, hop, node_a, node_b)
    stub = client.app.state.failover = StubFailover()
    url = f"/ui/failovers/{proposal}"
    assert client.post(f"{url}/confirm").status_code == 401
    login(client, "view")
    headers = csrf_of(client)
    assert client.post(f"{url}/confirm", headers=headers).status_code == 403
    client.cookies.clear()
    login(client, "ops")
    assert client.post(f"{url}/confirm").status_code == 403  # no CSRF
    headers = csrf_of(client)
    ok = client.post(f"{url}/confirm", headers=headers)
    assert ok.status_code == 204 and ok.headers["hx-refresh"] == "true"
    assert client.post(f"{url}/reject", headers=headers).status_code == 204
    assert stub.calls == [("confirm", proposal, "web", "ops"), ("reject", proposal, "web", "ops")]
    stub.error = "stale"
    assert "The fleet changed" in client.post(f"{url}/confirm", headers=headers).text
    stub.error = "not_found"
    assert "Proposal not found." in client.post("/ui/failovers/999/reject", headers=headers).text
    client.app.state.failover = None
    assert "disabled" in client.post(f"{url}/confirm", headers=headers).text
    with sessions() as s:
        events = s.scalars(select(Event).where(Event.kind.like("web.failover_%")).order_by(Event.id)).all()
    assert [(e.kind, e.subject, e.data) for e in events] == [("web.failover_confirm", "ops", {"proposal_id": proposal}), ("web.failover_reject", "ops", {"proposal_id": proposal})]


def make_requests(sessions):
    with sessions() as s:
        access = service_users.create_request(s, "access", 1001, "@Newbie", "New", "Bie").id
        other = service_users.create_request(s, "access", 1002, "second", None, None).id
    with sessions() as s:
        service_users.approve_request(s, other, 5, "root")
        service_users.create_request(s, "limit", 1002, "second", None, None, 7)
        limit = service_users.list_requests(s, "pending", "limit")[0].id
    return access, limit


def test_requests_page_filters_and_roles(ui, monkeypatch):
    client, sessions = ui
    _access, limit = make_requests(sessions)
    assert client.get("/ui/requests").status_code == 303
    login(client, "view")
    page = client.get("/ui/requests")
    assert page.status_code == 200 and "Requests (2)" in page.text and "newbie" in page.text and "device limit 3 &rarr; 7" in page.text
    assert "Approve" not in page.text and "approved" not in page.text.split("<tbody>")[1]
    assert "Requests (3)" in client.get("/ui/requests?status=all").text and "Requests (3)" in client.get("/ui/requests?status=bogus").text
    assert "Requests (1)" in client.get("/ui/requests?status=approved").text
    client.cookies.clear()
    login(client, "ops")
    assert "Approve" not in client.get("/ui/requests").text
    client.cookies.clear()
    login(client)
    admin_page = client.get("/ui/requests")
    assert f"/ui/requests/{limit}/approve" in admin_page.text and 'name="default_limit"' in admin_page.text
    monkeypatch.setattr(webui, "LIST_PAGE", 1)
    assert "Older" in client.get("/ui/requests").text and "Newer" not in client.get("/ui/requests").text
    second = client.get("/ui/requests?offset=1")
    assert "Newer" in second.text and "Older" not in second.text
    assert "Newer" not in client.get("/ui/requests?offset=-3").text


def test_empty_requests(ui):
    client, _ = ui
    login(client)
    assert "No requests" in client.get("/ui/requests").text


def test_admin_decides_requests(ui):
    client, sessions = ui
    access, limit = make_requests(sessions)
    login(client, "ops")
    headers = csrf_of(client)
    assert client.post(f"/ui/requests/{access}/approve", content="default_limit=2", headers=headers).status_code == 403
    assert client.post(f"/ui/requests/{access}/decline", headers=headers).status_code == 403
    client.cookies.clear()
    login(client)
    assert client.post(f"/ui/requests/{access}/approve", content="default_limit=2").status_code == 403  # no CSRF
    headers = csrf_of(client)
    assert "number" in client.post(f"/ui/requests/{access}/approve", content="default_limit=abc", headers=headers).text
    assert "number" in client.post(f"/ui/requests/{access}/approve", content="default_limit=-5", headers=headers).text
    ok = client.post(f"/ui/requests/{access}/approve", content="default_limit=2", headers=headers)
    assert ok.status_code == 204 and ok.headers["hx-refresh"] == "true"
    with sessions() as s:
        user = service_users.get_user(s, "newbie")
        assert user.config_limit == 2 and user.tg_id == 1001
        row = s.get(UserRequest, access)
        assert row.status == "approved" and row.admin_id is None
    assert "already processed" in client.post(f"/ui/requests/{access}/approve", headers=headers).text
    assert client.post(f"/ui/requests/{limit}/approve", headers=headers).status_code == 204  # default limit field is optional
    with sessions() as s:
        assert service_users.get_user(s, "second").config_limit == 7
    declined = add_declinable(sessions)
    assert client.post(f"/ui/requests/{declined}/decline", headers=headers).status_code == 204
    assert "already processed" in client.post(f"/ui/requests/{declined}/decline", headers=headers).text
    assert "not found" in client.post("/ui/requests/999/decline", headers=headers).text
    with sessions() as s:
        assert s.get(UserRequest, declined).status == "declined"
        events = s.scalars(select(Event).where(Event.kind.like("web.request_%")).order_by(Event.id)).all()
    assert [(e.kind, e.subject, e.data) for e in events] == [
        ("web.request_approve", "admin", {"request_id": access, "default_limit": 2}),
        ("web.request_approve", "admin", {"request_id": limit, "default_limit": 3}),
        ("web.request_decline", "admin", {"request_id": declined})]


def add_declinable(sessions):
    with sessions() as s:
        return service_users.create_request(s, "access", 2002, "third", None, None).id


def boot_client(tmp_path, crypto, monkeypatch, document=None, apply="false"):
    monkeypatch.setenv("BOOT_TEST_TOKEN", "super-secret-token")
    env = {}
    if document is not None:
        path = tmp_path / "boot.yaml"
        path.write_text(yaml.safe_dump(document))
        env = {"WGOCTOPUS_BOOTSTRAP_FILE": str(path), "WGOCTOPUS_BOOTSTRAP_APPLY": apply}
    app, sessions, engine = build(tmp_path, crypto, monkeypatch, **env)
    with sessions.begin() as s:
        webauth.create_account(s, "admin", PW, "admin")
        webauth.create_account(s, "ops", PW, "operator")
        webauth.create_account(s, "view", PW, "viewer")
    return app, sessions, engine


def test_bootstrap_page_unconfigured(tmp_path, crypto, monkeypatch):
    app, _, engine = boot_client(tmp_path, crypto, monkeypatch)
    with TestClient(app, follow_redirects=False) as client:
        assert client.get("/ui/bootstrap").status_code == 303
        login(client)
        page = client.get("/ui/bootstrap")
        assert page.status_code == 200 and "not configured" in page.text and "none since start" in page.text
        assert "Dry run" not in page.text
        assert "not configured" in client.post("/ui/bootstrap/apply", headers=csrf_of(client)).text
    engine.dispose()


def test_bootstrap_dry_run_and_apply_from_ui(tmp_path, crypto, monkeypatch):
    app, sessions, engine = boot_client(tmp_path, crypto, monkeypatch, DOC)
    with TestClient(app, follow_redirects=False) as client:
        login(client, "view")
        viewer_page = client.get("/ui/bootstrap")
        assert "boot.yaml" in viewer_page.text and str(tmp_path) not in viewer_page.text and "Dry run" not in viewer_page.text
        assert client.post("/ui/bootstrap/apply", headers=csrf_of(client)).status_code == 403
        client.cookies.clear()
        login(client, "ops")
        assert client.post("/ui/bootstrap/apply", headers=csrf_of(client)).status_code == 403
        client.cookies.clear()
        login(client)
        page = client.get("/ui/bootstrap")
        assert "Dry run" in page.text and "Apply on start" in page.text
        assert client.post("/ui/bootstrap/apply").status_code == 403  # no CSRF
        headers = csrf_of(client)
        dry = client.post("/ui/bootstrap/apply", headers=headers)
        assert dry.status_code == 200 and "Dry run" in dry.text and "awg-main" in dry.text and "node-1" in dry.text
        assert "super-secret-token" not in dry.text
        assert "none since start" in client.get("/ui/bootstrap").text
        with sessions() as s:
            assert s.scalar(select(func.count()).select_from(Instance)) == 0
        applied = client.post("/ui/bootstrap/apply?dry_run=false", headers=headers)
        assert applied.status_code == 200 and "Applied" in applied.text and "awg-main" in applied.text
        with sessions() as s:
            assert s.scalar(select(func.count()).select_from(Instance)) == 1
        assert client.get("/v1/bootstrap", headers=BEARER).json()["last_apply"]["ok"] is True
        assert "none since start" not in client.get("/ui/bootstrap").text and "created" in client.get("/ui/bootstrap").text
        again = client.post("/ui/bootstrap/apply?dry_run=false", headers=headers)
        assert "unchanged" in again.text
        with sessions() as s:
            events = s.scalars(select(Event).where(Event.kind == "web.bootstrap_apply").order_by(Event.id)).all()
        assert [e.data for e in events] == [{"dry_run": True}, {"dry_run": False}, {"dry_run": False}]
    engine.dispose()


def test_bootstrap_ui_reports_invalid_and_missing_file(tmp_path, crypto, monkeypatch):
    app, _, engine = boot_client(tmp_path, crypto, monkeypatch, DOC)
    with TestClient(app, follow_redirects=False) as client:
        login(client)
        headers = csrf_of(client)
        path = tmp_path / "boot.yaml"
        path.write_text(yaml.safe_dump({"version": 1, "nodes": [{"name": "BAD NAME"}]}))
        bad = client.post("/ui/bootstrap/apply", headers=headers)
        assert bad.status_code == 200 and 'role="alert"' in bad.text and "/nodes" in bad.text
        path.unlink()
        assert "not readable" in client.post("/ui/bootstrap/apply", headers=headers).text
    engine.dispose()
