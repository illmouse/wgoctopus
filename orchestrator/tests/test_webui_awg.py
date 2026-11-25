import base64
import html
import json

import pytest
from fastapi.testclient import TestClient
from test_api_web_auth import PW, build, login
from test_webui import csrf_of

from wgoctopus_orch import webauth
from wgoctopus_orch.awgparams import generate_obfuscation


@pytest.fixture
def ui(tmp_path, crypto, monkeypatch):
    app, sessions, engine = build(tmp_path, crypto, monkeypatch)
    with sessions.begin() as session:
        webauth.create_account(session, "admin", PW, "admin")
        webauth.create_account(session, "ops", PW, "operator")
        webauth.create_account(session, "view", PW, "viewer")
    with TestClient(app, follow_redirects=False) as client:
        yield client, sessions
    engine.dispose()


def _server_config():
    return "[Interface]\nAddress = 10.72.0.1/24\nListenPort = 51872\n"


def _csrf_form(client):
    return {"_csrf": client.get("/auth/me").json()["csrf_token"]}


def _import(client, name="awg-ui"):
    return client.post(
        "/ui/instances/import",
        data={"name": name, **_csrf_form(client)},
        files={"file": ("server.conf", _server_config())},
    )


def test_awg_json_routes_require_admin_and_csrf(ui):
    client, _ = ui
    assert client.post("/ui/instances/generate", json={}).status_code == 401
    login(client, "ops")
    assert client.post("/ui/instances/generate", json={}, headers=csrf_of(client)).status_code == 403
    login(client)
    assert client.post("/ui/instances/generate", json={}).status_code == 403
    assert client.post("/ui/instances/validate", json={}).status_code == 403

    headers = csrf_of(client)
    generated = client.post("/ui/instances/generate", json={"awg_version": "3.1"}, headers=headers)
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert "obfuscation" in body and "findings" in body
    validated = client.post("/ui/instances/validate", json={
        "awg_version": "3.1", "mtu": 1280, "obfuscation": body["obfuscation"],
    }, headers=headers)
    assert validated.status_code == 200
    assert not [item for item in validated.json()["findings"] if item["severity"] == "error"]


def test_import_upload_requires_admin_csrf_and_supports_size_limit(ui):
    client, _ = ui
    assert client.post("/ui/instances/import", data={"name": "anonymous"}, files={
        "file": ("server.conf", _server_config()),
    }).status_code == 401
    login(client, "ops")
    assert _import(client).status_code == 403
    login(client)
    oversized = client.post("/ui/instances/import", data={
        "name": "too-big", **_csrf_form(client),
    }, files={"file": ("large.conf", b"x" * 262_145)})
    assert oversized.status_code == 413
    imported = _import(client)
    assert imported.status_code == 201
    assert "Imported instance" in imported.text


def test_obfuscation_requires_confirmation_and_detail_masks_secret(ui):
    client, _ = ui
    login(client)
    imported = _import(client, "awg-obfuscation")
    assert imported.status_code == 201
    instance_id = int(html.unescape(imported.text).split("/ui/instances/")[1].split('"')[0])
    obfuscation = generate_obfuscation("3.1")
    secret = base64.b64encode(b"s" * 32).decode()
    obfuscation["header_protection_key"] = secret
    fields = {
        "awg_version": "3.1", "mtu": "1280",
        "obfuscation_json": json.dumps(obfuscation), **_csrf_form(client),
    }
    url = f"/ui/instances/{instance_id}/obfuscation"
    assert client.post(url, data=fields).status_code == 409
    assert client.post(url, data={**fields, "confirm_break_clients": "on"}).status_code == 303

    regenerate = f"/ui/instances/{instance_id}/obfuscation/regenerate"
    values = {"version": "3.1", "mtu": "1280", "intensity": "medium", **_csrf_form(client)}
    assert client.post(regenerate, data=values).status_code == 409
    assert client.post(regenerate, data={**values, "confirm_break_clients": "on"}).status_code == 303

    detail = client.get(f"/ui/instances/{instance_id}")
    assert detail.status_code == 200
    assert "header protection key set (masked)" in detail.text
    assert secret not in detail.text
