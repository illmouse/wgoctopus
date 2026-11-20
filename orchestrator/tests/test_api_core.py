import pytest
from sqlalchemy import select

from wgoctopus_orch.api import create_app
from wgoctopus_orch.models import Instance, Node


def test_auth_and_docs(api, monkeypatch):
    client, *_ = api
    response = client.get("/v1/instances", headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401 and "www-authenticate" in response.headers
    assert client.get("/healthz").status_code == client.get("/readyz").status_code == 200
    assert client.get("/openapi.json").status_code == 404
    monkeypatch.setenv("WGOCTOPUS_API_DOCS", "true")
    assert create_app(session_factory=api[1], crypto=api[3], migrate=False).openapi_url == "/openapi.json"


def test_create_app_requires_auth(monkeypatch):
    monkeypatch.delenv("WGOCTOPUS_API_TOKEN", raising=False)
    monkeypatch.delenv("WGOCTOPUS_API_TOKEN_FILE", raising=False)
    monkeypatch.setenv("WGOCTOPUS_API_ALLOW_NO_AUTH", "false")
    with pytest.raises(RuntimeError):
        create_app(crypto=object())


def test_instances(api):
    client, sessions, _, crypto = api
    body = {"name": "wg0", "listen_port": 51820, "address": "10.0.0.1/24"}
    created = client.post("/v1/instances", json=body)
    assert created.status_code == 201 and "public_key" in created.json()
    with sessions() as s:
        private = crypto.decrypt(s.scalar(select(Instance)).private_key_enc)
    assert str(private) not in created.text and "private_key" not in created.text
    assert client.post("/v1/instances", json={**body, "name": "Bad"}).status_code == 422
    assert client.post("/v1/instances", json={**body, "name": "wg1", "listen_port": 70000}).status_code == 422
    assert client.post("/v1/instances", json={**body, "name": "wg1", "address": "bad"}).status_code == 422
    assert client.post("/v1/instances", json=body).status_code == 409
    assert client.post("/v1/instances", json={**body, "name": "wg1"}).status_code == 409
    ident = created.json()["id"]
    assert len(client.get("/v1/instances").json()) == 1
    assert client.get(f"/v1/instances/{ident}").status_code == 200
    assert client.patch(f"/v1/instances/{ident}", json={"mtu": 1400}).status_code == 200
    assert client.patch(f"/v1/instances/{ident}", json={"name": "bad"}).status_code == 422
    assert client.get("/v1/instances/999").status_code == 404
    assert client.delete(f"/v1/instances/{ident}").status_code == 204


def test_placements_bump_and_kick(api):
    client, *_ = api
    instance = client.post("/v1/instances", json={"name":"wg0","listen_port":51820,"address":"10.0.0.1/24"}).json()
    node = client.post("/v1/nodes", json={"name":"node-a","ssh_host":"host","ssh_user":"root"}).json()
    nid, iid = node["id"], instance["id"]
    assert node["desired_revision"] == 0
    put = client.put(f"/v1/instances/{iid}/placements/{nid}", json={"role":"active","weight":2})
    assert put.status_code == 200 and client.get(f"/v1/nodes/{nid}").json()["desired_revision"] == 1
    assert api[2].kicks == [(nid,{})]
    assert client.put(f"/v1/instances/{iid}/placements/{nid}", json={"role":"invalid"}).status_code == 422
    assert client.put(f"/v1/instances/{iid}/placements/999", json={}).status_code == 404
    assert client.delete(f"/v1/instances/{iid}").status_code == 409
    assert client.delete(f"/v1/instances/{iid}/placements/{nid}").status_code == 204
    assert client.get(f"/v1/nodes/{nid}").json()["desired_revision"] == 2
    assert api[2].kicks == [(nid,{}),(nid,{})]


def test_nodes_write_only_token_and_guards(api):
    client, sessions, _, crypto = api
    secret = "never-return-this-agent-token"
    response = client.post("/v1/nodes", json={"name":"node-a","ssh_host":"host","ssh_user":"root","agent_token":secret})
    assert response.status_code == 201
    node = response.json(); nid=node["id"]
    assert secret not in response.text and "agent_token" not in response.text
    assert node["observed"] is not None and node["reconciler"] is None
    assert client.get("/v1/nodes").status_code == client.get(f"/v1/nodes/{nid}").status_code == 200
    assert client.post("/v1/nodes", json={"name":"bad","ssh_host":"host","ssh_user":"root","mgmt_mode":"other"}).status_code == 422
    rotated = "rotated-secret-token"
    patched = client.patch(f"/v1/nodes/{nid}", json={"agent_token":rotated,"enabled":False})
    assert patched.status_code == 200 and rotated not in patched.text
    with sessions() as s:
        assert str(crypto.decrypt(s.get(Node,nid).agent_token_enc)) == rotated
    assert secret not in client.get("/v1/nodes").text
    assert client.delete(f"/v1/nodes/{nid}").status_code == 204
