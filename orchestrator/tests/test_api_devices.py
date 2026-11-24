import re
import time
from datetime import UTC, datetime

from wgoctopus_orch.agent_metrics import PeerStat
from wgoctopus_orch.reconciler import Scrape


def test_device_api_lifecycle_and_stats(api):
    client, _, reconciler, _ = api
    instance = client.post("/v1/instances", json={"name": "devices", "listen_port": 51822, "address": "10.1.0.1/24"}).json()
    node = client.post("/v1/nodes", json={"name": "device-node", "ssh_host": "192.0.2.2", "ssh_user": "root"}).json()
    client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role": "active"})
    client.put("/v1/users/alice", json={"config_limit": 1})
    path = "/v1/users/alice/devices"
    first = client.post(path, json={"instance_id": instance["id"]})
    assert first.status_code == 201
    device = first.json()
    assert re.fullmatch(r"[0-9a-f]{8}", device["name"])
    assert client.post(path, json={"instance_id": instance["id"], "name": "bad.name"}).status_code == 422
    assert client.post(path, json={"instance_id": instance["id"], "name": device["name"]}).status_code == 409
    assert client.post(path, json={"instance_id": instance["id"], "name": "extra"}).status_code == 403
    second = client.post(path, json={"instance_id": instance["id"], "name": "extra", "admin_bypass": True}).json()
    assert client.post(path, json={"instance_id": 999}).status_code == 404
    assert client.get("/v1/users/alice/devices").json()[0]["id"] == device["id"]
    reconciler.scrapes_data = {node["id"]: Scrape(datetime.now(UTC), True, {}, {(instance["name"], device["public_key"]): PeerStat(time.time() - 20, 42, 84)})}
    stats = client.get(path).json()[0]
    assert stats["rx"] == 42 and stats["tx"] == 84 and stats["active"] is True
    assert stats["latest_handshake_at"]
    renamed = client.patch(f"/v1/devices/{device['id']}", json={"name": "renamed"}).json()
    assert renamed["name"] == "renamed"
    revision = client.get(f"/v1/nodes/{node['id']}").json()["desired_revision"]
    disabled = client.patch(f"/v1/devices/{device['id']}", json={"enabled": False})
    assert disabled.status_code == 200
    assert client.get(f"/v1/nodes/{node['id']}").json()["desired_revision"] > revision
    assert client.get(f"/v1/peers/{second['id']}/config?endpoint_host=example.invalid").status_code == 200
    assert client.delete(f"/v1/devices/{device['id']}").status_code == 204


def test_device_creation_rejects_disabled_user(api):
    client, _, _, _ = api
    instance = client.post("/v1/instances", json={"name": "disabled", "listen_port": 51823, "address": "10.2.0.1/24"}).json()
    client.put("/v1/users/alice", json={"config_limit": -1})
    client.post("/v1/users/alice/disable", json={"by": "operator"})
    assert client.post("/v1/users/alice/devices", json={"instance_id": instance["id"]}).status_code == 403
