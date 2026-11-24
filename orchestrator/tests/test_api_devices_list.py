import time
from datetime import UTC, datetime

from wgoctopus_orch.agent_metrics import PeerStat
from wgoctopus_orch.reconciler import Scrape


def _devices(client):
    instance = client.post("/v1/instances", json={"name": "list-devices", "listen_port": 51829, "address": "10.9.0.1/24"}).json()
    node = client.post("/v1/nodes", json={"name": "list-node", "ssh_host": "192.0.2.9", "ssh_user": "root"}).json()
    client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role": "active"})
    result = {}
    for owner in ("alice", "bob"):
        client.put(f"/v1/users/{owner}", json={})
        result[owner] = []
        for index in range(2):
            response = client.post(f"/v1/users/{owner}/devices", json={"instance_id": instance["id"], "name": f"{owner}{index}", "admin_bypass": True})
            assert response.status_code == 201
            result[owner].append(response.json())
    client.patch(f"/v1/devices/{result['alice'][1]['id']}", json={"enabled": False})
    return instance, node, result


def test_list_devices_filters_pagination_and_auth(api):
    client, _, reconciler, _ = api
    instance, node, devices = _devices(client)
    reconciler.scrapes_data = {node["id"]: Scrape(datetime.now(UTC), True, {}, {(instance["name"], devices["alice"][0]["public_key"]): PeerStat(time.time() - 20, 42, 84)})}

    response = client.get("/v1/devices")
    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == sorted(d["id"] for rows in devices.values() for d in rows)
    assert response.json()["total"] == 4
    assert [item["owner"] for item in client.get("/v1/devices?owner=%20ALICE%20").json()["items"]] == ["alice", "alice"]
    assert [item["id"] for item in client.get("/v1/devices?enabled=false").json()["items"]] == [devices["alice"][1]["id"]]
    assert [item["id"] for item in client.get("/v1/devices?active=true").json()["items"]] == [devices["alice"][0]["id"]]
    page = client.get("/v1/devices?limit=2&offset=1").json()
    assert page["total"] == 4
    assert [item["id"] for item in page["items"]] == sorted(d["id"] for rows in devices.values() for d in rows)[1:3]
    assert client.get("/v1/devices?owner=missing").json() == {"total": 0, "items": []}
    assert client.get("/v1/devices?limit=0").status_code == 422
    assert client.get("/v1/devices?limit=201").status_code == 422
    client.headers.pop("Authorization")
    assert client.get("/v1/devices").status_code == 401
