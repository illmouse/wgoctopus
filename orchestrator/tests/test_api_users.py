def test_users_resolve_update_and_filters(api):
    client, _, _, _ = api
    resolve = {"tg_id": 10, "username": "alice", "language": "en"}
    assert client.post("/v1/users/resolve", json=resolve).status_code == 404
    assert client.put("/v1/users/alice", json={"config_limit": 2}).status_code == 201
    assert client.post("/v1/users/resolve", json=resolve).json()["tg_id"] == 10
    assert client.post("/v1/users/resolve", json={**resolve, "username": "ally"}).json()["username"] == "ally"
    assert client.put("/v1/users/ally", json={"config_limit": 3}).status_code == 200
    assert client.put("/v1/users/root", json={"role": "admin"}).status_code == 201
    assert client.get("/v1/users", params={"status": "enabled", "role": "admin"}).json()[0]["username"] == "root"
    assert client.get("/v1/users/missing").status_code == 404
    assert client.patch("/v1/users/ally", json={"config_limit": 5}).json()["config_limit"] == 5
    assert client.patch("/v1/users/ally", json={"role": "admin"}).status_code == 200
    assert client.put("/v1/users/secondadmin", json={"role": "admin"}).status_code == 201
    assert client.patch("/v1/users/root", json={"role": "user"}).status_code == 200
    assert client.patch("/v1/users/secondadmin", json={"role": "user"}).status_code == 200
    assert client.patch("/v1/users/ally", json={"role": "user"}).status_code == 403
    assert client.patch("/v1/users/root", json={"role": "user"}).status_code == 200
    assert client.patch("/v1/users/ally", json={"role": "admin"}).status_code == 200
    assert client.patch("/v1/users/ally", json={"role": "user"}).status_code == 403
    assert client.post("/v1/users/ally/disable", json={"by": "operator"}).status_code == 403
    authorization = client.headers.pop("Authorization")
    assert client.get("/v1/users").status_code == 401
    client.headers["Authorization"] = authorization


def test_user_disable_enable_and_delete_kicks_owned_peer(api):
    client, _, reconciler, _ = api
    instance = client.post("/v1/instances", json={"name": "users", "listen_port": 51820, "address": "10.0.0.1/24"}).json()
    node = client.post("/v1/nodes", json={"name": "users-node", "ssh_host": "192.0.2.1", "ssh_user": "root"}).json()
    client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role": "active"})
    client.put("/v1/users/alice", json={"config_limit": -1})
    device = client.post("/v1/users/alice/devices", json={"instance_id": instance["id"]}).json()
    assert client.post("/v1/users/alice/disable", json={"by": "operator"}).status_code == 200
    assert client.post("/v1/users/alice/enable").status_code == 200
    reconciler.kicks.clear()
    assert client.delete("/v1/users/alice").status_code == 204
    assert reconciler.kicks
    assert client.get(f"/v1/devices/{device['id']}").status_code == 404
