def test_access_request_lifecycle(api):
    client, _, _, _ = api
    body = {"type": "access", "tg_id": 11, "username": "newbie", "first_name": "New", "last_name": "Person"}
    req = client.post("/v1/requests", json=body)
    assert req.status_code == 201
    ident = req.json()["id"]
    assert client.post("/v1/requests", json=body).status_code == 409
    assert client.get("/v1/requests", params={"type": "access", "status": "pending", "username": "newbie"}).json()[0]["id"] == ident
    assert client.get(f"/v1/requests/{ident}").json()["id"] == ident
    assert client.get("/v1/requests/999").status_code == 404
    assert client.put(f"/v1/requests/{ident}/refs", json={"refs": [[1, 2]]}).json()["notification_refs"] == [[1, 2]]
    approved = client.post(f"/v1/requests/{ident}/approve", json={"admin_tg_id": 1, "admin_username": "root", "default_limit": 7})
    assert approved.status_code == 200
    assert client.get("/v1/users/newbie").json()["config_limit"] == 7
    assert client.post(f"/v1/requests/{ident}/approve", json={"admin_tg_id": 1, "admin_username": "root"}).status_code == 409


def test_decline_and_limit_request(api):
    client, _, _, _ = api
    req = client.post("/v1/requests", json={"type": "access", "tg_id": 12, "username": "declined", "first_name": "D", "last_name": "User"}).json()
    assert client.post(f"/v1/requests/{req['id']}/decline", json={"admin_tg_id": 1, "admin_username": "root"}).status_code == 200
    client.put("/v1/users/bob", json={"config_limit": 2})
    client.post("/v1/users/resolve", json={"tg_id": 13, "username": "bob", "language": "en"})
    req = client.post("/v1/requests", json={"type": "limit", "tg_id": 13, "username": "bob", "first_name": "Bob", "last_name": "User", "requested_limit": 6}).json()
    assert client.post(f"/v1/requests/{req['id']}/approve", json={"admin_tg_id": 1, "admin_username": "root"}).status_code == 200
    assert client.get("/v1/users/bob").json()["config_limit"] == 6
