import base64

from sqlalchemy import select

from wgoctopus_orch.keys import generate_keypair
from wgoctopus_orch.models import Instance


def test_import_server_conf_secrets_are_not_returned(api_client):
    client, sessions, _, crypto = api_client
    private, public = generate_keypair()
    _, peer_public = generate_keypair()
    psk = base64.b64encode(b"x" * 32).decode()
    config = f"""[Interface]
PrivateKey = {private}
Address = 10.8.0.1/24
ListenPort = 51820

[Peer]
PublicKey = {peer_public}
PresharedKey = {psk}
AllowedIPs = 10.8.0.2/32
"""
    response = client.post("/v1/instances/import", json={"name": "imported", "config": config})
    assert response.status_code == 201, response.text
    assert private not in response.text and psk not in response.text
    assert "private_key" not in response.text
    with sessions() as session:
        instance = session.scalar(select(Instance))
        assert str(crypto.decrypt(instance.private_key_enc)) == private
        assert instance.public_key == public


def test_import_accepts_config_at_256_kib(api_client):
    client, *_ = api_client
    private, _ = generate_keypair()
    config = f"[Interface]\nPrivateKey = {private}\nAddress = 10.8.0.1/24\nListenPort = 51820\n"
    config = config + "#" * (262_144 - len(config.encode()))
    response = client.post("/v1/instances/import", json={"name": "at-limit", "config": config})
    assert response.status_code == 201, response.text

def test_import_accepts_multipart_file(api_client):
    client, *_ = api_client
    private, _ = generate_keypair()
    config = f"[Interface]\nPrivateKey = {private}\nAddress = 10.9.0.1/24\nListenPort = 51821\n"
    response = client.post("/v1/instances/import", data={"name": "multipart"}, files={"file": ("server.conf", config)})
    assert response.status_code == 201, response.text


def test_import_rejects_oversized_multipart_body(api_client):
    client, *_ = api_client
    response = client.post(
        "/v1/instances/import",
        data={"name": "oversized"},
        files={"file": ("server.conf", "x" * 262_145)},
    )
    assert response.status_code == 413


def test_import_rejects_oversized_chunked_multipart_body(api_client):
    client, *_ = api_client
    boundary = "chunked-boundary"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
        'filename="server.conf"\r\n\r\n'
        + "x" * (262_144 + 16_385)
        + f"\r\n--{boundary}--\r\n"
    ).encode()
    response = client.post(
        "/v1/instances/import",
        content=(body[i:i + 8192] for i in range(0, len(body), 8192)),
        headers={"content-type": f"multipart/form-data; boundary={boundary}"},
    )
    assert response.status_code == 413


def test_import_round_trips_instance_options_and_generated_key_warning(api_client):
    client, sessions, _, _ = api_client
    config = (
        "[Interface]\nAddress=10.9.0.1/24\nListenPort=51821\n"
        "MTU=1380\nDNS=1.1.1.1, 8.8.8.8\nEndpoint=conf.example:51821\n"
        "S1=12\nS2=12\nS3=12\nS4=12\n"
        "HeaderProtectionKey=" + base64.b64encode(b"a" * 32).decode() + "\n"
    )
    response = client.post("/v1/instances/import", json={"name": "roundtrip", "config": config})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["mtu"] == 1380
    assert body["awg_version"] == "3.1"
    assert body["client_dns"] == "1.1.1.1, 8.8.8.8"
    assert body["endpoint_host"] == "conf.example:51821"
    assert body["warnings"] == [{"code": "PRIVATE_KEY_GENERATED", "count": 1}]
    with sessions() as session:
        instance = session.scalar(select(Instance))
        assert instance.mtu == 1380
        assert instance.awg_version == "3.1"
        assert instance.obfuscation["header_protection_key"]

def test_import_rejects_peer_private_key(api_client):
    client, *_ = api_client
    private, _ = generate_keypair()
    peer_private, peer_public = generate_keypair()
    config = f"[Interface]\nPrivateKey = {private}\nAddress = 10.9.0.1/24\nListenPort = 51822\n[Peer]\nPrivateKey = {peer_private}\nPublicKey = {peer_public}\nAllowedIPs = 10.9.0.2/32\n"
    assert client.post("/v1/instances/import", json={"name": "private-peer", "config": config}).status_code == 422

def test_import_server_conf_normalizes_numeric_obfuscation(api_client):
    client, sessions, *_ = api_client
    config = """[Interface]
Address = 10.10.0.1/24
ListenPort = 51823
Jc = 5
Jmin = 128
Jmax = 512
S1 = 12
S2 = 24
S3 = 36
S4 = 48
"""
    response = client.post("/v1/instances/import", json={"name": "numeric-import", "config": config})
    assert response.status_code == 201, response.text
    with sessions() as session:
        instance = session.scalar(select(Instance))
        assert {key: instance.obfuscation[key] for key in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")} == {
            "jc": 5, "jmin": 128, "jmax": 512, "s1": 12, "s2": 24, "s3": 36, "s4": 48,
        }


def test_import_rejects_oversized_config(api_client):
    client, *_ = api_client
    assert client.post("/v1/instances/import", json={
        "name": "oversized", "config": "x" * 262_145
    }).status_code == 413
