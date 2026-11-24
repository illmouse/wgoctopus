import base64
import json
import random
from pathlib import Path

import jsonschema

from wgoctopus_orch.awgparams import generate_obfuscation, validate_obfuscation
from wgoctopus_orch.renderer import render_node_state
from wgoctopus_orch.service import render_client_config


def test_awg3_generation_and_validation():
    for version in ("3.0", "3.1"):
        for seed in range(40):
            rng = random.Random(seed)
            result = generate_obfuscation(version, rnd=rng.randint, rand_bytes=lambda n: bytes(range(n)))
            assert len(base64.b64decode(result["header_protection_key"])) == 32
            assert all(result[f"s{i}"] >= 12 for i in range(1, 5))
            lo = int(result["reject_after_time"].split("-")[0])
            assert lo >= 170
            assert not validate_obfuscation(result, version=version)
            assert result == generate_obfuscation(version, rnd=random.Random(seed).randint,
                                                  rand_bytes=lambda n: bytes(range(n)))
        assert ("random_trailers" in result) == (version == "3.1")
    legacy = generate_obfuscation("2.0", rnd=random.Random(10).randint)
    assert not set(legacy) & {"header_protection_key", "random_trailers", "rekey_timeout"}


def test_awg31_api_render_config_and_key_redaction(api, crypto):
    client, sessions, _reconciler, _ = api
    response = client.post("/v1/instances", json={"name": "awg31", "listen_port": 51981,
        "address": "10.81.0.1/24", "awg_version": "3.1"})
    assert response.status_code == 201, response.text
    instance = response.json()
    key = instance["obfuscation"].get("header_protection_key")
    assert key is None
    assert instance["obfuscation"]["header_protection_key_set"] is True
    node = client.post("/v1/nodes", json={"name": "awg31-node", "ssh_host": "127.0.0.1", "ssh_user": "test"}).json()
    client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role": "active"}).raise_for_status()
    with sessions() as db:
        state = render_node_state(db, node["id"], crypto)
        config = render_client_config(db, client.post(f"/v1/instances/{instance['id']}/peers", json={"name": "peer"}).json()["id"], "vpn.invalid", crypto=crypto)
    with Path("../schema/state.schema.json").open(encoding="utf-8") as source:
        jsonschema.validate(state, json.load(source))
    obf = state["interfaces"][0]["obfuscation"]
    assert obf["header_protection_key"] not in response.text
    assert f"HeaderProtectionKey = {obf['header_protection_key']}" in config
    assert obf["random_trailers"] is True
    for label in ("HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                  "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers = 1"):
        assert label in config
    assert "DisableCookies = 0" in config
    base = generate_obfuscation("3.1", rnd=random.Random(8).randint)
    base["s1"] = 11
    rejected = client.post("/v1/instances", json={"name": "badkey", "listen_port": 51982,
        "address": "10.82.0.1/24", "obfuscation": base})
    assert rejected.status_code == 422 and base["header_protection_key"] not in rejected.text
