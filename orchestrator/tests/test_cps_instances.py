import json
from pathlib import Path

import jsonschema
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.api import create_app
from wgoctopus_orch.config import Settings, schema_path
from wgoctopus_orch.reconciler import Reconciler
from wgoctopus_orch.renderer import render_node_state
from wgoctopus_orch.service import render_client_config
from wgoctopus_orch.transport import DirectHttpTransport


def _client(session, crypto, monkeypatch):
    sessions = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    settings = Settings(transport="direct")
    reconciler = Reconciler(sessions, lambda _: DirectHttpTransport(settings, crypto=crypto), settings, crypto=crypto)

    async def idle(stop_event):
        await stop_event.wait()

    reconciler.run = idle
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "cps-test-token")
    client = TestClient(create_app(session_factory=sessions, reconciler=reconciler, crypto=crypto, migrate=False))
    client.headers["Authorization"] = "Bearer cps-test-token"
    return client, sessions


def test_cps_profiles_create_render_schema_and_client_config(session, crypto, monkeypatch):
    client, sessions = _client(session, crypto, monkeypatch)
    with client:
        node = client.post("/v1/nodes", json={"name": "cps-node", "ssh_host": "127.0.0.1", "ssh_user": "test"}).json()
        profiles = ("quic_initial", "tls_client_hello", "dns_query", "wireguard_noise", "sip", "random")
        for index, profile in enumerate(profiles):
            body = {"name": f"cps{index}", "listen_port": 52000 + index, "address": f"10.90.{index}.1/24",
                    "cps_profile": profile}
            response = client.post("/v1/instances", json=body)
            assert response.status_code == 201, response.text
            instance = response.json()
            assert "private_key" not in instance
            client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role": "active"}).raise_for_status()
            with sessions() as db:
                first = render_node_state(db, node["id"], crypto)
                second = render_node_state(db, node["id"], crypto)
                assert first == second
                rendered = next(item for item in first["interfaces"] if item["name"] == body["name"])
                assert rendered["obfuscation"]["i1"]
                peer = client.post(f"/v1/instances/{instance['id']}/peers", json={"name": f"peer{index}"})
                assert peer.status_code == 201, peer.text
                config = render_client_config(db, peer.json()["id"], "192.0.2.10", crypto=crypto)
                assert "I1 = " in config
                with Path(schema_path()).open(encoding="utf-8") as file:
                    jsonschema.validate(first, json.load(file))

        explicit = {"jc": 1, "jmin": 64, "jmax": 128, "s1": 1, "s2": 2, "s3": 3, "s4": 4,
                    "h1": "1000-2000", "h2": "3000-4000", "h3": "5000-6000", "h4": "7000-8000"}
        result = client.post("/v1/instances", json={"name": "explicit", "listen_port": 52010,
            "address": "10.91.0.1/24", "obfuscation": explicit, "cps_profile": "quic_initial"})
        assert result.status_code == 201 and result.json()["obfuscation"] == explicit
        none = client.post("/v1/instances", json={"name": "cpsnone", "listen_port": 52011,
            "address": "10.92.0.1/24", "cps_profile": "none"})
        assert none.status_code == 201 and not any(k.startswith("i") for k in none.json()["obfuscation"])
        assert client.post("/v1/instances", json={"name": "badprofile", "listen_port": 52012,
            "address": "10.93.0.1/24", "cps_profile": "unknown"}).status_code == 422

        peer = client.post(f"/v1/instances/{none.json()['id']}/peers", json={"name": "cps-peer"})
        assert peer.status_code == 201, peer.text
        with sessions() as db:
            config = render_client_config(db, peer.json()["id"], "192.0.2.10", crypto=crypto)
        assert "I1 =" not in config


def test_explicit_legacy_obfuscation_is_accepted_but_bad_cps_is_rejected(session, crypto, monkeypatch):
    client, _ = _client(session, crypto, monkeypatch)
    legacy = {"jc": 1, "jmin": 8, "jmax": 80, "s1": 1, "s2": 2, "s3": 3, "s4": 4,
              "h1": "1", "h2": "2", "h3": "3", "h4": "4"}
    with client:
        ok = client.post("/v1/instances", json={"name": "legacy", "listen_port": 53001,
                                                "address": "10.91.0.1/24", "obfuscation": legacy})
        assert ok.status_code == 201, ok.text
        bad = client.post("/v1/instances", json={"name": "badcps", "listen_port": 53002,
                                                 "address": "10.91.1.1/24",
                                                 "obfuscation": {**legacy, "i1": "<zz-secret-marker>"}})
        assert bad.status_code == 422
        assert "zz-secret-marker" not in bad.text
