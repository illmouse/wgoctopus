import pytest


def test_awg_generation_and_validation(api):
    client, _, _, _ = api
    generated = client.post("/v1/awg/generate", json={"awg_version": "3.1"})
    assert generated.status_code == 200
    body = generated.json()
    assert not any(item["severity"] == "error" for item in body["findings"])
    assert all(item["severity"] == "warning" for item in body["findings"])
    assert any("packet loss" in item["message"] for item in body["findings"])
    validated = client.post("/v1/awg/validate", json={
        "awg_version": "3.1", "mtu": 1280, "obfuscation": body["obfuscation"],
    }).json()["findings"]
    assert not any(item["level"] == "error" for item in validated)
    assert all(item["level"] == "warning" for item in validated)

    invalid = client.post("/v1/awg/validate", json={
        "awg_version": "2.0", "mtu": 1280, "obfuscation": {},
    })
    assert invalid.status_code == 200
    assert invalid.json()["findings"]


def test_awg_generation_rejects_unsupported_input(api):
    client, _, _, _ = api
    assert client.post("/v1/awg/generate", json={"awg_version": "1.5"}).status_code == 422
    assert client.post("/v1/awg/generate", json={"intensity": "extreme"}).status_code == 422


@pytest.mark.parametrize("profile", ["quic_0rtt", "dtls_1_2", "dtls_1_3", "http3", "stun"])
def test_awg_generation_accepts_added_profiles(api, profile):
    from wgoctopus_orch.awgcps import KMOD_CHAIN_BUDGET, _cost

    client, _, _, _ = api
    response = client.post("/v1/awg/generate", json={"mimic_profile": profile})
    assert response.status_code == 200
    body = response.json()
    assert not any(item["severity"] == "error" for item in body["findings"])
    assert all(item["severity"] == "warning" for item in body["findings"])
    assert any("packet loss" in item["message"] for item in body["findings"])
    assert sum(_cost(body["obfuscation"].get(f"i{i}", "")) for i in range(1, 6)) <= KMOD_CHAIN_BUDGET


def test_awg_version_alias_and_finding_shape(api):
    client, _, _, _ = api
    generated = client.post("/v1/awg/generate", json={"version": "3.1"})
    assert generated.status_code == 200
    findings = generated.json()["findings"]
    assert not any(item["severity"] == "error" for item in findings)
    assert all(item["severity"] == "warning" for item in findings)
    assert any("packet loss" in item["message"] for item in findings)
    invalid = client.post("/v1/awg/validate", json={"version": "3.1", "obfuscation": {"jc": -1}})
    finding = invalid.json()["findings"][0]
    assert {"level", "field", "message"} <= finding.keys()

def test_awg_validate_rejects_nested_malformed_values(api):
    client, _, _, _ = api
    response = client.post("/v1/awg/validate", json={"obfuscation": {"jc": []}})
    assert response.status_code == 422
    assert response.json()["findings"]


@pytest.mark.parametrize("obfuscation", [
    {"jc": "bad-secret-marker"},
    {"s1": "bad"},
    {"i1": 3},
    {"random_trailers": True},
])
def test_awg_validate_malformed_scalars_are_findings(api, obfuscation):
    client, _, _, _ = api
    response = client.post("/v1/awg/validate", json={"obfuscation": obfuscation})
    assert response.status_code == 200
    findings = response.json()["findings"]
    assert any(item["level"] == "error" for item in findings)
    assert "secret-marker" not in response.text

def test_awg_validate_reports_s_collisions_as_warnings(api):
    client, _, _, _ = api
    obfuscation = {
        "jc": 1, "jmin": 100, "jmax": 200,
        "s1": 20, "s2": 76, "s3": 300, "s4": 400,
        "h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800",
    }
    findings = client.post("/v1/awg/validate", json={
        "awg_version": "3.1", "obfuscation": obfuscation,
    }).json()["findings"]
    assert any(item["level"] == "warning" and "S values collide" in item["message"] for item in findings)
    assert not any(item["level"] == "error" and "S collision" in item["message"] for item in findings)

def test_awg_generation_warns_for_wide_trailer_header_ranges(api, monkeypatch):
    from wgoctopus_orch import awgparams

    client, _, _, _ = api
    generated = {
        "jc": 1, "jmin": 100, "jmax": 200,
        "s1": 20, "s2": 80, "s3": 300, "s4": 400,
        "h1": "100-20100", "h2": "300-400", "h3": "500-600", "h4": "700-800",
        "random_trailers": True,
    }
    monkeypatch.setattr(awgparams, "generate_obfuscation", lambda *args, **kwargs: generated)
    response = client.post("/v1/awg/generate", json={
        "awg_version": "3.1", "random_trailers": True,
    })
    assert response.status_code == 200
    findings = response.json()["findings"]
    assert any(item["field"] == "random_trailers" and "packet loss" in item["message"] for item in findings)
    validated = client.post("/v1/awg/validate", json={
        "awg_version": "3.1", "obfuscation": generated,
    }).json()["findings"]
    warning = next(item["message"] for item in findings if "packet loss" in item["message"])
    assert warning == next(item["message"] for item in validated if "packet loss" in item["message"])
