def test_generation_options_and_findings(api):
    client, _, _, _ = api
    response = client.post("/v1/awg/generate", json={
        "awg_version": "3.1",
        "junk_level": 0,
        "size_class": "low",
        "s1": 20,
        "header_protection": False,
        "content_padding": False,
        "random_timings": False,
        "random_trailers": False,
        "disable_cookies": True,
        "mimic_profile": "dns_query",
        "mimic_host": "example.org",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["obfuscation"]["jc"] in (0, 1)
    assert body["obfuscation"]["s1"] == 20
    assert "header_protection_key" not in body["obfuscation"]
    assert "content_padding_addition" not in body["obfuscation"]
    assert body["obfuscation"]["i1"]
    assert any(item["severity"] == "warning" for item in body["findings"])


def test_generation_rejects_invalid_generation_options(api):
    client, _, _, _ = api
    assert client.post("/v1/awg/generate", json={"mode": "invalid"}).status_code == 422
    assert client.post("/v1/awg/generate", json={"junk_level": 16}).status_code == 422


def test_generation_warns_on_s_collisions_and_unsupported_random_trailers(api):
    client, _, _, _ = api
    collision = client.post("/v1/awg/generate", json={
        "s1": 20, "s2": 76,
    })
    assert collision.status_code == 200
    assert any("S values collide" in item["message"] for item in collision.json()["findings"])

    unsupported = client.post("/v1/awg/generate", json={
        "awg_version": "3.0", "random_trailers": True,
    })
    assert unsupported.status_code == 200
    body = unsupported.json()
    assert "random_trailers" not in body["obfuscation"]
    assert any("not supported by AWG 3.0" in item["message"] for item in body["findings"])
