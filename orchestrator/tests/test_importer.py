from wgoctopus_orch import importer


def test_cps_tag_rejected():
    problems = importer._validate({"i1": "<c>15", "i2": "", "i3": "", "i4": "", "i5": ""})
    assert any(code == "CPS_UNSUPPORTED_TAG" for code, _ in problems)


def test_h_overlap_and_s_header_rule():
    problems = importer._validate({"h1": "100-200", "h2": "200-300", "s1": "8",
                                   "header_protection_key": "synthetic"})
    assert ("H_OVERLAP", "h2") in problems
    assert ("S_HEADER_MINIMUM", "s1..s4") in problems


def test_amnezia_key_mismatch(tmp_path):
    path = tmp_path / "config"
    path.mkdir()
    (path / "config.json").write_text('{"awg":{"server":{"port":1,"address":"192.0.2.1/24",'
                                      '"keys":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",'
                                      '"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},"peers":{}}}')
    try:
        importer._parse("amnezia", tmp_path)
    except importer.ImportFailure as exc:
        assert str(exc) == "KEY_MISMATCH"
    else:
        raise AssertionError("expected key mismatch")


def test_wg0_ipv6_ignored_and_ipv4_parsed(tmp_path):
    path = tmp_path / "wg0.conf"
    path.write_text("[Peer]\nPublicKey = synthetic-key\nAllowedIPs = 192.0.2.2/32, 2001:db8::1/128 # ignored\n")
    assert importer._wg0_peers(path) == {("synthetic-key", "192.0.2.2")}


def test_cli_usage_requires_source():
    import pytest

    with pytest.raises(SystemExit) as exc:
        importer.main(["amnezia", "--name", "sample"])
    assert exc.value.code == 2
