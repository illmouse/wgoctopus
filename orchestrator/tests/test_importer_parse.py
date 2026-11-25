import json
import sqlite3

import pytest

from wgoctopus_orch import importer
from wgoctopus_orch.keys import generate_keypair


def amnezia(tmp_path):
    private, public = generate_keypair()
    directory = tmp_path / "config"
    directory.mkdir()
    (directory / "config.json").write_text(json.dumps({"awg": {
        "server": {"port": 51820, "address": "192.0.2.1/24", "endpoint": "example.org",
                   "keys": {"private_key": private, "public_key": public},
                   "junk": {"jc": 3, "h1": "12-20"}}, "peers": {}}}))
    return private, public


def test_amnezia_parse_and_client_config(tmp_path):
    amnezia(tmp_path)
    conf = tmp_path / "server_peers"
    conf.mkdir()
    (conf / "peer1.conf").write_text("DNS =  1.1.1.1, 8.8.8.8\nAllowedIPs=0.0.0.0/0\nPersistentKeepalive=25\n")
    parsed = importer.parse_amnezia(tmp_path)
    assert parsed.address == "192.0.2.1/24"
    assert parsed.client_dns == ["1.1.1.1", "8.8.8.8"]
    assert importer.awg_features(parsed) == {"fields": [], "cps_count": 0}


def test_missing_and_bad_amnezia(tmp_path):
    with pytest.raises(importer.ImportFailure, match="MISSING_FILE"):
        importer.parse_amnezia(tmp_path)
    directory = tmp_path / "config"
    directory.mkdir()
    (directory / "config.json").write_text("{}")
    with pytest.raises(importer.ImportFailure, match="BAD_STRUCTURE"):
        importer.parse_amnezia(tmp_path)


def test_server_conf_import_preserves_peer_names_and_awg_fields():
    from wgoctopus_orch.keys import generate_keypair

    private, public = generate_keypair()
    conf = f"""[Interface]
PrivateKey = {private}
Address = 10.0.0.1/24
ListenPort = 51820
Jc = 4
Jmin = 40
Jmax = 80
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 100-200
I1 = <b 0x01>
HeaderProtectionKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
ContentPaddingAddition = 1-3
RekeyAfterTime = 60
RandomTrailers = 1
DisableCookies = off
PostUp = ignored
PostDown = ignored

[Peer]
# Name = Primary
PublicKey = {public}
AllowedIPs = 10.0.0.2/32
"""
    parsed = importer.parse_server_conf(conf)
    assert parsed.peers[0].name == "Primary"
    assert parsed.obfuscation == {
        "jc": "4", "jmin": "40", "jmax": "80", "s1": "12", "s2": "12",
        "s3": "12", "s4": "12", "h1": "100-200",
        "i1": "<b 0x01>", "header_protection_key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
        "content_padding_addition": "1-3", "rekey_after_time": "60",
        "random_trailers": True, "disable_cookies": False,
    }
    assert parsed.awg_version == "3.1"
    assert not importer.validate_parsed(parsed)


def test_server_conf_generates_missing_private_key_with_warning():
    conf = "[Interface]\nAddress=10.0.0.1/24\nListenPort=51820\nPostUp=ignored\n"
    parsed = importer.parse_server_conf(conf)
    assert parsed.private_key and parsed.public_key
    assert parsed.warnings == [importer.Warning("PRIVATE_KEY_GENERATED", 1)]
    assert parsed.awg_version == "2.0"


def test_server_conf_imports_mtu_dns_and_endpoint():
    parsed = importer.parse_server_conf(
        "[Interface]\nAddress=10.0.0.1/24\nListenPort=51820\n"
        "MTU=1380\nDNS=1.1.1.1, 8.8.8.8\nEndpoint=edge.example:51820\n"
    )
    assert parsed.mtu == 1380
    assert parsed.client_dns == ["1.1.1.1", "8.8.8.8"]
    assert parsed.endpoint_host == "edge.example:51820"


def test_validation_is_value_free_and_collects_findings():
    parsed = importer.ParsedInstance("test", 1, "bad-address", "", "", {
        "i1": "<c>xx", "jmin": 8, "jmax": 2,
        "h1": "4294967296", "h2": "broken", "header_protection_key": "fake",
        "content_padding_addition": "invalid", "disable_cookies": "no",
    })
    problems = importer.validate_parsed(parsed)
    assert {p.code for p in problems} >= {
        "CPS_UNSUPPORTED_TAG", "INVALID_CPS", "INVALID_3X_FIELD", "H_RANGE",
        "J_RANGE", "ADDRESS_INVALID",
    }
    assert "fake" not in repr(problems)


def test_peer_validation_covers_invalid_ip_keys_and_missing_private_key():
    parsed = importer.ParsedInstance("amnezia", 1, "192.0.2.1/24", "", "", {}, peers=[
        importer.ParsedPeer("synthetic", "not-a-key", None, None, "192.0.2.1", True, None),
        importer.ParsedPeer("synthetic", "not-a-key", "bad-key", None, "192.0.2.1", True, None),
        importer.ParsedPeer("synthetic", "another-key", None, None, "bad-ip", True, None),
    ])
    problems = importer.validate_parsed(parsed)
    assert {problem.code for problem in problems} >= {
        "PEER_IP_OUT_OF_SUBNET", "DUPLICATE_PEER_IP", "DUPLICATE_PEER_KEY",
        "PEER_KEY_MISMATCH",
    }
    assert sum(warning.count for warning in parsed.warnings) == 2


def test_import_helpers_handle_invalid_kind_lists_and_warning_counts(tmp_path):
    with pytest.raises(importer.ImportFailure, match="BAD_STRUCTURE"):
        importer._parse("unknown", tmp_path)
    with pytest.raises(importer.ImportFailure, match="MISSING_FILE"):
        importer._parse("wgeasy", tmp_path)
    assert importer._split_list(None) is None
    assert importer._split_list([" 1.1.1.1 ", ""]) == ["1.1.1.1"]
    assert importer._split_list("1.1.1.1, 8.8.8.8") == ["1.1.1.1", "8.8.8.8"]
    assert importer._count_warnings([importer.Warning("IGNORED", 1),
                                     importer.Warning("IGNORED", 2)]) == [importer.Warning("IGNORED", 3)]


def test_wg0_invalid_allowed_ip_is_ignored(tmp_path):
    path = tmp_path / "wg0.conf"
    path.write_text("[Peer]\nPublicKey = synthetic\nAllowedIPs = invalid\n")
    assert importer._wg0_peers(path) == set()


def test_wgeasy_minimal_and_missing(tmp_path):
    with pytest.raises(importer.ImportFailure, match="MISSING_FILE"):
        importer.parse_wgeasy(tmp_path)
    private, public = generate_keypair()
    db = tmp_path / "wg-easy.db"
    with sqlite3.connect(db) as conn:
        conn.executescript("""
            CREATE TABLE interfaces_table(name TEXT, port INTEGER, private_key TEXT,
              public_key TEXT, ipv4_cidr TEXT, ipv6_cidr TEXT, mtu INTEGER,
              j_c INTEGER, j_min INTEGER, j_max INTEGER, s1 INTEGER, s2 INTEGER,
              s3 INTEGER, s4 INTEGER, h1 TEXT, h2 TEXT, h3 TEXT, h4 TEXT,
              i1 TEXT, i2 TEXT, i3 TEXT, i4 TEXT, i5 TEXT,
              header_protection_key TEXT, content_padding_addition TEXT,
              rekey_after_time TEXT, rekey_timeout TEXT, reject_after_time TEXT,
              keepalive_timeout TEXT, max_handshake_attempts TEXT,
              random_trailers INTEGER, disable_cookies TEXT);
            CREATE TABLE clients_table(id INTEGER, name TEXT, ipv4_address TEXT,
              private_key TEXT, public_key TEXT, pre_shared_key TEXT, enabled INTEGER,
              persistent_keepalive INTEGER, dns TEXT, allowed_ips TEXT, i1 TEXT, j_c INTEGER);
            CREATE TABLE user_configs_table(host TEXT, default_dns TEXT,
              default_allowed_ips TEXT, default_persistent_keepalive INTEGER,
              default_i1 TEXT, default_i2 TEXT, default_i3 TEXT, default_i4 TEXT, default_i5 TEXT);
        """)
        conn.execute("INSERT INTO interfaces_table VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            "wg0", 51820, private, public, "10.0.0.0/24", "", 1420,
            3, 1, 5, 12, 12, 12, 12, "1-2", None, None, None,
            None, None, None, None, None, None, None, None, None, None,
            None, None, 0, "off"))
        conn.execute("INSERT INTO user_configs_table VALUES(?,?,?,?,?,?,?,?,?)", (
            "example.org", '[" 1.1.1.1"]', '["0.0.0.0/0"]', 25,
            "<b 0x01>", None, None, None, None))
    parsed = importer.parse_wgeasy(tmp_path)
    assert parsed.address == "10.0.0.1/24"
    assert parsed.client_dns == ["1.1.1.1"]
    assert parsed.endpoint_host == "example.org"
