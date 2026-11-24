import io
import json

from cryptography.fernet import Fernet
from sqlalchemy import func, select

from wgoctopus_orch import __main__ as package_main
from wgoctopus_orch import importer, service
from wgoctopus_orch.crypto import Crypto
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.keys import generate_keypair
from wgoctopus_orch.models import Event, Instance, Peer
from wgoctopus_orch.service import create_instance


def _source(tmp_path):
    private, public = generate_keypair()
    peer_private, peer_public = generate_keypair()
    directory = tmp_path / "source"
    config = directory / "config"
    config.mkdir(parents=True)
    (config / "config.json").write_text(json.dumps({"awg": {
        "server": {"port": 51821, "address": "192.0.2.1/24", "endpoint": "example.org",
                    "keys": {"private_key": private, "public_key": public}, "junk": {}},
        "peers": {"synthetic": {"name": "synthetic", "public_key": peer_public,
                                  "private_key": peer_private, "ip": "192.0.2.2"}},
    }}))
    return directory


def test_dry_run_stages_render_without_real_writes(tmp_path, monkeypatch):
    source = _source(tmp_path)
    target = tmp_path / "real.db"
    monkeypatch.setenv("WGOCTOPUS_MASTER_KEY", Fernet.generate_key().decode())
    report = __import__("io").StringIO()
    assert importer.run_import("amnezia", source, "sample", dry_run=True,
                               db_url=str(target), out=report) == 0
    assert "mode: DRY-RUN" in report.getvalue()
    assert "rendered_state_sha256: " in report.getvalue()
    assert not target.exists()


def test_commit_creates_encrypted_instance_and_peer(tmp_path, monkeypatch):
    source = _source(tmp_path)
    target = tmp_path / "real.db"
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("WGOCTOPUS_MASTER_KEY", key)
    assert importer.run_import("amnezia", source, "sample", db_url=str(target)) == 0
    engine = make_engine(f"sqlite:///{target}")
    factory = make_session_factory(engine)
    with factory() as session:
        instance = session.scalar(select(Instance))
        peer = session.scalar(select(Peer))
        assert instance.name == "sample"
        assert instance.address == "192.0.2.1/24"
        assert Crypto(key).decrypt(instance.private_key_enc)
        assert peer.enabled
        assert Crypto(key).decrypt(peer.private_key_enc)
        assert session.scalar(select(func.count(Event.id))) == 2
    engine.dispose()


def test_validation_and_verification_fail_before_writes(tmp_path, monkeypatch):
    source = _source(tmp_path)
    original_parse = importer.parse_amnezia

    def invalid_parse(path):
        parsed = original_parse(path)
        parsed.obfuscation["i1"] = "<c>12"
        return parsed

    monkeypatch.setattr(importer, "parse_amnezia", invalid_parse)
    report = io.StringIO()
    assert importer.run_import("amnezia", source, "sample", dry_run=True, out=report) == 1
    assert "CPS_UNSUPPORTED_TAG" in report.getvalue()
    monkeypatch.setattr(importer, "parse_amnezia", original_parse)
    wg0 = tmp_path / "wg0.conf"
    wg0.write_text("[Peer]\nPublicKey = synthetic\nAllowedIPs = 192.0.2.99/32\n")
    report = io.StringIO()
    assert importer.run_import("amnezia", source, "sample", dry_run=True,
                               verify_wg0=wg0, out=report) == 1
    assert "only_source=1" in report.getvalue()


def test_duplicate_and_missing_master_key_refused(tmp_path, monkeypatch):
    source = _source(tmp_path)
    target = tmp_path / "real.db"
    url = f"sqlite:///{target}"
    upgrade_to_head(url)
    key = Fernet.generate_key().decode()
    engine = make_engine(url)
    factory = make_session_factory(engine)
    with factory() as session:
        create_instance(session, "sample", 51821, "192.0.2.1/24", crypto=Crypto(key))
    engine.dispose()
    monkeypatch.setenv("WGOCTOPUS_MASTER_KEY", key)
    assert importer.run_import("amnezia", source, "sample", db_url=str(target), out=io.StringIO()) == 2
    target.unlink()
    monkeypatch.delenv("WGOCTOPUS_MASTER_KEY")
    assert importer.run_import("amnezia", source, "sample", db_url=str(target), out=io.StringIO()) == 1


def test_apply_exception_removes_instance_peers_and_events(tmp_path, monkeypatch):
    source = _source(tmp_path)
    config = source / "config" / "config.json"
    data = json.loads(config.read_text())
    private, public = generate_keypair()
    data["awg"]["peers"]["synthetic2"] = {
        "name": "synthetic2", "public_key": public, "private_key": private,
        "ip": "192.0.2.3",
    }
    config.write_text(json.dumps(data))
    target = tmp_path / "real.db"
    monkeypatch.setenv("WGOCTOPUS_MASTER_KEY", Fernet.generate_key().decode())
    original = service.import_peer
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 4:
            raise RuntimeError("synthetic failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "import_peer", fail_second)
    report = io.StringIO()
    assert importer.run_import("amnezia", source, "sample", db_url=str(target), out=report) == 1
    assert "APPLY_FAILED:RuntimeError" in report.getvalue()
    engine = make_engine(f"sqlite:///{target}")
    factory = make_session_factory(engine)
    with factory() as session:
        assert session.scalar(select(Instance)) is None
        assert session.scalar(select(Peer)) is None
        assert session.scalar(select(Event)) is None
    engine.dispose()


def test_parse_failure_report_is_value_free(tmp_path):
    report = io.StringIO()
    assert importer.run_import("amnezia", tmp_path, "sensitive-name", dry_run=True, out=report) == 1
    assert "FAILED:MISSING_FILE" in report.getvalue()
    assert "sensitive-name" not in report.getvalue()


def test_verify_wg0_commit_and_mismatch_do_not_write(tmp_path):
    source = _source(tmp_path)
    parsed = importer.parse_amnezia(source)
    wg0 = tmp_path / "wg0.conf"
    wg0.write_text(f"[Peer]\nPublicKey = {parsed.peers[0].public_key}\nAllowedIPs = {parsed.peers[0].allowed_ip}/32\n")
    key = Fernet.generate_key()
    crypto = Crypto(key)
    target = tmp_path / "matched.db"
    report = io.StringIO()
    assert importer.run_import("amnezia", source, "sample", verify_wg0=wg0,
                               db_url=str(target), crypto=crypto, out=report) == 0
    assert "wg0_verify: matched=1 only_source=0 only_wg0=0" in report.getvalue()
    wg0.write_text("[Peer]\nPublicKey = absent\nAllowedIPs = 192.0.2.99/32\n")
    target = tmp_path / "mismatch.db"
    report = io.StringIO()
    assert importer.run_import("amnezia", source, "sample", verify_wg0=wg0,
                               db_url=str(target), crypto=crypto, out=report) == 1
    assert "WG0_MISMATCH" in report.getvalue()
    assert not target.exists()


def test_apply_failure_on_third_peer_rolls_back(tmp_path, monkeypatch):
    source = _source(tmp_path)
    config = source / "config" / "config.json"
    data = json.loads(config.read_text())
    for n in (2, 3):
        private, public = generate_keypair()
        data["awg"]["peers"][f"peer{n}"] = {"name": f"peer{n}", "public_key": public,
             "private_key": private, "ip": f"192.0.2.{n+1}"}
    config.write_text(json.dumps(data))
    original, calls = service.import_peer, 0
    def fail_third(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 6:  # three staging peers, then the third peer of the real commit
            raise RuntimeError("injected")
        return original(*args, **kwargs)
    monkeypatch.setattr(service, "import_peer", fail_third)
    report = io.StringIO()
    assert importer.run_import("amnezia", source, "sample", db_url=str(tmp_path / "failed.db"),
                               crypto=Crypto(Fernet.generate_key()), out=report) == 1
    assert "FAILED:APPLY_FAILED:RuntimeError" in report.getvalue()
    engine = make_engine(f"sqlite:///{tmp_path / 'failed.db'}")
    with make_session_factory(engine)() as session:
        assert session.scalar(select(Instance)) is None
        assert session.scalar(select(Peer)) is None
        assert session.scalar(select(Event)) is None
    engine.dispose()


def test_cli_dispatch_and_private_values_not_reported(tmp_path, monkeypatch):
    source = _source(tmp_path)
    parsed = importer.parse_amnezia(source)
    monkeypatch.setattr(importer, "parse_amnezia", lambda _: parsed)
    parsed.obfuscation.update(header_protection_key=generate_keypair()[0], jc=4, jmin=8, jmax=50,
                              s1=15, s2=20, s3=16, s4=18, h1="1", h2="2", h3="3", h4="4")
    report = io.StringIO()
    assert importer.run_import("amnezia", source, "sample", dry_run=True, out=report) == 0, report.getvalue()
    for secret in (parsed.private_key, parsed.peers[0].private_key,
                   parsed.obfuscation["header_protection_key"]):
        assert secret not in report.getvalue()
    monkeypatch.setattr(package_main.sys, "argv", ["wgoctopus_orch", "import", "amnezia", "--source", str(source), "--name", "sample", "--dry-run"])
    monkeypatch.setattr(importer, "main", lambda argv: 17)
    assert package_main.main() == 17
    monkeypatch.setattr(package_main.sys, "argv", ["wgoctopus_orch"])
    monkeypatch.setattr(package_main, "create_app", lambda: "app")
    monkeypatch.setattr(package_main.uvicorn, "run", lambda *a, **kw: None)
    assert package_main.main() is None
