import copy

import pytest
import yaml
from api_helpers import RecordingReconciler
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from test_bootstrap import DOC

from wgoctopus_orch.api import create_app


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "t")
    monkeypatch.setenv("BOOT_TEST_TOKEN", "x")


def make(session, crypto, monkeypatch, tmp_path, doc=None, apply=True):
    if doc is not None:
        path = tmp_path / "boot.yaml"
        path.write_text(yaml.safe_dump(doc))
        monkeypatch.setenv("WGOCTOPUS_BOOTSTRAP_FILE", str(path))
        monkeypatch.setenv("WGOCTOPUS_BOOTSTRAP_APPLY", "true" if apply else "false")
    rec = RecordingReconciler()
    app = create_app(session_factory=sessionmaker(bind=session.get_bind()), reconciler=rec, crypto=crypto, migrate=False)
    return app, rec


H = {"Authorization": "Bearer t"}


def test_requires_auth_and_unconfigured(session, crypto, monkeypatch, tmp_path):
    app, _ = make(session, crypto, monkeypatch, tmp_path)
    with TestClient(app) as c:
        assert c.get("/v1/bootstrap").status_code == 401
        assert c.post("/v1/bootstrap/apply", json={}).status_code == 401
        assert c.get("/v1/bootstrap", headers=H).json() == {"configured": False, "file": None, "last_apply": None}
        assert c.post("/v1/bootstrap/apply", json={}, headers=H).status_code == 404


def test_startup_applies_file_and_reports(session, crypto, monkeypatch, tmp_path):
    app, _ = make(session, crypto, monkeypatch, tmp_path, DOC)
    with TestClient(app) as c:
        status = c.get("/v1/bootstrap", headers=H).json()
        assert status["configured"] and status["file"] == "boot.yaml"
        assert status["last_apply"]["ok"] and status["last_apply"]["summary"]["created"] > 5
        assert len(c.get("/v1/instances", headers=H).json()) == 1
        again = c.post("/v1/bootstrap/apply", json={}, headers=H).json()
        assert not again["created"]
        assert c.get("/v1/bootstrap", headers=H).json()["last_apply"]["summary"]["created"] == 0


def test_apply_disabled_does_not_touch_db(session, crypto, monkeypatch, tmp_path):
    app, _ = make(session, crypto, monkeypatch, tmp_path, DOC, apply=False)
    with TestClient(app) as c:
        assert c.get("/v1/instances", headers=H).json() == []
        assert c.post("/v1/bootstrap/apply", json={"dry_run": True}, headers=H).json()["created"]["instances"]
        assert c.get("/v1/instances", headers=H).json() == []
        assert c.post("/v1/bootstrap/apply", json={}, headers=H).status_code == 200
        assert len(c.get("/v1/instances", headers=H).json()) == 1


def test_inline_document_validation_and_kicks(session, crypto, monkeypatch, tmp_path):
    app, rec = make(session, crypto, monkeypatch, tmp_path)
    with TestClient(app) as c:
        bad = copy.deepcopy(DOC)
        bad["bogus"] = 1
        r = c.post("/v1/bootstrap/apply", json={"document": bad}, headers=H)
        assert r.status_code == 422 and r.json() == {"error": "validation_error", "detail": ["/bogus"]}
        assert c.post("/v1/bootstrap/apply", json={"dry_run": "yes"}, headers=H).status_code == 422
        assert c.post("/v1/bootstrap/apply", json={"nope": 1}, headers=H).status_code == 422
        assert c.post("/v1/bootstrap/apply", json={"document": []}, headers=H).status_code == 422
        ok = c.post("/v1/bootstrap/apply", json={"document": DOC}, headers=H)
        assert ok.status_code == 200 and rec.kicks
        assert "super-secret" not in ok.text


def test_bad_file_fails_startup(session, crypto, monkeypatch, tmp_path):
    app, _ = make(session, crypto, monkeypatch, tmp_path, {"version": 1, "oops": 1})
    with pytest.raises(Exception, match="."), TestClient(app):
        pass


def test_cli_dry_run_and_apply(tmp_path, monkeypatch, capsys):
    import sys

    from cryptography.fernet import Fernet

    from wgoctopus_orch import __main__ as entry

    path = tmp_path / "b.yaml"
    path.write_text(yaml.safe_dump(DOC))
    monkeypatch.setenv("WGOCTOPUS_MASTER_KEY", Fernet.generate_key().decode())
    db = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setattr(sys, "argv", ["x", "bootstrap", "--file", str(path), "--dry-run", "--db", db])
    assert entry.main() == 0
    assert "created.instances: 1" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["x", "bootstrap", "--file", str(path), "--db", db])
    assert entry.main() == 0
    monkeypatch.setattr(sys, "argv", ["x", "bootstrap", "--file", str(path), "--db", db])
    assert entry.main() == 0
    assert "unchanged.instances: 1" in capsys.readouterr().out
    path.write_text("version: 1\nbad: 1\n")
    assert entry.main() == 1
