import asyncio
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.api import create_app
from wgoctopus_orch.config import Settings
from wgoctopus_orch.crypto import Crypto
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.reconciler import Reconciler
from wgoctopus_orch.transport import DirectHttpTransport


def test_upgrade_is_idempotent_and_database_survives_reopen(tmp_path):
    url = f"sqlite:///{tmp_path / 'upgrade.db'}"
    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE persisted_data (value TEXT)"))
        connection.execute(text("INSERT INTO persisted_data VALUES ('kept')"))
    engine.dispose()

    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT value FROM persisted_data")).scalar_one() == "kept"
    engine.dispose()


async def _converge(rec, predicate, attempts=20):
    """Reconcile until predicate holds (a lifespan reconciler may run concurrently)."""
    for _ in range(attempts):
        await rec.reconcile_once()
        if predicate():
            return
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_api_mutations_reconcile_to_fake_agent(session, fake_agent_factory, crypto, monkeypatch):
    agent, = await fake_agent_factory()
    node_sessions = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    settings = Settings(transport="direct")
    transport = DirectHttpTransport(settings, crypto=crypto)
    rec = Reconciler(node_sessions, lambda _: transport, settings, crypto=crypto)
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "integration-token")
    app = create_app(session_factory=node_sessions, reconciler=rec, crypto=crypto, migrate=False)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer integration-token"
        node = client.post("/v1/nodes", json={"name":"agent-a","ssh_host":"127.0.0.1","ssh_user":"test","agent_port":agent.port,"agent_token":agent.token}).json()
        instance = client.post("/v1/instances", json={"name":"wg0","listen_port":51820,"address":"10.0.0.1/24"}).json()
        client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role":"active"}).raise_for_status()
        peer = client.post(f"/v1/instances/{instance['id']}/peers", json={"name":"client"}).json()
        await rec.reconcile_once()
        applied = agent.state["interfaces"][0]
        assert applied["name"] == instance["name"] and applied["private_key"]
        assert any(p["public_key"] == peer["public_key"] for p in applied["peers"])
        client.patch(f"/v1/peers/{peer['id']}", json={"enabled":False}).raise_for_status()
        await _converge(rec, lambda: agent.state["interfaces"][0]["peers"] == [])
        assert agent.state["interfaces"][0]["peers"] == []
        client.patch(f"/v1/peers/{peer['id']}", json={"enabled":True}).raise_for_status()
        await _converge(rec, lambda: bool(agent.state["interfaces"][0]["peers"]))
        assert agent.state["interfaces"][0]["peers"][0]["public_key"] == peer["public_key"]


@pytest.mark.asyncio
async def test_active_standby_agents_receive_same_config(session, fake_agent_factory, crypto, monkeypatch):
    a, b = await fake_agent_factory(2)
    sessions = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    settings = Settings(transport="direct")
    rec = Reconciler(sessions, lambda _: DirectHttpTransport(settings, crypto=crypto), settings, crypto=crypto)
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "integration-token")
    with TestClient(create_app(session_factory=sessions, reconciler=rec, crypto=crypto, migrate=False)) as client:
        client.headers["Authorization"] = "Bearer integration-token"
        nodes = [client.post("/v1/nodes", json={"name":f"agent-{i}","ssh_host":"127.0.0.1","ssh_user":"test","agent_port":agent.port,"agent_token":agent.token}).json() for i, agent in enumerate((a,b))]
        obfuscation = {"jc":1,"jmin":1,"jmax":2,"s1":1,"s2":2,"s3":3,"s4":4,"h1":"1","h2":"2","h3":"3","h4":"4"}
        instance = client.post("/v1/instances", json={"name":"wg0","listen_port":51820,"address":"10.0.0.1/24","obfuscation":obfuscation}).json()
        for node, role in zip(nodes, ("active", "standby")):
            client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role":role}).raise_for_status()
        client.post(f"/v1/instances/{instance['id']}/peers", json={"name":"client"}).raise_for_status()
        await rec.reconcile_once()
    assert a.state["interfaces"] == b.state["interfaces"]


def test_app_lifespan_reconciler_and_migrations(tmp_path, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "test-token")
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    monkeypatch.setenv("WGOCTOPUS_DATABASE_URL", url)
    engine = make_engine(url)
    sessions = make_session_factory(engine)
    crypto = Crypto(Fernet.generate_key())
    rec = Reconciler(sessions, lambda _: None, Settings(transport="direct"), crypto=crypto)
    tasks = []
    async def tracked_run(stop):
        tasks.append(asyncio.current_task())
        await stop.wait()
    rec.run = tracked_run
    app = create_app(session_factory=sessions, reconciler=rec, crypto=crypto, migrate=True)
    with TestClient(app), sessions() as db:
        assert db.execute(text("select name from sqlite_master where type='table' and name='instances'")).scalar() == "instances"
    assert len(tasks) == 1 and tasks[0].done()
    engine.dispose()


def test_no_reconciler_when_disabled_and_no_migration(tmp_path, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "test-token")
    monkeypatch.setenv("WGOCTOPUS_RECONCILER_ENABLED", "false")
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    engine = make_engine(url)
    app = create_app(session_factory=make_session_factory(engine), crypto=Crypto(Fernet.generate_key()), migrate=False)
    with TestClient(app):
        assert app.state.reconciler is None
    with engine.connect() as connection:
        assert not connection.exec_driver_sql("select name from sqlite_master where type='table'").all()
    engine.dispose()


def test_readiness_failures_and_allow_no_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_ALLOW_NO_AUTH", "true")
    monkeypatch.delenv("WGOCTOPUS_API_TOKEN", raising=False)
    monkeypatch.delenv("WGOCTOPUS_API_TOKEN_FILE", raising=False)
    from wgoctopus_orch import api as api_module
    warning = Mock()
    monkeypatch.setattr(api_module.log, "warning", warning)
    crypto = Crypto(Fernet.generate_key())
    broken = lambda: (_ for _ in ()).throw(RuntimeError("db unavailable"))
    monkeypatch.setenv("WGOCTOPUS_RECONCILER_ENABLED", "false")
    app = create_app(session_factory=broken, crypto=crypto, migrate=False)
    url = f"sqlite:///{tmp_path / 'allow.db'}"
    upgrade_to_head(url)
    engine = make_engine(url)
    allow_app = create_app(session_factory=make_session_factory(engine), crypto=crypto, migrate=False)
    with TestClient(allow_app) as client:
        assert client.get("/v1/instances").status_code == 200
    with TestClient(app) as client:
        assert client.get("/readyz").status_code == 503
    assert warning.call_count == 2
    warning.assert_called_with("API authentication disabled; development mode only")
    engine.dispose()
    bad_crypto = type("BadCrypto", (), {"encrypt": lambda *_: (_ for _ in ()).throw(RuntimeError("missing key")), "decrypt": lambda *_: None})()
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "test-token")
    with TestClient(create_app(session_factory=lambda: None, crypto=bad_crypto, migrate=False)) as client:
        assert client.get("/readyz").status_code == 503


def test_main_requires_credentials_before_uvicorn(monkeypatch):
    import wgoctopus_orch.__main__ as entry
    monkeypatch.delenv("WGOCTOPUS_MASTER_KEY", raising=False)
    monkeypatch.delenv("WGOCTOPUS_MASTER_KEY_FILE", raising=False)
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "token")
    with pytest.raises(RuntimeError, match="MASTER_KEY"):
        entry.main()
    monkeypatch.setenv("WGOCTOPUS_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("WGOCTOPUS_API_TOKEN", raising=False)
    monkeypatch.setenv("WGOCTOPUS_API_ALLOW_NO_AUTH", "false")
    monkeypatch.setattr(entry.uvicorn, "run", lambda *a, **k: pytest.fail("server started"))
    with pytest.raises(RuntimeError, match="API_TOKEN"):
        entry.main()
