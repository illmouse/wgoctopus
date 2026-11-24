import threading
import time

from sqlalchemy import text

from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head


def test_sqlite_write_waits_for_busy_transaction(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'busy.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE writes (value INTEGER)"))
    factory = make_session_factory(engine)
    locked = threading.Event()

    def hold_write():
        with factory.begin() as session:
            session.execute(text("INSERT INTO writes VALUES (1)"))
            locked.set()
            time.sleep(1)

    thread = threading.Thread(target=hold_write)
    thread.start()
    assert locked.wait(timeout=5)
    started = time.monotonic()
    with factory.begin() as session:
        session.execute(text("INSERT INTO writes VALUES (2)"))
    elapsed = time.monotonic() - started
    thread.join(timeout=5)
    try:
        assert not thread.is_alive()
        assert elapsed >= 0.8
        with factory() as session:
            assert session.execute(text("SELECT COUNT(*) FROM writes")).scalar_one() == 2
    finally:
        engine.dispose()


def test_migrations_are_idempotent_and_preserve_existing_rows(tmp_path):
    url = f"sqlite:///{tmp_path / 'migration.db'}"
    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO events (ts, kind, subject, data) VALUES (CURRENT_TIMESTAMP, 'kept', '1', '{}')"))
    upgrade_to_head(url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT kind FROM events")).scalar_one() == "kept"
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0011_node_provisioning"
        assert {row[1] for row in connection.execute(text("PRAGMA table_info(provision_jobs)"))} >= {"node_id", "state", "options"}
        columns = {row[1] for row in connection.execute(text("PRAGMA table_info(instances)"))}
        assert {"endpoint_host", "client_dns", "client_keepalive", "client_allowed_ips"} <= columns
    engine.dispose()
