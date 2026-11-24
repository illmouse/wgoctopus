import hashlib
import io
import sqlite3

from sqlalchemy import select

from wgoctopus_orch import __main__, import_users
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.models import AdminUsernameHistory, BotUser, UserRequest


def source_db(path, *, username="sample_user"):
    with sqlite3.connect(path) as db:
        db.executescript("""
        CREATE TABLE users(username TEXT PRIMARY KEY, tg_id INTEGER UNIQUE, role TEXT,
          config_limit INTEGER, created_at TEXT, status TEXT, disabled_at TEXT, disabled_by TEXT,
          disabled_until TEXT, banned_by TEXT);
        CREATE TABLE requests(id INTEGER, tg_id INTEGER, username TEXT, first_name TEXT,
          last_name TEXT, status TEXT, admin_id INTEGER, admin_username TEXT,
          requested_at TEXT, decided_at TEXT, type TEXT, requested_limit INTEGER,
          previous_limit INTEGER, notification_refs TEXT);
        CREATE TABLE admin_username_history(username TEXT PRIMARY KEY);
        """)
        db.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (username, 12345678901, "user", 5, "2024-01-02 03:04:05", "banned",
                    "2024-01-03 00:00:00", "synthetic_admin", None, None))
        db.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?)",
                   ("sample_admin", None, "admin", -1, "2024-01-02 03:04:05", "active",
                    None, None, None, None))
        for row in ((1, 22222222222, username, "First", "Last", "pending", None, None,
                     "2024-02-01 00:00:00", None, "access", None, None, '[[123,456], ["7", "8"]]'),
                    (2, 33333333333, username, "First", None, "approved", 123, "sample_admin",
                     "2024-03-01 00:00:00", "2024-03-02 00:00:00", "limit", 7, 5, "garbage")):
            db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
        db.execute("INSERT INTO admin_username_history VALUES('sample_admin')")


def target(tmp_path):
    url = f"sqlite:///{tmp_path / 'target.db'}"
    upgrade_to_head(url)
    return url


def read_counts(url):
    engine = make_engine(url)
    with make_session_factory(engine)() as session:
        result = (session.scalars(select(BotUser)).all(), session.scalars(select(UserRequest)).all(),
                  session.scalars(select(AdminUsernameHistory)).all())
    engine.dispose()
    return result


def test_happy_path_and_idempotence_report_is_redacted(tmp_path):
    src, url = tmp_path / "users.db", target(tmp_path)
    source_db(src)
    before = hashlib.sha256(src.read_bytes()).hexdigest()
    report = io.StringIO()
    assert import_users.run_import(src, db_url=url, out=report) == 0
    text = report.getvalue()
    assert "users_created: 2" in text and "requests_created: 2" in text
    assert "history_created: 1" in text and "disabled: 1" in text
    assert "sample_user" not in text and "12345678901" not in text
    users, requests, history = read_counts(url)
    assert len(users) == 2 and len(requests) == 2 and len(history) == 1
    assert users[0].status == "disabled"
    assert requests[0].notification_refs == [[123, 456], [7, 8]]
    assert requests[1].notification_refs == []
    report = io.StringIO()
    assert import_users.run_import(src, db_url=url, out=report) == 0
    assert "users_existing: 2" in report.getvalue()
    assert "requests_existing: 2" in report.getvalue()
    assert hashlib.sha256(src.read_bytes()).hexdigest() == before


def test_dry_run_and_invalid_username_roll_back(tmp_path):
    src, url = tmp_path / "users.db", target(tmp_path)
    source_db(src)
    assert import_users.run_import(src, db_url=url, dry_run=True, out=io.StringIO()) == 0
    assert read_counts(url) == ([], [], [])
    src.unlink()
    source_db(src, username="bad username")
    report = io.StringIO()
    assert import_users.run_import(src, db_url=url, out=report) == 1
    assert read_counts(url) == ([], [], [])
    assert "bad username" not in report.getvalue()


def test_owner_warning_and_cli_dispatch(tmp_path, monkeypatch, capsys):
    src, url = tmp_path / "users.db", target(tmp_path)
    source_db(src)
    engine = make_engine(url)
    with make_session_factory(engine)() as session:
        from wgoctopus_orch.models import Instance, Peer
        instance = Instance(name="sample", listen_port=51820, address="192.0.2.1/24",
                            private_key_enc="x", public_key="x", obfuscation={})
        session.add(instance)
        session.flush()
        session.add(Peer(instance_id=instance.id, name="peer", public_key="x", allowed_ip="192.0.2.2",
                         owner="orphan_user"))
        session.commit()
    engine.dispose()
    monkeypatch.setattr(__main__.sys, "argv", ["app", "import-users", "--source", str(src), "--db", url])
    assert __main__.main() == 0
    assert "OWNERS_WITHOUT_USER 1" in capsys.readouterr().out
