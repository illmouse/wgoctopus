"""Import users and requests from the legacy Telegram bot database."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from .config import database_url
from .db import make_engine, make_session_factory, upgrade_to_head
from .importer import _columns, _database_url
from .models import AdminUsernameHistory, BotUser, Peer, UserRequest
from .service_users import UserError, normalize_username


def _timestamp(value):
    if value is None:
        return None
    parsed = datetime.fromisoformat(str(value))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _refs(value):
    try:
        refs = json.loads(value) if value else []
        if not isinstance(refs, list) or any(not isinstance(ref, (list, tuple)) or len(ref) != 2
                                             for ref in refs):
            return []
        return [[int(ref[0]), int(ref[1])] for ref in refs]
    except (ValueError, TypeError, json.JSONDecodeError):
        return []


def _rows(conn, table):
    columns = _columns(conn, table)
    if not columns:
        return []
    conn.row_factory = sqlite3.Row
    return [dict(row) for row in conn.execute(f'SELECT * FROM "{table}"')]


def run_import(source, *, dry_run=False, db_url=None, out=None):
    counts = {"users_total": 0, "users_created": 0, "users_existing": 0, "admins": 0,
              "disabled": 0, "requests_total": 0, "requests_created": 0,
              "requests_existing": 0, "history_total": 0, "history_created": 0,
              "owners_without_user": 0}
    problems = 0
    engine = None
    try:
        path = Path(source).resolve()
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as src:
            users, requests, history = (_rows(src, table) for table in
                                         ("users", "requests", "admin_username_history"))
        counts["users_total"], counts["requests_total"], counts["history_total"] = (
            len(users), len(requests), len(history))
        parsed_users = []
        for row in users:
            try:
                username = normalize_username(row.get("username"))
                role = row.get("role", "user")
                limit = int(row.get("config_limit", 3))
                tg_id = row.get("tg_id")
                status = {"active": "enabled", "banned": "disabled"}.get(
                    row.get("status", "enabled"), row.get("status", "enabled"))
                if role not in {"admin", "user"} or status not in {"enabled", "disabled"} or limit < -1:
                    raise ValueError
                parsed_users.append((username, tg_id, role, limit, status,
                                     _timestamp(row.get("created_at")) or datetime.now(UTC),
                                     _timestamp(row.get("disabled_at")), row.get("disabled_by")))
            except (UserError, ValueError, TypeError, OverflowError):
                problems += 1
        parsed_requests = []
        for row in requests:
            try:
                kind, status = row.get("type", "access"), row.get("status", "pending")
                if kind not in {"access", "limit"} or status not in {"pending", "approved", "declined"}:
                    raise ValueError
                parsed_requests.append({key: row.get(key) for key in (
                    "tg_id", "username", "first_name", "last_name", "admin_id", "admin_username",
                    "requested_limit", "previous_limit")} | {
                    "type": kind, "status": status, "requested_at": _timestamp(row.get("requested_at")) or datetime.now(UTC),
                    "decided_at": _timestamp(row.get("decided_at")),
                    "notification_refs": _refs(row.get("notification_refs"))})
            except (ValueError, TypeError, OverflowError):
                problems += 1
        parsed_history = []
        for row in history:
            try:
                parsed_history.append(normalize_username(row.get("username")))
            except UserError:
                problems += 1
        if problems:
            raise ValueError("INVALID_SOURCE")
        url = _database_url(db_url or database_url())
        upgrade_to_head(url)
        engine = make_engine(url)
        factory = make_session_factory(engine)
        with factory() as session:
            for username, tg_id, role, limit, status, created, disabled_at, disabled_by in parsed_users:
                counts["admins"] += role == "admin"
                counts["disabled"] += status == "disabled"
                existing = session.scalar(select(BotUser).where(BotUser.username == username))
                if existing:
                    counts["users_existing"] += 1
                    continue
                conflict = session.scalar(select(BotUser).where(BotUser.tg_id == tg_id)) if tg_id is not None else None
                if conflict:
                    problems += 1
                    raise ValueError("TG_ID_CONFLICT")
                session.add(BotUser(username=username, tg_id=tg_id, role=role, config_limit=limit,
                                    status=status, created_at=created, disabled_at=disabled_at,
                                    disabled_by=disabled_by))
                counts["users_created"] += 1
            session.flush()
            for item in parsed_requests:
                exists = session.scalar(select(UserRequest.id).where(
                    UserRequest.tg_id == item["tg_id"], UserRequest.type == item["type"],
                    UserRequest.requested_at == item["requested_at"]))
                if exists:
                    counts["requests_existing"] += 1
                else:
                    session.add(UserRequest(**item))
                    counts["requests_created"] += 1
            for username in parsed_history:
                if session.get(AdminUsernameHistory, username):
                    continue
                session.add(AdminUsernameHistory(username=username))
                counts["history_created"] += 1
            session.flush()
            owners = session.scalars(select(Peer.owner).where(Peer.owner.is_not(None)).distinct()).all()
            known = set(session.scalars(select(BotUser.username)).all())
            counts["owners_without_user"] = sum(owner not in known for owner in owners)
            if dry_run:
                session.rollback()
            else:
                session.commit()
    except Exception as exc:  # noqa: BLE001 - report only stable, non-sensitive error classes
        problems += 1 if problems == 0 else 0
        failure = "INVALID_SOURCE" if isinstance(exc, ValueError) else f"IMPORT_FAILED:{type(exc).__name__}"
        result, mode = f"FAILED:{failure}", "FAILED"
    else:
        result, mode = "OK", "DRY-RUN" if dry_run else "COMMITTED"
    finally:
        if engine:
            engine.dispose()
    warnings = (f"OWNERS_WITHOUT_USER {counts['owners_without_user']}"
                if counts["owners_without_user"] else "-")
    values = [("mode", mode), *counts.items(), ("warnings", warnings), ("problems", problems), ("result", result)]
    print("\n".join(f"{key}: {value}" for key, value in values), file=out or sys.stdout)
    return 1 if result != "OK" else 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--db")
    args = parser.parse_args(argv)
    return run_import(args.source, dry_run=args.dry_run, db_url=args.db)
