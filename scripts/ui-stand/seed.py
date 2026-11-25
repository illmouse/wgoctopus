"""Seed the UI stand database: bootstrap fleet, web accounts, peers, failover proposals, requests."""
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from wgoctopus_orch import bootstrap, service, service_users, webauth
from wgoctopus_orch.config import database_url
from wgoctopus_orch.crypto import Crypto
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.models import FailoverProposal, Instance, Node, WebAccount

PASSWORD = "stand-password-1"
url = database_url()
upgrade_to_head(url)
sessions = make_session_factory(make_engine(url))
crypto = Crypto()
bootstrap.apply_bootstrap(sessions, bootstrap.load_yaml(Path(sys.argv[1]).read_text()), crypto=crypto)

with sessions.begin() as s:
    for name, role in (("admin", "admin"), ("ops", "operator"), ("view", "viewer")):
        if not s.scalar(select(WebAccount.id).where(WebAccount.username == name)):
            webauth.create_account(s, name, PASSWORD, role)
    main = s.scalar(select(Instance).where(Instance.name == "awg-main"))
    small = s.scalar(select(Instance).where(Instance.name == "awg-small"))
    for index in range(60):  # more than one page of peers
        service.add_peer(s, main.id, f"phone-{index:02d}", owner="alice" if index % 3 == 0 else None, crypto=crypto)
    for index in range(3):
        service.add_peer(s, small.id, f"laptop-{index}", owner="bob", crypto=crypto)
    nodes = {n.name: n.id for n in s.scalars(select(Node))}
    now = datetime.now(UTC)
    for state, hours, by, error in (("executed", 1, "telegram", None), ("rejected", 1, "api", None), ("expired", -1, "system", None),
                                    ("failed", 1, "web", "candidate is no longer healthy")):  # pending ones: pending.py
        s.add(FailoverProposal(instance_id=main.id, hop_id=nodes["hop-1"], from_node_id=nodes["node-a"], to_node_id=nodes["node-b" if state != "pending" else "node-c"],
                               state=state, mode_at_creation="confirm", reason="probe_down", created_at=now - timedelta(minutes=30),
                               expires_at=now + timedelta(hours=hours), decided_at=None if state == "pending" else now, decided_by=by, error=error))

with sessions() as s:
    service_users.create_request(s, "access", 1001, "@newbie", "New", "Person")
    service_users.create_request(s, "access", 1003, "html_user", "<i>x</i>", "<b>Name</b>")
    known = service_users.create_request(s, "access", 1002, "second", "Second", None).id
    declined = service_users.create_request(s, "access", 1004, "nope", None, None).id
with sessions() as s:
    service_users.approve_request(s, known, 5, "root")
    service_users.decline_request(s, declined, 5, "root")
    service_users.create_request(s, "limit", 1002, "second", "Second", None, 7)
print("seeded")
