"""Top up two pending failover proposals (the evaluator cancels seeded ones on its first pass)."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from wgoctopus_orch.config import database_url
from wgoctopus_orch.db import make_engine, make_session_factory
from wgoctopus_orch.models import FailoverProposal, Instance, Node

sessions = make_session_factory(make_engine(database_url()))
with sessions.begin() as s:
    pending = s.scalar(select(func.count()).select_from(FailoverProposal).where(FailoverProposal.state == "pending"))
    main = s.scalar(select(Instance).where(Instance.name == "awg-main"))
    nodes = {n.name: n.id for n in s.scalars(select(Node))}
    now = datetime.now(UTC)
    for _ in range(2 - pending if pending < 2 else 0):
        s.add(FailoverProposal(instance_id=main.id, hop_id=nodes["hop-1"], from_node_id=nodes["node-a"], to_node_id=nodes["node-c"],
                               state="pending", mode_at_creation="confirm", reason="probe_down", created_at=now - timedelta(minutes=30),
                               expires_at=now + timedelta(hours=24)))
