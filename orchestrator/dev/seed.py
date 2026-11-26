#!/usr/bin/env python3
"""Create repeatable, local-only demo records without contacting any nodes."""
from datetime import UTC, datetime, timedelta

from wgoctopus_orch.config import database_url
from wgoctopus_orch.crypto import Crypto
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.models import BotUser, FailoverProposal, HopLink, Instance, Node, Peer, Placement, WebAccount
from wgoctopus_orch.service import add_peer, create_hop_link, create_instance, create_node, create_probe, place
from wgoctopus_orch.webauth import create_account

PASSWORDS = {"admin": "dev-admin-password", "operator": "dev-operator-password", "viewer": "dev-viewer-password"}


def main():
    url = database_url()
    upgrade_to_head(url)
    factory = make_session_factory(make_engine(url))
    crypto = Crypto()
    with factory.begin() as session:
        for username, role in (("admin", "admin"), ("operator", "operator"), ("viewer", "viewer")):
            account = session.query(WebAccount).filter_by(username=username).one_or_none()
            if account is None:
                create_account(session, username, PASSWORDS[username], role)
            else:
                account.role, account.enabled = role, True
        for username, tg_id, role in (("demo_alice", 10001, "user"), ("demo_bob", 10002, "admin")):
            if not session.query(BotUser).filter_by(username=username).first():
                session.add(BotUser(username=username, tg_id=tg_id, role=role, config_limit=3, status="enabled"))
        primary = session.query(Instance).filter_by(name="awg31").one_or_none()
        legacy = session.query(Instance).filter_by(name="awg20").one_or_none()
        if primary is None:
            primary = create_instance(session, "awg31", 51820, "10.31.0.1/24", crypto=crypto,
                                      awg_version="3.1", endpoint_host="127.0.0.1")
        if legacy is None:
            legacy = create_instance(session, "awg20", 51821, "10.20.0.1/24", crypto=crypto,
                                     awg_version="2.0", endpoint_host="127.0.0.1")
        edge = session.query(Node).filter_by(name="dev-edge").one_or_none()
        spare = session.query(Node).filter_by(name="dev-spare").one_or_none()
        hop = session.query(Node).filter_by(name="dev-hop").one_or_none()
        if edge is None:
            edge = create_node(session, "dev-edge", "127.0.0.1", "dev", agent_token="fake-edge",
                               mgmt_mode="push", crypto=crypto, egress_interface="lo")
        if spare is None:
            spare = create_node(session, "dev-spare", "127.0.0.1", "dev", agent_token="fake-spare",
                               mgmt_mode="push", crypto=crypto, egress_interface="lo")
        if hop is None:
            hop = create_node(session, "dev-hop", "127.0.0.1", "dev", kind="hop", mgmt_mode="push",
                              agent_token="fake-hop", hop_ip="127.0.0.1", crypto=crypto)
        for instance in (primary, legacy):
            if not session.query(Instance).filter(Instance.id == instance.id).first():
                continue
            if not session.query(Placement).filter_by(instance_id=instance.id, node_id=edge.id).first():
                place(session, instance.id, edge.id, "active", crypto=crypto)
            if not session.query(Placement).filter_by(instance_id=instance.id, node_id=spare.id).first():
                place(session, instance.id, spare.id, "standby", crypto=crypto)
            if not session.query(Peer).filter_by(instance_id=instance.id, name="demo-peer").first():
                add_peer(session, instance.id, "demo-peer", owner="demo_alice", crypto=crypto)
        if not session.query(HopLink).filter_by(hop_id=hop.id, instance_id=primary.id).first():
            create_hop_link(session, hop.id, primary.id, crypto=crypto)
            create_probe(session, hop.id, primary.id, edge.id, crypto=crypto)
        if not session.query(FailoverProposal).filter_by(instance_id=primary.id, state="pending").first():
            session.add(FailoverProposal(instance_id=primary.id, hop_id=hop.id, from_node_id=edge.id,
                to_node_id=spare.id, state="pending", mode_at_creation="confirm",
                reason="Demo proposal: simulated node health signal", created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=1)))
    print("Seeded accounts (passwords):")
    for user, password in PASSWORDS.items():
        print(f"  {user}: {password}")


if __name__ == "__main__":
    main()
