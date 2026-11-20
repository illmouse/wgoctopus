import json
from pathlib import Path

import jsonschema
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from wgoctopus_orch.db import make_engine, upgrade_to_head
from wgoctopus_orch.models import Event, HopLink, NodeRevision
from wgoctopus_orch.renderer import render_node_state
from wgoctopus_orch.service import (
    add_peer,
    bump_revision,
    create_hop_link,
    create_instance,
    create_node,
    delete_hop_link,
    place,
    switch_active,
)


def setup_hop(session, crypto):
    instance = create_instance(session, "wg0", 51820, "10.0.0.1/24", crypto=crypto)
    hop = create_node(session, "hop0", "192.0.2.1", "tester", kind="hop",
                      wan_interface="eth0", hop_ip="198.51.100.1", crypto=crypto)
    create_hop_link(session, hop.id, instance.id, crypto)
    return instance, hop


def test_routes_active_selection_and_schema(session, crypto):
    first, hop = setup_hop(session, crypto)
    second = create_instance(session, "wg1", 51821, "10.0.1.1/24", crypto=crypto)
    create_hop_link(session, hop.id, second.id, crypto)
    low = create_node(session, "backend-a", "192.0.2.2", "tester", backend_ip="192.0.2.10", crypto=crypto)
    high = create_node(session, "backend-b", "192.0.2.3", "tester", backend_ip="192.0.2.11", crypto=crypto)
    place(session, first.id, low.id, "active", 1, crypto)
    place(session, first.id, high.id, "active", 4, crypto)
    place(session, second.id, low.id, "standby", 2, crypto)
    state = render_node_state(session, hop.id, crypto)
    assert [r["listen_port"] for r in state["hop"]["routes"]] == [51820]
    assert state["hop"]["routes"][0] == {"listen_port": 51820, "backend_ip": "192.0.2.11", "backend_port": 51820, "name": "wg0"}
    schema = json.loads(Path("../schema/state.schema.json").read_text())
    jsonschema.validate(state, schema, format_checker=jsonschema.FormatChecker())


def test_switch_bumps_hop_and_noop_does_not(session, crypto):
    instance, hop = setup_hop(session, crypto)
    a = create_node(session, "backend-a", "192.0.2.2", "tester", backend_ip="192.0.2.10", crypto=crypto)
    b = create_node(session, "backend-b", "192.0.2.3", "tester", backend_ip="192.0.2.11", crypto=crypto)
    place(session, instance.id, a.id, crypto=crypto)
    place(session, instance.id, b.id, "standby", crypto=crypto)
    rev = session.get(NodeRevision, hop.id).desired_revision
    switch_active(session, instance.id, b.id, crypto)
    assert render_node_state(session, hop.id, crypto)["hop"]["routes"][0]["backend_ip"] == "192.0.2.11"
    assert session.get(NodeRevision, hop.id).desired_revision == rev + 1
    assert session.scalar(select(Event).where(Event.kind == "instance.switched"))
    rev += 1
    switch_active(session, instance.id, b.id, crypto)
    assert session.get(NodeRevision, hop.id).desired_revision == rev
    with pytest.raises(ValueError):
        switch_active(session, instance.id, 99999, crypto)


def test_invalid_targets_missing_routes_and_link_delete(session, crypto):
    instance, hop = setup_hop(session, crypto)
    with pytest.raises(ValueError):
        place(session, instance.id, hop.id, crypto=crypto)
    awg = create_node(session, "awg", "192.0.2.4", "tester", crypto=crypto)
    with pytest.raises(ValueError):
        create_hop_link(session, awg.id, instance.id, crypto)
    backend = create_node(session, "backend", "192.0.2.5", "tester", crypto=crypto)
    place(session, instance.id, backend.id, crypto=crypto)
    assert render_node_state(session, hop.id, crypto)["hop"]["routes"] == []
    before = session.get(NodeRevision, hop.id).desired_revision
    delete_hop_link(session, hop.id, instance.id, crypto)
    assert session.get(NodeRevision, hop.id).desired_revision == before
    assert session.scalar(select(HopLink).where(HopLink.hop_id == hop.id)) is None
    awg_before = render_node_state(session, backend.id, crypto)
    bump_revision(session, backend.id, crypto)
    assert render_node_state(session, backend.id, crypto) == awg_before
    add_peer(session, instance.id, "peer", crypto=crypto)
    assert session.get(NodeRevision, hop.id).desired_revision == before


def test_hops_migration_preserves_existing_nodes(tmp_path):
    url = f"sqlite:///{tmp_path / 'hops.db'}"
    here = Path(__file__).resolve().parents[1]
    config = Config(str(here / "alembic.ini"))
    config.set_main_option("script_location", str(here / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0001_initial")

    engine = make_engine(url)
    with engine.begin() as connection:
        connection.execute(text("""INSERT INTO nodes
            (id, name, ssh_host, ssh_port, ssh_user, mgmt_mode, agent_port,
             agent_token_enc, enabled, created_at)
            VALUES (1, 'existing', '192.0.2.1', 22, 'tester', 'agent', 8080,
                    'token', 1, '2024-01-01 00:00:00')"""))
    engine.dispose()

    upgrade_to_head(url)
    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.begin() as connection:
        row = connection.execute(text("""SELECT kind, wan_interface, hop_ip, backend_ip
            FROM nodes WHERE id = 1""")).one()
        assert row == ("awg", None, None, None)
        assert connection.execute(text("""SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = 'hop_links'""")).scalar_one() == "hop_links"
        connection.execute(text("""INSERT INTO instances
            (id, name, listen_port, address, private_key_enc, public_key,
             obfuscation, created_at)
            VALUES (1, 'wg0', 51820, '192.0.2.2/32', 'key', 'public', '{}',
                    '2024-01-01 00:00:00')"""))
        connection.execute(text("""INSERT INTO hop_links (hop_id, instance_id, created_at)
            VALUES (1, 1, '2024-01-01 00:00:00')"""))
        with pytest.raises(IntegrityError):
            connection.execute(text("""INSERT INTO hop_links (hop_id, instance_id, created_at)
                VALUES (1, 1, '2024-01-01 00:00:00')"""))
    engine.dispose()
