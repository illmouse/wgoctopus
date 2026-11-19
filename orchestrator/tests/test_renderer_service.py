import json
from pathlib import Path

import jsonschema
import pytest
from sqlalchemy import inspect

from wgoctopus_orch.db import make_engine
from wgoctopus_orch.models import Base, Event, NodeRevision
from wgoctopus_orch.renderer import render_node_state
from wgoctopus_orch.service import (
    add_peer,
    bump_revision,
    create_instance,
    create_node,
    place,
    remove_peer,
    render_client_config,
    set_peer_enabled,
)


def setup(session, crypto, address="10.22.0.1/29"):
    instance = create_instance(session, "awg0", 51820, address, crypto=crypto, mtu=1400,
                               egress_interface="eth0", snat_ip="192.0.2.3")
    node = create_node(session, "node-a", "203.0.113.10", "operator", agent_token="fake-token",
                       egress_interface="ens3", snat_ip="192.0.2.4", crypto=crypto)
    placement = place(session, instance.id, node.id, "standby", crypto=crypto)
    return instance, node, placement


def test_render_is_valid_deterministic_and_node_overrides_win(session, crypto):
    instance, node, _ = setup(session, crypto)
    peer1 = add_peer(session, instance.id, "one", crypto=crypto)
    peer2 = add_peer(session, instance.id, "two", crypto=crypto)
    state = render_node_state(session, node.id, crypto)
    assert state == render_node_state(session, node.id, crypto)
    assert [p["public_key"] for p in state["interfaces"][0]["peers"]] == sorted(
        [peer1.public_key, peer2.public_key])
    interface = state["interfaces"][0]
    assert interface["egress_interface"] == "ens3"
    assert interface["snat_ip"] == "192.0.2.4"
    assert interface["mtu"] == 1400
    with Path("../schema/state.schema.json").open(encoding="utf-8") as schema_file:
        jsonschema.validate(state, json.load(schema_file))
    instance2 = create_instance(session, "awg1", 51821, "10.23.0.1/24", crypto=crypto)
    place(session, instance2.id, node.id, crypto=crypto)
    assert [item["name"] for item in render_node_state(session, node.id, crypto)["interfaces"]] == ["awg0", "awg1"]


def test_disabled_peer_and_revision_change_semantics(session, crypto):
    instance, node, _ = setup(session, crypto)
    peer = add_peer(session, instance.id, "client", crypto=crypto)
    revision = session.get(NodeRevision, node.id).desired_revision
    assert revision == 2
    assert not bump_revision(session, node.id, crypto)
    peer = set_peer_enabled(session, peer.id, False, crypto)
    assert render_node_state(session, node.id, crypto)["interfaces"][0]["peers"] == []
    assert session.get(NodeRevision, node.id).desired_revision == revision + 1
    set_peer_enabled(session, peer.id, False, crypto)
    assert session.get(NodeRevision, node.id).desired_revision == revision + 1
    set_peer_enabled(session, peer.id, True, crypto)
    assert session.get(NodeRevision, node.id).desired_revision == revision + 2
    assert remove_peer(session, peer.id, crypto)
    assert not remove_peer(session, peer.id, crypto)
    assert session.get(NodeRevision, node.id).desired_revision == revision + 3
    assert session.query(Event).count() >= 7


def test_add_peer_bumps_every_placed_node_and_skips_used_ip(session, crypto):
    instance, node1, _ = setup(session, crypto)
    node2 = create_node(session, "node-b", "203.0.113.11", "operator", crypto=crypto)
    place(session, instance.id, node2.id, "active", crypto=crypto)
    first = add_peer(session, instance.id, "first", crypto=crypto)
    second = add_peer(session, instance.id, "second", crypto=crypto)
    assert first.allowed_ip == "10.22.0.2"
    assert second.allowed_ip == "10.22.0.3"
    assert session.get(NodeRevision, node1.id).desired_revision == 3
    assert session.get(NodeRevision, node2.id).desired_revision == 3
    assert "secret" not in repr(first)


def test_client_config_and_peer_without_private_key(session, crypto):
    instance, _node, _ = setup(session, crypto)
    peer = add_peer(session, instance.id, "client", crypto=crypto)
    config = render_client_config(session, peer.id, "vpn.example.invalid", dns="192.0.2.53", crypto=crypto)
    for expected in ("[Interface]", "PrivateKey = ", "Address = 10.22.0.2/32", "DNS = 192.0.2.53",
                     "Jc = ", "H4 = ", "[Peer]", f"PublicKey = {instance.public_key}",
                     "PresharedKey = ", "AllowedIPs = 0.0.0.0/0", "Endpoint = vpn.example.invalid:51820",
                     "PersistentKeepalive = 25"):
        assert expected in config
    peer.private_key_enc = None
    with pytest.raises(ValueError, match="no stored private"):
        render_client_config(session, peer.id, "vpn.example.invalid", crypto=crypto)
    peer.enabled = False
    with pytest.raises(ValueError, match="disabled"):
        render_client_config(session, peer.id, "vpn.example.invalid", crypto=crypto)


def test_invalid_names_missing_ids_and_subnet_exhaustion(session, crypto):
    with pytest.raises(ValueError, match="interface name"):
        create_instance(session, "invalid name", 51820, "10.1.0.1/24", crypto=crypto)
    with pytest.raises(ValueError, match="unknown node"):
        render_node_state(session, 555, crypto)
    instance = create_instance(session, "small", 51822, "10.3.0.1/30", crypto=crypto)
    add_peer(session, instance.id, "only", crypto=crypto)
    with pytest.raises(ValueError, match="no free"):
        add_peer(session, instance.id, "full", crypto=crypto)
    with pytest.raises(ValueError, match="unknown instance"):
        add_peer(session, 789, "missing", crypto=crypto)
    with pytest.raises(ValueError, match="role"):
        place(session, instance.id, 1, "invalid", crypto=crypto)


def test_migration_and_models_have_same_table_set(session, tmp_path):
    migrated = set(inspect(session.bind).get_table_names()) - {"alembic_version"}
    other_engine = make_engine(f"sqlite:///{tmp_path / 'model.db'}")
    Base.metadata.create_all(other_engine)
    modeled = set(inspect(other_engine).get_table_names())
    assert migrated == modeled
    other_engine.dispose()
