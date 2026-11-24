from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from wgoctopus_orch.db import make_engine, upgrade_to_head
from wgoctopus_orch.models import NodeRevision, Peer
from wgoctopus_orch.renderer import probe_iface_name, render_node_state
from wgoctopus_orch.service import (
    PROBE_OWNER,
    _bump_hops,
    _bump_probe_runners,
    bump_revision,
    create_hop_link,
    create_instance,
    create_node,
    create_probe,
    delete_probe,
    list_probes,
    place,
)


def setup(session, crypto):
    instance = create_instance(session, "wg0", 51820, "192.0.2.10/24", mtu=1380, crypto=crypto)
    hop = create_node(session, "hop0", "192.0.2.1", "tester", kind="hop",
                      wan_interface="eth0", hop_ip="198.51.100.1", crypto=crypto)
    runner = create_node(session, "runner", "203.0.113.1", "tester", crypto=crypto)
    server = create_node(session, "server", "203.0.113.2", "tester", crypto=crypto)
    unrelated = create_node(session, "unrelated", "203.0.113.3", "tester", crypto=crypto)
    create_hop_link(session, hop.id, instance.id, crypto)
    place(session, instance.id, server.id, crypto=crypto)
    return instance, hop, runner, server, unrelated


def test_probe_create_delete_render_and_revisions(session, crypto):
    instance, hop, runner, server, unrelated = setup(session, crypto)
    revisions = {n: session.get(NodeRevision, n).desired_revision
                 for n in (instance.id, runner.id, server.id, unrelated.id)}
    probe = create_probe(session, hop.id, instance.id, runner.id, crypto=crypto)
    peer = session.get(Peer, probe.peer_id)
    state = render_node_state(session, runner.id, crypto)
    interface = next(i for i in state["interfaces"] if i["name"] == probe_iface_name(probe.id))
    assert interface["mode"] == "client" and interface["listen_port"] == 0
    remote = interface["peers"][0]
    assert remote["endpoint"] == "198.51.100.1:51820"
    assert remote["persistent_keepalive"] == 5
    assert remote["preshared_key"] == crypto.decrypt(peer.preshared_key_enc)
    assert remote["allowed_ips"] == ["192.0.2.10/32"]
    server_peer = next(p for p in render_node_state(session, server.id, crypto)["interfaces"][0]["peers"]
                       if p["public_key"] == peer.public_key)
    assert server_peer["allowed_ips"] == [f"{peer.allowed_ip}/32"]
    assert server_peer["preshared_key"] == remote["preshared_key"]
    assert session.get(Peer, probe.peer_id).owner == PROBE_OWNER
    assert {n: session.get(NodeRevision, n).desired_revision for n in revisions} == {
        instance.id: revisions[instance.id], runner.id: revisions[runner.id] + 1,
        server.id: revisions[server.id] + 1, unrelated.id: revisions[unrelated.id],
    }
    assert render_node_state(session, runner.id, crypto) == render_node_state(session, runner.id, crypto)
    assert render_node_state(session, hop.id, crypto)["interfaces"] == []
    before = {n: session.get(NodeRevision, n).desired_revision for n in (runner.id, server.id)}
    assert delete_probe(session, probe.id, crypto)
    assert not render_node_state(session, runner.id, crypto)["interfaces"]
    assert not render_node_state(session, server.id, crypto)["interfaces"][0]["peers"]
    assert all(session.get(NodeRevision, n).desired_revision == before[n] + 1 for n in before)
    assert delete_probe(session, probe.id, crypto) is False


def test_probe_validation_and_uniqueness(session, crypto):
    instance = create_instance(session, "wg0", 51820, "192.0.2.10/24", crypto=crypto)
    hop = create_node(session, "hop", "192.0.2.1", "tester", kind="hop",
                      wan_interface="eth0", hop_ip="198.51.100.1", crypto=crypto)
    wrong_hop = create_node(session, "wrong", "192.0.2.2", "tester", crypto=crypto)
    runner = create_node(session, "runner", "203.0.113.1", "tester", crypto=crypto)
    disabled = create_node(session, "disabled", "203.0.113.2", "tester", enabled=False, crypto=crypto)
    with pytest.raises(ValueError):
        create_probe(session, wrong_hop.id, instance.id, runner.id, crypto=crypto)
    with pytest.raises(ValueError):
        create_probe(session, hop.id, instance.id, runner.id, crypto=crypto)
    create_hop_link(session, hop.id, instance.id, crypto)
    with pytest.raises(ValueError):
        create_probe(session, hop.id, instance.id, hop.id, crypto=crypto)
    with pytest.raises(ValueError):
        create_probe(session, hop.id, instance.id, disabled.id, crypto=crypto)
    probe = create_probe(session, hop.id, instance.id, runner.id, crypto=crypto)
    with pytest.raises(ValueError):
        create_probe(session, hop.id, instance.id, runner.id, crypto=crypto)
    assert list_probes(session) == [probe]


def test_probe_runner_tracks_hop_and_instance_changes(session, crypto):
    instance, hop, runner, _, _ = setup(session, crypto)
    probe = create_probe(session, hop.id, instance.id, runner.id, crypto=crypto)
    rev = session.get(NodeRevision, runner.id).desired_revision
    hop.hop_ip = "198.51.100.2"
    bump_revision(session, hop.id, crypto)
    _bump_probe_runners(session, hop_id=hop.id, crypto=crypto)
    assert session.get(NodeRevision, runner.id).desired_revision == rev + 1
    rev += 1
    instance.listen_port = 51821
    _bump_hops(session, instance.id, crypto)
    assert session.get(NodeRevision, runner.id).desired_revision == rev + 1
    iface = next(i for i in render_node_state(session, runner.id, crypto)["interfaces"]
                 if i["name"] == probe_iface_name(probe.id))
    assert iface["peers"][0]["endpoint"] == "198.51.100.2:51821"


def test_probe_migration_from_hops_preserves_data(tmp_path):
    url = f"sqlite:///{tmp_path / 'probes.db'}"
    here = Path(__file__).resolve().parents[1]
    config = Config(str(here / "alembic.ini"))
    config.set_main_option("script_location", str(here / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0002_hops")
    engine = make_engine(url)
    with engine.begin() as connection:
        connection.execute(text("""INSERT INTO nodes
            (id, name, ssh_host, ssh_port, ssh_user, mgmt_mode, agent_port,
             agent_token_enc, enabled, kind, created_at)
            VALUES (1, 'hop', '192.0.2.1', 22, 'tester', 'push', 18080,
                    'token', 1, 'hop', '2024-01-01 00:00:00')"""))
        connection.execute(text("""INSERT INTO instances
            (id, name, listen_port, address, private_key_enc, public_key, obfuscation, created_at)
            VALUES (1, 'wg0', 51820, '192.0.2.2/24', 'key', 'public', '{}', '2024-01-01 00:00:00')"""))
        connection.execute(text("""INSERT INTO peers
            (id, instance_id, name, public_key, allowed_ip, enabled, created_at, updated_at)
            VALUES (1, 1, 'probe-hop', 'public', '192.0.2.3', 1, '2024-01-01', '2024-01-01')"""))
    engine.dispose()
    upgrade_to_head(url)
    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.begin() as connection:
        assert connection.execute(text("SELECT count(*) FROM peers")).scalar_one() == 1
        connection.execute(text("INSERT INTO probes (hop_id, instance_id, runner_node_id, peer_id, created_at) VALUES (1, 1, 1, 1, '2024-01-01')"))
        with pytest.raises(IntegrityError):
            connection.execute(text("INSERT INTO probes (hop_id, instance_id, runner_node_id, peer_id, created_at) VALUES (1, 1, 1, 1, '2024-01-01')"))
    engine.dispose()


def test_bot_user_migration_preserves_data_and_is_idempotent(tmp_path):
    url = f"sqlite:///{tmp_path / 'bot-users.db'}"
    here = Path(__file__).resolve().parents[1]
    config = Config(str(here / "alembic.ini"))
    config.set_main_option("script_location", str(here / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0007_pull")
    engine = make_engine(url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO instances (id,name,listen_port,address,private_key_enc,public_key,obfuscation,created_at) VALUES (1,'wg0',51820,'192.0.2.2/24','key','public','{}','2024-01-01')"))
    engine.dispose()
    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.begin() as connection:
        assert connection.execute(text("SELECT name FROM instances WHERE id=1")).scalar_one() == "wg0"
        assert connection.execute(text("SELECT count(*) FROM bot_users")).scalar_one() == 0
    engine.dispose()
    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.begin() as connection:
        assert connection.execute(text("SELECT name FROM instances WHERE id=1")).scalar_one() == "wg0"
        assert connection.execute(text("SELECT count(*) FROM bot_users")).scalar_one() == 0
    engine.dispose()
