import pytest

from wgoctopus_orch.bootstrap import BootstrapError, validate


def test_bootstrap_collects_schema_and_reference_errors():
    with pytest.raises(BootstrapError) as error:
        validate({"version": 1, "bad": 1, "placements": [{"instance": "missing", "node": "missing"}],
                  "nodes": [{"name": "n", "kind": "awg"}],
                  "hop_links": [{"hop": "n", "instance": "missing"}]})
    assert "/bad" in error.value.errors
    assert "/placements/0/instance" in error.value.errors
    assert "/hop_links/0/hop" in error.value.errors


import copy

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.bootstrap import apply_bootstrap, load_yaml
from wgoctopus_orch.models import (
    BootstrapManaged,
    BotUser,
    Event,
    HopLink,
    Instance,
    Node,
    NodeRevision,
    Placement,
)

DOC = {
    "version": 1,
    "instances": [{"name": "awg-main", "listen_port": 13440, "address": "10.20.0.1/24", "awg_version": "3.1",
                   "cps_profile": "quic_initial", "mtu": 1280, "endpoint_host": "vpn.example.org",
                   "client_dns": ["9.9.9.9", "149.112.112.112"]}],
    "nodes": [
        {"name": "node-1", "ssh": {"host": "203.0.113.10", "user": "root"}, "backend_ip": "203.0.113.10",
         "agent_token": {"env": "BOOT_TEST_TOKEN"}},
        {"name": "hop-1", "kind": "hop", "ssh": {"host": "203.0.113.20", "user": "root"},
         "wan_interface": "eth0", "hop_ip": "203.0.113.20"},
    ],
    "placements": [{"instance": "awg-main", "node": "node-1", "role": "active"}],
    "hop_links": [{"hop": "hop-1", "instance": "awg-main"}],
    "users": [{"username": "admin", "role": "admin"}, {"username": "bob", "config_limit": 5}],
}


@pytest.fixture
def factory(session):
    return sessionmaker(bind=session.get_bind())


@pytest.fixture(autouse=True)
def token_env(monkeypatch):
    monkeypatch.setenv("BOOT_TEST_TOKEN", "super-secret-token")


def counts(factory):
    with factory() as s:
        return {
            "events": s.scalar(select(func.count(Event.id))),
            "revs": sorted(r.desired_revision for r in s.scalars(select(NodeRevision))),
            "instances": s.scalar(select(func.count(Instance.id))),
            "nodes": s.scalar(select(func.count(Node.id))),
            "users": s.scalar(select(func.count(BotUser.id))),
            "managed": s.scalar(select(func.count(BootstrapManaged.id))),
        }


def test_apply_creates_everything_and_is_idempotent(factory, crypto):
    report = apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto)
    assert report.created["instances"] == ["awg-main"]
    assert sorted(report.created["nodes"]) == ["hop-1", "node-1"]
    assert report.created["placements"] == ["awg-main:node-1"]
    assert report.created["hop_links"] == ["hop-1:awg-main"]
    assert sorted(report.created["users"]) == ["admin", "bob"]
    with factory() as s:
        inst = s.scalar(select(Instance))
        assert inst.mtu == 1280 and inst.endpoint_host == "vpn.example.org"
        assert inst.client_dns == "9.9.9.9, 149.112.112.112"
        assert s.scalar(select(BotUser).where(BotUser.username == "admin")).role == "admin"
        assert s.scalar(select(BotUser).where(BotUser.username == "bob")).config_limit == 5
        assert s.scalar(select(func.count(Placement.id))) == 1
        assert s.scalar(select(func.count(HopLink.id))) == 1
    before = counts(factory)
    again = apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto)
    assert not again.created and not again.updated and not again.pruned
    assert counts(factory) == before


def test_update_non_dangerous_fields_bumps_revisions(factory, crypto):
    apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto)
    before = counts(factory)
    doc = copy.deepcopy(DOC)
    doc["instances"][0]["mtu"] = 1380
    doc["instances"][0]["client_dns"] = ["1.1.1.1"]
    doc["users"][1]["config_limit"] = 9
    doc["users"][1]["role"] = "user"
    doc["placements"][0]["weight"] = 7
    report = apply_bootstrap(factory, doc, crypto=crypto)
    assert report.updated["instances"] == ["awg-main"]
    assert report.updated["users"] == ["bob"]
    assert report.updated["placements"] == ["awg-main:node-1"]
    after = counts(factory)
    assert sum(after["revs"]) > sum(before["revs"])
    with factory() as s:
        assert s.scalar(select(Instance)).mtu == 1380


@pytest.mark.parametrize("key,value", [("listen_port", 13441), ("address", "10.30.0.1/24")])
def test_dangerous_fields_cannot_change(factory, crypto, key, value):
    apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto)
    doc = copy.deepcopy(DOC)
    doc["instances"][0][key] = value
    with pytest.raises(BootstrapError) as error:
        apply_bootstrap(factory, doc, crypto=crypto)
    assert f"/instances/awg-main/{key}" in error.value.errors[0]
    with factory() as s:
        assert getattr(s.scalar(select(Instance)), key) != value


def test_dry_run_writes_nothing(factory, crypto):
    report = apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto, dry_run=True)
    assert report.created["instances"] == ["awg-main"]
    assert counts(factory)["instances"] == 0 and counts(factory)["events"] == 0
    assert counts(factory)["managed"] == 0


def test_missing_secret_is_reported_without_value(factory, crypto, monkeypatch):
    monkeypatch.delenv("BOOT_TEST_TOKEN")
    with pytest.raises(BootstrapError) as error:
        apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto)
    assert "super-secret-token" not in str(error.value)
    assert counts(factory)["instances"] == 0


def test_file_secret_and_plain_token(factory, crypto, tmp_path):
    path = tmp_path / "tok"
    path.write_text("from-file\n")
    doc = copy.deepcopy(DOC)
    doc["nodes"][0]["agent_token"] = {"file": str(path)}
    doc["nodes"][1]["agent_token"] = "plain-token"
    apply_bootstrap(factory, doc, crypto=crypto)
    with factory() as s:
        n1 = s.scalar(select(Node).where(Node.name == "node-1"))
        assert crypto.decrypt(n1.agent_token_enc) == "from-file"
        n2 = s.scalar(select(Node).where(Node.name == "hop-1"))
        assert crypto.decrypt(n2.agent_token_enc) == "plain-token"


def test_failure_mid_apply_rolls_back_everything(factory, crypto, monkeypatch):
    from wgoctopus_orch import service

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(service, "place", boom)
    with pytest.raises(RuntimeError):
        apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto)
    after = counts(factory)
    assert after["instances"] == 0 and after["nodes"] == 0 and after["users"] == 0 and after["managed"] == 0


def test_prune_only_removes_bootstrap_managed(factory, crypto):
    from wgoctopus_orch import service

    apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto)
    with factory() as s:
        service.create_instance(s, "manual", 14000, "10.50.0.1/24", crypto=crypto)
        s.commit()
    smaller = {"version": 1, "settings": {"prune": True},
               "instances": [], "nodes": [{"name": "node-1", "ssh": {"host": "203.0.113.10", "user": "root"}}],
               "users": [{"username": "admin", "role": "admin"}]}
    report = apply_bootstrap(factory, smaller, crypto=crypto)
    assert report.pruned["instances"] == ["awg-main"]
    assert report.pruned["nodes"] == ["hop-1"]
    assert report.pruned["users"] == ["bob"]
    with factory() as s:
        names = {i.name for i in s.scalars(select(Instance))}
        assert names == {"manual"}
        assert s.scalar(select(func.count(Placement.id))) == 0
        assert s.scalar(select(func.count(HopLink.id))) == 0


def test_no_prune_by_default(factory, crypto):
    apply_bootstrap(factory, copy.deepcopy(DOC), crypto=crypto)
    apply_bootstrap(factory, {"version": 1}, crypto=crypto)
    assert counts(factory)["instances"] == 1


@pytest.mark.parametrize("mutate,path", [
    (lambda d: d.pop("version"), "/version"),
    (lambda d: d.update(version=2), "/version"),
    (lambda d: d["instances"].append(copy.deepcopy(d["instances"][0])), "/instances/1/name"),
    (lambda d: d["nodes"][0].update(kind="x"), "/nodes/0/kind"),
    (lambda d: d["nodes"][0].update(mgmt_mode="x"), "/nodes/0/mgmt_mode"),
    (lambda d: d["nodes"][0].update(agent_token={"env": 1}), "/nodes/0/agent_token"),
    (lambda d: d["nodes"][0].update(agent_token={"env": "A", "file": "b"}), "/nodes/0/agent_token"),
    (lambda d: d["nodes"][0]["ssh"].pop("host"), "/nodes/0/ssh/host"),
    (lambda d: d["instances"][0].update(awg_version="1.0"), "/instances/0/awg_version"),
    (lambda d: d["instances"][0].update(cps_profile="zzz"), "/instances/0/cps_profile"),
    (lambda d: d["placements"][0].update(role="boss"), "/placements/0/role"),
    (lambda d: d["placements"].append(copy.deepcopy(d["placements"][0])), "/placements/1"),
    (lambda d: d["placements"][0].update(node="hop-1"), "/placements/0/node"),
    (lambda d: d["hop_links"][0].update(hop="node-1"), "/hop_links/0/hop"),
    (lambda d: d["hop_links"].append(copy.deepcopy(d["hop_links"][0])), "/hop_links/1"),
    (lambda d: d["users"][0].update(role="root"), "/users/0/role"),
    (lambda d: d.update(instances={}), "/instances"),
    (lambda d: d["settings"].update(x=1) if "settings" in d else d.update(settings={"x": 1}), "/settings/x"),
])
def test_validation_paths(mutate, path):
    doc = copy.deepcopy(DOC)
    mutate(doc)
    with pytest.raises(BootstrapError) as error:
        validate(doc)
    assert path in error.value.errors


def test_validate_rejects_non_mapping_and_bad_yaml():
    with pytest.raises(BootstrapError):
        validate([])
    with pytest.raises(BootstrapError):
        load_yaml("a: [unclosed")
    assert load_yaml("version: 1")["version"] == 1


def test_bootstrap_node_protected_and_provision(session, crypto, monkeypatch):
    from wgoctopus_orch.models import Node
    monkeypatch.setenv("BOOT_TEST_TOKEN", "x")
    sessions = sessionmaker(bind=session.get_bind())
    doc = copy.deepcopy(DOC)
    doc["nodes"][0]["protected"] = True
    doc["nodes"][0]["provision"] = {"auto": True, "mgmt_user": "wgo"}
    apply_bootstrap(sessions, doc, crypto=crypto)
    session.expire_all()
    node = session.scalar(select(Node).where(Node.name == doc["nodes"][0]["name"]))
    assert node.protected is True and node.provision_options == {"auto": True, "mgmt_user": "wgo"}
    doc["nodes"][0]["protected"] = False
    report = apply_bootstrap(sessions, doc, crypto=crypto)
    assert doc["nodes"][0]["name"] in report.updated["nodes"]
    session.expire_all()
    assert session.get(Node, node.id).protected is False
    for bad in ({"protected": "yes"}, {"provision": {"nope": 1}}):
        broken = copy.deepcopy(DOC)
        broken["nodes"][0].update(bad)
        with pytest.raises(BootstrapError):
            apply_bootstrap(sessions, broken, crypto=crypto, dry_run=True)
