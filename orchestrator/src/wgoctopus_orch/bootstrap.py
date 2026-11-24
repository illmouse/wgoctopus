"""Declarative, transactional bootstrap configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sqlalchemy import select

from . import service, service_users
from .models import BootstrapManaged, BotUser, HopLink, Instance, Node, Placement


class BootstrapError(ValueError):
    def __init__(self, errors):
        self.errors = sorted(set(errors))
        super().__init__("; ".join(self.errors))


class _DryRunRollback(Exception):
    pass


@dataclass
class Report:
    created: dict = field(default_factory=dict)
    updated: dict = field(default_factory=dict)
    unchanged: dict = field(default_factory=dict)
    pruned: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


SCHEMA = {
    "settings": {"prune"}, "instances": {"name", "listen_port", "address", "awg_version", "cps_profile", "intensity", "mtu", "egress_interface", "snat_ip", "endpoint_host", "client_dns", "client_keepalive", "client_allowed_ips"},
    "nodes": {"name", "kind", "mgmt_mode", "ssh", "agent_port", "agent_token", "pull_public_key", "egress_interface", "snat_ip", "backend_ip", "wan_interface", "hop_ip", "enabled"},
    "placements": {"instance", "node", "role", "weight"}, "hop_links": {"hop", "instance"},
    "users": {"username", "role", "config_limit"},
}


def load_yaml(text):
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        raise BootstrapError(["/"]) from None


def _keys(item, allowed, path, errors, required=()):
    if not isinstance(item, dict):
        errors.append(path); return
    errors.extend(f"{path}/{key}" for key in item if key not in allowed)
    errors.extend(f"{path}/{key}" for key in required if key not in item)


def validate(document):
    errors = []
    _keys(document, {"version", *SCHEMA}, "", errors, ("version",))
    if not isinstance(document, dict):
        raise BootstrapError(errors)
    if document.get("version") != 1: errors.append("/version")
    if "settings" in document: _keys(document["settings"], {"prune"}, "/settings", errors)
    collections = {key: document.get(key, []) for key in SCHEMA if key != "settings"}
    for key, rows in collections.items():
        if not isinstance(rows, list): errors.append(f"/{key}"); continue
        required = {"instances": ("name", "listen_port", "address"), "nodes": ("name", "ssh"), "placements": ("instance", "node"), "hop_links": ("hop", "instance"), "users": ("username",)}[key]
        seen = set()
        for i, row in enumerate(rows):
            p = f"/{key}/{i}"
            _keys(row, SCHEMA[key], p, errors, required)
            if isinstance(row, dict):
                ident = row.get("name", row.get("username"))
                if key in {"instances", "nodes", "users"} and ident in seen: errors.append(p + "/name")
                seen.add(ident)
                if key == "nodes":
                    _keys(row.get("ssh", {}), {"host", "port", "user"}, p+"/ssh", errors, ("host", "user"))
                    token = row.get("agent_token")
                    if isinstance(token, dict) and (set(token) not in ({"env"}, {"file"}) or not isinstance(next(iter(token.values()), None), str)): errors.append(p+"/agent_token")
                    if row.get("kind", "awg") not in {"awg", "hop"}: errors.append(p+"/kind")
                    if row.get("mgmt_mode", "push") not in {"push", "pull", "auto"}: errors.append(p+"/mgmt_mode")
                if key == "instances":
                    if row.get("awg_version", "2.0") not in {"2.0", "3.0", "3.1"}: errors.append(p+"/awg_version")
                    if row.get("cps_profile") not in (None, "none", "quic_initial", "tls_client_hello", "dns_query", "wireguard_noise", "sip", "random"): errors.append(p+"/cps_profile")
                if key == "placements" and row.get("role", "active") not in {"active", "standby"}: errors.append(p+"/role")
                if key == "users" and row.get("role", "user") not in {"admin", "user"}: errors.append(p+"/role")
    inames = {r.get("name") for r in collections["instances"] if isinstance(r, dict)}
    nodes = {r.get("name"): r for r in collections["nodes"] if isinstance(r, dict)}
    nrefs = set()
    for i, row in enumerate(collections["placements"] if isinstance(collections["placements"], list) else []):
        if not isinstance(row, dict): continue
        if row.get("instance") not in inames: errors.append(f"/placements/{i}/instance")
        if row.get("node") not in nodes or nodes[row["node"]].get("kind", "awg") != "awg": errors.append(f"/placements/{i}/node")
        key=(row.get("instance"),row.get("node"))
        if key in nrefs: errors.append(f"/placements/{i}")
        nrefs.add(key)
    hrefs=set()
    for i,row in enumerate(collections["hop_links"] if isinstance(collections["hop_links"],list) else []):
        if not isinstance(row,dict): continue
        if row.get("hop") not in nodes or (row.get("hop") in nodes and nodes[row["hop"]].get("kind", "awg") != "hop"): errors.append(f"/hop_links/{i}/hop")
        if row.get("instance") not in inames: errors.append(f"/hop_links/{i}/instance")
        key=(row.get("hop"),row.get("instance"))
        if key in hrefs: errors.append(f"/hop_links/{i}")
        hrefs.add(key)
    if errors: raise BootstrapError(errors)
    return document


def _secret(value):
    if not isinstance(value, dict): return value
    kind, name = next(iter(value.items()))
    try: return os.environ[name] if kind == "env" else Path(name).read_text().strip()
    except (KeyError, OSError): raise BootstrapError([f"/nodes/agent_token/{kind}/{name}"]) from None


def apply_bootstrap(session_factory, document, *, crypto, dry_run=False):
    document = validate(document)
    report = Report()
    categories = {k: document.get(k, []) for k in ("instances", "nodes", "placements", "hop_links", "users")}
    with session_factory() as session:
        try:
            with session.begin():
                if session.get_bind().dialect.name == "sqlite":
                    # pysqlite does not BEGIN before SAVEPOINT; open a real transaction so that
                    # nested service transactions, dry runs and failures roll back atomically.
                    session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                ids = {}
                for kind in ("instances", "nodes", "users"):
                    model = {"instances": Instance, "nodes": Node, "users": BotUser}[kind]
                    for row in categories[kind]:
                        name = row.get("name", row.get("username")); existing = session.scalar(select(model).where(getattr(model, "name", getattr(model, "username", None)) == name))
                        if existing is None:
                            if kind == "instances":
                                params={k:v for k,v in row.items() if k not in {"name","listen_port","address"}}
                                for key in ("client_dns", "client_allowed_ips"):
                                    if isinstance(params.get(key), list): params[key] = ", ".join(params[key])
                                obj=service.create_instance(session,name,row["listen_port"],row["address"],crypto=crypto,**params)
                            elif kind == "nodes":
                                ssh=row.get("ssh",{}); obj=service.create_node(session,name,ssh.get("host","-"),ssh.get("user","pull"),ssh_port=ssh.get("port",22),mgmt_mode=row.get("mgmt_mode","push"),agent_port=row.get("agent_port",18080),agent_token=_secret(row["agent_token"]) if row.get("agent_token") is not None else None,kind=row.get("kind","awg"),pull_public_key=row.get("pull_public_key"),egress_interface=row.get("egress_interface"),snat_ip=row.get("snat_ip"),backend_ip=row.get("backend_ip"),wan_interface=row.get("wan_interface"),hop_ip=row.get("hop_ip"),enabled=row.get("enabled",True),crypto=crypto)
                            else:
                                obj=service_users.ensure_admin(session,name) if row.get("role","user")=="admin" else service_users.ensure_user(session,name,config_limit=row.get("config_limit",3))
                            report.created.setdefault(kind,[]).append(name)
                            session.add(BootstrapManaged(kind=kind,name=name))
                        else:
                            changed=False
                            if kind == "instances":
                                for key in ("listen_port","address"):
                                    if key in row and getattr(existing,key) != row[key]: raise BootstrapError([f"/instances/{name}/{key}: cannot change via bootstrap"])
                                for key in ("mtu","egress_interface","snat_ip","endpoint_host","client_dns","client_keepalive","client_allowed_ips"):
                                    if key in row:
                                        value = ", ".join(row[key]) if key == "client_dns" and isinstance(row[key],list) else row[key]
                                        value = service.validate_client_dns(value) if key=="client_dns" else service.validate_client_allowed_ips(value) if key=="client_allowed_ips" else service.validate_endpoint_host(value) if key=="endpoint_host" else value
                                        if getattr(existing,key)!=value: setattr(existing,key,value); changed=True
                                if changed:
                                    for nid in session.scalars(select(Placement.node_id).where(Placement.instance_id==existing.id)): service.bump_revision(session,nid,crypto)
                                    service._bump_hops(session,existing.id,crypto)
                            elif kind == "users":
                                if "config_limit" in row and existing.config_limit != row["config_limit"]: existing.config_limit=row["config_limit"]; changed=True
                                if "role" in row and existing.role != row["role"]: existing.role=row["role"]; changed=True
                            if changed: report.updated.setdefault(kind,[]).append(name)
                            else: report.unchanged.setdefault(kind,[]).append(name)
                        ids.setdefault(kind,{})[name]=obj if existing is None else existing
                for row in categories["placements"]:
                    inst=ids["instances"].get(row["instance"]) or session.scalar(select(Instance).where(Instance.name==row["instance"]))
                    node=ids["nodes"].get(row["node"]) or session.scalar(select(Node).where(Node.name==row["node"]))
                    p=session.scalar(select(Placement).where(Placement.instance_id==inst.id,Placement.node_id==node.id))
                    if p is None: service.place(session,inst.id,node.id,row.get("role","active"),row.get("weight",1),crypto); report.created.setdefault("placements",[]).append(f"{row['instance']}:{row['node']}")
                    elif (p.role,p.weight)!=(row.get("role","active"),row.get("weight",1)):
                        p.role,p.weight=row.get("role","active"),row.get("weight",1); session.flush(); service.bump_revision(session,node.id,crypto); service._bump_hops(session,inst.id,crypto); report.updated.setdefault("placements",[]).append(f"{row['instance']}:{row['node']}")
                    else: report.unchanged.setdefault("placements",[]).append(f"{row['instance']}:{row['node']}")
                for row in categories["hop_links"]:
                    inst=session.scalar(select(Instance).where(Instance.name==row["instance"])); hop=session.scalar(select(Node).where(Node.name==row["hop"]))
                    exists=session.scalar(select(HopLink.id).where(HopLink.instance_id==inst.id,HopLink.hop_id==hop.id))
                    if exists: report.unchanged.setdefault("hop_links",[]).append(f"{row['hop']}:{row['instance']}")
                    else: service.create_hop_link(session,hop.id,inst.id,crypto); report.created.setdefault("hop_links",[]).append(f"{row['hop']}:{row['instance']}")
                if document.get("settings",{}).get("prune"):
                    keep={k:{r.get("name",r.get("username")) for r in categories[k]} for k in ("instances","nodes","users")}
                    for managed in session.scalars(select(BootstrapManaged)).all():
                        if managed.name not in keep.get(managed.kind,set()):
                            obj=session.scalar(select({"instances":Instance,"nodes":Node,"users":BotUser}[managed.kind]).where(getattr({"instances":Instance,"nodes":Node,"users":BotUser}[managed.kind],"name",getattr(BotUser,"username",None))==managed.name))
                            if obj is not None: session.delete(obj); report.pruned.setdefault(managed.kind,[]).append(managed.name)
                            session.delete(managed)
                if dry_run: raise _DryRunRollback
        except _DryRunRollback:
            session.rollback()
        except Exception:
            session.rollback(); raise
    return report
