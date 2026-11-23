"""Render the canonical desired-state shape accepted by the Go agent."""

import json

import jsonschema
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import schema_path
from .crypto import Crypto
from .models import HopLink, Instance, Node, NodeRevision, Peer, Placement, Probe

PROBE_KEEPALIVE = 5


def probe_iface_name(probe_id: int) -> str:
    return f"wgp{probe_id}"


def active_placement(session: Session, instance_id: int):
    return session.scalars(select(Placement).where(
        Placement.instance_id == instance_id, Placement.role == "active"
    ).order_by(Placement.weight.desc(), Placement.node_id)).first()


def render_node_state(session: Session, node_id: int, crypto: Crypto | None = None) -> dict:
    crypto = crypto or Crypto()
    node = session.get(Node, node_id)
    if node is None:
        raise ValueError(f"unknown node {node_id}")
    revision = session.get(NodeRevision, node_id)
    if node.kind == "hop":
        routes = []
        links = session.scalars(select(HopLink).where(HopLink.hop_id == node_id)).all()
        for link in links:
            active = active_placement(session, link.instance_id)
            if active is None:
                continue
            backend = session.get(Node, active.node_id)
            instance = session.get(Instance, link.instance_id)
            if backend is not None and backend.backend_ip:
                routes.append({"listen_port": instance.listen_port, "backend_ip": backend.backend_ip,
                               "backend_port": instance.listen_port, "name": instance.name})
        result = {"revision": revision.desired_revision if revision else 0, "interfaces": [],
                  "hop": {"wan_interface": node.wan_interface, "hop_ip": node.hop_ip,
                          "routes": sorted(routes, key=lambda route: route["listen_port"])}}
        with schema_path().open(encoding="utf-8") as file:
            schema = json.load(file)
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(result)
        return result
    interfaces = []
    placements = session.scalars(select(Placement).where(Placement.node_id == node_id)).all()
    for placement in sorted(placements, key=lambda item: session.get(Instance, item.instance_id).name):
        instance = session.get(Instance, placement.instance_id)
        interface = {
            "name": instance.name,
            "listen_port": instance.listen_port,
            "private_key": str(crypto.decrypt(instance.private_key_enc)),
            "address": instance.address,
            "obfuscation": {key: value for key, value in instance.obfuscation.items()
                            if not (key in {f"i{i}" for i in range(1, 6)} and value == "")},
            "peers": [],
        }
        for field in ("mtu", "egress_interface", "snat_ip"):
            value = (getattr(node, field) or getattr(instance, field)) if field != "mtu" else instance.mtu
            if value is not None:
                interface[field] = value
        peers = session.scalars(select(Peer).where(Peer.instance_id == instance.id, Peer.enabled.is_(True))).all()
        for peer in sorted(peers, key=lambda item: item.public_key):
            prefix = 128 if ":" in peer.allowed_ip else 32
            rendered = {"public_key": peer.public_key, "allowed_ips": [f"{peer.allowed_ip}/{prefix}"]}
            if peer.preshared_key_enc:
                rendered["preshared_key"] = str(crypto.decrypt(peer.preshared_key_enc))
            interface["peers"].append(rendered)
        interfaces.append(interface)
    probes = session.scalars(select(Probe).where(Probe.runner_node_id == node_id)).all()
    for probe in sorted(probes, key=lambda item: probe_iface_name(item.id)):
        hop = session.get(Node, probe.hop_id)
        if hop is None or not hop.hop_ip:
            continue
        instance = session.get(Instance, probe.instance_id)
        peer = session.get(Peer, probe.peer_id)
        if peer is None or not peer.enabled:
            continue
        server_ip = instance.address.split("/", 1)[0]
        probe_interface = {
            "name": probe_iface_name(probe.id),
            "mode": "client",
            "listen_port": 0,
            "private_key": str(crypto.decrypt(peer.private_key_enc)),
            "address": f"{peer.allowed_ip}/32",
            "obfuscation": {key: value for key, value in instance.obfuscation.items()
                            if not (key in {f"i{i}" for i in range(1, 6)} and value == "")},
            "peers": [{
                "public_key": instance.public_key,
                "allowed_ips": [f"{server_ip}/32"],
                "endpoint": f"{hop.hop_ip}:{instance.listen_port}",
                "persistent_keepalive": PROBE_KEEPALIVE,
            }],
        }
        if peer.preshared_key_enc:
            probe_interface["peers"][0]["preshared_key"] = str(crypto.decrypt(peer.preshared_key_enc))
        if instance.mtu is not None:
            probe_interface["mtu"] = instance.mtu
        interfaces.append(probe_interface)
    result = {"revision": revision.desired_revision if revision else 0, "interfaces": interfaces}
    with schema_path().open(encoding="utf-8") as file:
        schema = json.load(file)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(result)
    return result
