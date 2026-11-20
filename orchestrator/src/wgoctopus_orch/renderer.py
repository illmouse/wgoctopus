"""Render the canonical desired-state shape accepted by the Go agent."""

import json

import jsonschema
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import schema_path
from .crypto import Crypto
from .models import HopLink, Instance, Node, NodeRevision, Peer, Placement


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
            active = session.scalars(select(Placement).where(
                Placement.instance_id == link.instance_id, Placement.role == "active"
            ).order_by(Placement.weight.desc(), Placement.node_id)).first()
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
            "obfuscation": instance.obfuscation,
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
    result = {"revision": revision.desired_revision if revision else 0, "interfaces": interfaces}
    with schema_path().open(encoding="utf-8") as file:
        schema = json.load(file)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(result)
    return result
