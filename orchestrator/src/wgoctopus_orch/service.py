"""Transactional operations for desired state."""

import hashlib
import ipaddress
import json
import re
import secrets
from contextlib import contextmanager

from sqlalchemy import select
from sqlalchemy.orm import Session

from .crypto import Crypto
from .keys import generate_keypair, generate_psk, next_free_peer_ip
from .models import Event, Instance, Node, NodeObserved, NodeRevision, Peer, Placement, now_utc
from .renderer import render_node_state


def _crypto(crypto):
    return crypto or Crypto()


@contextmanager
def _transaction(session):
    with (session.begin_nested() if session.in_transaction() else session.begin()):
        yield


def _event(session, kind, subject, data=None):
    session.add(Event(kind=kind, subject=subject, data=data or {}))


def _default_obfuscation():
    starts = sorted(secrets.SystemRandom().sample(range(1000, 4_000_000_000, 100), 4))
    return {"jc": secrets.randbelow(5) + 4, "jmin": 8, "jmax": 80,
            "s1": 1, "s2": 2, "s3": 3, "s4": 4,
            **{f"h{i + 1}": f"{start}-{start + 5}" for i, start in enumerate(starts)}}


def create_instance(session: Session, name, listen_port, address, *, obfuscation=None, mtu=None,
                    egress_interface=None, snat_ip=None, crypto=None):
    if not re.fullmatch(r"[A-Za-z0-9_=+.-]{1,15}", name):
        raise ValueError("instance name must be a valid state interface name (1-15 characters)")
    ipaddress.ip_interface(address)
    private, public = generate_keypair()
    instance = Instance(name=name, listen_port=listen_port, address=address,
                        private_key_enc=_crypto(crypto).encrypt(private), public_key=public,
                        obfuscation=obfuscation or _default_obfuscation(), mtu=mtu,
                        egress_interface=egress_interface, snat_ip=snat_ip)
    with _transaction(session):
        session.add(instance)
        session.flush()
        _event(session, "instance.created", str(instance.id), {"name": name})
    return instance


def create_node(session: Session, name, ssh_host, ssh_user, *, ssh_port=22, mgmt_mode="push",
                agent_port=18080, agent_token=None, egress_interface=None, snat_ip=None,
                enabled=True, crypto=None):
    if mgmt_mode not in {"push", "pull"}:
        raise ValueError("mgmt_mode must be 'push' or 'pull'")
    node = Node(name=name, ssh_host=ssh_host, ssh_port=ssh_port, ssh_user=ssh_user,
                mgmt_mode=mgmt_mode, agent_port=agent_port,
                agent_token_enc=_crypto(crypto).encrypt(agent_token or secrets.token_urlsafe(32)),
                egress_interface=egress_interface, snat_ip=snat_ip, enabled=enabled)
    with _transaction(session):
        session.add(node)
        session.flush()
        session.add_all([NodeRevision(node_id=node.id), NodeObserved(node_id=node.id)])
        _event(session, "node.created", str(node.id), {"name": name})
    return node


def _checksum(session, node_id, crypto):
    state = render_node_state(session, node_id, crypto)
    state.pop("revision")
    return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def bump_revision(session: Session, node_id: int, crypto=None) -> bool:
    crypto = _crypto(crypto)
    with _transaction(session):
        row = session.get(NodeRevision, node_id)
        if row is None:
            raise ValueError(f"unknown node {node_id}")
        checksum = _checksum(session, node_id, crypto)
        if row.desired_checksum == checksum:
            return False
        row.desired_revision += 1
        row.desired_checksum = checksum
        row.updated_at = now_utc()
        _event(session, "node.revision", str(node_id), {"revision": row.desired_revision, "checksum": checksum})
        return True


def place(session: Session, instance_id, node_id, role="active", weight=1, crypto=None):
    if role not in {"active", "standby"}:
        raise ValueError("role must be 'active' or 'standby'")
    with _transaction(session):
        placement = Placement(instance_id=instance_id, node_id=node_id, role=role, weight=weight)
        session.add(placement)
        session.flush()
        _event(session, "placement.created", f"{instance_id}:{node_id}", {"role": role, "weight": weight})
    bump_revision(session, node_id, crypto)
    return placement


def add_peer(session: Session, instance_id, name, *, owner=None, crypto=None):
    crypto = _crypto(crypto)
    with _transaction(session):
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise ValueError(f"unknown instance {instance_id}")
        private, public = generate_keypair()
        used = set(session.scalars(select(Peer.allowed_ip).where(Peer.instance_id == instance_id)).all())
        allowed_ip = next_free_peer_ip(instance.address, used)
        peer = Peer(instance_id=instance_id, name=name, public_key=public,
                    private_key_enc=crypto.encrypt(private), preshared_key_enc=crypto.encrypt(generate_psk()),
                    allowed_ip=allowed_ip, owner=owner)
        session.add(peer)
        session.flush()
        node_ids = session.scalars(select(Placement.node_id).where(Placement.instance_id == instance_id)).all()
        _event(session, "peer.created", str(peer.id), {"instance_id": instance_id, "allowed_ip": allowed_ip})
    for node_id in node_ids:
        bump_revision(session, node_id, crypto)
    return peer


def set_peer_enabled(session: Session, peer_id, enabled: bool, crypto=None):
    with _transaction(session):
        peer = session.get(Peer, peer_id)
        if peer is None:
            raise ValueError(f"unknown peer {peer_id}")
        changed = peer.enabled != enabled
        peer.enabled = enabled
        peer.updated_at = now_utc()
        node_ids = session.scalars(select(Placement.node_id).where(Placement.instance_id == peer.instance_id)).all()
        _event(session, "peer.enabled", str(peer_id), {"enabled": enabled}) if changed else None
    for node_id in node_ids:
        bump_revision(session, node_id, crypto)
    return peer


def remove_peer(session: Session, peer_id, crypto=None):
    with _transaction(session):
        peer = session.get(Peer, peer_id)
        if peer is None:
            return False
        node_ids = session.scalars(select(Placement.node_id).where(Placement.instance_id == peer.instance_id)).all()
        _event(session, "peer.removed", str(peer_id), {"instance_id": peer.instance_id})
        session.delete(peer)
    for node_id in node_ids:
        bump_revision(session, node_id, crypto)
    return True


def render_client_config(session: Session, peer_id, endpoint_host, *, dns=None, crypto=None) -> str:
    peer = session.get(Peer, peer_id)
    if peer is None or not peer.enabled:
        raise ValueError("peer not found or disabled")
    if not peer.private_key_enc:
        raise ValueError("peer has no stored private key")
    instance = session.get(Instance, peer.instance_id)
    c = _crypto(crypto)
    o = instance.obfuscation
    lines = ["[Interface]", f"PrivateKey = {c.decrypt(peer.private_key_enc)}",
             f"Address = {peer.allowed_ip}/32" if ":" not in peer.allowed_ip else f"Address = {peer.allowed_ip}/128"]
    if dns:
        lines.append(f"DNS = {dns}")
    names = {"jc": "Jc", "jmin": "Jmin", "jmax": "Jmax", **{f"s{i}": f"S{i}" for i in range(1, 5)},
             **{f"h{i}": f"H{i}" for i in range(1, 5)}, **{f"i{i}": f"I{i}" for i in range(1, 6)}}
    lines.extend(f"{label} = {o[key]}" for key, label in names.items() if key in o)
    lines.extend(["", "[Peer]", f"PublicKey = {instance.public_key}"])
    if peer.preshared_key_enc:
        lines.append(f"PresharedKey = {c.decrypt(peer.preshared_key_enc)}")
    lines.extend(["AllowedIPs = 0.0.0.0/0", f"Endpoint = {endpoint_host}:{instance.listen_port}",
                  "PersistentKeepalive = 25", ""])
    return "\n".join(lines)
