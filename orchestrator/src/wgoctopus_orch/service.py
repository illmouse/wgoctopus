"""Transactional operations for desired state."""

import hashlib
import ipaddress
import json
import re
import secrets
from contextlib import contextmanager

from sqlalchemy import select
from sqlalchemy.orm import Session

from .awgcps import generate_cps, validate_cps_chain
from .awgparams import generate_obfuscation, validate_3x_fields, validate_obfuscation
from .crypto import Crypto
from .keys import derive_public, generate_keypair, generate_psk, next_free_peer_ip
from .models import (
    Event,
    HopLink,
    Instance,
    Node,
    NodeObserved,
    NodeRevision,
    Peer,
    Placement,
    Probe,
    now_utc,
)
from .renderer import render_node_state

PROBE_OWNER = "__probe__"


def _crypto(crypto):
    return crypto or Crypto()


@contextmanager
def _transaction(session):
    with (session.begin_nested() if session.in_transaction() else session.begin()):
        yield


def _event(session, kind, subject, data=None):
    session.add(Event(kind=kind, subject=subject, data=data or {}))


def _default_obfuscation(mtu=None, version="2.0"):
    return generate_obfuscation(version=version, mtu=mtu or 1500)


def validate_endpoint_host(value):
    if value is None:
        return None
    try:
        if len(value) > 253 or not value or any(c.isspace() for c in value) or "://" in value:
            raise ValueError
        try:
            ipaddress.ip_address(value)
        except ValueError:
            value = value.removesuffix(".")
            if not value or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                                for part in value.split(".")):
                raise ValueError
        return value
    except (TypeError, ValueError):
        raise ValueError("invalid endpoint_host") from None


def _ip_list(value, parser, field):
    if value is None:
        return None
    try:
        entries = [parser(part.strip()) for part in value.split(",")]
        if not entries or any(not part.strip() for part in value.split(",")):
            raise ValueError
        return ", ".join(str(entry) for entry in entries)
    except (AttributeError, TypeError, ValueError):
        raise ValueError(f"invalid {field}") from None


def validate_client_dns(value):
    return _ip_list(value, ipaddress.ip_address, "client_dns")


def validate_client_allowed_ips(value):
    return _ip_list(value, ipaddress.ip_network, "client_allowed_ips")


def create_instance(session: Session, name, listen_port, address, *, obfuscation=None, mtu=None,
                    cps_profile=None, intensity="medium",
                    egress_interface=None, snat_ip=None, private_key=None, endpoint_host=None,
                    client_dns=None, client_keepalive=None, client_allowed_ips=None, crypto=None, awg_version="2.0"):
    if not re.fullmatch(r"[A-Za-z0-9_=+.-]{1,15}", name):
        raise ValueError("instance name must be a valid state interface name (1-15 characters)")
    ipaddress.ip_interface(address)
    generated = obfuscation is None
    if generated:
        effective_mtu = mtu or 1500
        obfuscation = _default_obfuscation(effective_mtu, awg_version)
        if cps_profile is not None and cps_profile != "none":
            obfuscation.update({key: value for key, value in generate_cps(
                cps_profile, mtu=effective_mtu, intensity=intensity
            ).items() if value})
    # Quality rules (S collisions, H range form, MTU) apply only to values we generate; explicit
    # values (e.g. imported from an existing server) are accepted as the daemon accepts them and
    # are fully checked by the agent on push. Only the CPS syntax is checked here.
    try:
        checks = validate_obfuscation(obfuscation, mtu=mtu or 1500, version=awg_version) if generated else validate_3x_fields(obfuscation)
        invalid = checks or validate_cps_chain(
            {key: value for key, value in obfuscation.items() if key in {f"i{i}" for i in range(1, 6)}}
        )
    except (AttributeError, TypeError, ValueError):
        invalid = True
    if invalid:
        raise ValueError("invalid obfuscation parameters")
    endpoint_host = validate_endpoint_host(endpoint_host)
    client_dns = validate_client_dns(client_dns)
    client_allowed_ips = validate_client_allowed_ips(client_allowed_ips)
    if client_keepalive is not None and (not isinstance(client_keepalive, int) or not 0 <= client_keepalive <= 65535):
        raise ValueError("invalid client_keepalive")
    try:
        if private_key is not None and (len(private_key) != 44 or len(__import__("base64").b64decode(private_key, validate=True)) != 32):
            raise ValueError
        public = derive_public(private_key) if private_key is not None else None
    except (ValueError, TypeError):
        raise ValueError("invalid private key") from None
    private, public_generated = generate_keypair() if private_key is None else (private_key, public)
    public = public or public_generated
    instance = Instance(name=name, listen_port=listen_port, address=address,
                        private_key_enc=_crypto(crypto).encrypt(private), public_key=public,
                        obfuscation=obfuscation, mtu=mtu,
                        egress_interface=egress_interface, snat_ip=snat_ip, endpoint_host=endpoint_host,
                        client_dns=client_dns, client_keepalive=client_keepalive,
                        client_allowed_ips=client_allowed_ips)
    with _transaction(session):
        session.add(instance)
        session.flush()
        _event(session, "instance.created", str(instance.id), {"name": name})
    return instance


def create_node(session: Session, name, ssh_host, ssh_user, *, ssh_port=22, mgmt_mode="push",
                agent_port=18080, agent_token=None, egress_interface=None, snat_ip=None,
                enabled=True, kind="awg", wan_interface=None, hop_ip=None, backend_ip=None, pull_public_key=None, crypto=None):
    if mgmt_mode not in {"push", "pull", "auto"}:
        raise ValueError("mgmt_mode must be 'push', 'pull', or 'auto'")
    node = Node(name=name, ssh_host=ssh_host, ssh_port=ssh_port, ssh_user=ssh_user,
                mgmt_mode=mgmt_mode, agent_port=agent_port,
                agent_token_enc=_crypto(crypto).encrypt(agent_token or secrets.token_urlsafe(32)),
                egress_interface=egress_interface, snat_ip=snat_ip, enabled=enabled,
                kind=kind, wan_interface=wan_interface, hop_ip=hop_ip, backend_ip=backend_ip,
                pull_public_key=pull_public_key)
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


def _bump_hops(session, instance_id, crypto=None):
    for hop_id in session.scalars(select(HopLink.hop_id).where(HopLink.instance_id == instance_id)):
        bump_revision(session, hop_id, crypto)
    _bump_probe_runners(session, instance_id=instance_id, crypto=crypto)


def _bump_probe_runners(session, *, instance_id=None, hop_id=None, runner_node_id=None, crypto=None):
    query = select(Probe.runner_node_id)
    if instance_id is not None:
        query = query.where(Probe.instance_id == instance_id)
    if hop_id is not None:
        query = query.where(Probe.hop_id == hop_id)
    if runner_node_id is not None:
        query = query.where(Probe.runner_node_id == runner_node_id)
    for node_id in set(session.scalars(query)):
        bump_revision(session, node_id, crypto)


def place(session: Session, instance_id, node_id, role="active", weight=1, crypto=None):
    if role not in {"active", "standby"}:
        raise ValueError("role must be 'active' or 'standby'")
    with _transaction(session):
        node = session.get(Node, node_id)
        if node is not None and node.kind == "hop":
            raise ValueError("cannot place an instance on a hop node")
        placement = Placement(instance_id=instance_id, node_id=node_id, role=role, weight=weight)
        session.add(placement)
        session.flush()
        _event(session, "placement.created", f"{instance_id}:{node_id}", {"role": role, "weight": weight})
    bump_revision(session, node_id, crypto)
    _bump_hops(session, instance_id, crypto)
    return placement


def create_hop_link(session: Session, hop_id, instance_id, crypto=None):
    with _transaction(session):
        hop = session.get(Node, hop_id)
        if hop is None or hop.kind != "hop":
            raise ValueError("hop link requires a hop node")
        link = HopLink(hop_id=hop_id, instance_id=instance_id)
        session.add(link)
        session.flush()
        _event(session, "hop_link.created", f"{hop_id}:{instance_id}")
    bump_revision(session, hop_id, crypto)
    return link


def create_probe(session: Session, hop_id, instance_id, runner_node_id, *, crypto=None):
    with _transaction(session):
        hop = session.get(Node, hop_id)
        if hop is None or hop.kind != "hop" or not hop.hop_ip:
            raise ValueError("probe requires a hop node with hop_ip")
        if session.get(Instance, instance_id) is None:
            raise ValueError(f"unknown instance {instance_id}")
        if session.scalar(select(HopLink.id).where(
            HopLink.hop_id == hop_id, HopLink.instance_id == instance_id
        )) is None:
            raise ValueError("probe requires an existing hop link")
        runner = session.get(Node, runner_node_id)
        if runner is None or runner.kind != "awg" or not runner.enabled:
            raise ValueError("probe runner must be an enabled awg node")
        if session.scalar(select(Probe.id).where(
            Probe.hop_id == hop_id, Probe.instance_id == instance_id
        )) is not None:
            raise ValueError("probe already exists")
        peer = add_peer(session, instance_id, f"probe-{hop.name}", owner=PROBE_OWNER, crypto=crypto)
        probe = Probe(hop_id=hop_id, instance_id=instance_id, runner_node_id=runner_node_id, peer_id=peer.id)
        session.add(probe)
        session.flush()
        _event(session, "probe.created", str(probe.id),
               {"hop": hop_id, "instance": instance_id, "runner": runner_node_id})
    _bump_probe_runners(session, instance_id=instance_id, crypto=crypto)
    bump_revision(session, runner_node_id, crypto)
    return probe


def delete_probe(session: Session, probe_id, crypto=None):
    with _transaction(session):
        probe = session.get(Probe, probe_id)
        if probe is None:
            return False
        instance_id, hop_id, runner_node_id, peer_id = (
            probe.instance_id, probe.hop_id, probe.runner_node_id, probe.peer_id
        )
        session.delete(probe)
        session.flush()
        remove_peer(session, peer_id, crypto)
        _event(session, "probe.deleted", str(probe_id),
               {"hop": hop_id, "instance": instance_id, "runner": runner_node_id})
    _bump_probe_runners(session, instance_id=instance_id, crypto=crypto)
    bump_revision(session, runner_node_id, crypto)
    return True


def list_probes(session: Session):
    return session.scalars(select(Probe).order_by(Probe.id)).all()


def delete_hop_link(session: Session, hop_id, instance_id, crypto=None):
    with _transaction(session):
        link = session.scalar(select(HopLink).where(HopLink.hop_id == hop_id, HopLink.instance_id == instance_id))
        if link is None:
            return False
        session.delete(link)
        _event(session, "hop_link.deleted", f"{hop_id}:{instance_id}")
    bump_revision(session, hop_id, crypto)
    return True


def switch_active(session: Session, instance_id, node_id, crypto=None):
    with _transaction(session):
        placements = session.scalars(select(Placement).where(Placement.instance_id == instance_id)).all()
        target = next((p for p in placements if p.node_id == node_id), None)
        if target is None:
            raise ValueError("node has no placement for instance")
        previous = sorted((p for p in placements if p.role == "active"), key=lambda p: (-p.weight, p.node_id))
        old_node = session.get(Node, previous[0].node_id) if previous else None
        for placement in placements:
            placement.role = "active" if placement is target else "standby"
        _event(session, "instance.switched", str(instance_id),
               {"from": old_node.name if old_node else None, "to": session.get(Node, node_id).name})
    for placement in placements:
        bump_revision(session, placement.node_id, crypto)
    _bump_hops(session, instance_id, crypto)
    return target


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
        if owner != PROBE_OWNER:  # the system probe peer is invisible; probe.created covers it
            _event(session, "peer.created", str(peer.id), {"instance_id": instance_id, "allowed_ip": allowed_ip})
    for node_id in node_ids:
        bump_revision(session, node_id, crypto)
    return peer


def import_peer(session: Session, instance_id, name, *, public_key=None, private_key=None,
                preshared_key=None, allowed_ip, enabled=True, owner=None, crypto=None):
    crypto = _crypto(crypto)
    if private_key is None and public_key is None:
        raise ValueError("public_key or private_key is required")
    try:
        derived = derive_public(private_key) if private_key is not None else None
    except (ValueError, TypeError):
        raise ValueError("invalid private key") from None
    if public_key is not None and derived is not None and public_key != derived:
        raise ValueError("key mismatch")
    public_key = public_key or derived
    with _transaction(session):
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise ValueError(f"unknown instance {instance_id}")
        try:
            address = ipaddress.ip_address(allowed_ip)
            network = ipaddress.ip_interface(instance.address).network
            instance_ip = ipaddress.ip_interface(instance.address).ip
            if address.version != 4 or address not in network or address in (network.network_address, network.broadcast_address, instance_ip):
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("invalid allowed_ip") from None
        if session.scalar(select(Peer.id).where(Peer.instance_id == instance_id, Peer.allowed_ip == str(address))):
            raise ValueError("allowed_ip already exists")
        if session.scalar(select(Peer.id).where(Peer.instance_id == instance_id, Peer.public_key == public_key)):
            raise ValueError("public_key already exists")
        peer = Peer(instance_id=instance_id, name=name, public_key=public_key,
                    private_key_enc=crypto.encrypt(private_key) if private_key is not None else "",
                    preshared_key_enc=crypto.encrypt(preshared_key) if preshared_key else "",
                    allowed_ip=str(address), enabled=enabled, owner=owner)
        session.add(peer)
        session.flush()
        _event(session, "peer.created", str(peer.id), {"instance_id": instance_id, "allowed_ip": peer.allowed_ip})
        node_ids = session.scalars(select(Placement.node_id).where(Placement.instance_id == instance_id)).all()
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
        if peer.owner != PROBE_OWNER:
            _event(session, "peer.removed", str(peer_id), {"instance_id": peer.instance_id})
        session.delete(peer)
    for node_id in node_ids:
        bump_revision(session, node_id, crypto)
    return True


def render_client_config(session: Session, peer_id, endpoint_host=None, *, dns=None, crypto=None) -> str:
    peer = session.get(Peer, peer_id)
    if peer is None or not peer.enabled:
        raise ValueError("peer not found or disabled")
    if not peer.private_key_enc:
        raise ValueError("peer has no stored private key")
    instance = session.get(Instance, peer.instance_id)
    endpoint_host = instance.endpoint_host or endpoint_host
    if not endpoint_host:
        raise ValueError("endpoint_host is required")
    dns = instance.client_dns if dns is None else dns
    c = _crypto(crypto)
    o = instance.obfuscation
    lines = ["[Interface]", f"PrivateKey = {c.decrypt(peer.private_key_enc)}",
             f"Address = {peer.allowed_ip}/32" if ":" not in peer.allowed_ip else f"Address = {peer.allowed_ip}/128"]
    if dns:
        lines.append(f"DNS = {dns}")
    if instance.mtu is not None:
        lines.append(f"MTU = {instance.mtu}")
    names = {"jc": "Jc", "jmin": "Jmin", "jmax": "Jmax", **{f"s{i}": f"S{i}" for i in range(1, 5)},
             **{f"h{i}": f"H{i}" for i in range(1, 5)}, **{f"i{i}": f"I{i}" for i in range(1, 6)}}
    lines.extend(f"{label} = {o[key]}" for key, label in names.items() if key in o and o[key] != "")
    config_names = {"header_protection_key": "HeaderProtectionKey", "content_padding_addition": "ContentPaddingAddition",
                    "rekey_after_time": "RekeyAfterTime", "rekey_timeout": "RekeyTimeout",
                    "reject_after_time": "RejectAfterTime", "keepalive_timeout": "KeepaliveTimeout",
                    "max_handshake_attempts": "MaxHandshakeAttempts"}
    lines.extend(f"{label} = {o[key]}" for key, label in config_names.items() if key in o and o[key] != "")
    if o.get("random_trailers") or o.get("disable_cookies"):
        lines.extend((f"RandomTrailers = {int(bool(o.get('random_trailers')))}",
                      f"DisableCookies = {int(bool(o.get('disable_cookies')))}"))
    lines.extend(["", "[Peer]", f"PublicKey = {instance.public_key}"])
    if peer.preshared_key_enc:
        lines.append(f"PresharedKey = {c.decrypt(peer.preshared_key_enc)}")
    lines.extend([f"AllowedIPs = {instance.client_allowed_ips or '0.0.0.0/0'}", f"Endpoint = {endpoint_host}:{instance.listen_port}",
                  f"PersistentKeepalive = {instance.client_keepalive if instance.client_keepalive is not None else 25}", ""])
    return "\n".join(lines)
