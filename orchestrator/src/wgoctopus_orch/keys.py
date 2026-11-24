"""WireGuard-compatible X25519 key and peer-address helpers."""

import base64
import ipaddress
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def generate_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw_private).decode(), base64.b64encode(raw_public).decode()


def derive_public(private_b64: str) -> str:
    private = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64, validate=True))
    return base64.b64encode(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )).decode()


def generate_psk() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def next_free_peer_ip(address: str, used: set[str]) -> str:
    interface = ipaddress.ip_interface(address)
    network = interface.network
    reserved = {str(interface.ip), *used}
    for ip in network.hosts():
        candidate = str(ip)
        if candidate not in reserved:
            return candidate
    raise ValueError(f"no free peer IPs in {network}")
