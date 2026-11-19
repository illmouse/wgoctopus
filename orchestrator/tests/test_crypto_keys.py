import base64

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from wgoctopus_orch.crypto import Crypto, Secret
from wgoctopus_orch.keys import generate_keypair, generate_psk, next_free_peer_ip


def test_crypto_redacts_roundtrip_and_rejects_wrong_key():
    first, second = Crypto(Fernet.generate_key()), Crypto(Fernet.generate_key())
    ciphertext = first.encrypt("sensitive")
    assert first.decrypt(ciphertext) == "sensitive"
    assert "sensitive" not in repr(first.decrypt(ciphertext))
    assert "sensitive" not in repr(Secret("sensitive"))
    with pytest.raises(RuntimeError, match="decryption failed"):
        second.decrypt(ciphertext)
    with pytest.raises(RuntimeError, match="set WGOCTOPUS"):
        Crypto("")
    with pytest.raises(RuntimeError, match="invalid WGOCTOPUS"):
        Crypto("not-a-fernet-key")


def test_keypair_and_psk_are_wireguard_keys():
    private, public = generate_keypair()
    raw = base64.b64decode(private)
    derived = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.b64encode(derived).decode() == public
    assert len(base64.b64decode(generate_psk())) == 32


def test_ip_allocation_skips_server_and_used_addresses_and_exhaustion():
    assert next_free_peer_ip("10.2.0.1/29", set()) == "10.2.0.2"
    assert next_free_peer_ip("10.2.0.1/29", {"10.2.0.2"}) == "10.2.0.3"
    with pytest.raises(ValueError, match="no free"):
        next_free_peer_ip("10.2.0.1/30", {"10.2.0.2"})
