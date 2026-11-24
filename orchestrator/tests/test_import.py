import base64

import pytest

from wgoctopus_orch.keys import derive_public
from wgoctopus_orch.models import Event
from wgoctopus_orch.service import create_instance, import_peer, render_client_config


def fixed_private(seed):
    return base64.b64encode(bytes([seed]) * 32).decode()


def test_create_instance_preserves_private_key_and_normalizes_client_settings(session, crypto):
    private = fixed_private(7)
    instance = create_instance(session, "import0", 51821, "192.0.2.1/24", private_key=private,
                               endpoint_host="vpn.example.invalid", client_dns=" 192.0.2.53, 2001:db8::53 ",
                               client_keepalive=0, client_allowed_ips=" 10.0.0.0/8, 2001:db8::/32 ", crypto=crypto)
    assert instance.public_key == derive_public(private)
    assert crypto.decrypt(instance.private_key_enc) == private
    peer_private = fixed_private(8)
    peer = import_peer(session, instance.id, "imported", private_key=peer_private,
                       preshared_key=fixed_private(9), allowed_ip="192.0.2.2", crypto=crypto)
    config = render_client_config(session, peer.id, crypto=crypto)
    assert "DNS = 192.0.2.53, 2001:db8::53" in config
    assert "AllowedIPs = 10.0.0.0/8, 2001:db8::/32" in config
    assert "PersistentKeepalive = 0" in config
    assert "PresharedKey = " in config
    assert private not in repr(session.query(Event).all())


def test_import_peer_key_mismatch_and_invalid_addresses(session, crypto):
    instance = create_instance(session, "import1", 51822, "192.0.2.1/29", crypto=crypto)
    with pytest.raises(ValueError, match="key mismatch"):
        import_peer(session, instance.id, "bad", public_key=derive_public(fixed_private(1)),
                    private_key=fixed_private(2), allowed_ip="192.0.2.2", crypto=crypto)
    for address in ("192.0.2.1", "192.0.2.0", "192.0.2.7", "198.51.100.1"):
        with pytest.raises(ValueError, match="allowed_ip"):
            import_peer(session, instance.id, "bad", public_key=derive_public(fixed_private(3)),
                        allowed_ip=address, crypto=crypto)
