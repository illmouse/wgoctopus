import random
import re

import pytest

from wgoctopus_orch.awgcps import PROFILES, generate_cps, validate_cps


def seeded(seed):
    rng = random.Random(seed)
    return rng.randint, lambda n: bytes(rng.randrange(256) for _ in range(n))


@pytest.mark.parametrize("profile", PROFILES)
def test_profiles_validate_and_are_deterministic(profile):
    for seed in range(300):
        rnd, rb = seeded(seed)
        first = generate_cps(profile, rnd=rnd, rand_bytes=rb)
        rnd2, rb2 = seeded(seed)
        assert first == generate_cps(profile, rnd=rnd2, rand_bytes=rb2)
        assert all(not validate_cps(value, allow_c=False) for value in first.values())


def test_quic_header_and_length():
    rnd, rb = seeded(7)
    raw = bytes.fromhex(re.search(r"<b 0x([0-9a-f]+)>", generate_cps(rnd=rnd, rand_bytes=rb)["i1"]).group(1))
    assert raw[0] & 0xC0 == 0xC0
    assert raw[1:5] == b"\0\0\0\1"
    assert 8 <= raw[5] <= 20
    offset = 6 + raw[5]
    offset += 1 + raw[offset]
    offset += 1
    first = raw[offset]
    n = 1 << (first >> 6)
    declared = int.from_bytes(raw[offset:offset+n], "big") & ((1 << (8*n-2))-1)
    assert declared == len(raw) - offset - n


@pytest.mark.parametrize("profile,begins", [("tls_client_hello", "160301"), ("wireguard_noise", "01000000")])
def test_binary_profile_prefix(profile, begins):
    rnd, rb = seeded(12)
    raw = bytes.fromhex(re.search(r"<b 0x([0-9a-f]+)>", generate_cps(profile, rnd=rnd, rand_bytes=rb)["i1"]).group(1))
    assert raw.startswith(bytes.fromhex(begins))


@pytest.mark.parametrize("profile,begins", [
    ("quic_0rtt", "d000000001"), ("dtls_1_2", "16fefd"),
    ("dtls_1_3", "16fefc"), ("http3", "c000000001"),
    ("stun", "000100002112a442"),
])
def test_added_profiles_have_protocol_headers_and_bounded_chains(profile, begins):
    from wgoctopus_orch.awgcps import KMOD_CHAIN_BUDGET, _cost, validate_cps_chain

    rnd, rb = seeded(23)
    chain = generate_cps(profile, rnd=rnd, rand_bytes=rb, mtu=1280)
    raw = bytes.fromhex(re.search(r"<b 0x([0-9a-f]+)>", chain["i1"]).group(1))
    assert raw.startswith(bytes.fromhex(begins))
    assert sum(_cost(value) for value in chain.values()) <= KMOD_CHAIN_BUDGET
    assert validate_cps_chain(chain) == []


@pytest.mark.parametrize("value", ["<x>", "abc", "<r>", "<b 0xABC>", "<r 1x>"])
def test_rejects_invalid_tags(value):
    assert validate_cps(value)
