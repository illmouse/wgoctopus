"""AmneziaWG CPS signature-chain generation.

Profile packet shapes adapted from Any-Tech-ARCHITECT (MIT).
"""
from __future__ import annotations

import re
import secrets
import struct
from collections.abc import Callable

PROFILES = ("quic_initial", "tls_client_hello", "dns_query", "wireguard_noise", "sip", "random", "none")
SNI_HOSTS = ("www.google.com", "www.youtube.com", "www.facebook.com", "www.amazon.com", "www.microsoft.com", "www.apple.com", "www.wikipedia.org", "www.reddit.com", "www.cloudflare.com", "www.instagram.com", "www.linkedin.com", "www.netflix.com", "www.github.com", "www.dropbox.com", "www.yahoo.com", "www.bing.com", "www.mozilla.org", "www.wordpress.com", "www.twitch.tv", "www.spotify.com", "www.paypal.com", "www.ebay.com", "www.nytimes.com", "www.cnn.com", "www.bbc.com", "www.adobe.com", "www.salesforce.com", "www.zoom.us", "www.slack.com", "www.telegram.org", "www.whatsapp.com", "www.booking.com", "www.airbnb.com", "www.shopify.com", "www.oracle.com", "www.ibm.com", "www.intel.com", "www.nvidia.com", "www.tesla.com", "www.gov.uk")
KMOD_CHAIN_BUDGET = 3200
_TAG = re.compile(r"<(b 0x[0-9a-fA-F]*|t|c|r \d+|rc \d+|rd \d+|d|ds|dz)>")
Rnd = Callable[[int, int], int]


def _bytes(n: int, rand_bytes: Callable[[int], bytes]) -> bytes:
    return rand_bytes(n)


def _blob(data: bytes) -> str:
    return f"<b 0x{data.hex()}>"


def _varint(n: int) -> bytes:
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack(">H", n | 0x4000)
    return struct.pack(">I", n | 0x80000000)


def _quic(rnd: Rnd, rb: Callable[[int], bytes], mtu: int) -> str:
    pn = rnd(1, 4)
    dcid, scid = _bytes(rnd(8, 20), rb), _bytes(rnd(0, 20), rb)
    prefix = bytes([0xC0 | (pn - 1)]) + b"\0\0\0\1" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\0"
    pad = max(0, min(max(0, mtu - 28), 1200) - len(prefix) - 1 - pn - 1 - 1 - 1)
    tags = "<t>" + "".join(f"<r {min(1000, pad - i)}>" for i in range(0, pad, 1000))
    length = pn + pad
    packet = prefix + _varint(length) + _bytes(pn, rb) + bytes(pad)
    return _blob(packet) + f"<rc {len(dcid)}>" + tags


def _tls(rnd: Rnd, rb: Callable[[int], bytes], mtu: int) -> str:
    pad = max(0, min(256, mtu - 100))
    hello = b"\x01\x00\x00\x2f\x03\x03" + _bytes(32, rb)
    record = b"\x16\x03\x01" + struct.pack(">H", len(hello)) + hello
    return _blob(record) + f"<rc {rnd(8, 20)}><r {pad}><t>"


def _dns(rnd: Rnd, rb: Callable[[int], bytes], mtu: int) -> str:
    host = SNI_HOSTS[rnd(0, len(SNI_HOSTS) - 1)]
    qname = b"".join(bytes([len(x)]) + x.encode() for x in host.split(".")) + b"\0"
    ident = _bytes(2, rb)
    packet = ident + b"\x01\x00\0\1\0\0\0\0\0\1" + qname + b"\0\1\0\1" + b"\0\0)\x04\xd0\0\0\0\0\0\0"
    return _blob(packet) + f"<r {max(4, min(64, mtu - len(packet)))}><t>"


def _noise(rnd: Rnd, rb: Callable[[int], bytes]) -> str:
    blobs = (b"\x01\0\0\0" + _bytes(4, rb), _bytes(32, rb), _bytes(48, rb), _bytes(28, rb), _bytes(32, rb))
    return "".join(_blob(b) for b in blobs) + f"<r {rnd(4, 64)}><t><rc {rnd(8, 20)}>"


def _sip(rnd: Rnd, rb: Callable[[int], bytes], mtu: int) -> str:
    host = SNI_HOSTS[rnd(0, len(SNI_HOSTS) - 1)]
    branch = "z9hG4bK" + rb(8).hex()
    request = f"REGISTER sip:{host} SIP/2.0\r\nVia: SIP/2.0/UDP {host};branch={branch}\r\nFrom: <sip:user@{host}>\r\nTo: <sip:user@{host}>\r\nCall-ID: {rb(12).hex()}\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
    raw = request.encode()
    return _blob(raw) + f"<rc {len(host)}><t><r {max(0, min(64, mtu - len(raw)))}>"


def _entropy(rnd: Rnd, rb: Callable[[int], bytes], iv: int, allow_c: bool) -> str:
    tags = []
    if iv >= 2:
        tags.append(_blob(rb(rnd(4, 8) * iv)))
    tags += [f"<r {rnd(4, 64)}>", "<t>", f"<rc {rnd(4, 12)}>", f"<rd {rnd(4, 8)}>"]
    if allow_c:
        tags.append("<c>")
    for i in range(len(tags) - 1, 0, -1):
        j = rnd(0, i)
        tags[i], tags[j] = tags[j], tags[i]
    return "".join(tags) or "<r 10>"


def _cost(value: str) -> int:
    size = 0
    for tag in _TAG.findall(value):
        if tag.startswith("b 0x"):
            size += len(tag[4:]) // 2
        elif tag == "t" or tag == "c":
            size += 4
        elif tag.startswith(("r ", "rc ", "rd ")):
            size += int(tag.rsplit(" ", 1)[1])
    return 4 + ((size + len(value.encode()) * 0 + 1 + 3) // 4) * 4 if value else 0


def generate_cps(profile: str = "quic_initial", *, mtu: int = 1500, intensity: str = "medium", rnd=None, rand_bytes=None, use_tag_c: bool = False, mimic_all: bool = False) -> dict[str, str]:
    """Generate I1-I5 CPS tags using injectable inclusive RNG and byte source."""
    rnd = rnd or secrets.randbelow
    if rnd is secrets.randbelow:
        rnd = lambda lo, hi: secrets.randbelow(hi - lo + 1) + lo
    rb = rand_bytes or secrets.token_bytes
    iv = {"low": 1, "medium": 2, "high": 3}.get(intensity, 2)
    builders = {"quic_initial": _quic, "tls_client_hello": _tls, "dns_query": _dns, "wireguard_noise": _noise, "sip": _sip}
    picked = profile
    if profile == "random":
        picked = tuple(builders)[rnd(0, len(builders) - 1)]
    if picked == "none":
        return dict.fromkeys(("i1", "i2", "i3", "i4", "i5"), "")
    if picked not in builders:
        raise ValueError(f"unknown CPS profile: {picked[:80]}")
    def packet(name: str) -> str:
        return builders[name](rnd, rb, mtu) if name in ("quic_initial", "tls_client_hello", "dns_query", "sip") else builders[name](rnd, rb)
    chains = [packet(picked)] + [packet(picked) if mimic_all else _entropy(rnd, rb, iv, use_tag_c) for _ in range(4)]
    while sum(map(_cost, chains)) > KMOD_CHAIN_BUDGET:
        slot = next((i for i in range(4, 0, -1) if chains[i]), None)
        if slot is None:
            break
        if slot > 1:
            chains[slot] = _entropy(rnd, rb, 1, use_tag_c)
        else:
            chains[slot] = ""
    return dict(zip(("i1", "i2", "i3", "i4", "i5"), chains))


def validate_cps(value: str, *, allow_c: bool = True) -> list[str]:
    """Return CPS tag syntax errors without echoing untrusted values."""
    errors, pos = [], 0
    for match in _TAG.finditer(value):
        if match.start() != pos:
            errors.append(f"invalid CPS syntax near offset {pos}")
            return errors
        tag = match.group(1)
        if tag == "c" and not allow_c:
            errors.append("unsupported <c> tag")
        if tag.startswith("b 0x") and len(tag[4:]) % 2:
            errors.append("<b 0x...> must contain an even number of hex digits")
        pos = match.end()
    if pos != len(value):
        errors.append(f"invalid CPS syntax near offset {pos}")
    return errors


def validate_cps_chain(chain: dict[str, str]) -> list[str]:
    """Validate each populated slot and the combined kernel-module budget."""
    errors = [f"{key}: {error}" for key, value in chain.items() if value for error in validate_cps(value)]
    if sum(_cost(v) for v in chain.values()) > KMOD_CHAIN_BUDGET:
        errors.append(f"CPS chain exceeds {KMOD_CHAIN_BUDGET}-byte budget")
    return errors
