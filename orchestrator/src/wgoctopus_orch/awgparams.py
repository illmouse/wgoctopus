"""AWG obfuscation parameter generation.

Algorithms adapted from Any-Tech-ARCHITECT (c) 2026 VAI_PROG (Vadim), MIT License.
See docs/third-party-awg-generator.md for attribution and license details.
For AWG 3.1 callers should default MTU to 1280; that is a caller concern.
"""
from __future__ import annotations

import base64
import secrets
from collections.abc import Callable

Rnd = Callable[[int, int], int]
_S_MAX, _S3_MAX, _S4_MAX = 150, 64, 32
_FLOOR = 12
_ZONES = ((100_000_000, 900_000_000, 100_000_000),
          (1_200_000_000, 2_000_000_000, 100_000_000),
          (2_400_000_000, 3_200_000_000, 100_000_000),
          (3_600_000_000, 4_000_000_000, 150_000_000))


def _rnd(lo: int, hi: int) -> int:
    return lo + secrets.randbelow(hi - lo + 1)


def _step(value: int, ceiling: int) -> int:
    return value - 1 if value >= ceiling else value + 1


def _sizes(version: str, rnd: Rnd) -> tuple[int, int, int, int]:
    s = [rnd(1, _S_MAX), rnd(1, _S_MAX), rnd(1, _S3_MAX), rnd(1, _S4_MAX)]
    if version in ("3.0", "3.1"):
        s = [v if v >= _FLOOR else rnd(_FLOOR, ceiling)
             for v, ceiling in zip(s, (_S_MAX, _S_MAX, _S3_MAX, _S4_MAX))]
    # Match protocol offsets and also ensure the rendered padded sizes are unique.
    offsets, ceilings = (0, 56, 84, 0), (_S_MAX, _S_MAX, _S3_MAX, _S4_MAX)
    for i in (1, 2):
        forbidden = {s[0] + offsets[i]} if i == 1 else {s[0] + 84, s[1] + 28}
        for _ in range(10):
            if s[i] not in forbidden:
                break
            s[i] = _step(s[i], ceilings[i])
    for _ in range(500):
        padded = (s[0] + 148, s[1] + 92, s[2] + 64, s[3] + 32)
        if len(set(padded)) == 4:
            return tuple(s)
        i = next(i for i in range(4) if padded[i] in padded[:i])
        s[i] = _step(s[i], ceilings[i])
    raise ValueError("unable to generate distinct S values")


def generate_obfuscation(version: str = "2.0", mtu: int = 1500, intensity: str = "medium",
                         *, rnd: Rnd | None = None, client_max_h: int = 0xFFFFFFFF,
                         max_jc: int = 10, rand_bytes: Callable[[int], bytes] | None = None,
                         mode: str = "normal", junk_level: int | None = None,
                         size_class: str | None = None, fixed_s: dict | None = None,
                         narrow_h: bool = False, header_protection: bool | None = None,
                         content_padding: bool | None = None, random_timings: bool = True,
                         random_trailers: bool | None = None, disable_cookies: bool = False,
                         disable_h: bool = False, unite_s: bool = False) -> dict:
    """Generate schema-compatible AWG 2.0/3.x values using inclusive draws."""
    if version not in ("2.0", "3.0", "3.1"):
        raise ValueError(f"unsupported AWG version: {version}")
    if intensity not in ("low", "medium", "high"):
        raise ValueError(f"unsupported intensity: {intensity}")
    if mode not in ("router", "extreme", "normal"):
        raise ValueError(f"unsupported mode: {mode}")
    if size_class not in (None, "low", "med", "high"):
        raise ValueError(f"unsupported size class: {size_class}")
    draw = rnd or _rnd
    jc = {"low": 3, "medium": 5, "high": 8}[intensity] if junk_level is None else junk_level
    if not 0 <= jc <= 15:
        raise ValueError("junk_level must be between 0 and 15")
    if mode == "router":
        jc = min(jc, 4)
    elif mode == "extreme":
        jc = max(jc, 8)
    jc = max(0, min(max_jc, 15, jc + draw(-1, 1)))
    size = {"low": "low", "medium": "med", "high": "high"}[intensity] if size_class is None else size_class
    min_bounds = {"low": (64, 256), "med": (128, 512), "high": (256, 768)}
    max_bounds = {"low": (256, 512), "med": (512, 1024), "high": (768, 1280)}
    jmin, jmax = draw(*min_bounds[size]), draw(*max_bounds[size])
    if jmax <= jmin + 64:
        jmax = jmin + 64 + draw(64, 256)
    cap = mtu - 28
    jmax = min(jmax, cap)
    if jmax <= jmin:
        jmin = max(1, jmax - 64 - draw(0, 64))
    s1, s2, s3, s4 = _sizes(version, draw)
    sizes = [s1, s2, s3, s4]
    if fixed_s:
        for i in range(1, 5):
            if i in fixed_s:
                sizes[i - 1] = fixed_s[i]
            elif f"s{i}" in fixed_s:
                sizes[i - 1] = fixed_s[f"s{i}"]
    if unite_s:
        sizes = [sizes[0]] * 4
    s1, s2, s3, s4 = sizes
    out = {"jc": jc, "jmin": jmin, "jmax": jmax, "s1": s1, "s2": s2, "s3": s3, "s4": s4}
    for i, (lo, hi, spread) in enumerate(_ZONES, 1):
        if narrow_h:
            spread = min(spread, 10_000_000)
        width = draw(1000, 10_000 if narrow_h else 50_000)
        base = draw(lo, max(lo, hi - spread - width))
        start = base + draw(0, spread)
        end = start + width
        if end > client_max_h:
            start -= end - client_max_h
            end = client_max_h
        out[f"h{i}"] = f"{start}-{end}"
    if version in ("3.0", "3.1"):
        j = {"low": 10, "medium": 25, "high": 45}[intensity]
        lo, hi = {"low": (8, 64), "medium": (16, 128), "high": (24, 200)}[intensity]
        pad_lo = draw(lo, (lo + hi) // 2)
        pad_hi = draw(pad_lo + 8, hi)
        def timer(a, b, spread):
            start = draw(a, b)
            end = start + draw(*spread)
            return f"{start}-{end}" if start != end else str(start)
        if content_padding is not False:
            out["content_padding_addition"] = f"{pad_lo}-{pad_hi}"
        if random_timings:
            rekey_timeout = timer(4, 6, (1, 4))
            keepalive_timeout = timer(8, 14, (2, 8))
            ra_lo = draw(100, 120)
            ra_hi = ra_lo + draw(10, j)
            ka_hi = int(keepalive_timeout.split("-")[-1])
            timeout_hi = int(rekey_timeout.split("-")[-1])
            reject_lo = max(170, ra_hi + ka_hi + timeout_hi + 15)
            out.update(rekey_after_time=f"{ra_lo}-{ra_hi}", rekey_timeout=rekey_timeout,
                       keepalive_timeout=keepalive_timeout, reject_after_time=f"{reject_lo}-{reject_lo + draw(10, j)}",
                       max_handshake_attempts=timer(12, 18, (2, 10)))
        if header_protection is not False:
            out["header_protection_key"] = base64.b64encode((rand_bytes or secrets.token_bytes)(32)).decode()
    if version == "3.1" and random_trailers is not False:
        out["random_trailers"] = True
    if disable_cookies:
        out["disable_cookies"] = True
    if disable_h:
        out.update(h1="1-1", h2="2-2", h3="3-3", h4="4-4")
    if fixed_s and not unite_s:
        # User-specified values take precedence; validation reports collisions.
        for i in range(1, 5):
            if i in fixed_s or f"s{i}" in fixed_s:
                out[f"s{i}"] = sizes[i - 1]
    return out


def validate_obfuscation(obf: dict, *, mtu: int = 1500, version: str = "2.0") -> list[str]:
    """Return validation errors; an empty list means the values are usable."""
    errors = []
    numeric = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")
    invalid_numeric = [key for key in numeric if key in obf and (not isinstance(obf[key], int) or isinstance(obf[key], bool))]
    errors.extend(f"invalid {key}: must be an integer" for key in invalid_numeric)
    required = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"}
    errors.extend(f"missing key: {key}" for key in sorted(required - obf.keys()))
    if not required <= obf.keys() or invalid_numeric:
        return errors
    if not (0 <= obf["jc"] <= 15): errors.append("jc must be between 0 and 15")
    if not (obf["jmin"] < obf["jmax"] <= mtu): errors.append("invalid Jmin/Jmax/MTU")
    s = [obf[f"s{i}"] for i in range(1, 5)]
    if s[1] == s[0] + 56 or s[2] in (s[0] + 84, s[1] + 28): errors.append("S collision")
    padded = [s[0] + 148, s[1] + 92, s[2] + 64, s[3] + 32]
    if len(set(padded)) != 4: errors.append("padded S sizes overlap")
    if version in ("3.0", "3.1") and any(v < 12 for v in s): errors.append("3.x S values must be >= 12")
    if version in ("3.0", "3.1"):
        errors.extend(validate_3x_fields(obf))
    ranges = []
    for i in range(1, 5):
        try:
            parts = obf[f"h{i}"].split("-")
            if len(parts) not in (1, 2): raise ValueError
            lo, hi = map(int, parts) if len(parts) == 2 else (int(parts[0]), int(parts[0]))
            if lo < 0 or lo > hi or hi > 0xFFFFFFFF: raise ValueError
            if (version in ("3.0", "3.1") or len(parts) == 2) and any(1 <= v <= 4 for v in (lo, hi)):
                errors.append(f"h{i} uses disabled header value")
            ranges.append((lo, hi))
        except (ValueError, AttributeError):
            errors.append(f"invalid h{i} range")
    disabled = ranges == [(1, 1), (2, 2), (3, 3), (4, 4)]
    if len(ranges) == 4 and not disabled and any(
        max(a, c) <= min(b, d)
        for i, (a, b) in enumerate(ranges) for c, d in ranges[i + 1:]
    ):
        errors.append("H ranges overlap")
    return errors


def validate_3x_fields(obf: dict) -> list[str]:
    errors = []
    if "header_protection_key" in obf:
        try:
            if len(base64.b64decode(obf["header_protection_key"], validate=True)) != 32: raise ValueError
        except (ValueError, TypeError):
            errors.append("invalid header protection key")
        try:
            if any(f"s{i}" in obf and int(obf[f"s{i}"]) < 12 for i in range(1, 5)):
                errors.append("header protection key requires S values >= 12")
        except (TypeError, ValueError):
            errors.append("header protection key requires numeric S values")
    for key in ("content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts"):
        if key in obf:
            try:
                parts = obf[key].split("-")
                if len(parts) not in (1, 2) or any(not p.isdigit() for p in parts) or (len(parts) == 2 and int(parts[0]) > int(parts[1])): raise ValueError
            except (ValueError, AttributeError):
                errors.append(f"invalid {key} range")
    for key in ("random_trailers", "disable_cookies"):
        if key in obf and not isinstance(obf[key], bool): errors.append(f"invalid {key}")
    return errors
