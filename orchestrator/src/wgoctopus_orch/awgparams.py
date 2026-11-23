"""AWG obfuscation parameter generation.

Algorithms adapted from Any-Tech-ARCHITECT (c) 2026 VAI_PROG (Vadim), MIT License.
For AWG 3.1 callers should default MTU to 1280; that is a caller concern.
"""
from __future__ import annotations

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
                         max_jc: int = 10) -> dict:
    """Generate schema-compatible AWG 2.0/3.x values using inclusive draws."""
    if version not in ("2.0", "3.0", "3.1"):
        raise ValueError(f"unsupported AWG version: {version}")
    if intensity not in ("low", "medium", "high"):
        raise ValueError(f"unsupported intensity: {intensity}")
    draw = rnd or _rnd
    jc = {"low": 3, "medium": 5, "high": 8}[intensity]
    jc = max(1, min(max_jc, 15, jc + draw(-1, 1)))
    min_bounds = {"low": (64, 256), "medium": (128, 512), "high": (256, 768)}
    max_bounds = {"low": (256, 512), "medium": (512, 1024), "high": (768, 1280)}
    jmin, jmax = draw(*min_bounds[intensity]), draw(*max_bounds[intensity])
    if jmax <= jmin + 64:
        jmax = jmin + 64 + draw(64, 256)
    cap = mtu - 28
    jmax = min(jmax, cap)
    if jmax <= jmin:
        jmin = max(1, jmax - 64 - draw(0, 64))
    s1, s2, s3, s4 = _sizes(version, draw)
    out = {"jc": jc, "jmin": jmin, "jmax": jmax, "s1": s1, "s2": s2, "s3": s3, "s4": s4}
    for i, (lo, hi, spread) in enumerate(_ZONES, 1):
        width = draw(1000, 50_000)
        base = draw(lo, max(lo, hi - spread - width))
        start = base + draw(0, spread)
        end = start + width
        if end > client_max_h:
            start -= end - client_max_h
            end = client_max_h
        out[f"h{i}"] = f"{start}-{end}"
    return out


def validate_obfuscation(obf: dict, *, mtu: int = 1500, version: str = "2.0") -> list[str]:
    """Return validation errors; an empty list means the values are usable."""
    errors = []
    required = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"}
    errors.extend(f"missing key: {key}" for key in sorted(required - obf.keys()))
    if not required <= obf.keys():
        return errors
    if not (obf["jc"] >= 1): errors.append("jc must be >= 1")
    if not (obf["jmin"] < obf["jmax"] <= mtu): errors.append("invalid Jmin/Jmax/MTU")
    s = [obf[f"s{i}"] for i in range(1, 5)]
    if s[1] == s[0] + 56 or s[2] in (s[0] + 84, s[1] + 28): errors.append("S collision")
    padded = [s[0] + 148, s[1] + 92, s[2] + 64, s[3] + 32]
    if len(set(padded)) != 4: errors.append("padded S sizes overlap")
    if version in ("3.0", "3.1") and any(v < 12 for v in s): errors.append("3.x S values must be >= 12")
    ranges = []
    for i in range(1, 5):
        try:
            parts = obf[f"h{i}"].split("-")
            if len(parts) != 2: raise ValueError
            lo, hi = map(int, parts)
            if lo < 0 or lo > hi or hi > 0xFFFFFFFF: raise ValueError
            if any(1 <= v <= 4 for v in (lo, hi)): errors.append(f"h{i} uses disabled header value")
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
