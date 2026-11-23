"""Parser for agent Prometheus text exposition."""

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    name: str
    labels: dict[str, str]
    value: float


_SAMPLE = re.compile(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+\d+)?\s*$')
_LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:\\.|[^"\\])*)"\s*(?:,|$)')


def parse_agent_metrics(text: str) -> list[Sample]:
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            match = _SAMPLE.fullmatch(line)
            if not match:
                continue
            labels = {}
            raw = match.group(2)
            while raw:
                label = _LABEL.match(raw)
                if not label:
                    raise ValueError
                labels[label.group(1)] = re.sub(
                    r'\\([\\n"])', lambda m: {"\\": "\\", "n": "\n", '"': '"'}[m.group(1)],
                    label.group(2))
                raw = raw[label.end():]
            value = float(match.group(3))
            if not math.isnan(value):
                result.append(Sample(match.group(1), labels, value))
        except (ValueError, OverflowError):
            continue
    return result


@dataclass(frozen=True)
class PeerStat:
    handshake_ts: float
    rx: int
    tx: int


def extract_peer_stats(samples):
    interfaces, grouped = {}, {}
    for sample in samples:
        interface = sample.labels.get("interface")
        key = sample.labels.get("public_key")
        if not interface:
            continue
        if sample.name == "wg_interface_up":
            interfaces[interface] = {"up": bool(sample.value)}
        if key:
            grouped.setdefault((interface, key), {})[sample.name] = sample.value
    peers = {identity: PeerStat(values.get("wg_peer_last_handshake_timestamp_seconds", 0.0),
                                int(values.get("wg_peer_rx_bytes_total", 0)),
                                int(values.get("wg_peer_tx_bytes_total", 0)))
             for identity, values in grouped.items()}
    return interfaces, peers
