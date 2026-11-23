"""In-memory evaluation of synthetic probe handshakes."""

from dataclasses import dataclass
from enum import StrEnum


class ProbeState(StrEnum):
    UNKNOWN = "UNKNOWN"
    UP = "UP"
    DOWN = "DOWN"


@dataclass
class ProbeRecord:
    state: ProbeState = ProbeState.UNKNOWN
    first_seen: float | None = None
    last_handshake_ts: float | None = None
    age: float | None = None


class ProbeStatusTracker:
    def __init__(self, stale_seconds=180, grace_seconds=60):
        self.stale_seconds, self.grace_seconds = stale_seconds, grace_seconds
        self.records: dict[int, ProbeRecord] = {}

    def evaluate(self, probe_id, scrape, node_in_sync, iface, public_key, now):
        record = self.records.setdefault(probe_id, ProbeRecord())
        if not scrape or not scrape.ok or not node_in_sync or iface not in scrape.interfaces:
            if scrape and scrape.ok and iface not in scrape.interfaces:
                record.first_seen = record.last_handshake_ts = record.age = None
            return ProbeState.UNKNOWN, None
        record.first_seen = now if record.first_seen is None else record.first_seen
        stat = scrape.peers.get((iface, public_key))
        handshake = stat.handshake_ts if stat else 0
        age = max(0.0, now - handshake) if handshake > 0 else None
        record.last_handshake_ts, record.age = (handshake or None), age
        if handshake > 0:
            state = ProbeState.UP if age <= self.stale_seconds else ProbeState.DOWN
        elif now - record.first_seen > self.grace_seconds:
            state = ProbeState.DOWN
        else:
            state = ProbeState.UNKNOWN
        record.state = state if state != ProbeState.UNKNOWN else record.state
        return state, age

    def discard(self, probe_id):
        self.records.pop(probe_id, None)
