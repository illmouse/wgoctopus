from types import SimpleNamespace

from wgoctopus_orch.probe_status import ProbeState, ProbeStatusTracker


def test_probe_status_rules_and_no_unknown_flapping():
    tracker = ProbeStatusTracker(stale_seconds=10, grace_seconds=5)
    iface, key = "wgp1", "key"
    absent = SimpleNamespace(ok=True, interfaces={}, peers={})
    present = SimpleNamespace(ok=True, interfaces={iface: {}}, peers={})
    failed = SimpleNamespace(ok=False, interfaces={iface: {}}, peers={})
    assert tracker.evaluate(1, None, True, iface, key, 0)[0] == ProbeState.UNKNOWN
    assert tracker.evaluate(1, failed, True, iface, key, 0)[0] == ProbeState.UNKNOWN
    assert tracker.evaluate(1, present, False, iface, key, 0)[0] == ProbeState.UNKNOWN
    assert tracker.evaluate(1, absent, True, iface, key, 0)[0] == ProbeState.UNKNOWN
    assert tracker.evaluate(1, present, True, iface, key, 10)[0] == ProbeState.UNKNOWN
    stat = SimpleNamespace(handshake_ts=105, rx=0, tx=0)
    present.peers = {(iface, key): stat}
    assert tracker.evaluate(1, present, True, iface, key, 105)[0] == ProbeState.UP
    assert tracker.evaluate(1, failed, True, iface, key, 106)[0] == ProbeState.UNKNOWN
    assert tracker.evaluate(1, present, True, iface, key, 106)[0] == ProbeState.UP
    stat.handshake_ts = 90
    assert tracker.evaluate(1, present, True, iface, key, 106)[0] == ProbeState.DOWN
    stat.handshake_ts = 0
    assert tracker.evaluate(1, present, True, iface, key, 111)[0] == ProbeState.DOWN
    tracker.evaluate(1, absent, True, iface, key, 112)
    tracker.evaluate(1, present, True, iface, key, 200)
    assert tracker.records[1].first_seen == 200
