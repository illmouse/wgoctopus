from datetime import UTC, datetime

from wgoctopus_orch.agent_metrics import PeerStat
from wgoctopus_orch.api import device_stats
from wgoctopus_orch.reconciler import Scrape


def test_device_stats_uses_freshest_matching_node():
    now = datetime.now(UTC).timestamp()
    data = {
        1: Scrape(datetime.now(UTC), True, {}, {("wg0", "key"): PeerStat(now - 500, 1, 2)}),
        2: Scrape(datetime.now(UTC), True, {}, {("wg0", "key"): PeerStat(now - 30, 3, 4)}),
    }
    assert device_stats(data, "wg0", "key", now)["rx"] == 3


def test_device_stats_no_handshake_and_active_boundary():
    now = datetime.now(UTC).timestamp()
    empty = {1: Scrape(datetime.now(UTC), True, {}, {("wg0", "key"): PeerStat(0, 100, 200)})}
    stats = device_stats(empty, "wg0", "key", now)
    assert stats["rx"] == stats["tx"] == 0 and stats["active"] is False
    fresh = {1: Scrape(datetime.now(UTC), True, {}, {("wg0", "key"): PeerStat(now - 180, 100, 200)})}
    assert device_stats(fresh, "wg0", "key", now)["active"] is True
