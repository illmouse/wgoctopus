from datetime import UTC, datetime


def device_stats(scrapes, instance_name, public_key, now):
    """Return the freshest cached handshake for a peer across all nodes."""
    latest = None
    for scrape in (scrapes or {}).values():
        for (interface, key), stat in (scrape.peers or {}).items():
            if interface != instance_name or key != public_key or not stat.handshake_ts:
                continue
            if latest is None or stat.handshake_ts > latest.handshake_ts:
                latest = stat
    if latest is None:
        return {"latest_handshake_at": None, "rx": 0, "tx": 0, "active": False}
    stamp = datetime.fromtimestamp(latest.handshake_ts, UTC)
    current = now.timestamp() if isinstance(now, datetime) else now
    age = current - latest.handshake_ts
    return {"latest_handshake_at": stamp, "rx": latest.rx, "tx": latest.tx, "active": age <= 180}
