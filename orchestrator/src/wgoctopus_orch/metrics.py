"""Prometheus 0.0.4 text exposition for orchestrator state."""

from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .config import Settings
from .models import (
    Event,
    FailoverProposal,
    HopLink,
    Instance,
    Node,
    NodeObserved,
    NodeRevision,
    Peer,
    Probe,
    ProvisionJob,
)
from .reconciler import NodeState
from .renderer import active_placement, probe_iface_name


def escape_label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_metrics(session: Session, reconciler=None, version="0.1.0", now=None, alerts=None, failover=None, bot=None, pull_server=None) -> str:
    lines = []

    def sample(name, labels, value):
        label_text = ",".join(f'{key}="{escape_label(val)}"' for key, val in labels.items())
        lines.append(f"{name}{{{label_text}}} {value}" if labels else f"{name} {value}")

    def family(name, kind, help_text):
        lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"))

    family("wgoctopus_alerts_enabled", "gauge", "Whether alert delivery is enabled.")
    family("wgoctopus_alerts_sent_total", "counter", "Alerts sent.")
    family("wgoctopus_alerts_failed_total", "counter", "Alert delivery failures.")
    family("wgoctopus_alerts_dropped_total", "counter", "Alerts dropped or suppressed.")
    family("wgoctopus_alerts_pending", "gauge", "Alerts pending delivery.")
    alert_counts = alerts.counters() if alerts else {}
    sample("wgoctopus_alerts_enabled", {}, int(alerts is not None))
    mode = Settings.from_env().failover_mode
    family("wgoctopus_failover_mode", "gauge", "Configured failover mode.")
    for value in ("off", "confirm", "auto"):
        sample("wgoctopus_failover_mode", {"mode": value}, int(mode == value))
    family("wgoctopus_failover_proposals", "gauge", "Failover proposals by state.")
    proposal_counts = dict(session.execute(select(FailoverProposal.state, func.count(FailoverProposal.id)).group_by(FailoverProposal.state)).all())
    for value in ("pending", "executed", "rejected", "expired", "cancelled", "failed"):
        sample("wgoctopus_failover_proposals", {"state": value}, proposal_counts.get(value, 0))
    family("wgoctopus_failover_pending", "gauge", "Pending failover proposals.")
    sample("wgoctopus_failover_pending", {}, proposal_counts.get("pending", 0))
    for metric, key in (("wgoctopus_alerts_sent_total", "sent"), ("wgoctopus_alerts_failed_total", "failed"), ("wgoctopus_alerts_dropped_total", "dropped"), ("wgoctopus_alerts_pending", "pending")):
        sample(metric, {}, alert_counts.get(key, 0))
    family("wgoctopus_telegram_callbacks_total", "counter", "Telegram failover callback outcomes.")
    for result in ("ok", "denied", "invalid", "rejected_by_engine", "error"):
        sample("wgoctopus_telegram_callbacks_total", {"result": result}, (bot.results if bot else {}).get(result, 0))
    family("wgoctopus_telegram_bot_enabled", "gauge", "Whether the Telegram callback bot is enabled.")
    sample("wgoctopus_telegram_bot_enabled", {}, int(bot is not None))

    family("wgoctopus_build_info", "gauge", "Orchestrator build information.")
    sample("wgoctopus_build_info", {"version": version}, 1)
    nodes = session.scalars(select(Node).order_by(Node.name)).all()
    family("wgoctopus_pull_server_enabled", "gauge", "Whether the pull SSH listener is enabled.")
    sample("wgoctopus_pull_server_enabled", {}, int(pull_server is not None))
    family("wgoctopus_provision_jobs", "gauge", "Provisioning jobs by state.")
    counts = dict(session.execute(select(ProvisionJob.state, func.count()).group_by(ProvisionJob.state)).all())
    for state in ("queued", "running", "succeeded", "failed", "cancelled"):
        sample("wgoctopus_provision_jobs", {"state": state}, counts.get(state, 0))
    family("wgoctopus_pull_tunnel_up", "gauge", "Whether a pull tunnel is connected.")
    for node in nodes:
        if node.mgmt_mode in ("pull", "auto"):
            sample("wgoctopus_pull_tunnel_up", {"node": node.name}, int(bool(pull_server and pull_server.is_connected(node.id))))
    family("wgoctopus_pull_connections_total", "counter", "Pull SSH connection outcomes.")
    for result in ("ok", "denied"):
        sample("wgoctopus_pull_connections_total", {"result": result}, pull_server.counters.get("connections_" + result, 0) if pull_server else 0)
    instances = session.scalars(select(Instance).order_by(Instance.name)).all()
    counts = {}
    for node in nodes:
        counts[node.kind] = counts.get(node.kind, 0) + 1
    family("wgoctopus_nodes", "gauge", "Nodes by kind.")
    for kind in sorted(counts):
        sample("wgoctopus_nodes", {"kind": kind}, counts[kind])
    family("wgoctopus_node_state", "gauge", "One-hot reconciler state for each node.")
    family("wgoctopus_node_enabled", "gauge", "Whether a node is enabled.")
    family("wgoctopus_node_desired_revision", "gauge", "Latest desired node revision.")
    family("wgoctopus_node_applied_revision", "gauge", "Latest applied node revision.")
    family("wgoctopus_node_last_seen_timestamp_seconds", "gauge", "Last observed timestamp.")
    family("wgoctopus_node_consecutive_failures", "gauge", "Consecutive reconcile failures.")
    status_fn = getattr(reconciler, "status", None)
    statuses = status_fn() if callable(status_fn) else {}
    for node in nodes:
        status = statuses.get(node.id)
        state = status.state.value if status else NodeState.UNKNOWN.value
        for possible in NodeState:
            sample("wgoctopus_node_state", {"node": node.name, "kind": node.kind, "state": possible.value}, int(state == possible.value))
        sample("wgoctopus_node_enabled", {"node": node.name, "kind": node.kind}, int(node.enabled))
        revision = session.get(NodeRevision, node.id)
        if revision:
            sample("wgoctopus_node_desired_revision", {"node": node.name}, revision.desired_revision)
        observed = session.get(NodeObserved, node.id)
        if observed:
            if observed.applied_revision is not None:
                sample("wgoctopus_node_applied_revision", {"node": node.name}, observed.applied_revision)
            if observed.last_seen_at is not None:
                seen = observed.last_seen_at
                if seen.tzinfo is None:
                    seen = seen.replace(tzinfo=UTC)
                sample("wgoctopus_node_last_seen_timestamp_seconds", {"node": node.name}, seen.timestamp())
        sample("wgoctopus_node_consecutive_failures", {"node": node.name}, status.consecutive_failures if status else 0)
    family("wgoctopus_instances", "gauge", "Configured instances.")
    sample("wgoctopus_instances", {}, len(instances))
    family("wgoctopus_peers", "gauge", "Peers per instance.")
    family("wgoctopus_peers_enabled", "gauge", "Enabled peers per instance.")
    for instance in instances:
        visible = or_(Peer.owner.is_(None), Peer.owner != "__probe__")
        for metric, query in (("wgoctopus_peers", select(func.count(Peer.id)).where(Peer.instance_id == instance.id, visible)),
                              ("wgoctopus_peers_enabled", select(func.count(Peer.id)).where(Peer.instance_id == instance.id, visible, Peer.enabled.is_(True)))):
            sample(metric, {"instance": instance.name}, session.scalar(query) or 0)
    family("wgoctopus_instance_active_node", "gauge", "Active node placement for an instance.")
    for instance in instances:
        active = active_placement(session, instance.id)
        node = session.get(Node, active.node_id) if active else None
        if node:
            sample("wgoctopus_instance_active_node", {"instance": instance.name, "node": node.name}, 1)
    family("wgoctopus_hop_route", "gauge", "Resolved routes configured on hop nodes.")
    links = session.scalars(select(HopLink).order_by(HopLink.hop_id, HopLink.instance_id)).all()
    for link in links:
        hop = session.get(Node, link.hop_id)
        instance = session.get(Instance, link.instance_id)
        active = active_placement(session, link.instance_id)
        backend = session.get(Node, active.node_id) if active else None
        if hop and instance and backend and backend.backend_ip:
            sample("wgoctopus_hop_route", {"hop": hop.name, "instance": instance.name, "port": instance.listen_port}, 1)
    family("wgoctopus_events_total", "counter", "Persisted event count by kind.")
    for kind, count in session.execute(select(Event.kind, func.count(Event.id)).group_by(Event.kind).order_by(Event.kind)):
        sample("wgoctopus_events_total", {"kind": kind}, count)
    if callable(status_fn):
        family("wgoctopus_reconcile_outcomes_total", "counter", "Reconcile outcomes since process start; resets on restart.")
        for outcome, count in sorted(reconciler.counters().items()) if hasattr(reconciler, "counters") else ():
            sample("wgoctopus_reconcile_outcomes_total", {"outcome": outcome}, count)
        family("wgoctopus_reconcile_last_duration_seconds", "gauge", "Duration of the last node push.")
        for node in nodes:
            status = statuses.get(node.id)
            if status and status.last_duration_seconds is not None:
                sample("wgoctopus_reconcile_last_duration_seconds", {"node": node.name}, status.last_duration_seconds)
    scrapes_fn = getattr(reconciler, "scrapes", None)
    scrapes = scrapes_fn() if callable(scrapes_fn) else {}
    families = (
        ("wgoctopus_node_scrape_success", "gauge", "Whether the latest node metrics scrape succeeded."),
        ("wgoctopus_node_scrape_timestamp_seconds", "gauge", "Timestamp of the latest node metrics scrape."),
        ("wgoctopus_interface_up", "gauge", "Whether the WireGuard interface is up."),
        ("wgoctopus_peer_last_handshake_timestamp_seconds", "gauge", "Peer's last handshake timestamp; zero means never."),
        ("wgoctopus_peer_handshake_age_seconds", "gauge", "Seconds since the peer's last handshake."),
        ("wgoctopus_peer_rx_bytes_total", "counter", "Peer received bytes."),
        ("wgoctopus_peer_tx_bytes_total", "counter", "Peer transmitted bytes."),
        ("wgoctopus_instance_peers_active", "gauge", "Peers with handshake age at most 180 seconds."),
        ("wgoctopus_unknown_peers", "gauge", "Scraped peers absent from the orchestrator database."),
    )
    for name, kind, help_text in families:
        family(name, kind, help_text)
    family("wgoctopus_probe_state", "gauge", "One-hot synthetic probe state.")
    family("wgoctopus_probe_handshake_age_seconds", "gauge", "Seconds since the synthetic probe handshake.")
    probe_status_fn = getattr(reconciler, "probe_statuses", None)
    probe_statuses = probe_status_fn() if callable(probe_status_fn) else {}
    for probe in session.scalars(select(Probe).order_by(Probe.id)):
        hop, instance, runner = session.get(Node, probe.hop_id), session.get(Instance, probe.instance_id), session.get(Node, probe.runner_node_id)
        labels = {"probe": probe_iface_name(probe.id), "hop": hop.name if hop else str(probe.hop_id),
                  "instance": instance.name if instance else str(probe.instance_id), "runner": runner.name if runner else str(probe.runner_node_id)}
        status = probe_statuses.get(probe.id)
        state = status.state.value if status else "UNKNOWN"
        for possible in ("UNKNOWN", "UP", "DOWN"):
            sample("wgoctopus_probe_state", {**labels, "state": possible}, int(state == possible))
        age = getattr(status, "age_seconds", None)
        if age is not None:
            sample("wgoctopus_probe_handshake_age_seconds", labels, age)
    current = (now or datetime.now(UTC)).timestamp() if isinstance(now, (datetime, type(None))) else float(now)
    for node in nodes:
        scrape = scrapes.get(node.id)
        if not scrape:
            continue
        labels = {"node": node.name}
        sample("wgoctopus_node_scrape_success", labels, int(scrape.ok))
        sample("wgoctopus_node_scrape_timestamp_seconds", labels, scrape.at.timestamp())
        known = {(instance_name, peer.public_key): peer.name for peer, instance_name in
                 session.execute(select(Peer, Instance.name).join(Instance).where(or_(Peer.owner.is_(None), Peer.owner != "__probe__")).order_by(Peer.id)).all()}
        probe_interfaces = {probe_iface_name(probe.id) for probe in session.scalars(select(Probe)).all()}
        unknown = {}
        for interface, state in sorted(scrape.interfaces.items()):
            sample("wgoctopus_interface_up", {"node": node.name, "instance": interface}, int(state["up"]))
        active_counts = {}
        for (interface, key), stat in sorted(scrape.peers.items()):
            if interface in probe_interfaces:
                continue
            peer_name = known.get((interface, key))
            if peer_name is None:
                unknown[interface] = unknown.get(interface, 0) + 1
                continue
            peer_labels = {"node": node.name, "instance": interface, "peer": peer_name}
            age = current - stat.handshake_ts if stat.handshake_ts > 0 else None
            sample("wgoctopus_peer_last_handshake_timestamp_seconds", peer_labels, stat.handshake_ts)
            if age is not None:
                sample("wgoctopus_peer_handshake_age_seconds", peer_labels, age)
                active_counts[interface] = active_counts.get(interface, 0) + int(age <= 180)
            sample("wgoctopus_peer_rx_bytes_total", peer_labels, stat.rx)
            sample("wgoctopus_peer_tx_bytes_total", peer_labels, stat.tx)
        for interface in sorted(set(scrape.interfaces) | set(active_counts) | set(unknown)):
            sample("wgoctopus_instance_peers_active", {"node": node.name, "instance": interface}, active_counts.get(interface, 0))
        for interface, count in sorted(unknown.items()):
            sample("wgoctopus_unknown_peers", {"node": node.name, "instance": interface}, count)
    return "\n".join(lines) + "\n"
