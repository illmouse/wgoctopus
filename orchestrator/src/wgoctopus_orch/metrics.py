"""Prometheus 0.0.4 text exposition for orchestrator state."""

from datetime import UTC

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Event, HopLink, Instance, Node, NodeObserved, NodeRevision, Peer
from .reconciler import NodeState
from .renderer import active_placement


def escape_label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_metrics(session: Session, reconciler=None, version="0.1.0") -> str:
    lines = []

    def sample(name, labels, value):
        label_text = ",".join(f'{key}="{escape_label(val)}"' for key, val in labels.items())
        lines.append(f"{name}{{{label_text}}} {value}" if labels else f"{name} {value}")

    def family(name, kind, help_text):
        lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"))

    family("wgoctopus_build_info", "gauge", "Orchestrator build information.")
    sample("wgoctopus_build_info", {"version": version}, 1)
    nodes = session.scalars(select(Node).order_by(Node.name)).all()
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
    statuses = reconciler.status() if reconciler else {}
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
        for metric, query in (("wgoctopus_peers", select(func.count(Peer.id)).where(Peer.instance_id == instance.id)),
                              ("wgoctopus_peers_enabled", select(func.count(Peer.id)).where(Peer.instance_id == instance.id, Peer.enabled.is_(True)))):
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
            sample("wgoctopus_hop_route", {"hop": hop.name, "instance": instance.name, "backend_ip": backend.backend_ip, "port": instance.listen_port}, 1)
    family("wgoctopus_events_total", "counter", "Persisted event count by kind.")
    for kind, count in session.execute(select(Event.kind, func.count(Event.id)).group_by(Event.kind).order_by(Event.kind)):
        sample("wgoctopus_events_total", {"kind": kind}, count)
    if reconciler:
        family("wgoctopus_reconcile_outcomes_total", "counter", "Reconcile outcomes since process start; resets on restart.")
        for outcome, count in sorted(reconciler.counters().items()) if hasattr(reconciler, "counters") else ():
            sample("wgoctopus_reconcile_outcomes_total", {"outcome": outcome}, count)
        family("wgoctopus_reconcile_last_duration_seconds", "gauge", "Duration of the last node push.")
        for node in nodes:
            status = statuses.get(node.id)
            if status and status.last_duration_seconds is not None:
                sample("wgoctopus_reconcile_last_duration_seconds", {"node": node.name}, status.last_duration_seconds)
    return "\n".join(lines) + "\n"
