"""Probe-driven failover proposal evaluation and lifecycle."""

import time
from datetime import UTC, datetime

from sqlalchemy import select

from .models import Event, FailoverProposal, HopLink, Instance, Node, Placement, Probe
from .renderer import active_placement
from .service import switch_active


def build_failover(session_factory, reconciler, settings, on_executed=None):
    return FailoverEngine(session_factory, reconciler, settings, on_executed=on_executed)


class FailoverError(Exception):
    def __init__(self, code, message=None):
        self.code = code
        super().__init__(message or code)


def pick_candidate(session, instance_id, from_node_id, statuses, scrapes):
    """Pick the highest-weight healthy AWG standby; probe runners may be active."""
    choices = []
    for placement in session.scalars(select(Placement).where(
            Placement.instance_id == instance_id, Placement.role != "active")).all():
        node = session.get(Node, placement.node_id)
        scrape = scrapes.get(placement.node_id)
        state = statuses.get(placement.node_id)
        if (node and node.kind == "awg" and node.enabled and state and
                _status_value(state) == "IN_SYNC" and scrape and scrape.ok and
                (interface := scrape.interfaces.get(session.get(Instance, instance_id).name)) and
                interface.get("up", False)):
            choices.append((placement.weight, placement.node_id))
    return min(choices, key=lambda item: (-item[0], item[1]))[1] if choices else None


class FailoverEngine:
    def __init__(self, session_factory, reconciler, settings, clock=time.time, on_executed=None):
        self.session_factory, self.reconciler, self.settings = session_factory, reconciler, settings
        self.clock, self.on_executed = clock, on_executed
        self._down_since, self._no_candidate = {}, set()

    def _healthy_candidate(self, session, instance_id, from_node_id):
        return pick_candidate(session, instance_id, from_node_id, self.reconciler.status(), self.reconciler.scrapes())

    def evaluate_once(self):
        if self.settings.failover_mode == "off":
            return
        now = self.clock()
        statuses, probe_statuses = self.reconciler.status(), self.reconciler.probe_statuses()
        scrapes = self.reconciler.scrapes()
        with self.session_factory() as session:
            self._expire_or_cancel_pending(session, now, probe_statuses, statuses, scrapes)
            self._auto_confirm(session)
            self._scan_links(session, now, probe_statuses, statuses, scrapes)
            session.commit()

    def _expire_or_cancel_pending(self, session, now, probe_statuses, statuses, scrapes):
        pending = session.scalars(select(FailoverProposal).where(FailoverProposal.state == "pending")).all()
        for proposal in pending:
            if proposal.expires_at.timestamp() <= now:
                proposal.state, proposal.decided_at, proposal.decided_by = "expired", _dt(now), "system"
                session.add(Event(kind="failover.expired", subject=str(proposal.id), data={"proposal_id": proposal.id}))
            elif not self._condition(session, proposal.instance_id, proposal.hop_id, proposal.from_node_id,
                                     probe_statuses, statuses, scrapes):
                proposal.state, proposal.decided_at, proposal.decided_by = "cancelled", _dt(now), "system"
                session.add(Event(kind="failover.cancelled", subject=str(proposal.id), data={"proposal_id": proposal.id, "reason": "condition_cleared"}))

    def _auto_confirm(self, session):
        if self.settings.failover_mode != "auto":
            return
        session.commit()
        auto_ids = [p.id for p in session.scalars(select(FailoverProposal).where(FailoverProposal.state == "pending")).all()]
        for proposal_id in auto_ids:
            try:
                self.confirm(proposal_id, by="auto")
            except FailoverError:
                pass

    def _scan_links(self, session, now, probe_statuses, statuses, scrapes):
        existing_instances = {p.instance_id for p in session.scalars(select(FailoverProposal).where(
            FailoverProposal.state == "pending")).all()}
        for link in session.scalars(select(HopLink)).all():
            active = active_placement(session, link.instance_id)
            if active is None or link.instance_id in existing_instances:
                continue
            probes = session.scalars(select(Probe).where(Probe.hop_id == link.hop_id,
                                                         Probe.instance_id == link.instance_id)).all()
            if not probes:
                continue
            key_probes = [p for p in probes if p.id in probe_statuses]
            if not key_probes:
                continue
            hop_status = statuses.get(link.hop_id)
            if not hop_status or _status_value(hop_status) != "IN_SYNC":
                continue
            for probe in key_probes:
                if not self._probe_is_failing(probe, probe_statuses, statuses):
                    continue
                key = probe.id
                started = self._down_since.setdefault(key, now)
                if now - started < self.settings.failover_down_seconds:
                    continue
                if self._all_probes_down(probes, probe_statuses):
                    continue
                if self._in_cooldown(session, link.instance_id, now):
                    continue
                candidate = pick_candidate(session, link.instance_id, active.node_id, statuses, scrapes)
                if candidate is None:
                    if key not in self._no_candidate:
                        session.add(Event(kind="failover.no_candidate", subject=str(link.instance_id),
                                          data={"instance_id": link.instance_id, "from_node_id": active.node_id}))
                        self._no_candidate.add(key)
                    continue
                proposal = self._create_proposal(session, link, active.node_id, candidate, now)
                existing_instances.add(link.instance_id)
                if self.settings.failover_mode == "auto":
                    session.commit()
                    self.confirm(proposal.id, by="auto")
                break

    def _probe_is_failing(self, probe, probe_statuses, statuses):
        state = _status_value(probe_statuses[probe.id])
        if state == "UP":
            self._down_since.pop(probe.id, None)
            self._no_candidate.discard(probe.id)
            return False
        if state != "DOWN":
            return False
        runner_state = statuses.get(probe.runner_node_id)
        return bool(runner_state and _status_value(runner_state) == "IN_SYNC")

    @staticmethod
    def _all_probes_down(probes, probe_statuses):
        return len(probes) > 1 and all(
            p.id in probe_statuses and _status_value(probe_statuses[p.id]) == "DOWN" for p in probes)

    def _in_cooldown(self, session, instance_id, now):
        last = session.scalar(select(FailoverProposal).where(
            FailoverProposal.instance_id == instance_id, FailoverProposal.state == "executed"
        ).order_by(FailoverProposal.decided_at.desc()))
        return bool(last and now - last.decided_at.timestamp() < self.settings.failover_cooldown_seconds)

    def _create_proposal(self, session, link, from_node_id, candidate, now):
        proposal = FailoverProposal(instance_id=link.instance_id, hop_id=link.hop_id,
            from_node_id=from_node_id, to_node_id=candidate, state="pending",
            mode_at_creation=self.settings.failover_mode, reason="probe_down",
            created_at=_dt(now), expires_at=_dt(now + self.settings.failover_proposal_ttl_seconds))
        session.add(proposal)
        session.flush()
        session.add(Event(kind="failover.proposed", subject=str(proposal.id), data={"proposal_id": proposal.id,
            "instance_id": link.instance_id, "from_node_id": from_node_id, "to_node_id": candidate,
            "mode": self.settings.failover_mode, "expires_at": proposal.expires_at.isoformat()}))
        return proposal

    def _condition(self, session, instance_id, hop_id, from_node_id, probes, statuses, scrapes):
        active = active_placement(session, instance_id)
        if active is None or active.node_id != from_node_id:
            return False
        ids = session.scalars(select(Probe.id).where(Probe.instance_id == instance_id, Probe.hop_id == hop_id)).all()
        if not any(i in probes and _status_value(probes[i]) == "DOWN" for i in ids):
            return False
        return self._healthy_candidate(session, instance_id, from_node_id) is not None

    def confirm(self, proposal_id, *, by, actor=None):
        with self.session_factory() as session:
            proposal = session.get(FailoverProposal, proposal_id)
            if proposal is None:
                raise FailoverError("not_found")
            if proposal.state != "pending":
                raise FailoverError("not_pending")
            now = self.clock()
            if proposal.expires_at.timestamp() <= now:
                proposal.state, proposal.decided_at, proposal.decided_by = "expired", _dt(now), "system"
                session.add(Event(kind="failover.expired", subject=str(proposal.id), data={"proposal_id": proposal.id}))
                session.commit()
                raise FailoverError("expired")
            active = active_placement(session, proposal.instance_id)
            if active is None or active.node_id != proposal.from_node_id:
                proposal.state, proposal.decided_at, proposal.decided_by = "failed", _dt(now), by
                proposal.error = "active placement changed"
                session.commit()
                raise FailoverError("stale")
            if self._healthy_candidate(session, proposal.instance_id, proposal.from_node_id) != proposal.to_node_id:
                proposal.state, proposal.decided_at, proposal.decided_by = "failed", _dt(now), by
                proposal.error = "candidate is no longer healthy"
                session.commit()
                raise FailoverError("no_candidate")
            try:
                with session.begin_nested():
                    switch_active(session, proposal.instance_id, proposal.to_node_id,
                                  crypto=getattr(self.reconciler, "crypto", None))
                    proposal.state, proposal.decided_at, proposal.decided_by = "executed", _dt(now), by
                    data = {"proposal_id": proposal.id,
                        "instance_id": proposal.instance_id, "from": proposal.from_node_id,
                        "to": proposal.to_node_id, "by": by}
                    if actor is not None: data["actor"] = actor
                    session.add(Event(kind="failover.executed", subject=str(proposal.id), data=data))
                session.commit()
            except Exception:
                session.rollback()
                proposal = session.get(FailoverProposal, proposal_id)
                proposal.state, proposal.decided_at, proposal.decided_by = "failed", _dt(now), by
                proposal.error = "switch_active failed"
                session.add(Event(kind="failover.failed", subject=str(proposal.id), data={"proposal_id": proposal.id}))
                session.commit()
                raise
        if self.on_executed:
            self.on_executed(proposal.instance_id, proposal.to_node_id)
        return proposal

    def reject(self, proposal_id, *, by, actor=None):
        with self.session_factory() as session:
            proposal = session.get(FailoverProposal, proposal_id)
            if proposal is None:
                raise FailoverError("not_found")
            if proposal.state != "pending":
                raise FailoverError("not_pending")
            proposal.state, proposal.decided_at, proposal.decided_by = "rejected", _dt(self.clock()), by
            data = {"proposal_id": proposal.id, "by": by}
            if actor is not None: data["actor"] = actor
            session.add(Event(kind="failover.rejected", subject=str(proposal.id), data=data))
            session.commit()
            return proposal


def _dt(timestamp):
    return datetime.fromtimestamp(timestamp, UTC)


def _status_value(obj):
    state = getattr(obj, "state", obj)
    return str(getattr(state, "value", state))
