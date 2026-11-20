"""Memory-only periodic desired-state reconciliation."""

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sqlalchemy import select

from .models import Event, Node
from .push import PushOutcome, PushStatus, push_node

log = logging.getLogger(__name__)


class NodeState(StrEnum):
    IN_SYNC = "IN_SYNC"
    SYNCING = "SYNCING"
    UNREACHABLE = "UNREACHABLE"
    BLOCKED_DANGEROUS = "BLOCKED_DANGEROUS"
    BLOCKED_REVISION_AHEAD = "BLOCKED_REVISION_AHEAD"
    BLOCKED_INVALID = "BLOCKED_INVALID"
    BLOCKED_AUTH = "BLOCKED_AUTH"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


@dataclass
class NodeStatus:
    state: NodeState = NodeState.UNKNOWN
    last_attempt_at: datetime | None = None
    next_attempt_at: datetime | None = None
    consecutive_failures: int = 0
    last_outcome: PushOutcome | None = None
    last_error: str | None = None


class Reconciler:
    def __init__(self, session_factory, transport_factory, settings, *, clock=time.monotonic,
                 sleep=asyncio.sleep, random_fn=random.random, crypto=None):
        self.session_factory, self.transport_factory, self.settings = session_factory, transport_factory, settings
        self.clock, self.sleep, self.random_fn = clock, sleep, random_fn
        self.crypto = crypto
        self._status, self._next = {}, {}
        self._forced, self._kicks = set(), set()
        self._kick = asyncio.Event()

    def kick(self, node_id, force=False):
        self._kicks.add(node_id)
        if force:
            self._forced.add(node_id)
        self._kick.set()

    async def reconcile_once(self, node_ids=None):
        with self.session_factory() as session:
            query = select(Node.id)
            if node_ids is not None:
                query = query.where(Node.id.in_(node_ids))
            records = list(session.execute(select(Node.id, Node.enabled)))
        requested = set(node_ids) if node_ids is not None else {i for i, _ in records}
        for ident, enabled in records:
            if ident in requested and not enabled:
                self._status[ident] = NodeStatus(state=NodeState.DISABLED)
        ids = [ident for ident, enabled in records if enabled and ident in requested]
        semaphore = asyncio.Semaphore(self.settings.reconcile_concurrency)

        async def run(ident):
            if self.clock() < self._next.get(ident, float("-inf")) and ident not in self._forced:
                return ident, None
            self._forced.discard(ident)
            async with semaphore:
                return ident, await self._one(ident)

        pairs = await asyncio.gather(*(run(i) for i in ids))
        return {i: outcome for i, outcome in pairs if outcome is not None}

    async def _one(self, ident, allow_dangerous=False):
        previous = self._status.get(ident, NodeStatus())
        started = datetime.now().astimezone()
        try:
            with self.session_factory() as session:
                node = session.get(Node, ident)
                if node is None or not node.enabled:
                    return PushOutcome(PushStatus.SKIPPED_DISABLED)
                transport = self.transport_factory(node)
                outcome = await asyncio.wait_for(
                    push_node(session, ident, transport=transport, allow_dangerous=allow_dangerous,
                              crypto=self.crypto),
                    timeout=self.settings.reconcile_node_timeout)
                session.commit()
        except Exception as exc:  # noqa: BLE001 - one node must never stop the cycle
            log.warning("Reconcile failed for node %s (%s)", ident, type(exc).__name__)
            outcome = PushOutcome(PushStatus.FAILED, error="reconciliation failed")
            self._event(ident, "reconcile.error", {"error_kind": type(exc).__name__})

        states = {
            PushStatus.OK: NodeState.IN_SYNC, PushStatus.UP_TO_DATE: NodeState.IN_SYNC,
            PushStatus.SKIPPED_DISABLED: NodeState.DISABLED,
            PushStatus.BLOCKED_DANGEROUS: NodeState.BLOCKED_DANGEROUS,
            PushStatus.REVISION_AHEAD: NodeState.BLOCKED_REVISION_AHEAD,
            PushStatus.INVALID: NodeState.BLOCKED_INVALID, PushStatus.UNAUTHORIZED: NodeState.BLOCKED_AUTH,
            PushStatus.FAILED: NodeState.UNREACHABLE,
        }
        state = states[outcome.status]
        failures = previous.consecutive_failures
        if state == NodeState.UNREACHABLE:
            failures += 1
            base = min(5 * 2 ** (failures - 1), self.settings.reconcile_max_backoff)
            delay = min(base * (.8 + .4 * self.random_fn()), self.settings.reconcile_max_backoff)
            self._next[ident] = self.clock() + delay
            if previous.state not in {NodeState.UNREACHABLE, NodeState.UNKNOWN}:
                self._event(ident, "node.unreachable", {})
        elif state.name.startswith("BLOCKED_"):
            failures = 0
            self._next[ident] = self.clock() + self.settings.reconcile_blocked_recheck
            if state != previous.state:
                self._event(ident, "node.blocked", {"kind": state.value})
        else:
            self._next.pop(ident, None)
            if previous.state == NodeState.UNREACHABLE:
                self._event(ident, "node.recovered", {})
            elif previous.state not in {NodeState.UNKNOWN, NodeState.IN_SYNC}:
                self._event(ident, "node.in_sync", {})
            failures = 0
        self._status[ident] = NodeStatus(state, started, None, failures, outcome,
                                         outcome.error if outcome.error in {"unauthorized", "agent unreachable", "agent request timed out", "agent request failed"} else None)
        # Expose monotonic retry deadlines as UTC timestamps only where meaningful.
        return outcome

    def _event(self, ident, kind, data):
        with self.session_factory() as session:
            session.add(Event(kind=kind, subject=str(ident), data=data))
            session.commit()

    def status(self):
        result = dict(self._status)
        for ident, status in result.items():
            if ident in self._next:
                remaining = max(0, self._next[ident] - self.clock())
                from datetime import UTC, timedelta
                status.next_attempt_at = datetime.now(UTC) + timedelta(seconds=remaining)
        return result

    async def apply_dangerous(self, node_id):
        outcome = await self._one(node_id, allow_dangerous=True)
        self._event(node_id, "reconcile.dangerous_override", {})
        return outcome

    async def run(self, stop_event):
        while not stop_event.is_set():
            await self.reconcile_once()
            self._kick.clear()
            waiter = asyncio.create_task(self._kick.wait())
            stopper = asyncio.create_task(stop_event.wait())
            done, pending = await asyncio.wait((waiter, stopper), timeout=self.settings.reconcile_interval,
                                               return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if stopper in done:
                break
            if waiter in done:
                ids, self._kicks = self._kicks, set()
                await self.reconcile_once(ids)


def build_reconciler(settings, session_factory=None):
    if session_factory is None:
        from .db import make_engine, make_session_factory
        session_factory = make_session_factory(make_engine())
    from .transport import DirectHttpTransport, SshTunnelTransport
    transport_cls = DirectHttpTransport if settings.transport == "direct" else SshTunnelTransport
    return Reconciler(session_factory, lambda _node: transport_cls(settings), settings)
