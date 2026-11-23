"""Single-node, one-shot desired-state delivery (retry belongs to reconciliation)."""

from dataclasses import dataclass
from enum import StrEnum

import httpx

from .agent_client import AgentClient, ErrorKind
from .crypto import Crypto
from .models import Event, Node, NodeObserved, now_utc
from .renderer import render_node_state


class PushStatus(StrEnum):
    OK = "ok"
    UP_TO_DATE = "up_to_date"
    SKIPPED_DISABLED = "skipped_disabled"
    REVISION_AHEAD = "revision_ahead"
    BLOCKED_DANGEROUS = "blocked_dangerous"
    UNAUTHORIZED = "unauthorized"
    INVALID = "invalid"
    FAILED = "failed"


@dataclass
class PushOutcome:
    status: PushStatus
    revision: int | None = None
    reasons: list[str] | None = None
    error: str | None = None


async def push_node(session, node_id, *, transport, allow_dangerous=False, crypto=None):
    crypto = crypto or Crypto()
    node = session.get(Node, node_id)
    if node is None:
        raise ValueError(f"unknown node {node_id}")
    if not node.enabled:
        return PushOutcome(PushStatus.SKIPPED_DISABLED)
    desired = render_node_state(session, node_id, crypto)
    desired_revision = desired["revision"]
    observed = session.get(NodeObserved, node_id)
    async with transport.open(node) as connection:
        client = AgentClient(connection)
        try:
            remote_revision, remote_checksum, _ = await client.get_state()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                outcome = PushOutcome(PushStatus.UNAUTHORIZED, desired_revision, error="unauthorized")
                _record(session, node, observed, "push.failed", {"error_kind": ErrorKind.UNAUTHORIZED.value}, error=outcome.error)
                return outcome
            outcome = PushOutcome(PushStatus.FAILED, desired_revision, error="agent request failed")
            _record(session, node, observed, "push.failed", {"error_kind": ErrorKind.OTHER.value}, error=outcome.error)
            return outcome
        except httpx.RequestError:
            outcome = PushOutcome(PushStatus.FAILED, desired_revision, error="agent unreachable")
            _record(session, node, observed, "push.failed", {"error_kind": "unreachable"},
                    error=outcome.error, healthy=False)
            return outcome
        if remote_revision > desired_revision:
            return PushOutcome(PushStatus.REVISION_AHEAD, desired_revision)
        if remote_revision == desired_revision and not (observed and observed.applied_revision == desired_revision):
            if observed is None:
                observed = NodeObserved(node_id=node.id)
                session.add(observed)
            _record(session, node, observed, "push.ok", {"revision": desired_revision, "adopted": True},
                    healthy=True, applied_revision=remote_revision, applied_checksum=remote_checksum)
            return PushOutcome(PushStatus.OK, desired_revision)
        if remote_revision == desired_revision and observed and observed.applied_revision == desired_revision:
            if remote_checksum == observed.applied_checksum:
                return PushOutcome(PushStatus.UP_TO_DATE, desired_revision)
            # Agent checksums are authoritative and may not be reproducible by
            # the orchestrator. Same-revision drift cannot safely be PUT again:
            # agents reject it as stale, so report it rather than auto-correct.
            _record(session, node, observed, "node.drift", {"revision": desired_revision})
            return PushOutcome(PushStatus.UP_TO_DATE, desired_revision, error="remote state drift")
        result = await client.put_state(desired, allow_dangerous=allow_dangerous)
        if result.ok:
            try:
                applied_revision, checksum, _ = await client.get_state()
            except (httpx.RequestError, httpx.HTTPStatusError):
                applied_revision, checksum = desired_revision, None
            _record(session, node, observed, "push.ok", {"revision": desired_revision},
                    healthy=True, applied_revision=applied_revision, applied_checksum=checksum)
            return PushOutcome(PushStatus.OK, desired_revision)
        status = {
            ErrorKind.DANGEROUS: PushStatus.BLOCKED_DANGEROUS,
            ErrorKind.UNAUTHORIZED: PushStatus.UNAUTHORIZED,
            ErrorKind.INVALID: PushStatus.INVALID,
        }.get(result.error_kind, PushStatus.FAILED)
        healthy = False if result.error_kind in {ErrorKind.UNREACHABLE, ErrorKind.TIMEOUT} else None
        message = result.message or "agent request failed"
        _record(session, node, observed, "push.failed", {"error_kind": result.error_kind.value},
                error=message, healthy=healthy)
        return PushOutcome(status, desired_revision, result.reasons, message)


def _record(session, node, observed, kind, data, *, error=None, healthy=None,
            applied_revision=None, applied_checksum=None):
    if observed:
        observed.last_seen_at = now_utc()
        observed.last_error = error
        if healthy is not None:
            observed.healthy = healthy
        if applied_revision is not None:
            observed.applied_revision, observed.applied_checksum = applied_revision, applied_checksum
    session.add(Event(kind=kind, subject=str(node.id), data=data))
    session.flush()
