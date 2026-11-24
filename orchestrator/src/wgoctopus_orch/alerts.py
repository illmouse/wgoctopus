"""Transport-independent event notification dispatcher."""

import asyncio
import logging
import time
from collections import deque
from datetime import UTC
from typing import Protocol

import httpx
from sqlalchemy import func, select

from .models import AlertState, Event, Instance, Node, Probe

log = logging.getLogger(__name__)


class NotifyError(Exception):
    """A notification could not be delivered."""

    def __init__(self, message: str, *, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, *, api_base: str = "https://api.telegram.org", timeout: float = 10, client=None):
        self._token, self.chat_id = token, chat_id
        self.chat_ids = [value.strip() for value in chat_id.split(",")]
        self.api_base, self.timeout, self.client = api_base.rstrip("/"), timeout, client

    def __repr__(self):
        return f"TelegramNotifier(chat_id={self.chat_id!r})"

    __str__ = __repr__

    async def send(self, text: str, *, buttons: list[list[tuple[str, str]]] | None = None) -> None:
        url = f"{self.api_base}/bot{self._token}/sendMessage"
        payload = {"text": text[:4000], "disable_web_page_preview": True}
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": [[{"text": label, "callback_data": data} for label, data in row] for row in buttons]}
        failures = []
        for chat_id in self.chat_ids:
            try:
                request_payload = {**payload, "chat_id": chat_id}
                if self.client is None:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        response = await client.post(url, json=request_payload)
                else:
                    response = await self.client.post(url, json=request_payload)
                if response.status_code == 429:
                    retry_after = response.json().get("parameters", {}).get("retry_after")
                    raise NotifyError("Telegram rate limit exceeded", retry_after=float(retry_after) if retry_after is not None else None)
                if response.status_code >= 400:
                    raise NotifyError("Telegram request failed")
                if response.json().get("ok") is not True:
                    raise NotifyError("Telegram rejected the message")
            except httpx.TimeoutException:
                failures.append(NotifyError("Telegram request timed out"))
            except httpx.HTTPError:
                failures.append(NotifyError("Telegram network error"))
            except (ValueError, AttributeError):
                failures.append(NotifyError("Telegram returned an invalid response"))
            except NotifyError as exc:
                failures.append(exc)
        if len(failures) == len(self.chat_ids):
            raise failures[0]


class Notifier(Protocol):
    async def send(self, text: str, *, buttons: list[list[tuple[str, str]]] | None = None) -> None: ...


RULES = {
    "node.unreachable": ("CRITICAL", "Node unreachable"), "node.recovered": ("INFO", "Node recovered"),
    "node.blocked": ("CRITICAL", "Node blocked"), "node.drift": ("WARNING", "Node drift"),
    "probe.down": ("CRITICAL", "Probe down"), "probe.up": ("INFO", "Probe up"),
    "instance.switched": ("WARNING", "Instance switched"), "reconcile.error": ("WARNING", "Reconcile error"),
    "failover.proposed": ("CRITICAL", "Failover proposed"), "failover.executed": ("WARNING", "Failover executed"),
    "failover.no_candidate": ("CRITICAL", "Failover has no candidate"), "failover.failed": ("CRITICAL", "Failover failed"),
    "failover.expired": ("WARNING", "Failover expired"), "failover.cancelled": ("INFO", "Failover cancelled"),
    "failover.rejected": ("INFO", "Failover rejected"),
}
DOWN = {"node.unreachable": "node.recovered", "probe.down": "probe.up"}


class AlertDispatcher:
    def __init__(self, session_factory, notifier, *, delay_seconds=60, max_per_minute=20,
                 poll_seconds=5, kinds=None, clock=time.monotonic, buttons_enabled=False):
        self.session_factory, self.notifier = session_factory, notifier
        self.delay_seconds, self.max_per_minute = delay_seconds, max_per_minute
        self.poll_seconds, self.kinds, self.clock = poll_seconds, kinds, clock
        self.buttons_enabled = buttons_enabled
        self._retry_at, self._failures = 0.0, 0
        self._sent_times, self._overflow = deque(), []
        self._overflow_since = None
        self._pending = 0
        self._down_since = {}
        self._counts = {"sent": 0, "failed": 0, "dropped": 0, "pending": 0}

    def counters(self):
        return {**self._counts, "pending": self._pending}

    async def send_test(self):
        try:
            await self.notifier.send("wgoctopus alert test")
        except Exception as exc:
            raise NotifyError("notification failed") from exc

    def _label(self, session, event):
        data = event.data or {}
        subject = event.subject
        if event.kind.startswith("node."):
            node = session.get(Node, int(subject)) if subject.isdigit() else None
            subject = node.name if node else subject
        elif event.kind.startswith("probe."):
            probe = session.get(Probe, int(subject)) if subject.isdigit() else None
            if probe:
                hop = session.get(Node, probe.hop_id)
                instance = session.get(Instance, probe.instance_id)
                subject = f"{hop.name if hop else probe.hop_id} / {instance.name if instance else probe.instance_id}"
        elif event.kind == "instance.switched":
            instance = session.get(Instance, int(subject)) if subject.isdigit() else None
            subject = instance.name if instance else subject
        detail = ""
        if event.kind.startswith("failover.") and data.get("proposal_id"):
            from .models import FailoverProposal
            proposal = session.get(FailoverProposal, data["proposal_id"])
            if proposal:
                instance = session.get(Instance, proposal.instance_id)
                before, after = session.get(Node, proposal.from_node_id), session.get(Node, proposal.to_node_id)
                subject = instance.name if instance else str(proposal.instance_id)
                if event.kind == "failover.proposed":
                    detail = f" #{proposal.id}: {before.name if before else proposal.from_node_id} to {after.name if after else proposal.to_node_id}; expires {proposal.expires_at.isoformat()}"
                    if proposal.mode_at_creation == "confirm":
                        detail += f"; confirm via API: POST /v1/failovers/{proposal.id}/confirm"
                    if self.buttons_enabled:
                        detail += "; confirm or reject using the buttons below"
        if event.kind == "node.blocked" and isinstance(data.get("kind"), str):
            detail = f" ({data['kind']})"
        elif event.kind == "instance.switched":
            before, after = data.get("from"), data.get("to")
            if isinstance(before, str) and isinstance(after, str):
                detail = f" {before} to {after}"
        return subject, detail

    async def _deliver(self, text, buttons=None):
        try:
            if buttons:
                await self.notifier.send(text, buttons=buttons)
            else:
                await self.notifier.send(text)
        except NotifyError:
            self._counts["failed"] += 1
            self._failures += 1
            self._retry_at = self.clock() + min(5 * 2 ** (self._failures - 1), 300)
            log.warning("Alert delivery failed; retry scheduled")
            return False
        self._failures, self._retry_at = 0, 0
        self._counts["sent"] += 1
        self._sent_times.append(self.clock())
        return True

    async def poll_once(self):
        with self.session_factory() as session:
            state = session.get(AlertState, "last_event_id")
            if state is None:
                last = session.scalar(select(func.max(Event.id))) or 0
                session.add(AlertState(key="last_event_id", value=str(last)))
                session.commit()
                return
            cursor = int(state.value)
            events = session.scalars(select(Event).where(Event.id > cursor).order_by(Event.id)).all()
            self._pending = len(events)
            now = self.clock()
            while self._sent_times and now - self._sent_times[0] >= 60:
                self._sent_times.popleft()
            active = RULES.keys() if self.kinds is None else self.kinds
            recovered_ids = set()
            for index, event in enumerate(events):
                if event.id in recovered_ids:
                    continue
                if now < self._retry_at:
                    break
                if event.kind not in active:
                    state.value = str(event.id)
                    self._pending -= 1
                    session.commit()
                    continue
                if event.kind in DOWN:
                    recovery = next((e for e in events[index + 1:] if e.kind == DOWN[event.kind]
                                     and e.subject == event.subject
                                     and (e.ts - event.ts).total_seconds() <= self.delay_seconds), None)
                    if recovery:
                        for dropped in (event, recovery):
                            state.value = str(dropped.id)
                            self._counts["dropped"] += 1
                            self._pending -= 1
                            session.commit()
                        recovered_ids.add(recovery.id)
                        continue
                    key = (event.kind, event.subject)
                    started = self._down_since.setdefault(key, now)
                    if now - started < self.delay_seconds:
                        for later in events[index + 1:]:
                            if later.kind in DOWN:
                                self._down_since.setdefault((later.kind, later.subject), now)
                        break
                    self._down_since.pop(key, None)
                if len(self._sent_times) >= self.max_per_minute:
                    if not self._overflow:
                        self._overflow_since = now
                    self._overflow.append(event.kind)
                    state.value = str(event.id)
                    self._counts["dropped"] += 1
                    self._pending -= 1
                    session.commit()
                    continue
                severity, title = RULES[event.kind]
                name, detail = self._label(session, event)
                ts = event.ts.replace(tzinfo=UTC) if event.ts.tzinfo is None else event.ts.astimezone(UTC)
                text = f"[{severity}] {title}: {name}{detail}\n{ts:%Y-%m-%d %H:%M:%S} UTC"
                buttons = [[("Confirm", f"fo:c:{event.data['proposal_id']}"), ("Reject", f"fo:r:{event.data['proposal_id']}")]] if self.buttons_enabled and event.kind == "failover.proposed" and (event.data or {}).get("proposal_id") else None
                if not await self._deliver(text, buttons):
                    break
                state.value = str(event.id)
                self._pending -= 1
                session.commit()
            if self._overflow and now - self._overflow_since >= 60:
                kinds = ", ".join(sorted(set(self._overflow)))
                if await self._deliver(f"{len(self._overflow)} more alerts suppressed (kinds: {kinds})"):
                    self._overflow.clear()
                    self._overflow_since = None

    async def run(self, stop: asyncio.Event):
        while not stop.is_set():
            await self.poll_once()
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.poll_seconds)
            except TimeoutError:
                pass
