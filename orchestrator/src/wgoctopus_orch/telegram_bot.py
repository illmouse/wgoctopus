"""Secure long-poll Telegram callback handler for failover decisions."""
# ruff: noqa: BLE001, S110

import asyncio
import logging
import re
import time

from .failover import FailoverError
from .models import AlertState

log = logging.getLogger(__name__)
_CALLBACK = re.compile(r"^fo:(c|r):(\d+)$")
_ANSWERS = {"not_pending": "Already decided", "expired": "Proposal expired", "stale": "Proposal is stale", "no_candidate": "No candidate", "not_found": "Proposal not found"}


class TelegramBot:
    def __init__(self, token, chat_id, api_base, client, engine, session_factory,
                 allowed_user_ids, poll_timeout=25, clock=time.monotonic):
        self._token, self.chat_id = token, str(chat_id)
        self.api_base, self.client, self.engine = api_base.rstrip("/"), client, engine
        self.session_factory, self.allowed_user_ids = session_factory, set(allowed_user_ids)
        self.poll_timeout, self.clock = poll_timeout, clock
        with session_factory() as session:
            state = session.get(AlertState, "telegram_update_offset")
            self.offset = int(state.value) if state else 0
        self.results = {key: 0 for key in ("ok", "denied", "invalid", "rejected_by_engine", "error")}

    async def _request(self, method, payload):
        response = await self.client.post(f"{self.api_base}/bot{self._token}/{method}", json=payload)
        response.raise_for_status()
        if response.json().get("ok") is not True:
            raise RuntimeError("Telegram API rejected request")
        return response.json().get("result")

    async def poll_once(self):
        updates = await self._request("getUpdates", {"offset": self.offset, "timeout": self.poll_timeout, "allowed_updates": ["callback_query"]})
        for update in updates or []:
            try:
                await self.handle_callback(update)
            finally:
                self.offset = max(self.offset, int(update.get("update_id", -1)) + 1)
                with self.session_factory() as session:
                    state = session.get(AlertState, "telegram_update_offset")
                    if state is None:
                        session.add(AlertState(key="telegram_update_offset", value=str(self.offset)))
                    else:
                        state.value = str(self.offset)
                    session.commit()

    async def handle_callback(self, update):
        query = update.get("callback_query") or {}
        callback_id = query.get("id")
        data = query.get("data", "")
        message = query.get("message") or {}
        user = query.get("from") or {}
        match = _CALLBACK.fullmatch(data) if isinstance(data, str) else None
        if not match:
            self.results["invalid"] += 1
            await self._answer(callback_id, "Invalid action")
            return
        if user.get("id") not in self.allowed_user_ids or str((message.get("chat") or {}).get("id")) != self.chat_id:
            self.results["denied"] += 1
            await self._answer(callback_id, "Not allowed")
            return
        try:
            action = "confirm" if match.group(1) == "c" else "reject"
            await asyncio.to_thread(getattr(self.engine, action), int(match.group(2)), by="telegram")
            result, answer = "ok", "Confirmed" if action == "confirm" else "Rejected"
        except FailoverError as exc:
            result, answer = "rejected_by_engine", _ANSWERS.get(exc.code, "Could not decide")
        except Exception as exc:
            result, answer = "error", "Could not process action"
            log.warning("Telegram callback failed (%s)", type(exc).__name__)
        self.results[result] += 1
        await self._answer(callback_id, answer)
        if message.get("message_id") is not None:
            try:
                await self._request("editMessageReplyMarkup", {"chat_id": self.chat_id, "message_id": message["message_id"], "reply_markup": {"inline_keyboard": []}})
            except Exception:
                pass

    async def _answer(self, callback_id, text):
        if callback_id is not None:
            try:
                await self._request("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})
            except Exception:
                pass

    async def run(self):
        backoff = 2
        while True:
            try:
                await self.poll_once()
                backoff = 2
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("Telegram polling failed (%s)", type(exc).__name__)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
