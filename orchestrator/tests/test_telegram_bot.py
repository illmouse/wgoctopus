import asyncio
import json
import logging
from datetime import UTC, datetime
from unittest.mock import Mock

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_api_failover import _add_proposal
from test_api_failover import _setup as failover_setup

from wgoctopus_orch.alerts import AlertDispatcher, TelegramNotifier
from wgoctopus_orch.api import create_app
from wgoctopus_orch.config import Settings
from wgoctopus_orch.failover import FailoverEngine, FailoverError
from wgoctopus_orch.models import AlertState, Event, FailoverProposal
from wgoctopus_orch.renderer import active_placement
from wgoctopus_orch.telegram_bot import TelegramBot

TOKEN = "123:FAKETOKEN"
CHAT = "-100123"


class TelegramHarness:
    def __init__(self, responses=None):
        self.requests = []
        self.responses = list(responses or [])

    async def __call__(self, request):
        payload = json.loads(request.content or b"{}")
        self.requests.append((request.url.path.rsplit("/", 1)[-1], payload, str(request.url)))
        method = self.requests[-1][0]
        response = self.responses.pop(0) if self.responses else {"ok": True, "result": [] if method == "getUpdates" else True}
        if isinstance(response, Exception):
            raise response
        return httpx.Response(200, json=response)


def bot_for(session, engine, handler, *, allowed=(7,), chat=CHAT):
    return TelegramBot(TOKEN, chat, "https://api.telegram.org", httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                       engine, lambda: __import__("sqlalchemy.orm", fromlist=["sessionmaker"]).sessionmaker(bind=session.get_bind(), expire_on_commit=False)(), allowed)


def update(data="fo:c:1", user=7, chat=CHAT, ident=1):
    query = {"id": "cb1", "from": {"id": user}}
    if data is not ...:
        query["data"] = data
    if chat is not ...:
        query["message"] = {"chat": {"id": chat}, "message_id": 42}
    return {"update_id": ident, "callback_query": query}


class SpyEngine:
    def __init__(self):
        self.confirm, self.reject = Mock(), Mock()


@pytest.mark.asyncio
async def test_allowed_confirm_and_reject_are_acknowledged(session):
    harness = TelegramHarness()
    engine = SpyEngine()
    bot = bot_for(session, engine, harness)
    await bot.handle_callback(update())
    await bot.handle_callback(update("fo:r:2", ident=2))
    assert engine.confirm.call_args == ((1,), {"by": "telegram"})
    assert engine.reject.call_args == ((2,), {"by": "telegram"})
    assert [r[0] for r in harness.requests] == ["answerCallbackQuery", "editMessageReplyMarkup"] * 2
    assert harness.requests[0][1]["text"] == "Confirmed"
    assert harness.requests[1][1]["reply_markup"] == {"inline_keyboard": []}
    assert bot.results["ok"] == 2
    await bot.client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [update(user=99), update(chat="-100999")])
async def test_denied_callbacks_do_not_call_engine_or_edit(session, payload):
    harness, engine = TelegramHarness(), SpyEngine()
    bot = bot_for(session, engine, harness)
    await bot.handle_callback(payload)
    assert not engine.confirm.called and not engine.reject.called
    assert [(m, p.get("text")) for m, p, _ in harness.requests] == [("answerCallbackQuery", "Not allowed")]
    assert bot.results["denied"] == 1
    await bot.client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("data", ["fo:x:1", "fo:c:abc", "fo:c:1;drop", 3, None, ...])
async def test_invalid_callbacks_do_not_call_engine(session, data):
    harness, engine = TelegramHarness(), SpyEngine()
    bot = bot_for(session, engine, harness)
    await bot.handle_callback(update(data=data))
    assert not engine.confirm.called and not engine.reject.called
    assert harness.requests[0][1]["text"] == "Invalid action"
    assert len(harness.requests) == 1 and bot.results["invalid"] == 1
    await bot.client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("code,answer", [("not_pending", "Already decided"), ("expired", "Proposal expired"),
    ("stale", "Proposal is stale"), ("no_candidate", "No candidate"), ("not_found", "Proposal not found")])
async def test_engine_errors_are_reported_as_rejections(session, code, answer):
    class Broken:
        def confirm(self, *_args, **_kwargs):
            raise FailoverError(code, code)
    harness, bot = TelegramHarness(), bot_for(session, Broken(), TelegramHarness())
    bot.client = httpx.AsyncClient(transport=httpx.MockTransport(harness))
    await bot.handle_callback(update())
    assert harness.requests[0][1]["text"] == answer
    assert bot.results["rejected_by_engine"] == 1
    await bot.client.aclose()


@pytest.mark.asyncio
async def test_unexpected_engine_failure_is_sanitized(session, caplog):
    class Broken:
        def confirm(self, *_args, **_kwargs):
            raise RuntimeError("SECRET-EXCEPTION")
    harness = TelegramHarness()
    bot = bot_for(session, Broken(), harness)
    with caplog.at_level(logging.WARNING):
        await bot.handle_callback(update())
    assert bot.results["error"] == 1
    assert harness.requests[0][1]["text"] == "Could not process action"
    assert "SECRET-EXCEPTION" not in caplog.text
    await bot.client.aclose()


@pytest.mark.asyncio
async def test_double_confirm_is_not_pending(session, fake_agent_factory, crypto, monkeypatch):
    client, sessions, _, active, _, hop, instance, standby, _ = await failover_setup(session, fake_agent_factory, crypto, monkeypatch)
    ident = _add_proposal(sessions, active, hop, instance, standby)
    engine = FailoverEngine(sessions, client.app.state.reconciler, Settings(), clock=lambda: datetime.now(UTC).timestamp())
    # A missing reconciler health sample is irrelevant after the first successful switch; exercise engine idempotency.
    harness = TelegramHarness()
    bot = bot_for(session, engine, harness)
    await bot.handle_callback(update(f"fo:c:{ident}"))
    await bot.handle_callback(update(f"fo:c:{ident}", ident=2))
    assert bot.results["ok"] == bot.results["rejected_by_engine"] == 1
    assert harness.requests[2][1]["text"] == "Already decided"
    with sessions() as db:
        assert db.get(FailoverProposal, ident).state == "executed"
    await bot.client.aclose()
    client.close()


@pytest.mark.asyncio
async def test_poll_persists_offset_and_requests_callbacks(session):
    harness = TelegramHarness([{"ok": True, "result": [update("garbage", ident=10), update(data="fo:c:2", user=99, ident=11)]}])
    factory = __import__("sqlalchemy.orm", fromlist=["sessionmaker"]).sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    bot = TelegramBot(TOKEN, CHAT, "https://api.telegram.org", httpx.AsyncClient(transport=httpx.MockTransport(harness)), SpyEngine(), factory, [7], 13)
    await bot.poll_once()
    with factory() as db:
        assert db.get(AlertState, "telegram_update_offset").value == "12"
    assert harness.requests[0][0] == "getUpdates"
    assert harness.requests[0][1] == {"offset": 0, "timeout": 13, "allowed_updates": ["callback_query"]}
    second = TelegramBot(TOKEN, CHAT, "https://api.telegram.org", httpx.AsyncClient(transport=httpx.MockTransport(TelegramHarness())), SpyEngine(), factory, [7], 13)
    await second.poll_once()
    assert second.client is not None and second.offset == 12
    await bot.client.aclose(); await second.client.aclose()


@pytest.mark.asyncio
async def test_run_recovers_with_backoff_and_redacts_endpoint(session, monkeypatch, caplog):
    harness = TelegramHarness([httpx.ConnectError("secret failure"), {"ok": True, "result": []}])
    bot = bot_for(session, SpyEngine(), harness)
    delays = []
    async def sleep(value):
        delays.append(value)
        if len(delays) == 1:
            raise asyncio.CancelledError
    monkeypatch.setattr(asyncio, "sleep", sleep)
    with caplog.at_level(logging.WARNING), pytest.raises(asyncio.CancelledError):
        await bot.run()
    assert delays == [2]
    assert "FAKETOKEN" not in caplog.text and "api.telegram.org" not in caplog.text
    assert len(harness.requests) == 1
    await bot.client.aclose()


@pytest.mark.asyncio
async def test_api_ok_false_is_retried_by_run(session, monkeypatch):
    harness = TelegramHarness([{"ok": False, "description": "secret"}])
    bot = bot_for(session, SpyEngine(), harness)
    async def stop(_):
        raise asyncio.CancelledError
    monkeypatch.setattr(asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        await bot.run()
    assert len(harness.requests) == 1
    await bot.client.aclose()


def test_settings_telegram_validation_and_secret_repr(monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_ALLOWED_USER_IDS", "a,b")
    with pytest.raises(ValueError, match="comma-separated integers"):
        Settings.from_env()
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_ALLOWED_USER_IDS", "")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_BUTTONS", "true")
    with pytest.raises(ValueError, match="requires allowed user IDs"):
        Settings.from_env()
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_BUTTONS", "auto")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_ALLOWED_USER_IDS", "7")
    monkeypatch.setenv("WGOCTOPUS_ALERTS_ENABLED", "false")
    assert not Settings.from_env().telegram_buttons_enabled
    monkeypatch.setenv("WGOCTOPUS_ALERTS_ENABLED", "true")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_TOKEN", TOKEN)
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_CHAT_ID", CHAT)
    settings = Settings.from_env()
    assert settings.telegram_buttons_enabled and settings.telegram_poll_timeout == 25
    assert TOKEN not in repr(settings) and TOKEN not in str(settings)


@pytest.mark.asyncio
async def test_alerts_button_markup_and_notifier_payload(session):
    class Capture:
        def __init__(self): self.sent = []
        async def send(self, text, **kwargs): self.sent.append((text, kwargs))
    session.add(AlertState(key="last_event_id", value="0")); session.commit()
    session.add_all([Event(kind="failover.proposed", subject="1", data={"proposal_id": 1}, ts=datetime.now(UTC)),
                     Event(kind="node.drift", subject="node", data={}, ts=datetime.now(UTC))]); session.commit()
    capture = Capture()
    dispatcher = AlertDispatcher(lambda: __import__("sqlalchemy.orm", fromlist=["sessionmaker"]).sessionmaker(bind=session.get_bind(), expire_on_commit=False)(), capture, delay_seconds=0, buttons_enabled=True)
    await dispatcher.poll_once()
    assert capture.sent[0][1]["buttons"][0][0][1] == "fo:c:1"
    assert capture.sent[0][1]["buttons"][0][1][1] == "fo:r:1"
    assert capture.sent[1][1] == {}
    assert all(len(data.encode()) <= 64 for _, opts in capture.sent for row in opts.get("buttons", []) for _, data in row)
    dispatcher.buttons_enabled = False
    assert not dispatcher.buttons_enabled
    sent = []
    async def handler(request):
        sent.append(json.loads(request.content)); return httpx.Response(200, json={"ok": True, "result": True})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(TOKEN, CHAT, client=client)
    await notifier.send("text")
    await notifier.send("text", buttons=[[('Confirm', 'fo:c:1')]])
    assert "reply_markup" not in sent[0] and sent[1]["reply_markup"]["inline_keyboard"][0][0]["callback_data"] == "fo:c:1"
    await client.aclose()


@pytest.mark.asyncio
async def test_api_status_metrics_and_injected_bot_lifecycle(session, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_ALLOW_NO_AUTH", "true")
    monkeypatch.setenv("WGOCTOPUS_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_BUTTONS", "true")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_ALLOWED_USER_IDS", "7")
    monkeypatch.setenv("WGOCTOPUS_ALERTS_ENABLED", "true")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_TOKEN", TOKEN); monkeypatch.setenv("WGOCTOPUS_TELEGRAM_CHAT_ID", CHAT)
    class Bot:
        def __init__(self): self.started = False; self.stopped = False; self.client = None; self.results = {"ok": 1, "denied": 2, "invalid": 0, "rejected_by_engine": 0, "error": 0}
        async def run(self):
            self.started = True
            try:
                await asyncio.Event().wait()
            finally:
                self.stopped = True
    class Alerts:
        def counters(self): return {}
        async def run(self, stop): await stop.wait()
    bot = Bot()
    bot.client = httpx.AsyncClient(transport=httpx.MockTransport(TelegramHarness()))
    app = create_app(session_factory=lambda: session, migrate=False, alerts=Alerts(), bot=bot)
    with TestClient(app) as client:
        assert client.get("/v1/alerts").json()["buttons_enabled"] is True
        metrics = client.get("/metrics").text
        assert "wgoctopus_telegram_bot_enabled 1" in metrics
        assert 'wgoctopus_telegram_callbacks_total{result="ok"} 1' in metrics
        assert 'wgoctopus_telegram_callbacks_total{result="denied"} 2' in metrics
    assert bot.started and bot.stopped
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_BUTTONS", "false")
    app2 = create_app(session_factory=lambda: session, migrate=False, alerts=Alerts())
    with TestClient(app2) as client:
        assert client.get("/v1/alerts").json()["buttons_enabled"] is False


@pytest.mark.asyncio
async def test_real_engine_callback_switches_placement_and_records_telegram(session, fake_agent_factory, crypto, monkeypatch):
    client, sessions, _, active, _, hop, instance, standby, _ = await failover_setup(session, fake_agent_factory, crypto, monkeypatch)
    ident = _add_proposal(sessions, active, hop, instance, standby)
    engine = FailoverEngine(sessions, client.app.state.reconciler, Settings(), clock=lambda: datetime.now(UTC).timestamp())
    harness = TelegramHarness()
    bot = bot_for(session, engine, harness)
    await bot.handle_callback(update(f"fo:c:{ident}"))
    with sessions() as db:
        proposal = db.get(FailoverProposal, ident)
        event = db.scalar(select(Event).where(Event.kind == "failover.executed", Event.subject == str(ident)))
        assert (proposal.state, proposal.decided_by) == ("executed", "telegram")
        assert active_placement(db, instance["id"]).node_id == standby["id"]
        assert event.data["by"] == "telegram"
    assert bot.results["ok"] == 1
    await bot.client.aclose(); client.close()
