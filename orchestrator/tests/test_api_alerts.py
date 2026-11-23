import time

import pytest
from fastapi.testclient import TestClient

from wgoctopus_orch.alerts import AlertDispatcher, NotifyError
from wgoctopus_orch.api import create_app
from wgoctopus_orch.config import Settings
from wgoctopus_orch.models import Event


class FakeNotifier:
    def __init__(self, fail=False):
        self.messages = []
        self.fail = fail

    async def send(self, text):
        if self.fail:
            raise NotifyError("nope")
        self.messages.append(text)


def test_alert_endpoints(api, caplog):
    client, sessions, _reconciler, crypto = api
    assert client.get("/v1/alerts").json() == {"enabled": False, "counters": {"sent": 0, "failed": 0, "dropped": 0, "pending": 0}}
    assert client.post("/v1/alerts/test").status_code == 409
    client.headers.pop("Authorization")
    assert client.get("/v1/alerts").status_code == 401
    assert client.post("/v1/alerts/test").status_code == 401
    client.headers["Authorization"] = "Bearer test-admin-token"

    notifier = FakeNotifier()
    dispatcher = AlertDispatcher(sessions, notifier)
    app = create_app(session_factory=sessions, reconciler=_reconciler, crypto=crypto, alerts=dispatcher, migrate=False)
    with TestClient(app) as enabled:
        enabled.headers["Authorization"] = "Bearer test-admin-token"
        assert enabled.post("/v1/alerts/test").status_code == 202
        assert enabled.post("/v1/alerts/test").json() == {"sent": True}
        assert notifier.messages == ["wgoctopus alert test", "wgoctopus alert test"]
        assert enabled.get("/v1/alerts").json()["counters"]["sent"] == 0

    bad = AlertDispatcher(sessions, FakeNotifier(fail=True))
    app = create_app(session_factory=sessions, reconciler=_reconciler, crypto=crypto, alerts=bad, migrate=False)
    with TestClient(app) as failed:
        failed.headers["Authorization"] = "Bearer test-admin-token"
        response = failed.post("/v1/alerts/test")
        assert response.status_code == 502
        assert response.json()["detail"] == "notification failed"
        assert "123456:TEST-TOKEN" not in response.text
        assert "123456:TEST-TOKEN" not in caplog.text


def test_alert_event_dispatches_and_metrics(api):
    _client, sessions, reconciler, crypto = api
    notifier = FakeNotifier()
    dispatcher = AlertDispatcher(sessions, notifier, delay_seconds=0, poll_seconds=0.01)
    app = create_app(session_factory=sessions, reconciler=reconciler, crypto=crypto, alerts=dispatcher, migrate=False)
    with TestClient(app) as event_client:
        event_client.headers["Authorization"] = "Bearer test-admin-token"
        created = event_client.post("/v1/nodes", json={"name": "alert-node", "ssh_host": "192.0.2.10", "ssh_user": "root", "agent_token": "agent-secret"})
        assert created.status_code == 201
        node_id = created.json()["id"]
        with sessions() as session:
            session.add(Event(kind="node.blocked", subject=str(node_id), data={"kind": "blocked_dangerous"}))
            session.commit()
        deadline = time.monotonic() + 5
        while not notifier.messages and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(notifier.messages) == 1
        assert "alert-node" in notifier.messages[0]
        metrics = event_client.get("/metrics").text
        assert "wgoctopus_alerts_enabled 1" in metrics
        assert "wgoctopus_alerts_sent_total 1" in metrics
        assert "wgoctopus_alerts_failed_total 0" in metrics
        assert "wgoctopus_alerts_dropped_total 0" in metrics
        assert "wgoctopus_alerts_pending 0" in metrics
        assert "123456:TEST-TOKEN" not in metrics and "secret-chat" not in metrics


def test_disabled_alert_metrics(api):
    client, *_ = api
    assert "wgoctopus_alerts_enabled 0" in client.get("/metrics").text


def test_lifespan_builds_alerts_from_env(api, monkeypatch):
    _client, sessions, reconciler, crypto = api
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_TOKEN", "123456:TEST-TOKEN")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_CHAT_ID", "chat")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_API_BASE", "http://127.0.0.1:9")
    monkeypatch.setenv("WGOCTOPUS_ALERTS_ENABLED", "auto")
    app = create_app(session_factory=sessions, reconciler=reconciler, crypto=crypto,
                     notifier=FakeNotifier(), migrate=False)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer test-admin-token"
        assert client.get("/v1/alerts").json()["enabled"] is True


@pytest.mark.parametrize("enabled,token,chat,expected", [
    ("auto", None, None, False), ("auto", "123456:TEST-TOKEN", "chat", True),
    ("false", "123456:TEST-TOKEN", "chat", False),
])
def test_settings_alert_env(monkeypatch, enabled, token, chat, expected):
    monkeypatch.setenv("WGOCTOPUS_ALERTS_ENABLED", enabled)
    for name, value in (("WGOCTOPUS_TELEGRAM_TOKEN", token), ("WGOCTOPUS_TELEGRAM_CHAT_ID", chat)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    settings = Settings.from_env()
    assert settings.alerts_enabled is expected
    if token:
        assert token not in repr(settings)


def test_settings_token_file_and_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_ALERTS_ENABLED", "auto")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_TOKEN", "123456:ENV-SECRET")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_CHAT_ID", "chat")
    path = tmp_path / "token"
    path.write_text(" 123456:FILE-SECRET \n")
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_TOKEN_FILE", str(path))
    assert Settings.from_env().telegram_token == "123456:FILE-SECRET"
    monkeypatch.setenv("WGOCTOPUS_TELEGRAM_TOKEN_FILE", str(tmp_path / "missing"))
    with pytest.raises(ValueError) as error:
        Settings.from_env()
    assert "SECRET" not in str(error.value)
    monkeypatch.delenv("WGOCTOPUS_TELEGRAM_TOKEN_FILE")
    monkeypatch.delenv("WGOCTOPUS_TELEGRAM_TOKEN")
    monkeypatch.delenv("WGOCTOPUS_TELEGRAM_CHAT_ID")
    monkeypatch.setenv("WGOCTOPUS_ALERTS_ENABLED", "true")
    with pytest.raises(ValueError):
        Settings.from_env()
    monkeypatch.setenv("WGOCTOPUS_ALERTS_ENABLED", "no")
    with pytest.raises(ValueError):
        Settings.from_env()


def test_settings_kinds_and_numbers(monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_ALERT_KINDS", "node.blocked, probe.down")
    monkeypatch.setenv("WGOCTOPUS_ALERT_DELAY_SECONDS", "2.5")
    monkeypatch.setenv("WGOCTOPUS_ALERT_MAX_PER_MINUTE", "7")
    monkeypatch.setenv("WGOCTOPUS_ALERT_POLL_SECONDS", "0.25")
    settings = Settings.from_env()
    assert settings.alert_kinds == ("node.blocked", "probe.down")
    assert (settings.alert_delay_seconds, settings.alert_max_per_minute, settings.alert_poll_seconds) == (2.5, 7, 0.25)
    monkeypatch.setenv("WGOCTOPUS_ALERT_KINDS", "unknown.alert")
    with pytest.raises(ValueError, match="unknown.alert"):
        Settings.from_env()
