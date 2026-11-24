from wgoctopus_bot import __main__ as entry


def test_main_builds_and_polls(monkeypatch):
    calls = {}

    class App:
        def run_polling(self, **kw):
            calls["poll"] = kw

    class Cfg:
        bot_log_level = "INFO"

    monkeypatch.setattr(entry.Config, "from_env", classmethod(lambda cls: Cfg()))
    monkeypatch.setattr(entry, "build_application", lambda cfg: App())
    entry.main()
    assert calls["poll"]["allowed_updates"] == ["message", "callback_query"]
