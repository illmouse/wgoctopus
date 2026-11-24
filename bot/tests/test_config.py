import pytest

from wgoctopus_bot.config import Config


def test_env_and_username_normalization(monkeypatch):
    for key, value in {"BOT_TOKEN": "token", "ORCH_URL": "https://orch/", "ORCH_TOKEN": "secret", "BOT_INSTANCE": "wg", "ADMIN_USERNAMES": " @ALICE,alice, Bob ", "USERNAMES": "@CAROL,carol", "DEFAULT_CONFIG_LIMIT": "-1"}.items():
        monkeypatch.setenv(key, value)
    config = Config.from_env()
    assert config.orch_url == "https://orch"
    assert config.admin_usernames == {"alice", "bob"}
    assert config.usernames == {"carol"}
    assert config.default_config_limit == -1


def test_secret_file_and_missing_values(monkeypatch, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("secret-token\n")
    monkeypatch.setenv("BOT_TOKEN_FILE", str(secret))
    monkeypatch.setenv("ORCH_URL", "https://orch")
    monkeypatch.setenv("ORCH_TOKEN", "token")
    monkeypatch.setenv("BOT_INSTANCE", "wg")
    assert Config.from_env().bot_token == "secret-token"
    monkeypatch.delenv("BOT_TOKEN_FILE")
    for key in ("ORCH_URL", "ORCH_TOKEN", "BOT_INSTANCE"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValueError, match="BOT_TOKEN") as error:
        Config.from_env()
    assert "secret-token" not in str(error.value)


def test_bad_limit(monkeypatch):
    monkeypatch.setenv("DEFAULT_CONFIG_LIMIT", "-2")
    with pytest.raises(ValueError, match="at least -1"):
        Config.from_env()
