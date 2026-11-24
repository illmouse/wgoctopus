"""Environment configuration; credential values are hidden from repr."""
import os
from dataclasses import dataclass, field
from pathlib import Path


def _secret(name: str) -> str:
    value = os.getenv(name)
    path = os.getenv(f"{name}_FILE")
    if value is None and path:
        value = Path(path).read_text().strip()
    return value or ""


def _items(name: str) -> frozenset[str]:
    return frozenset(item for value in os.getenv(name, "").split(",") if (item := value.strip().lstrip("@").lower()))


@dataclass(frozen=True)
class Config:
    bot_token: str = field(repr=False)
    orch_url: str = "http://orchestrator:8080"
    orch_token: str = field(default="", repr=False)
    bot_instance: str = ""
    admin_usernames: frozenset[str] = frozenset()
    usernames: frozenset[str] = frozenset()
    default_config_limit: int = 3
    bot_log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Config":
        limit = int(os.getenv("DEFAULT_CONFIG_LIMIT", "3"))
        if limit < -1:
            raise ValueError("DEFAULT_CONFIG_LIMIT must be at least -1")
        config = cls(
            _secret("BOT_TOKEN"),
            os.getenv("ORCH_URL", "http://orchestrator:8080").rstrip("/"),
            _secret("ORCH_TOKEN"),
            os.getenv("BOT_INSTANCE", ""),
            _items("ADMIN_USERNAMES"),
            _items("USERNAMES"),
            limit,
            os.getenv("BOT_LOG_LEVEL", "INFO"),
        )
        required = {"BOT_TOKEN": _secret("BOT_TOKEN"), "ORCH_URL": os.getenv("ORCH_URL", ""), "ORCH_TOKEN": _secret("ORCH_TOKEN"), "BOT_INSTANCE": os.getenv("BOT_INSTANCE", "")}
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
        return config
