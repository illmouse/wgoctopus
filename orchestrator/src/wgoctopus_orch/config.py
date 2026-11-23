"""Environment-backed application settings."""

import os
from dataclasses import dataclass, field
from pathlib import Path


def database_url() -> str:
    return os.getenv("WGOCTOPUS_DATABASE_URL", "sqlite:///./wgoctopus.db")


def schema_path() -> Path:
    configured = os.getenv("WGOCTOPUS_SCHEMA_PATH")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "schema" / "state.schema.json"


@dataclass(frozen=True)
class Settings:
    transport: str = "ssh"
    ssh_key_file: str | None = None
    ssh_key_passphrase_file: str | None = None
    ssh_known_hosts: str | None = None
    ssh_tofu: bool = False
    ssh_connect_timeout: float = 15
    agent_request_timeout: float = 30
    reconcile_interval: float = 30
    reconcile_concurrency: int = 4
    reconcile_max_backoff: float = 300
    reconcile_blocked_recheck: float = 300
    reconcile_node_timeout: float = 120
    metrics_public: bool = False
    scrape_enabled: bool = True
    scrape_timeout: float = 10
    probe_stale_seconds: float = 180
    probe_grace_seconds: float = 60
    telegram_token: str | None = field(default=None, repr=False)
    telegram_chat_id: str | None = None
    telegram_api_base: str = "https://api.telegram.org"
    alerts_enabled: bool = False
    alert_delay_seconds: float = 60
    alert_max_per_minute: int = 20
    alert_poll_seconds: float = 5
    alert_kinds: tuple[str, ...] | None = None

    @classmethod
    def from_env(cls):
        transport = os.getenv("WGOCTOPUS_TRANSPORT", "ssh")
        if transport not in {"ssh", "direct"}:
            raise ValueError("WGOCTOPUS_TRANSPORT must be ssh or direct")
        token = os.getenv("WGOCTOPUS_TELEGRAM_TOKEN")
        token_file = os.getenv("WGOCTOPUS_TELEGRAM_TOKEN_FILE")
        if token_file:
            try:
                token = Path(token_file).read_text().strip()
            except OSError as exc:
                raise ValueError("cannot read WGOCTOPUS_TELEGRAM_TOKEN_FILE") from exc
        chat_id = os.getenv("WGOCTOPUS_TELEGRAM_CHAT_ID")
        alerts = os.getenv("WGOCTOPUS_ALERTS_ENABLED", "auto").lower()
        if alerts not in {"auto", "true", "false"}:
            raise ValueError("WGOCTOPUS_ALERTS_ENABLED must be auto, true, or false")
        if alerts == "true" and not (token and chat_id):
            raise ValueError("WGOCTOPUS_ALERTS_ENABLED=true requires Telegram token and chat ID")
        kinds_text = os.getenv("WGOCTOPUS_ALERT_KINDS", "")
        kinds = tuple(k.strip() for k in kinds_text.split(",") if k.strip()) or None
        from .alerts import RULES
        unknown = set(kinds or ()) - RULES.keys()
        if unknown:
            raise ValueError(f"unknown alert kinds: {', '.join(sorted(unknown))}")
        return cls(transport, os.getenv("WGOCTOPUS_SSH_KEY_FILE"),
                   os.getenv("WGOCTOPUS_SSH_KEY_PASSPHRASE_FILE"),
                   os.getenv("WGOCTOPUS_SSH_KNOWN_HOSTS"),
                   os.getenv("WGOCTOPUS_SSH_TOFU", "false").lower() == "true",
                   float(os.getenv("WGOCTOPUS_SSH_CONNECT_TIMEOUT", "15")),
                    float(os.getenv("WGOCTOPUS_AGENT_REQUEST_TIMEOUT", "30")),
                    float(os.getenv("WGOCTOPUS_RECONCILE_INTERVAL", "30")),
                    int(os.getenv("WGOCTOPUS_RECONCILE_CONCURRENCY", "4")),
                    float(os.getenv("WGOCTOPUS_RECONCILE_MAX_BACKOFF", "300")),
                    float(os.getenv("WGOCTOPUS_RECONCILE_BLOCKED_RECHECK", "300")),
                    float(os.getenv("WGOCTOPUS_RECONCILE_NODE_TIMEOUT", "120")),
                   os.getenv("WGOCTOPUS_METRICS_PUBLIC", "false").lower() == "true",
                   os.getenv("WGOCTOPUS_SCRAPE_ENABLED", "true").lower() == "true",
                   float(os.getenv("WGOCTOPUS_SCRAPE_TIMEOUT", "10")),
                   float(os.getenv("WGOCTOPUS_PROBE_STALE_SECONDS", "180")),
                   float(os.getenv("WGOCTOPUS_PROBE_GRACE_SECONDS", "60")), token, chat_id,
                   os.getenv("WGOCTOPUS_TELEGRAM_API_BASE", "https://api.telegram.org"),
                   alerts == "true" or (alerts == "auto" and bool(token and chat_id)),
                   float(os.getenv("WGOCTOPUS_ALERT_DELAY_SECONDS", "60")),
                   int(os.getenv("WGOCTOPUS_ALERT_MAX_PER_MINUTE", "20")),
                   float(os.getenv("WGOCTOPUS_ALERT_POLL_SECONDS", "5")), kinds)
