"""Environment-backed application settings."""

import os
import re
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
    failover_mode: str = "confirm"
    failover_down_seconds: float = 120
    failover_proposal_ttl_seconds: float = 900
    failover_cooldown_seconds: float = 600
    failover_eval_interval: float = 15
    telegram_buttons: bool = False
    telegram_failover_buttons: bool = False
    telegram_allowed_user_ids: tuple[int, ...] = ()
    telegram_poll_timeout: int = 25
    pull_listen: str = ""
    pull_host_key_file: str | None = None
    pull_login_timeout: float = 20
    bootstrap_file: str | None = None
    bootstrap_apply: bool = True
    agent_image: str = "ghcr.io/illmouse/wgoctopus-agent:latest"
    web_enabled: bool = True
    web_session_ttl: int = 28800
    web_session_idle: int = 3600
    web_cookie_secure: bool = True
    web_admin_username: str = "admin"
    web_admin_password: str | None = field(default=None, repr=False)

    @property
    def telegram_buttons_enabled(self):
        return self.telegram_buttons and self.alerts_enabled and bool(self.telegram_allowed_user_ids)

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
        if chat_id is not None:
            chat_ids = [value.strip() for value in chat_id.split(",")]
            if not all(chat_ids):
                raise ValueError("WGOCTOPUS_TELEGRAM_CHAT_ID must contain non-empty chat IDs")
            chat_id = ",".join(chat_ids)
        alerts = os.getenv("WGOCTOPUS_ALERTS_ENABLED", "auto").lower()
        if alerts not in {"auto", "true", "false"}:
            raise ValueError("WGOCTOPUS_ALERTS_ENABLED must be auto, true, or false")
        if alerts == "true" and not (token and chat_id):
            raise ValueError("WGOCTOPUS_ALERTS_ENABLED=true requires Telegram token and chat ID")
        failover_mode = os.getenv("WGOCTOPUS_FAILOVER_MODE", "confirm")
        if failover_mode not in {"off", "confirm", "auto"}:
            raise ValueError("WGOCTOPUS_FAILOVER_MODE must be off, confirm, or auto")
        kinds_text = os.getenv("WGOCTOPUS_ALERT_KINDS", "")
        kinds = tuple(k.strip() for k in kinds_text.split(",") if k.strip()) or None
        from .alerts import RULES
        unknown = set(kinds or ()) - RULES.keys()
        if unknown:
            raise ValueError(f"unknown alert kinds: {', '.join(sorted(unknown))}")
        allowed_text = os.getenv("WGOCTOPUS_TELEGRAM_ALLOWED_USER_IDS", "")
        try:
            allowed_ids = tuple(int(value.strip()) for value in allowed_text.split(",") if value.strip())
        except ValueError as exc:
            raise ValueError("WGOCTOPUS_TELEGRAM_ALLOWED_USER_IDS must be comma-separated integers") from exc
        buttons = os.getenv("WGOCTOPUS_TELEGRAM_BUTTONS", "auto").lower()
        if buttons not in {"auto", "true", "false"}:
            raise ValueError("WGOCTOPUS_TELEGRAM_BUTTONS must be auto, true, or false")
        alerts_enabled = alerts == "true" or (alerts == "auto" and bool(token and chat_id))
        failover_buttons = os.getenv("WGOCTOPUS_TELEGRAM_FAILOVER_BUTTONS", "auto").lower()
        if failover_buttons not in {"auto", "true", "false"}:
            raise ValueError("WGOCTOPUS_TELEGRAM_FAILOVER_BUTTONS must be auto, true, or false")
        if buttons == "true" and not allowed_ids:
            raise ValueError("WGOCTOPUS_TELEGRAM_BUTTONS=true requires allowed user IDs")
        poll_timeout = int(os.getenv("WGOCTOPUS_TELEGRAM_POLL_TIMEOUT", "25"))
        settings = cls(transport, os.getenv("WGOCTOPUS_SSH_KEY_FILE"),
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
                    alerts_enabled,
                   float(os.getenv("WGOCTOPUS_ALERT_DELAY_SECONDS", "60")),
                   int(os.getenv("WGOCTOPUS_ALERT_MAX_PER_MINUTE", "20")),
                   float(os.getenv("WGOCTOPUS_ALERT_POLL_SECONDS", "5")), kinds,
                   failover_mode,
                   float(os.getenv("WGOCTOPUS_FAILOVER_DOWN_SECONDS", "120")),
                   float(os.getenv("WGOCTOPUS_FAILOVER_PROPOSAL_TTL", "900")),
                   float(os.getenv("WGOCTOPUS_FAILOVER_COOLDOWN", "600")),
                    float(os.getenv("WGOCTOPUS_FAILOVER_EVAL_INTERVAL", "15")),
                     buttons == "true" or (buttons == "auto" and alerts_enabled and bool(allowed_ids)),
                     failover_buttons == "true" or (failover_buttons == "auto" and alerts_enabled),
                     allowed_ids, poll_timeout)
        pull_listen = os.getenv("WGOCTOPUS_PULL_LISTEN", "")
        if pull_listen and not re.fullmatch(r"(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):[0-9]{1,5}", pull_listen):
            raise ValueError("WGOCTOPUS_PULL_LISTEN must be host:port")
        if pull_listen and int(pull_listen.rsplit(":", 1)[1]) > 65535:
            raise ValueError("WGOCTOPUS_PULL_LISTEN port must be <= 65535")
        bootstrap_apply = os.getenv("WGOCTOPUS_BOOTSTRAP_APPLY", "true").lower()
        if bootstrap_apply not in {"true", "false"}:
            raise ValueError("WGOCTOPUS_BOOTSTRAP_APPLY must be true or false")
        web_enabled = os.getenv("WGOCTOPUS_WEB_ENABLED", "true").lower()
        secure = os.getenv("WGOCTOPUS_WEB_COOKIE_SECURE", "auto").lower()
        if web_enabled not in {"true", "false"} or secure not in {"auto", "true", "false"}:
            raise ValueError("invalid web authentication setting")
        web_password = os.getenv("WGOCTOPUS_WEB_ADMIN_PASSWORD")
        password_file = os.getenv("WGOCTOPUS_WEB_ADMIN_PASSWORD_FILE")
        if password_file:
            try:
                web_password = Path(password_file).read_text().strip()
            except OSError as exc:
                raise ValueError("cannot read WGOCTOPUS_WEB_ADMIN_PASSWORD_FILE") from exc
        return cls(**{**settings.__dict__, "pull_listen": pull_listen,
                      "pull_host_key_file": os.getenv("WGOCTOPUS_PULL_HOST_KEY_FILE"),
                      "pull_login_timeout": float(os.getenv("WGOCTOPUS_PULL_LOGIN_TIMEOUT", "20")),
                      "bootstrap_file": os.getenv("WGOCTOPUS_BOOTSTRAP_FILE") or None,
                      "bootstrap_apply": bootstrap_apply == "true",
                      "agent_image": os.getenv("WGOCTOPUS_AGENT_IMAGE", "ghcr.io/illmouse/wgoctopus-agent:latest"),
                      "web_enabled": web_enabled == "true",
                      "web_session_ttl": int(os.getenv("WGOCTOPUS_WEB_SESSION_TTL", "28800")),
                      "web_session_idle": int(os.getenv("WGOCTOPUS_WEB_SESSION_IDLE", "3600")),
                      "web_cookie_secure": secure != "false",
                      "web_admin_username": os.getenv("WGOCTOPUS_WEB_ADMIN_USERNAME", "admin"),
                      "web_admin_password": web_password})
