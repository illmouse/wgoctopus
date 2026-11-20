"""Environment-backed application settings."""

import os
from dataclasses import dataclass
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

    @classmethod
    def from_env(cls):
        transport = os.getenv("WGOCTOPUS_TRANSPORT", "ssh")
        if transport not in {"ssh", "direct"}:
            raise ValueError("WGOCTOPUS_TRANSPORT must be ssh or direct")
        return cls(transport, os.getenv("WGOCTOPUS_SSH_KEY_FILE"),
                   os.getenv("WGOCTOPUS_SSH_KEY_PASSPHRASE_FILE"),
                   os.getenv("WGOCTOPUS_SSH_KNOWN_HOSTS"),
                   os.getenv("WGOCTOPUS_SSH_TOFU", "false").lower() == "true",
                   float(os.getenv("WGOCTOPUS_SSH_CONNECT_TIMEOUT", "15")),
                   float(os.getenv("WGOCTOPUS_AGENT_REQUEST_TIMEOUT", "30")))
