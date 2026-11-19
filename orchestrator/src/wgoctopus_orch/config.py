"""Environment-backed application settings."""

import os
from pathlib import Path


def database_url() -> str:
    return os.getenv("WGOCTOPUS_DATABASE_URL", "sqlite:///./wgoctopus.db")


def schema_path() -> Path:
    configured = os.getenv("WGOCTOPUS_SCHEMA_PATH")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "schema" / "state.schema.json"
