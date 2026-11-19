"""Fernet encryption helpers for persisted secrets."""

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class Secret(str):
    """String secret with a non-disclosing representation."""

    def __repr__(self) -> str:
        return "Secret('[redacted]')"


class Crypto:
    def __init__(self, key: str | bytes | None = None):
        if key is None:
            key = os.getenv("WGOCTOPUS_MASTER_KEY")
            key_file = os.getenv("WGOCTOPUS_MASTER_KEY_FILE")
            if key is None and key_file:
                try:
                    key = Path(key_file).read_bytes().strip()
                except OSError as exc:
                    raise RuntimeError("cannot read WGOCTOPUS_MASTER_KEY_FILE") from exc
        if not key:
            raise RuntimeError("set WGOCTOPUS_MASTER_KEY or WGOCTOPUS_MASTER_KEY_FILE")
        try:
            self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("invalid WGOCTOPUS_MASTER_KEY: expected Fernet URL-safe key") from exc

    def encrypt(self, value: Secret | str) -> str:
        return self._fernet.encrypt(str(value).encode()).decode()

    def decrypt(self, value: str) -> Secret:
        try:
            return Secret(self._fernet.decrypt(value.encode()).decode())
        except (InvalidToken, ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("secret decryption failed; check WGOCTOPUS_MASTER_KEY") from exc
