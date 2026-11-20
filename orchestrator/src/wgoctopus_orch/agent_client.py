"""Typed, secret-conscious client for the agent HTTP contract."""

from dataclasses import dataclass
from enum import Enum

import httpx


class ErrorKind(str, Enum):
    STALE_REVISION = "stale_revision"
    DANGEROUS = "dangerous"
    INVALID = "invalid"
    TIMEOUT = "timeout"
    UNAUTHORIZED = "unauthorized"
    UNREACHABLE = "unreachable"
    OTHER = "other"


@dataclass
class PutResult:
    ok: bool
    status: int
    revision: int | None = None
    checksum: str | None = None
    error_kind: ErrorKind | None = None
    reasons: list[str] | None = None
    message: str | None = None


class AgentClient:
    def __init__(self, session, timeout=30):
        self.session, self.timeout = session, timeout

    async def healthz(self):
        response = await self.session.request("GET", "/healthz", timeout=self.timeout)
        response.raise_for_status()
        return response.text

    async def get_state(self):
        response = await self.session.request("GET", "/v1/state", timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        state = data.get("state", {})
        return data.get("revision", state.get("revision")), data.get("checksum"), state

    async def put_state(self, state: dict, *, allow_dangerous=False):
        try:
            response = await self.session.request(
                "PUT", "/v1/state", json=state,
                params={"allow_dangerous": "true"} if allow_dangerous else None,
                timeout=self.timeout,
            )
        except httpx.TimeoutException:
            return PutResult(False, 0, error_kind=ErrorKind.TIMEOUT, message="agent request timed out")
        except httpx.RequestError:
            return PutResult(False, 0, error_kind=ErrorKind.UNREACHABLE, message="agent unreachable")
        if response.status_code == 204:
            return PutResult(True, 204, state.get("revision"))
        reasons = []
        message = "agent request failed"
        if response.status_code == 409:
            try:
                payload = response.json()
                reasons = payload.get("reasons", []) or []
            except ValueError:
                pass
        elif response.status_code == 401:
            message = "unauthorized"
        elif response.status_code == 422:
            message = "invalid state"
        elif response.status_code == 504:
            message = "agent apply timed out"
        kind = {401: ErrorKind.UNAUTHORIZED, 409: ErrorKind.DANGEROUS if reasons else ErrorKind.STALE_REVISION,
                422: ErrorKind.INVALID, 504: ErrorKind.TIMEOUT}.get(response.status_code, ErrorKind.OTHER)
        return PutResult(False, response.status_code, error_kind=kind, reasons=reasons, message=message)

    async def metrics_text(self):
        response = await self.session.request("GET", "/metrics", timeout=self.timeout)
        response.raise_for_status()
        return response.text
