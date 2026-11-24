"""Small typed async client for the orchestrator's bot-facing REST API."""
from typing import Any

import httpx


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str = "") -> None:
        self.status, self.code, self.detail = status, code, detail
        super().__init__(f"orchestrator {status}: {code}")


class OrchApi:
    def __init__(self, url: str, token: str, client: httpx.AsyncClient | None = None) -> None:
        self.client = client or httpx.AsyncClient(base_url=url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        self._owns_client = client is None
        self._instances: dict[str, int] = {}

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = await self.client.request(method, path, **kwargs)
        if response.is_error:
            try:
                body = response.json()
                err = body.get("detail", body)
                code, detail = err.get("error", "request_failed"), err.get("detail", "")
            except (ValueError, AttributeError):
                code, detail = "request_failed", ""
            raise ApiError(response.status_code, str(code), str(detail))
        return response.json() if response.content else None

    async def resolve(self, tg_id: int, username: str | None, language: str) -> dict[str, Any]:
        return await self._request("POST", "/v1/users/resolve", json={"tg_id": tg_id, "username": username, "language": language})

    async def ensure_user(self, username: str, role: str = "user", config_limit: int = 3) -> Any:
        return await self._request("PUT", f"/v1/users/{username}", json={"role": role, "config_limit": config_limit})

    async def list_users(self, **params: Any) -> list[dict[str, Any]]:
        return await self._request("GET", "/v1/users", params=params)

    async def get_user(self, username: str) -> dict[str, Any]:
        return await self._request("GET", f"/v1/users/{username}")

    async def patch_user(self, username: str, **data: Any) -> Any:
        return await self._request("PATCH", f"/v1/users/{username}", json=data)

    async def delete_user(self, username: str) -> Any:
        return await self._request("DELETE", f"/v1/users/{username}")

    async def disable_user(self, username: str, by: str) -> Any:
        return await self._request("POST", f"/v1/users/{username}/disable", json={"by": by})

    async def enable_user(self, username: str) -> Any:
        return await self._request("POST", f"/v1/users/{username}/enable")

    async def create_request(self, **data: Any) -> Any:
        return await self._request("POST", "/v1/requests", json=data)

    async def list_requests(self, **params: Any) -> list[dict[str, Any]]:
        return await self._request("GET", "/v1/requests", params=params)

    async def get_request(self, request_id: int) -> dict[str, Any]:
        return await self._request("GET", f"/v1/requests/{request_id}")

    async def approve_request(self, request_id: int, **data: Any) -> Any:
        return await self._request("POST", f"/v1/requests/{request_id}/approve", json=data)

    async def decline_request(self, request_id: int, **data: Any) -> Any:
        return await self._request("POST", f"/v1/requests/{request_id}/decline", json=data)

    async def set_request_refs(self, request_id: int, refs: list[list[int]]) -> Any:
        return await self._request("PUT", f"/v1/requests/{request_id}/refs", json={"refs": refs})

    async def devices(self, username: str) -> list[dict[str, Any]]:
        return await self._request("GET", f"/v1/users/{username}/devices")

    async def all_devices(self, **params: Any) -> dict[str, Any]:
        return await self._request("GET", "/v1/devices", params=params)

    async def create_device(self, username: str, instance_id: int, name: str | None = None) -> Any:
        return await self._request("POST", f"/v1/users/{username}/devices", json={"instance_id": instance_id, "name": name})

    async def device(self, device_id: int) -> dict[str, Any]:
        return await self._request("GET", f"/v1/devices/{device_id}")

    async def patch_device(self, device_id: int, **data: Any) -> Any:
        return await self._request("PATCH", f"/v1/devices/{device_id}", json=data)

    async def delete_device(self, device_id: int) -> Any:
        return await self._request("DELETE", f"/v1/devices/{device_id}")

    async def device_config(self, device_id: int) -> bytes:
        response = await self.client.get(f"/v1/peers/{device_id}/config")
        if response.is_error:
            try:
                body = response.json(); err = body.get("detail", body)
                raise ApiError(response.status_code, str(err.get("error", "request_failed")), str(err.get("detail", "")))
            except ValueError:
                raise ApiError(response.status_code, "request_failed") from None
        return response.content

    async def instances(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/v1/instances")

    async def instance_id(self, name: str) -> int:
        if name not in self._instances:
            self._instances.update({i["name"]: i["id"] for i in await self.instances()})
        return self._instances[name]
