"""In-memory orchestrator fake for router tests."""

from copy import deepcopy
from typing import Any

from wgoctopus_bot.api import ApiError


class FakeApi:
    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {
            "alice": {"username": "alice", "tg_id": 1, "role": "user", "status": "enabled", "config_limit": 2, "language": "en"},
            "bob": {"username": "bob", "tg_id": 3, "role": "user", "status": "enabled", "config_limit": 2, "language": "en"},
            "root": {"username": "root", "tg_id": 2, "role": "admin", "status": "enabled", "config_limit": -1, "language": "en"},
        }
        self.devices_data: list[dict[str, Any]] = []
        self.requests: dict[int, dict[str, Any]] = {}
        self.admins = [self.users["root"], {"username": "ghost", "role": "admin", "status": "enabled"}]
        self.next_id = 1
        self.refs: dict[int, list[list[int]]] = {}
        self.config = b"[Interface]\nPrivateKey = secret\n"

    async def confirm_failover(self, proposal_id: int, *, actor: str) -> Any:
        return self._failover("confirm", proposal_id, actor)

    async def reject_failover(self, proposal_id: int, *, actor: str) -> Any:
        return self._failover("reject", proposal_id, actor)

    def _failover(self, action: str, proposal_id: int, actor: str) -> Any:
        self.failover_calls = getattr(self, "failover_calls", [])
        self.failover_calls.append((action, proposal_id, actor))
        error = getattr(self, "failover_error", None)
        if error:
            raise error
        return {"id": proposal_id}

    async def resolve(self, tg_id: int, username: str | None, language: str) -> dict[str, Any]:
        user = self.users.get((username or "").lower())
        if user is None:
            raise ApiError(404, "not_found")
        return {**user, "language": language}

    async def get_user(self, username: str) -> dict[str, Any]:
        return self.users[username]

    async def devices(self, username: str) -> list[dict[str, Any]]:
        return [deepcopy(device) for device in self.devices_data if device["owner"] == username]

    async def all_devices(self, **params: Any) -> dict[str, Any]:
        items = deepcopy(self.devices_data)
        return {"total": len(items), "items": items}

    async def device(self, ident: int) -> dict[str, Any]:
        for device in self.devices_data:
            if device["id"] == ident:
                return deepcopy(device)
        raise ApiError(404, "not_found")

    async def device_config(self, ident: int) -> bytes:
        await self.device(ident)
        return self.config

    async def instance_id(self, name: str) -> int:
        return 9

    async def create_device(self, username: str, instance_id: int, name: str) -> dict[str, Any]:
        user_devices = await self.devices(username)
        limit = self.users[username]["config_limit"]
        if limit != -1 and len(user_devices) >= limit:
            raise ApiError(403, "forbidden")
        if any(d["name"] == name and d["owner"] == username for d in self.devices_data):
            raise ApiError(409, "conflict")
        device = {"id": self.next_id, "instance_id": instance_id, "instance": "test", "name": name,
                  "public_key": "pub", "allowed_ip": "10.0.0.2/32", "enabled": True,
                  "owner": username, "created_at": "2025-01-01T00:00:00Z",
                  "latest_handshake_at": None, "rx": 1024, "tx": 2048, "active": False}
        self.next_id += 1
        self.devices_data.append(device)
        return deepcopy(device)

    async def patch_device(self, ident: int, **data: Any) -> dict[str, Any]:
        for device in self.devices_data:
            if device["id"] == ident:
                device.update(data)
                return deepcopy(device)
        raise ApiError(404, "not_found")

    async def list_users(self, **params: Any) -> list[dict[str, Any]]:
        if self.admins and params.get("role") == "admin":
            return deepcopy(self.admins)
        users = list(self.users.values())
        return deepcopy([u for u in users if all(u.get(key) == value for key, value in params.items())])

    async def patch_user(self, username: str, **data: Any) -> dict[str, Any]:
        self.users[username].update(data)
        return deepcopy(self.users[username])

    async def delete_user(self, username: str) -> None:
        del self.users[username]

    async def disable_user(self, username: str, by: str) -> None:
        self.users[username]["status"] = "disabled"

    async def enable_user(self, username: str) -> None:
        self.users[username]["status"] = "enabled"

    async def ensure_user(self, username: str, role: str = "user", config_limit: int = 3) -> None:
        self.users[username] = {"username": username, "tg_id": None, "role": role, "status": "enabled", "config_limit": config_limit}

    async def delete_device(self, ident: int) -> None:
        self.devices_data[:] = [d for d in self.devices_data if d["id"] != ident]

    async def create_request(self, **data: Any) -> dict[str, Any]:
        if any(r["tg_id"] == data.get("tg_id") and r["status"] == "pending" for r in self.requests.values()):
            raise ApiError(409, "conflict")
        ident = self.next_id
        self.next_id += 1
        request = {"id": ident, "status": "pending", "notification_refs": [], **data}
        if data.get("type") == "limit":
            request["previous_limit"] = self.users[data["username"]]["config_limit"]
        self.requests[ident] = request
        return deepcopy(request)

    async def get_request(self, ident: int) -> dict[str, Any]:
        if ident not in self.requests:
            raise ApiError(404, "not_found")
        return deepcopy(self.requests[ident])

    async def list_requests(self, status: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        items = sorted((r for r in self.requests.values() if status is None or r.get("status") == status), key=lambda r: r["id"])
        return deepcopy(items[offset:offset + limit])

    async def set_request_refs(self, ident: int, refs: list[list[int]]) -> None:
        self.refs[ident] = refs
        self.requests[ident]["notification_refs"] = refs

    async def approve_request(self, ident: int, **data: Any) -> dict[str, Any]:
        request = self.requests[ident]
        if request["status"] != "pending":
            raise ApiError(409, "conflict")
        request.update(status="approved", admin_username=data["admin_username"])
        user = self.users.get(request.get("username"))
        if user is None:
            username = request.get("username") or f"user{request['tg_id']}"
            user = {"username": username, "tg_id": request["tg_id"], "role": "user",
                    "status": "enabled", "language": request.get("language", "en"),
                    "config_limit": request.get("requested_limit", data["default_limit"])}
            self.users[username] = user
        if request.get("type") == "limit":
            user["config_limit"] = request["requested_limit"]
        return deepcopy(user)

    async def decline_request(self, ident: int, **data: Any) -> None:
        request = self.requests[ident]
        if request["status"] != "pending":
            raise ApiError(409, "conflict")
        request.update(status="declined", admin_username=data["admin_username"])
