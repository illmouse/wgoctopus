"""Pure command and callback routing."""

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .api import ApiError
from .i18n import lang_from_code, t
from .screens import (
    Screen,
    device_card,
    devices_screen,
    main_menu,
    request_admin_screen,
    request_done_text,
)

NAME = re.compile(r"^[A-Za-z0-9_-]{1,15}$")


@dataclass(frozen=True)
class Actor:
    """Authenticated Telegram identity."""

    username: str
    tg_id: int
    role: str
    lang: str = "en"


@dataclass(frozen=True)
class ShowScreen:
    screen: Screen
    edit: bool = False


@dataclass(frozen=True)
class SendDocument:
    filename: str
    content: bytes
    caption: str


@dataclass(frozen=True)
class Notify:
    tg_id: int
    screen: Screen | str


@dataclass(frozen=True)
class EditAdminCopies:
    refs: list[list[int]]
    text: str


@dataclass(frozen=True)
class AskInput:
    kind: str
    payload: dict[str, Any]
    prompt: str


@dataclass(frozen=True)
class Toast:
    text: str
    alert: bool = False


@dataclass(frozen=True)
class ResultBundle:
    """Multiple effects produced by one decision."""

    results: list["Result"]
    request_id: int | None = None


Result = ShowScreen | SendDocument | Notify | EditAdminCopies | AskInput | Toast | ResultBundle
SendCallback = Callable[[int, Screen], Awaitable[tuple[int, int] | None]]


@dataclass(frozen=True)
class Config:
    """Router settings required by orchestrator operations."""

    bot_instance: str
    default_limit: int = 3


def _authorize(actor: Actor, device: dict[str, Any]) -> None:
    if actor.role != "admin" and device.get("owner") != actor.username:
        raise PermissionError


def _api_error(exc: ApiError, actor: Actor, used: int = 0, limit: int = 0) -> Toast:
    if exc.status == 403:
        message = t(actor.lang, "device_limit_reached", used=used, limit=limit)
    elif exc.status == 404:
        message = t(actor.lang, "not_found")
    elif exc.status == 409:
        message = t(actor.lang, "name_taken")
    else:
        message = t(actor.lang, "api_error")
    return Toast(message)


async def _devices(actor: Actor, api: Any, flt: str = "all", page: int = 0) -> ShowScreen:
    devices = await api.devices(actor.username)
    user = await api.get_user(actor.username)
    limit = int(user.get("config_limit", 3))
    screen = devices_screen(actor.lang, devices, flt, page, len(devices), limit)
    return ShowScreen(screen, True)


async def _admins(api: Any) -> list[dict[str, Any]]:
    users = await api.list_users(role="admin", status="enabled")
    return [user for user in users if user.get("tg_id") and user.get("status") == "enabled"]


async def _notify_admins(
    api: Any,
    request: dict[str, Any],
    send: SendCallback,
) -> list[list[int]]:
    refs = []
    for admin in await _admins(api):
        lang = lang_from_code(admin.get("language"))
        try:
            ref = await send(admin["tg_id"], request_admin_screen(lang, request))
        except (RuntimeError, OSError):
            continue
        if ref is not None:
            refs.append([ref[0], ref[1]])
    await api.set_request_refs(int(request["id"]), refs)
    return refs


async def handle_callback(
    data: str,
    actor: Actor,
    api: Any,
    config: Config | Any = Config("", 3),
) -> Result:
    """Handle a callback, converting API errors to user-facing results."""
    try:
        if data == "menu:devices":
            return await _devices(actor, api)
        if data.startswith("dev:"):
            _, flt, raw_page = data.split(":", 2)
            return await _devices(actor, api, flt, int(raw_page))
        if data == "menu" or data == "start":
            return ShowScreen(main_menu(actor.lang, actor.role), True)
        if data == "create:self":
            user = await api.get_user(actor.username)
            devices = await api.devices(actor.username)
            limit = int(user.get("config_limit", 3))
            if limit != -1 and len(devices) >= limit:
                return Toast(t(actor.lang, "device_limit_reached", used=len(devices), limit=limit))
            return AskInput("create_name", {}, t(actor.lang, "ask_name"))
        if data.startswith(("cfg:", "ren:", "pinfo:")):
            kind, raw_id = data.split(":", 1)
            ident = int(raw_id)
            device = await api.device(ident)
            _authorize(actor, device)
            if kind == "cfg":
                content = await api.device_config(ident)
                return SendDocument(
                    f"{device.get('name', 'device')}.conf",
                    content,
                    t(actor.lang, "config_caption"),
                )
            if kind == "ren":
                return AskInput("rename", {"id": ident}, t(actor.lang, "ask_rename"))
            return ShowScreen(device_card(actor.lang, device), True)
        if data == "close":
            return Toast("")
        if data == "reqlim":
            if actor.role == "admin":
                return Toast(t(actor.lang, "admin_use_limit_cmd"))
            return AskInput("limit_req", {}, t(actor.lang, "ask_limit"))
        if data.startswith("req:"):
            return await _decide_request(data, actor, api, config)
    except PermissionError:
        return Toast(t(actor.lang, "forbidden"), alert=True)
    except ApiError as exc:
        if data.startswith("req:") and exc.status == 409:
            return Toast(t(actor.lang, "already_processed"))
        if data.startswith("cfg:") and exc.status == 403:
            return Toast(t(actor.lang, "forbidden"), alert=True)
        return _api_error(exc, actor)
    except httpx.HTTPError:
        return Toast(t(actor.lang, "api_error"))
    except (ValueError, KeyError):
        return Toast("")
    return Toast("")


async def _decide_request(data: str, actor: Actor, api: Any, config: Any) -> Result:
    if actor.role != "admin":
        return Toast(t(actor.lang, "forbidden"), alert=True)
    _, action, raw_id = data.split(":", 2)
    ident = int(raw_id)
    request = await api.get_request(ident)
    if action == "a":
        user = await api.approve_request(
            ident,
            admin_tg_id=actor.tg_id,
            admin_username=actor.username,
            default_limit=config.default_limit,
        )
        status = "approved"
        requester_text = t(lang_from_code((user or {}).get("language")), "registered", limit=(user or {}).get("config_limit", request.get("requested_limit", config.default_limit)))
    elif action == "d":
        await api.decline_request(
            ident,
            admin_tg_id=actor.tg_id,
            admin_username=actor.username,
        )
        status = "declined"
        requester_text = t(lang_from_code(request.get("language")), "declined")
    else:
        return Toast("")
    done = dict(request)
    done["status"] = status
    done["admin_username"] = actor.username
    refs = request.get("notification_refs", [])
    return ResultBundle(
        [
            EditAdminCopies(refs, request_done_text(actor.lang, done)),
            Notify(int(request.get("tg_id", 0)), requester_text),
        ]
    )


async def handle_input(
    kind: str,
    payload: dict[str, Any],
    actor: Actor,
    api: Any,
    text: str,
    config: Config | Any,
) -> Result:
    """Validate and apply a prompted input."""
    try:
        if kind in {"create_name", "create"}:
            if not NAME.fullmatch(text):
                return Toast(t(actor.lang, "invalid_name"))
            user = await api.get_user(actor.username)
            devices = await api.devices(actor.username)
            limit = int(user.get("config_limit", 3))
            if limit != -1 and len(devices) >= limit:
                return Toast(t(actor.lang, "device_limit_reached", used=len(devices), limit=limit))
            result = await api.create_device(
                actor.username,
                await api.instance_id(config.bot_instance),
                text,
            )
            return ShowScreen(device_card(actor.lang, result), False)
        if kind == "rename":
            if not NAME.fullmatch(text):
                return Toast(t(actor.lang, "invalid_name"))
            ident = int(payload["id"])
            device = await api.device(ident)
            _authorize(actor, device)
            renamed = await api.patch_device(ident, name=text)
            return ShowScreen(device_card(actor.lang, renamed or {**device, "name": text}), False)
        if kind == "limit_req":
            if actor.role == "admin":
                return Toast(t(actor.lang, "admin_use_limit_cmd"))
            try:
                requested = int(text)
            except ValueError:
                return Toast(t(actor.lang, "limit_invalid"))
            user = await api.get_user(actor.username)
            current = int(user.get("config_limit", 3))
            if requested < -1 or requested == current:
                return Toast(t(actor.lang, "limit_invalid"))
            await api.create_request(
                type="limit",
                tg_id=actor.tg_id,
                username=actor.username,
                requested_limit=requested,
            )
            return Toast(t(actor.lang, "request_sent"))
    except PermissionError:
        return Toast(t(actor.lang, "forbidden"), alert=True)
    except ApiError as exc:
        if exc.status == 409:
            return Toast(t(actor.lang, "name_taken" if kind in {"create", "create_name", "rename"} else "request_pending"))
        if kind in {"create", "create_name"} and exc.status == 403:
            try:
                user = await api.get_user(actor.username)
                count = len(await api.devices(actor.username))
                return Toast(t(actor.lang, "device_limit_reached", used=count, limit=user.get("config_limit", "?")))
            except ApiError:
                pass
        return _api_error(exc, actor)
    except httpx.HTTPError:
        return Toast(t(actor.lang, "api_error"))
    return Toast("")


async def cmd_create(actor: Actor, api: Any, config: Config | Any) -> Result:
    """Create a device using an automatically generated name."""
    devices = await api.devices(actor.username)
    names = {str(device.get("name", "")) for device in devices}
    suffix = len(devices) + 1
    name = f"device_{suffix}"
    while name in names:
        suffix += 1
        name = f"device_{suffix}"
    return await handle_input("create_name", {}, actor, api, name, config)


async def cmd_givemepowers(
    tg_user: Any,
    api: Any,
    send: SendCallback,
) -> list[Result]:
    """Create an access request and notify registered administrators."""
    lang = lang_from_code(getattr(tg_user, "lang", None))
    try:
        request = await api.create_request(
            type="access",
            tg_id=tg_user.id,
            username=tg_user.username,
            first_name=tg_user.first_name,
            last_name=tg_user.last_name,
        )
    except ApiError as exc:
        if exc.status == 409:
            return [Toast(t(lang, "request_pending"))]
        return [Toast(t(lang, "api_error"))]
    try:
        admins = await _admins(api)
    except ApiError:
        return [Toast(t(lang, "api_error"))]
    if not admins:
        return [Toast(t(lang, "no_admin"))]
    await _notify_admins(api, request, send)
    return [Toast(t(lang, "request_sent"))]


async def handle_text(kind: str, actor: Actor, api: Any, text: str) -> Result:
    """Compatibility wrapper for the legacy text-handler call shape."""
    return await handle_input(kind, {}, actor, api, text, Config(""))
