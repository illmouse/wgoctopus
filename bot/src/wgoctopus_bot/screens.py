"""Pure rendering of bot screens."""

from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from typing import Any

from .i18n import t


@dataclass(frozen=True)
class Button:
    """An inline button."""

    label: str
    data: str


@dataclass(frozen=True)
class Screen:
    """Text and inline keyboard rows."""

    text: str
    buttons: list[list[Button]]


def _button(label: str, data: str) -> Button:
    if len(data.encode("utf-8")) > 64:
        raise ValueError("callback_data exceeds Telegram's 64-byte limit")
    return Button(label, data)


def format_bytes(value: float | None) -> str:
    """Format byte counts using binary units."""
    amount = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


def handshake_age(value: str | None, now: datetime | None = None) -> str:
    """Format an ISO handshake timestamp as elapsed time."""
    if not value:
        return "—"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    current = now or datetime.now(UTC)
    seconds = max(0, int((current - parsed).total_seconds()))
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 48 * 3600:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def main_menu(lang: str, role: str) -> Screen:
    """Build the main navigation screen."""
    rows = [[_button(t(lang, "devices"), "menu:devices")]]
    if role == "admin":
        rows.append([_button(t(lang, "users"), "menu:users")])
        rows.append([_button(t(lang, "requests_menu", count=""), "menu:requests")])
    rows.append([_button(t(lang, "add"), "create:self")])
    if role != "admin":
        rows.append([_button(t(lang, "limit"), "reqlim")])
    rows.append([_button(t(lang, "close"), "close")])
    return Screen(t(lang, "menu"), rows)


def requests_screen(lang: str, requests: list[dict[str, Any]], tab: str, page: int, total: int, pending: int) -> Screen:
    pages = max(1, ((pending if tab == "pending" else total) + 9) // 10)
    page = max(0, min(page, pages - 1))
    rows = [[_button(t(lang, "requests_all", count=total), "reqs:all:0"), _button(t(lang, "requests_pending", count=pending), "reqs:pending:0")]]
    lines = []
    for request in requests:
        status = request.get("status", "pending")
        lines.append(t(lang, "request_row", id=request["id"], icon="⏳" if status == "pending" else "✅", status=t(lang, "request_status_" + status), kind=t(lang, "request_" + request.get("type", "access")), username=request.get("username") or "—", limit=request.get("requested_limit", "—"), date=str(request.get("created_at", "—"))[:10], admin=request.get("admin_username") or "—"))
        if status == "pending":
            rows.append([_button(t(lang, "approve"), f"req:a:{request['id']}"), _button(t(lang, "decline_button"), f"req:d:{request['id']}")])
    if page or page < pages - 1: rows.append([_button("‹", f"reqs:{tab}:{max(0,page-1)}"), _button("›", f"reqs:{tab}:{page+1}")])
    rows.append([_button(t(lang, "back"), "menu")])
    return Screen("\n".join(lines) or t(lang, "none_requests"), rows)


def devices_screen(
    lang: str,
    devices: list[dict[str, Any]],
    flt: str,
    page: int,
    used: int,
    limit: int,
    show_owner: bool = False,
) -> Screen:
    """Build a filtered and paginated device list."""
    predicates = {
        "active": lambda device: bool(device.get("active")),
        "enabled": lambda device: bool(device.get("enabled")),
        "disabled": lambda device: not device.get("enabled"),
    }
    selected = [device for device in devices if flt not in predicates or predicates[flt](device)]
    pages = max(1, (len(selected) + 7) // 8)
    page = max(0, min(page, pages - 1))
    rows = [[_button(t(lang, key), f"dev:{key}:0") for key in ("all", "active", "enabled", "disabled")]]
    for device in selected[page * 8 : page * 8 + 8]:
        name = escape(str(device.get("name", "")), quote=False)
        age = handshake_age(device.get("latest_handshake_at"))
        label = f"{name} {age}"
        if show_owner:
            label += f" · {escape(str(device.get('owner', '')), quote=False)}"
        rows.append([_button(label, f"pinfo:{device['id']}")])
    if page > 0 or page < pages - 1:
        rows.append([_button("‹", f"dev:{flt}:{page - 1}"), _button("›", f"dev:{flt}:{page + 1}")])
    rows.append([_button(t(lang, "close"), "close")])
    shown_limit = "∞" if limit == -1 else str(limit)
    text = t(lang, "limit_line", used=used, limit=shown_limit)
    if show_owner:
        text = t(lang, "devices_total", total=len(devices))
    if not selected:
        text += "\n" + t(lang, "none")
    return Screen(text, rows)


def device_card(lang: str, device: dict[str, Any], can_manage_state: bool = False) -> Screen:
    """Build a device details card."""
    ident = device["id"]
    status = t(lang, "status_on" if device.get("enabled") else "status_off")
    text = t(
        lang,
        "device",
        name=escape(str(device.get("name", "")), quote=False),
        owner=escape(str(device.get("owner", "")), quote=False),
        status=status,
        ip=escape(str(device.get("allowed_ip", "—")), quote=False),
        created=escape(str(device.get("created_at", "—")), quote=False),
        activity=handshake_age(device.get("latest_handshake_at")),
        rx=format_bytes(device.get("rx")),
        tx=format_bytes(device.get("tx")),
    )
    rows = [[_button(t(lang, "download"), f"cfg:{ident}")], [_button(t(lang, "rename"), f"ren:{ident}")]]
    if can_manage_state:
        action = "toggle_off" if device.get("enabled") else "toggle_on"
        rows.append([_button(t(lang, action), f"dev_toggle:{ident}")])
        rows.append([_button(t(lang, "delete"), f"dev_del:{ident}")])
    if can_manage_state:
        rows.append([_button(t(lang, "back"), "menu:devices"), _button(t(lang, "close"), "close")])
        return Screen(text, rows)
    rows.append([_button(t(lang, "back"), "menu:devices"), _button(t(lang, "close"), "close")])
    return Screen(text, rows)


def users_screen(lang: str, users: list[dict[str, Any]], flt: str, page: int) -> Screen:
    filtered = [u for u in users if flt == "all" or (u.get("status") == ("enabled" if flt == "enabled" else "disabled"))]
    filtered.sort(key=lambda u: (u.get("role") != "admin", str(u.get("username", "")).lower()))
    pages = max(1, (len(filtered) + 7) // 8)
    page = max(0, min(page, pages - 1))
    rows = [[_button(t(lang, key), f"users:{key}:{0}") for key in ("all", "enabled", "disabled")]]
    for user in filtered[page * 8:page * 8 + 8]:
        name = str(user.get("username", ""))
        label = ("(admin) " if user.get("role") == "admin" else "") + ("⛔ " if user.get("status") == "disabled" else "") + name
        if len(f"user:{name}".encode()) <= 64:
            rows.append([_button(label, f"user:{name}")])
    if page or page < pages - 1:
        rows.append([_button("‹", f"users:{flt}:{page-1}"), _button("›", f"users:{flt}:{page+1}")])
    rows.append([_button(t(lang, "close"), "close")])
    return Screen(t(lang, "users_total", total=len(filtered)), rows)


def user_card(lang: str, user: dict[str, Any]) -> Screen:
    name = str(user.get("username", ""))
    limit = user.get("config_limit", 3)
    text = t(lang, "user_card", username=escape(name), role=escape(str(user.get("role", "user"))),
             used=user.get("device_count", 0), limit="∞" if limit == -1 else limit,
             tg_id=user.get("tg_id") or "pending", status=t(lang, "status_off" if user.get("status") == "disabled" else "status_on"))
    rows = []
    if len(f"udev:{name}".encode()) <= 64:
        rows.append([_button(t(lang, "user_devices"), f"udev:{name}")])
        for label, data in (("user_limit", f"ulimit:{name}"), ("userdis", f"userdis:{name}"), ("userena", f"userena:{name}"), ("urole", f"urole:{name}:user" if user.get("role") == "admin" else f"urole:{name}:admin"), ("udel", f"udel:{name}")):
            rows.append([_button(t(lang, label), data)])
    rows.append([_button(t(lang, "back"), "menu:users"), _button(t(lang, "close"), "close")])
    return Screen(text, rows)


def request_admin_screen(lang: str, request: dict[str, Any]) -> Screen:
    """Build an administrator request message."""
    ident = request["id"]
    if request.get("type") == "limit":
        text = t(
            lang,
            "limit_request_admin",
            id=ident,
            username=escape(str(request.get("username", "")), quote=False),
            current=request.get("previous_limit", "—"),
            requested=request.get("requested_limit", "—"),
        )
    else:
        name = " ".join(
            part for part in (request.get("first_name"), request.get("last_name")) if part
        ) or "—"
        text = t(
            lang,
            "access_request_admin",
            id=ident,
            username=escape(str(request.get("username") or "—"), quote=False),
            name=escape(str(name), quote=False),
        )
    buttons = [[_button(t(lang, "approve"), f"req:a:{ident}"), _button(t(lang, "decline_button"), f"req:d:{ident}")]]
    return Screen(text, buttons)


def request_done_text(lang: str, request: dict[str, Any]) -> str:
    """Build the final text for edited admin copies."""
    return t(
        lang,
        "request_done_admin",
        id=request["id"],
        status=escape(str(request.get("status", "processed")), quote=False),
        by=escape(str(request.get("admin_username", "")), quote=False),
    )
