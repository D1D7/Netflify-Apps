"""Roles for app users: admin (everything) and viewer (sees everything, changes nothing).

Who is acting travels as a plain string through commands and AI tools:
    "app:<name>"   admin account in the app          "view:<name>"  viewer account in the app
    "telegram:<id>", "cli:<user>", "remote:<ip>"      (unchanged)
"""

from __future__ import annotations

# Commands that change something (settings, devices, NetAgent itself) or wake/act on the network.
VIEWER_BLOCKED_COMMANDS = {
    "change", "approve", "reject", "save-change", "undo",          # device configuration
    "update", "selfbackup", "notify", "import", "demo",              # NetAgent itself / its data
    "mute", "unmute", "maintenance", "ack", "schedule", "unschedule",
    "note", "delnote", "discover-add", "discover-cancel", "site",
    "name", "wake", "users",
}
VIEWER_BLOCKED_TOOLS = {"save_note", "delete_note", "ipam_set", "propose_config_change"}


def web_user(name: str, role: str) -> str:
    return f"{'view' if role == 'viewer' else 'app'}:{name}"


def is_viewer(user: str) -> bool:
    return (user or "").startswith("view:")


def display_name(user: str) -> str:
    """'app:nodo' -> 'nodo', 'view:gio' -> 'gio (ნახვა)', 'telegram:123' -> 'Telegram 123'."""
    kind, _, rest = (user or "?").partition(":")
    if kind == "app":
        return rest or "admin"
    if kind == "view":
        return f"{rest} (ნახვა)"
    if kind == "telegram":
        return f"Telegram {rest}"
    if kind == "remote":
        return f"სხვა NetAgent ({rest})"
    return user or "?"


DENIED = "⛔ შენს ანგარიშს მხოლოდ ნახვის უფლება აქვს — ეს ბრძანება ადმინისტრატორს შეუძლია."
