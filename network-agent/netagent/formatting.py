"""Convert the agent's Markdown-ish answers to Telegram HTML and split long messages."""

from __future__ import annotations

import html
import re
from typing import Any

TELEGRAM_LIMIT = 3800  # Telegram's hard limit is 4096; leave room for tags


def split_markdown(text: str, limit: int = TELEGRAM_LIMIT) -> list[str]:
    """Split on line boundaries, keeping ``` code fences balanced in every chunk."""
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    in_fence = False
    for line in text.split("\n"):
        while len(line) > limit:  # pathological single long line
            head, line = line[:limit], line[limit:]
            current.append(head)
            chunks.append("\n".join(current) + ("\n```" if in_fence else ""))
            current, size = (["```"] if in_fence else []), 0
        if size + len(line) + 1 > limit and current:
            chunks.append("\n".join(current) + ("\n```" if in_fence else ""))
            current, size = (["```"] if in_fence else []), 0
        current.append(line)
        size += len(line) + 1
        if line.strip().startswith("```"):
            in_fence = not in_fence
    if current and any(part.strip() for part in current):
        chunks.append("\n".join(current) + ("\n```" if in_fence else ""))
    return chunks or [""]


_FENCE_RE = re.compile(r"```[ \t]*([\w+-]*)[ \t]*\n?(.*?)```", re.S)


def _inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*\n]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?m)^#{1,6}\s+(.+)$", r"<b>\1</b>", text)
    return text


def markdown_to_telegram_html(text: str) -> str:
    out: list[str] = []
    pos = 0
    for m in _FENCE_RE.finditer(text):
        out.append(_inline(text[pos : m.start()]))
        code = m.group(2).rstrip("\n")
        out.append(f"<pre>{html.escape(code, quote=False)}</pre>")
        pos = m.end()
    out.append(_inline(text[pos:]))
    return "".join(out).strip()


def first_line(text: str) -> str:
    """First non-empty line (Netmiko errors span many lines of advice)."""
    return next((ln.strip() for ln in str(text).splitlines() if ln.strip()), "")


# Short progress labels for tool calls (shown while the agent works).
TOOL_LABELS = {
    "list_devices": "📋 მოწყობილობების სია",
    "get_device_data": "📡 {device}: {data}",
    "get_data_from_many": "📡 ყველა{filter_s}: {data}",
    "run_show_command": "💻 {device}: {command}",
    "find_on_network": "🔎 ძებნა: {query}",
    "device_config_summary": "📄 {device}: config-ის ანალიზი",
    "ping": "📶 ping {host}",
    "traceroute": "🛣 traceroute {host}",
    "dns_lookup": "🌐 DNS {name}",
    "tcp_port_check": "🔌 {host}:{port}",
    "subnet_calculator": "🧮 subnet {network}",
    "check_reachability": "🩺 ხელმისაწვდომობა{filter_s}",
    "backup_configs": "💾 backup{filter_s}",
    "config_changes": "📝 {device}: ცვლილებები",
    "export_excel": "📊 Excel: {filename}",
    "security_audit": "🛡 აუდიტი{filter_s}",
    "subnet_usage": "🔢 IP-ები: {network}",
    "device_health": "🩺 {device}: მდგომარეობა",
    "latency_history": "📈 {device}: ისტორია",
    "get_notes": "📝 შენიშვნები",
    "save_note": "📝 შენიშვნის შენახვა",
    "delete_note": "📝 შენიშვნის წაშლა",
    "discover_devices": "🔍 სკანირება: {network}",
    "network_topology": "🗺 ქსელის რუკა",
    "syslog_search": "📜 ლოგები",
}


def describe_tool(name: str, args: dict[str, Any]) -> str:
    template = TOOL_LABELS.get(name, f"🔧 {name}")
    filter_s = f" ({args['filter']})" if args.get("filter") else ""
    try:
        return template.format(filter_s=filter_s, **args)
    except (KeyError, IndexError, ValueError):
        return f"🔧 {name}"
