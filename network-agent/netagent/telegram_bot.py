"""Telegram interface.

Run:  python -m netagent.telegram_bot
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from datetime import datetime
from datetime import time as dtime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Message, Update
from telegram.constants import ChatAction, ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from .agent import NetAgent, Reply
from .alerts import ALL, AlertMutes, format_duration, parse_duration
from .audit import log_event
from .config import settings
from .formatting import first_line, markdown_to_telegram_html, split_markdown
from .health import ReachabilityMonitor, check_many
from .inventory import InventoryError
from .security import CommandRejected, mask_secrets, validate_command
from .state import StateStore
from .tools import device as dev
from .tools.extract import extract_network_data
from .usage import UsageTracker
from .history import LatencyHistory
from .notes import NoteStore
from .watch import DeepMonitor

log = logging.getLogger("netagent.telegram")

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_FILE_CHARS_TO_MODEL = 60_000
MAX_INLINE_CMD_OUTPUT = 3500
MAX_IMAGE_BYTES = 5 * 1024 * 1024
IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
DEFAULT_MUTE = 3600

HELP_TEXT = """\
🤖 <b>NetAgent</b> — ქსელის ასისტენტი (მხოლოდ წაკითხვის რეჟიმი)

უბრალოდ მომწერე, მაგალითად:
• <code>R1-ის ინტერფეისების IP-ები მაჩვენე</code>
• <code>192.168.1.57 სადაა ჩართული?</code>
• <code>რომელი IP-ებია თავისუფალი 192.168.10.0/24-ში?</code>
• <code>ყველა მოწყობილობის OS ვერსია Excel-ში</code>
• <code>რა შეიცვალა SW-Core-1-ის კონფიგში?</code>
• <code>რამდენად უსაფრთხოა ქსელი?</code>
• <code>ping R1-დან 8.8.8.8-მდე</code>

📄 ატვირთე config ან log ფაილი და ამოვიღებ IP-ებს, VLAN-ებს, ინტერფეისებს.
📸 გამომიგზავნე ფოტო (ეკრანი, შეცდომა, ტოპოლოგია, rack) და გავაანალიზებ.

<b>სწრაფი ბრძანებები (AI-ს გარეშე, უფასო):</b>
/menu — ღილაკები
/status — რომელი მოწყობილობაა ჩართული/გათიშული
/cmd R1 show ip route — ბრძანება პირდაპირ მოწყობილობაზე
/cmd all show clock — ყველა მოწყობილობაზე
/health R1 — ინტერფეისები, BGP, OSPF, CPU
/graph R1 — latency გრაფიკი (ბოლო 24 სთ)
/discover 10.0.0.0/24 — ახალი მოწყობილობების ძებნა
/note R1 ISP: Magti, ID 12345 — შენიშვნის შენახვა
/notes R1 — შენიშვნები  ·  /delnote R1 2 — წაშლა
/audit — უსაფრთხოების აუდიტი
/backup — config-ების backup
/report — ქსელის რეპორტი
/mute R1 2h — ალერტების დადუმება (/mute all 30m)
/unmute R1 — დადუმების მოხსნა
/usage — AI ხარჯი
/devices — მოწყობილობების სია
/reset — საუბრის თავიდან დაწყება"""

BOT_COMMANDS = [
    BotCommand("menu", "ღილაკების მენიუ"),
    BotCommand("status", "მოწყობილობების სტატუსი (up/down)"),
    BotCommand("cmd", "show ბრძანება: /cmd R1 show ip route"),
    BotCommand("health", "მოწყობილობის მდგომარეობა: /health R1"),
    BotCommand("graph", "latency გრაფიკი: /graph R1"),
    BotCommand("audit", "უსაფრთხოების აუდიტი"),
    BotCommand("discover", "მოწყობილობების ძებნა: /discover 10.0.0.0/24"),
    BotCommand("note", "შენიშვნა: /note R1 ტექსტი"),
    BotCommand("notes", "შენიშვნები: /notes R1"),
    BotCommand("report", "ქსელის რეპორტი"),
    BotCommand("backup", "config-ების backup"),
    BotCommand("mute", "ალერტების დადუმება: /mute R1 2h"),
    BotCommand("unmute", "დადუმების მოხსნა: /unmute R1"),
    BotCommand("usage", "AI ხარჯი"),
    BotCommand("devices", "მოწყობილობების სია"),
    BotCommand("reset", "საუბრის თავიდან დაწყება"),
    BotCommand("help", "დახმარება და მაგალითები"),
    BotCommand("id", "ჩემი Telegram ID"),
]

MENU = InlineKeyboardMarkup(
    [
        [
            InlineKeyboardButton("🩺 სტატუსი", callback_data="status"),
            InlineKeyboardButton("📋 მოწყობილობები", callback_data="devices"),
        ],
        [
            InlineKeyboardButton("📊 რეპორტი", callback_data="report"),
            InlineKeyboardButton("🛡 აუდიტი", callback_data="audit"),
        ],
        [
            InlineKeyboardButton("💾 Backup", callback_data="backup"),
            InlineKeyboardButton("💰 ხარჯი", callback_data="usage"),
        ],
        [
            InlineKeyboardButton("🌐 ყველა IP → Excel", callback_data="ask:all_ips"),
            InlineKeyboardButton("🖥 OS ვერსიები", callback_data="ask:versions"),
        ],
        [
            InlineKeyboardButton("🔴 გათიშული პორტები", callback_data="ask:down_ports"),
            InlineKeyboardButton("🔗 Neighbors", callback_data="ask:neighbors"),
        ],
        [
            InlineKeyboardButton("🔕 დადუმებული", callback_data="mutes"),
            InlineKeyboardButton("📝 შენიშვნები", callback_data="notes_all"),
            InlineKeyboardButton("❓ მაგალითები", callback_data="help"),
            InlineKeyboardButton("🔄 თავიდან", callback_data="reset"),
        ],
    ]
)

FOLLOWUP = InlineKeyboardMarkup(
    [[
        InlineKeyboardButton("🔄 განახლება", callback_data="fu:refresh"),
        InlineKeyboardButton("📊 Excel-ად", callback_data="fu:excel"),
    ]]
)

QUICK_QUESTIONS = {
    "all_ips": "ყველა მოწყობილობიდან ამოიღე ინტერფეისების IP მისამართები და გამიგზავნე Excel ფაილად "
    "(სვეტები: მოწყობილობა, ინტერფეისი, IP, სტატუსი). ჩატში მხოლოდ მოკლე შეჯამება.",
    "versions": "ყველა მოწყობილობის მოდელი, OS ვერსია და uptime ცხრილად.",
    "down_ports": "ყველა მოწყობილობაზე იპოვე ინტერფეისები, რომლებიც down-ია (administratively down ცალკე "
    "აღნიშნე). მოკლედ, მოწყობილობების მიხედვით დაჯგუფებული.",
    "neighbors": "ყველა მოწყობილობის CDP/LLDP neighbor-ები: ვინ ვისთანაა მიერთებული და რომელი პორტებით.",
}
EXCEL_FOLLOWUP = "წინა პასუხის მონაცემები გამომიგზავნე Excel ფაილად (export_excel). ჩატში მხოლოდ მოკლე შეჯამება."

_TOOL_LABELS = {
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
}


def _describe_tool(name: str, args: dict[str, Any]) -> str:
    template = _TOOL_LABELS.get(name, f"🔧 {name}")
    filter_s = f" ({args['filter']})" if args.get("filter") else ""
    try:
        return template.format(filter_s=filter_s, **args)
    except (KeyError, IndexError, ValueError):
        return f"🔧 {name}"


# Created in main() so importing this module needs no API key and touches no files.
agent: NetAgent
mutes: AlertMutes
usage: UsageTracker
notes: NoteStore
history: LatencyHistory
monitor = ReachabilityMonitor()
deep_monitor = DeepMonitor()
_last_question: dict[int, Any] = {}
_pending_discovery: dict[int, tuple[list, str]] = {}


def _is_allowed(update: Update) -> bool:
    user = update.effective_user
    return bool(user and user.id in settings.telegram_allowed_users)


async def _deny(update: Update) -> None:
    user = update.effective_user
    msg = update.effective_message
    if msg and user:
        await msg.reply_text(
            f"⛔ წვდომა არ გაქვს.\nშენი Telegram ID: {user.id}\n"
            "ადმინისტრატორმა უნდა დაამატოს ის TELEGRAM_ALLOWED_USERS-ში (.env)."
        )
    log.warning("denied user %s", user.id if user else "?")


async def send_markdown(message: Message, text: str, reply_markup=None) -> None:
    chunks = [c for c in split_markdown(text) if c.strip()] or ["(ცარიელი)"]
    for i, chunk in enumerate(chunks):
        markup = reply_markup if i == len(chunks) - 1 else None
        try:
            await message.reply_text(
                markdown_to_telegram_html(chunk), parse_mode=ParseMode.HTML, reply_markup=markup
            )
        except BadRequest:
            await message.reply_text(chunk, reply_markup=markup)


async def send_files(message: Message, files: list[Path]) -> None:
    for path in files:
        try:
            with path.open("rb") as fh:
                await message.reply_document(fh, filename=path.name)
        except Exception as exc:  # noqa: BLE001
            log.exception("failed to send %s", path)
            await message.reply_text(f"⚠️ ფაილის გაგზავნა ვერ მოხერხდა: {path.name} ({exc})")


async def _broadcast(app: Application, text: str, reply_markup=None) -> None:
    chunks = split_markdown(text)
    for uid in settings.telegram_allowed_users:
        for i, chunk in enumerate(chunks):
            markup = reply_markup if i == len(chunks) - 1 else None
            try:
                await app.bot.send_message(
                    uid, markdown_to_telegram_html(chunk), parse_mode=ParseMode.HTML, reply_markup=markup
                )
            except Exception:  # noqa: BLE001 - user may have never started the bot
                log.warning("could not message user %s", uid)


def _mute_buttons(devices: list[str]) -> InlineKeyboardMarkup | None:
    rows = []
    for name in devices[:6]:
        data = f"mute:{name}:{DEFAULT_MUTE}"
        if len(data.encode()) <= 64:  # Telegram callback_data limit
            rows.append([InlineKeyboardButton(f"🔕 {name} — 1 სთ", callback_data=data)])
    if len(devices) > 1:
        rows.append([InlineKeyboardButton("🔕 ყველა — 1 სთ", callback_data=f"mute:{ALL}:{DEFAULT_MUTE}")])
    return InlineKeyboardMarkup(rows) if rows else None


async def _typing_loop(context: ContextTypes.DEFAULT_TYPE, chat_id: int, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await context.bot.send_chat_action(chat_id, ChatAction.TYPING)
        except Exception:  # noqa: BLE001
            pass
        try:
            await asyncio.wait_for(stop.wait(), timeout=4.5)
        except asyncio.TimeoutError:
            pass


async def _ask_agent(update: Update, context: ContextTypes.DEFAULT_TYPE, content: Any, remember: bool = True) -> None:
    message = update.effective_message
    chat_id = update.effective_chat.id
    if remember:
        _last_question[chat_id] = content
    loop = asyncio.get_running_loop()
    status = await message.reply_text("⏳ ვამუშავებ...")
    steps: list[str] = []

    def _ignore_result(fut) -> None:
        try:
            fut.result()
        except Exception:  # noqa: BLE001 - "message is not modified" etc.
            pass

    def on_tool(name: str, args: dict[str, Any]) -> None:
        steps.append(_describe_tool(name, args))
        body = "⏳ ვამუშავებ...\n" + "\n".join(steps[-10:])
        fut = asyncio.run_coroutine_threadsafe(status.edit_text(body[:4000]), loop)
        fut.add_done_callback(_ignore_result)

    stop = asyncio.Event()
    typing_task = asyncio.create_task(_typing_loop(context, chat_id, stop))
    try:
        reply: Reply = await asyncio.to_thread(
            agent.chat,
            f"tg:{chat_id}",
            content,
            user=f"telegram:{update.effective_user.id}",
            channel="telegram",
            on_tool=on_tool,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("agent failure")
        reply = Reply(f"⚠️ შიდა შეცდომა: {type(exc).__name__}")
    finally:
        stop.set()
        await typing_task

    try:
        await status.delete()
    except Exception:  # noqa: BLE001
        pass
    # Follow-up buttons only on real answers that did not already produce a file.
    followup = FOLLOWUP if steps and not reply.files and not reply.text.startswith(("⚠️", "💰")) else None
    await send_markdown(message, reply.text, reply_markup=followup)
    await send_files(message, reply.files)


# ---------------------------------------------------------------------------
# Deterministic actions (no AI cost)
# ---------------------------------------------------------------------------

def _format_status() -> str:
    inv = agent.inventory()
    results = check_many(list(inv.devices.values()))
    if not results:
        return "inventory ცარიელია."
    up = sum(r.up for r in results)
    lines = [f"🩺 **სტატუსი**: {up}/{len(results)} ხელმისაწვდომი", "```"]
    for r in sorted(results, key=lambda r: (r.up, r.device)):
        mark = "🟢" if r.up else "🔴"
        extra = f"{r.latency_ms:.0f}ms" if r.up and r.latency_ms is not None else r.reason
        muted = " 🔕" if mutes.is_muted(r.device) else ""
        lines.append(f"{mark} {r.device:<14} {r.host:<15} {extra}{muted}")
    lines.append("```")
    return "\n".join(lines)


def _format_devices() -> str:
    inv = agent.inventory()
    if not inv.devices:
        return "inventory ცარიელია."
    lines = [f"{d.name:<14} {d.host:<15} {d.device_type}" for d in inv.devices.values()]
    return f"📋 მოწყობილობები ({len(lines)}):\n```\n" + "\n".join(lines) + "\n```"


def _run_backup() -> str:
    from .backup import BackupStore, backup_devices

    inv = agent.inventory()
    devices = list(inv.devices.values())
    if not devices:
        return "inventory ცარიელია."
    reach = {r.device: r for r in check_many(devices)}
    reachable = [d for d in devices if reach[d.name].up]
    results = backup_devices(inv, reachable, BackupStore(settings.backup_dir)) if reachable else {}
    lines = ["💾 **Backup**", "```"]
    for d in devices:
        if not reach[d.name].up:
            lines.append(f"🔴 {d.name:<14} მიუწვდომელია ({reach[d.name].reason})")
    for name, r in results.items():
        if "error" in r:
            lines.append(f"⚠️ {name:<14} {first_line(r['error'])[:60]}")
        elif r.get("first_backup"):
            lines.append(f"🆕 {name:<14} პირველი backup")
        elif r.get("saved"):
            lines.append(f"📝 {name:<14} შეიცვალა +{r.get('added', 0)}/-{r.get('removed', 0)}")
        else:
            lines.append(f"✅ {name:<14} ცვლილება არ არის")
    lines.append("```")
    return "\n".join(lines)


def _run_report() -> str:
    from .report import build_report

    return build_report(agent.inventory(), mutes=mutes, usage=usage)


def _run_audit() -> str:
    from .compliance import format_findings
    from .report import run_security_audit

    results, duplicates, errors = run_security_audit(agent.inventory())
    if not results and not errors:
        return "inventory ცარიელია."
    return format_findings(results, duplicates, errors)


_ACTIONS = {
    "status": ("🩺 ვამოწმებ მოწყობილობებს...", _format_status),
    "devices": (None, _format_devices),
    "backup": ("💾 ვიღებ backup-ს...", _run_backup),
    "report": ("📊 ვამზადებ რეპორტს...", _run_report),
    "audit": ("🛡 ვამოწმებ კონფიგურაციებს...", _run_audit),
    "usage": (None, lambda: usage.summary()),
    "mutes": (None, lambda: mutes.describe()),
    "notes_all": (None, lambda: _notes_overview()),
}


def _notes_overview() -> str:
    from .notes import GENERAL

    data = notes.all()
    if not data:
        return "📝 შენიშვნები ჯერ არ არის.\nდამატება: /note R1 ტექსტი  ან უბრალოდ მომწერე „დაიმახსოვრე ...“"
    lines = ["📝 **შენიშვნები:**"]
    for target, items in sorted(data.items()):
        name = "ზოგადი" if target == GENERAL else target
        lines.append(f"• {name}: {len(items)}  → /notes {'' if target == GENERAL else target}".rstrip())
    return "\n".join(lines)


async def _run_action(message: Message, action: str) -> None:
    waiting, fn = _ACTIONS[action]
    note = await message.reply_text(waiting) if waiting else None
    try:
        text = await asyncio.to_thread(fn)
    except Exception as exc:  # noqa: BLE001
        log.exception("action %s failed", action)
        text = f"⚠️ {exc}"
    if note:
        try:
            await note.delete()
        except Exception:  # noqa: BLE001
            pass
    await send_markdown(message, text)


def run_cmd(target: str, command: str, user: str) -> tuple[str, Path | None]:
    """/cmd: run one read-only command on a device, a filter match, or all devices."""
    inv = agent.inventory()
    if target.lower() in {"all", "*", "ყველა"}:
        devices = list(inv.devices.values())
    else:
        try:
            devices = [inv.get(target)]
        except InventoryError:
            devices = inv.filter(target)
            if not devices:
                raise
    for d in devices:
        validate_command(command, d.device_type)

    results = dev.run_on_devices(
        inv, devices, lambda d: dev.run_commands(inv, d, [command], parse=False, max_chars=200_000)
    )
    for d in devices:
        r = results[d.name]
        ok = isinstance(r, list) and bool(r) and "error" not in r[0]
        log_event(settings.audit_log_path, user=user, tool="telegram_cmd",
                  args={"device": d.name, "command": command}, ok=ok, device_access=True)

    parts = []
    for name, r in results.items():
        if isinstance(r, dict) and "error" in r:
            parts.append(f"⚠️ {name}: {first_line(r['error'])}")
            continue
        res = r[0]
        body = res.get("output") if "output" in res else f"⚠️ {first_line(res.get('error', ''))}"
        parts.append(f"📟 **{name}** › `{command}`\n```\n{(body or '(ცარიელი)').rstrip()}\n```")
    text = "\n\n".join(parts)
    if len(text) <= MAX_INLINE_CMD_OUTPUT:
        return text, None

    settings.export_dir.mkdir(parents=True, exist_ok=True)
    path = settings.export_dir / f"cmd-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
    plain = "\n\n".join(
        f"===== {name}: {command} =====\n"
        + ((r[0].get("output") or r[0].get("error", "")) if isinstance(r, list) else r.get("error", ""))
        for name, r in results.items()
    )
    path.write_text(plain, encoding="utf-8")
    return f"📟 `{command}` — {len(devices)} მოწყობილობა, output დიდია, გიგზავნი ფაილად.", path


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    await update.effective_message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML, reply_markup=MENU)


async def cmd_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    await update.effective_message.reply_text("აირჩიე:", reply_markup=MENU)


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(f"შენი Telegram ID: {update.effective_user.id}")


async def cmd_reset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    agent.reset(f"tg:{update.effective_chat.id}")
    _last_question.pop(update.effective_chat.id, None)
    await update.effective_message.reply_text("🔄 საუბარი თავიდან დაიწყო.")


async def cmd_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    message = update.effective_message
    args = context.args or []
    if len(args) < 2:
        return await message.reply_text(
            "გამოყენება:\n/cmd R1 show ip interface brief\n/cmd all show clock\n/cmd HQ show version"
        )
    target, command = args[0], " ".join(args[1:])
    note = await message.reply_text(f"💻 {target}: {command} ...")
    try:
        text, path = await asyncio.to_thread(run_cmd, target, command, f"telegram:{update.effective_user.id}")
    except (CommandRejected, InventoryError) as exc:
        text, path = f"⛔ {exc}", None
    except Exception as exc:  # noqa: BLE001
        log.exception("/cmd failed")
        text, path = f"⚠️ {first_line(str(exc))}", None
    try:
        await note.delete()
    except Exception:  # noqa: BLE001
        pass
    await send_markdown(message, text)
    if path:
        await send_files(message, [path])


def _mute_target(name: str) -> str:
    if name.lower() in {"all", "*", "ყველა"}:
        return ALL
    return agent.inventory().get(name).name  # raises InventoryError for unknown devices


async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    args = context.args or []
    if not args:
        return await update.effective_message.reply_text(
            "გამოყენება: /mute R1 2h  ·  /mute all 30m  ·  /mute R1 (1 სთ)\n\n" + mutes.describe()
        )
    try:
        target = _mute_target(args[0])
        seconds = parse_duration(args[1]) if len(args) > 1 else DEFAULT_MUTE
    except (InventoryError, ValueError) as exc:
        return await update.effective_message.reply_text(f"⚠️ {exc}")
    mutes.mute(target, seconds)
    name = "ყველა მოწყობილობა" if target == ALL else target
    await update.effective_message.reply_text(f"🔕 {name}: ალერტები დადუმებულია {format_duration(seconds)}-ით.")


async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    args = context.args or []
    if not args or args[0].lower() in {"all", "*", "ყველა"}:
        mutes.unmute_all()
        return await update.effective_message.reply_text("🔔 ყველა დადუმება მოიხსნა.")
    try:
        target = _mute_target(args[0])
    except InventoryError as exc:
        return await update.effective_message.reply_text(f"⚠️ {exc}")
    existed = mutes.unmute(target)
    await update.effective_message.reply_text(
        f"🔔 {target}: დადუმება მოიხსნა." if existed else f"{target} დადუმებული არ იყო."
    )


def _resolve_device(name: str):
    return agent.inventory().get(name)


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    from .watch import collect, format_health_text

    message = update.effective_message
    if not context.args:
        return await message.reply_text("გამოყენება: /health R1")
    try:
        device = _resolve_device(context.args[0])
    except InventoryError as exc:
        return await message.reply_text(f"⚠️ {exc}")
    note = await message.reply_text(f"🩺 ვამოწმებ {device.name}...")
    try:
        snap = await asyncio.to_thread(collect, agent.inventory(), device, True)
        text = format_health_text(device.name, snap)
    except Exception as exc:  # noqa: BLE001
        text = f"⚠️ {device.name}: {first_line(str(exc))}"
    try:
        await note.delete()
    except Exception:  # noqa: BLE001
        pass
    await send_markdown(message, text)


async def cmd_graph(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    from .charts import latency_chart

    message = update.effective_message
    args = context.args or []
    if not args:
        return await message.reply_text("გამოყენება: /graph R1  ან  /graph R1 48")
    try:
        device = _resolve_device(args[0])
        hours = max(1, min(336, int(args[1]))) if len(args) > 1 else 24
    except (InventoryError, ValueError) as exc:
        return await message.reply_text(f"⚠️ {exc}")
    points = history.read(device.name, hours)
    if not points:
        return await message.reply_text(
            f"📈 {device.name}: ისტორია ჯერ არ არის. მონიტორინგი ყოველ {settings.monitor_interval} წუთში აგროვებს მონაცემებს."
        )
    stats = history.stats(device.name, hours)
    path = settings.export_dir / f"latency-{device.name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.png"
    try:
        await asyncio.to_thread(latency_chart, device.name, points, path, hours, stats)
    except Exception as exc:  # noqa: BLE001
        log.exception("chart failed")
        return await message.reply_text(f"⚠️ გრაფიკი ვერ შეიქმნა: {exc}")
    caption = f"{device.name}: uptime {stats['uptime_percent']}%" + (
        f", საშ. {stats['avg_ms']} ms, მაქს. {stats['max_ms']} ms" if "avg_ms" in stats else "")
    with path.open("rb") as fh:
        await message.reply_photo(fh, caption=caption)


async def cmd_discover(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    from .discovery import discover, format_candidates

    message = update.effective_message
    args = context.args or []
    if not args:
        return await message.reply_text(
            "გამოყენება: /discover 10.0.0.0/24\nსხვა credentials პროფილით: /discover 10.0.0.0/24 mikrotik"
        )
    network, cred = args[0], (args[1] if len(args) > 1 else "default")
    note = await message.reply_text(f"🔍 ვასკანერებ {network} (შეიძლება 1-2 წუთი დასჭირდეს)...")
    try:
        cands = await asyncio.to_thread(discover, agent.inventory(), network, 22, cred)
        text = format_candidates(cands)
    except Exception as exc:  # noqa: BLE001
        cands, text = [], f"⚠️ {first_line(str(exc))}"
    try:
        await note.delete()
    except Exception:  # noqa: BLE001
        pass
    new = [c for c in cands if c.device_type and not c.already_in_inventory]
    markup = None
    if new:
        _pending_discovery[update.effective_chat.id] = (new, cred)
        markup = InlineKeyboardMarkup([[
            InlineKeyboardButton(f"➕ დამატება ({len(new)})", callback_data="disc:add"),
            InlineKeyboardButton("❌ არა", callback_data="disc:cancel"),
        ]])
    await send_markdown(message, text, reply_markup=markup)


def _split_target(args: list[str]) -> tuple[str, list[str]]:
    """First argument is a device if it exists in the inventory, otherwise the note is general."""
    if args:
        try:
            return _resolve_device(args[0]).name, args[1:]
        except InventoryError:
            pass
    return "", args


async def cmd_note(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    target, rest = _split_target(context.args or [])
    text = " ".join(rest).strip()
    if not text:
        return await update.effective_message.reply_text(
            "გამოყენება: /note R1 ISP: Magti, circuit 12345\nზოგადი: /note ოფისის ქსელი 10.0.0.0/16"
        )
    try:
        count = notes.add(target, text, author=f"telegram:{update.effective_user.id}")
    except ValueError as exc:
        return await update.effective_message.reply_text(f"⚠️ {exc}")
    await update.effective_message.reply_text(f"📝 შენახულია ({target or 'ზოგადი'}, სულ {count}).")


async def cmd_notes(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    if not context.args:
        return await send_markdown(update.effective_message, _notes_overview())
    target, _ = _split_target(context.args)
    if not target and context.args[0].lower() not in {"general", "ზოგადი"}:
        return await update.effective_message.reply_text(f"⚠️ მოწყობილობა '{context.args[0]}' ვერ ვიპოვე")
    await send_markdown(update.effective_message, notes.format(target))


async def cmd_delnote(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    target, rest = _split_target(context.args or [])
    try:
        removed = notes.delete(target, int(rest[0]))
    except (IndexError, ValueError) as exc:
        msg = str(exc) if isinstance(exc, ValueError) and "შენიშვნა" in str(exc) else "გამოყენება: /delnote R1 2"
        return await update.effective_message.reply_text(f"⚠️ {msg}")
    await update.effective_message.reply_text(f"🗑 წაიშალა: {removed.get('text', '')[:100]}")


def _action_command(action: str):
    async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not _is_allowed(update):
            return await _deny(update)
        await _run_action(update.effective_message, action)

    return handler


async def on_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not _is_allowed(update):
        await query.answer("⛔ წვდომა არ გაქვს", show_alert=True)
        return
    data = query.data or ""
    chat_id = update.effective_chat.id

    if data.startswith("mute:"):
        target, _, secs = data[len("mute:"):].rpartition(":")
        if not target or not secs.isdigit():
            return await query.answer()
        mutes.mute(target, int(secs))
        name = "ყველა" if target == ALL else target
        await query.answer(f"🔕 {name} დადუმდა {format_duration(int(secs))}-ით")
        await query.message.reply_text(f"🔕 {name}: ალერტები დადუმებულია {format_duration(int(secs))}-ით. მოხსნა: /unmute")
        return

    await query.answer()
    if data in {"disc:add", "disc:cancel"}:
        pending = _pending_discovery.pop(chat_id, None)
        if data == "disc:cancel" or not pending:
            return await query.message.reply_text("გაუქმდა." if data == "disc:cancel" else "ეს სია ვადაგასულია, თავიდან გაუშვი /discover.")
        from .discovery import add_to_inventory

        cands, cred = pending
        try:
            added = await asyncio.to_thread(add_to_inventory, settings.inventory_path, cands, cred)
        except Exception as exc:  # noqa: BLE001
            return await query.message.reply_text(f"⚠️ inventory-ში ჩაწერა ვერ მოხერხდა: {exc}")
        return await query.message.reply_text(
            f"✅ დაემატა {len(added)}: " + ", ".join(added) + "\nსახელები შეგიძლია შეცვალო inventory/devices.yaml-ში."
            if added else "ახალი არაფერი დაემატა."
        )
    if data in _ACTIONS:
        await _run_action(query.message, data)
    elif data == "help":
        await query.message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML)
    elif data == "reset":
        agent.reset(f"tg:{chat_id}")
        _last_question.pop(chat_id, None)
        await query.message.reply_text("🔄 საუბარი თავიდან დაიწყო.")
    elif data.startswith("ask:") and data[4:] in QUICK_QUESTIONS:
        await _ask_agent(update, context, QUICK_QUESTIONS[data[4:]])
    elif data == "fu:refresh":
        if chat_id not in _last_question:
            return await query.message.reply_text("გასამეორებელი კითხვა არ მაქვს.")
        await _ask_agent(update, context, _last_question[chat_id])
    elif data == "fu:excel":
        await _ask_agent(update, context, EXCEL_FOLLOWUP, remember=False)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    await _ask_agent(update, context, update.effective_message.text)


def _image_content(data: bytes, media_type: str, caption: str | None) -> list[dict]:
    return [
        {"type": "image", "source": {"type": "base64", "media_type": media_type,
                                     "data": base64.b64encode(data).decode("ascii")}},
        {"type": "text", "text": caption or "რა ჩანს ამ სურათზე? თუ შეცდომაა ან პრობლემა — ამიხსენი და მითხარი, როგორ გავასწორო."},
    ]


async def on_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    message = update.effective_message
    photo = message.photo[-1]  # largest size
    if photo.file_size and photo.file_size > MAX_IMAGE_BYTES:
        return await message.reply_text("⚠️ სურათი ძალიან დიდია (მაქს. 5 MB).")
    data = bytes(await (await photo.get_file()).download_as_bytearray())
    await _ask_agent(update, context, _image_content(data, "image/jpeg", message.caption))


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    message = update.effective_message
    doc = message.document
    if (doc.mime_type or "").lower() in IMAGE_TYPES:
        if doc.file_size and doc.file_size > MAX_IMAGE_BYTES:
            return await message.reply_text("⚠️ სურათი ძალიან დიდია (მაქს. 5 MB).")
        data = bytes(await (await doc.get_file()).download_as_bytearray())
        return await _ask_agent(update, context, _image_content(data, doc.mime_type.lower(), message.caption))
    if doc.file_size and doc.file_size > MAX_UPLOAD_BYTES:
        return await message.reply_text("⚠️ ფაილი ძალიან დიდია (მაქს. 2 MB).")
    tg_file = await doc.get_file()
    raw = bytes(await tg_file.download_as_bytearray())
    if raw.count(b"\x00") > 10:
        return await message.reply_text("⚠️ ეს ტექსტური ფაილი არ არის (config, log, txt, csv...).")
    text = mask_secrets(raw.decode("utf-8", errors="replace"))
    extracted = extract_network_data(text)
    question = message.caption or "გააანალიზე ეს ფაილი: ამოიღე IP მისამართები, ქსელები, VLAN-ები, ინტერფეისები და აღნიშნე პრობლემები."
    truncated = len(text) > MAX_FILE_CHARS_TO_MODEL
    content = [
        {"type": "text", "text": question},
        {
            "type": "text",
            "text": (
                f"<uploaded_file name={json.dumps(doc.file_name or 'file.txt')}>\n"
                f"{text[:MAX_FILE_CHARS_TO_MODEL]}\n"
                f"</uploaded_file>"
                + ("\n(ფაილი შემოკლებულია, სრული ამოღება იხ. ქვემოთ)" if truncated else "")
            ),
        },
        {
            "type": "text",
            "text": "Automatic extraction from the full file (exact, deterministic):\n"
            + json.dumps(extracted, ensure_ascii=False, indent=1),
        },
    ]
    await _ask_agent(update, context, content)


# ---------------------------------------------------------------------------
# Scheduled jobs
# ---------------------------------------------------------------------------

async def job_monitor(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        inv = agent.inventory()
        results = await asyncio.to_thread(check_many, list(inv.devices.values()))
    except Exception:  # noqa: BLE001
        log.exception("monitor check failed")
        return
    try:
        await asyncio.to_thread(history.record, results)
    except Exception:  # noqa: BLE001
        log.exception("history record failed")
    downtimes = {r.device: monitor.down_duration(r.device) for r in results if r.up}
    changes = [(r, s) for r, s in monitor.update(results) if not mutes.is_muted(r.device)]
    if not changes:
        return
    lines = []
    for r, state in changes:
        if state == "down":
            lines.append(f"🔴 **{r.device}** ({r.host}) მიუწვდომელია — {r.reason}")
        else:
            took = downtimes.get(r.device)
            lines.append(
                f"🟢 **{r.device}** ({r.host}) ისევ ხელმისაწვდომია"
                + (f" (გათიშული იყო {format_duration(took)})" if took else "")
            )
    down = [r.device for r, s in changes if s == "down"]
    await _broadcast(context.application, "🚨 **ალერტი**\n" + "\n".join(lines), _mute_buttons(down))


async def job_deep_monitor(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        inv = agent.inventory()
        alerts = await asyncio.to_thread(deep_monitor.run, inv, list(inv.devices.values()))
    except Exception:  # noqa: BLE001
        log.exception("deep monitor failed")
        return
    alerts = [(d, a) for d, a in alerts if not mutes.is_muted(d)]
    if not alerts:
        return
    devices = sorted({d for d, _ in alerts})
    await _broadcast(context.application, "🚨 **ალერტი**\n" + "\n".join(a for _, a in alerts), _mute_buttons(devices))


def _diff_snippet(diff: str, max_lines: int = 15) -> str:
    changed = [
        ln for ln in diff.splitlines()
        if (ln.startswith("+") or ln.startswith("-")) and not ln.startswith(("+++", "---"))
    ]
    more = len(changed) - max_lines
    return "\n".join(changed[:max_lines]) + (f"\n... (+{more} ხაზი)" if more > 0 else "")


def detect_config_changes() -> list[dict]:
    """Back up reachable devices; return the ones whose configuration changed."""
    from .backup import BackupStore, backup_devices

    inv = agent.inventory()
    devices = list(inv.devices.values())
    reachable = [inv.devices[r.device] for r in check_many(devices) if r.up]
    if not reachable:
        return []
    results = backup_devices(inv, reachable, BackupStore(settings.backup_dir))
    return [
        {"device": name, **r}
        for name, r in results.items()
        if r.get("saved") and not r.get("first_backup") and r.get("diff")
    ]


async def job_config_watch(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        changes = await asyncio.to_thread(detect_config_changes)
    except Exception:  # noqa: BLE001
        log.exception("config watch failed")
        return
    changes = [c for c in changes if not mutes.is_muted(c["device"])]
    for c in changes:
        text = (
            f"📝 **{c['device']}**: კონფიგურაცია შეიცვალა (+{c.get('added', 0)} / −{c.get('removed', 0)})\n"
            f"```\n{_diff_snippet(c['diff'])}\n```\n"
            f"ახსნისთვის მკითხე: „რა შეიცვალა {c['device']}-ზე?“"
        )
        await _broadcast(context.application, text, _mute_buttons([c["device"]]))


async def job_daily_report(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        text = await asyncio.to_thread(_run_report)
    except Exception as exc:  # noqa: BLE001
        log.exception("daily report failed")
        text = f"⚠️ დღიური რეპორტი ვერ შედგა: {exc}"
    await _broadcast(context.application, text)


def _parse_hhmm(value: str) -> tuple[int, int] | None:
    try:
        h, m = value.split(":")
        h, m = int(h), int(m)
        if 0 <= h < 24 and 0 <= m < 60:
            return h, m
    except ValueError:
        pass
    return None


async def _post_init(app: Application) -> None:
    try:
        await app.bot.set_my_commands(BOT_COMMANDS)
    except Exception:  # noqa: BLE001
        log.warning("could not set bot commands")

    jq = app.job_queue
    if jq is None:
        log.warning("JobQueue მიუწვდომელია: pip install 'python-telegram-bot[job-queue]' — მონიტორინგი გამორთულია")
        return
    if settings.monitor_interval > 0:
        jq.run_repeating(job_monitor, interval=settings.monitor_interval * 60, first=20, name="monitor")
        log.info("reachability monitoring every %s min", settings.monitor_interval)
    if settings.deep_monitor_interval > 0:
        jq.run_repeating(
            job_deep_monitor, interval=settings.deep_monitor_interval * 60, first=45, name="deep_monitor"
        )
        log.info("deep monitoring (watch) every %s min", settings.deep_monitor_interval)
    if settings.config_watch_interval > 0:
        jq.run_repeating(
            job_config_watch, interval=settings.config_watch_interval * 60, first=90, name="config_watch"
        )
        log.info("config change detection every %s min", settings.config_watch_interval)
    hhmm = _parse_hhmm(settings.daily_report_time) if settings.daily_report_time else None
    if hhmm:
        tz = ZoneInfo(settings.timezone)
        jq.run_daily(job_daily_report, time=dtime(hhmm[0], hhmm[1], tzinfo=tz), name="daily_report")
        log.info("daily report at %02d:%02d %s", hhmm[0], hhmm[1], settings.timezone)


def init_services() -> None:
    """Create the agent and persistent state (separate from main() for testing)."""
    global agent, mutes, usage, notes, history
    state = StateStore(settings.data_dir / "state.json")
    mutes = AlertMutes(state)
    usage = UsageTracker(state, settings.daily_budget_usd)
    notes = NoteStore(state)
    history = LatencyHistory(settings.data_dir / "latency")
    agent = NetAgent(usage=usage, notes=notes, history=history)


def main() -> None:
    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if not settings.telegram_token:
        raise SystemExit("TELEGRAM_BOT_TOKEN არ არის მითითებული .env ფაილში")
    if not settings.telegram_allowed_users:
        log.warning(
            "TELEGRAM_ALLOWED_USERS ცარიელია — ბოტი ყველას უარს ეტყვის. "
            "მიწერე ბოტს /id, შემდეგ ჩაწერე ID .env-ში და გადატვირთე."
        )
    init_services()

    app = (
        Application.builder()
        .token(settings.telegram_token)
        .concurrent_updates(True)
        .post_init(_post_init)
        .build()
    )
    app.add_handler(CommandHandler(["start", "help"], cmd_start))
    app.add_handler(CommandHandler("menu", cmd_menu))
    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(CommandHandler("reset", cmd_reset))
    app.add_handler(CommandHandler("cmd", cmd_cmd))
    app.add_handler(CommandHandler("mute", cmd_mute))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_handler(CommandHandler("health", cmd_health))
    app.add_handler(CommandHandler("graph", cmd_graph))
    app.add_handler(CommandHandler("discover", cmd_discover))
    app.add_handler(CommandHandler("note", cmd_note))
    app.add_handler(CommandHandler("notes", cmd_notes))
    app.add_handler(CommandHandler("delnote", cmd_delnote))
    for action in _ACTIONS:
        app.add_handler(CommandHandler(action, _action_command(action)))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.PHOTO, on_photo))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    log.info("NetAgent Telegram bot started (model=%s)", settings.model)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
