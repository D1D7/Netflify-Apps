"""Telegram interface.

Run:  python -m netagent.telegram_bot
"""

from __future__ import annotations

import asyncio
import json
import logging
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
from .formatting import first_line
from .config import settings
from .formatting import markdown_to_telegram_html, split_markdown
from .health import ReachabilityMonitor, check_many
from .security import mask_secrets
from .tools.extract import extract_network_data

log = logging.getLogger("netagent.telegram")

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_FILE_CHARS_TO_MODEL = 60_000

HELP_TEXT = """\
🤖 <b>NetAgent</b> — ქსელის ასისტენტი (მხოლოდ წაკითხვის რეჟიმი)

უბრალოდ მომწერე, მაგალითად:
• <code>R1-ის ინტერფეისების IP-ები მაჩვენე</code>
• <code>192.168.1.57 სადაა ჩართული?</code>
• <code>რომელ მოწყობილობაზეა 10.10.0.0/24?</code>
• <code>ყველა მოწყობილობის OS ვერსია Excel-ში</code>
• <code>რა შეიცვალა SW-Core-1-ის კონფიგში?</code>
• <code>10.0.0.0/22 დაყავი /26-ებად</code>

📄 ატვირთე config ან log ფაილი და ამოვიღებ IP-ებს, VLAN-ებს, ინტერფეისებს.

ბრძანებები:
/menu — ღილაკები
/status — რომელი მოწყობილობაა ჩართული/გათიშული
/backup — ყველა config-ის backup
/report — ქსელის რეპორტი
/devices — მოწყობილობების სია
/reset — საუბრის თავიდან დაწყება
/id — შენი Telegram ID"""

BOT_COMMANDS = [
    BotCommand("menu", "ღილაკების მენიუ"),
    BotCommand("status", "მოწყობილობების სტატუსი (up/down)"),
    BotCommand("report", "ქსელის რეპორტი"),
    BotCommand("backup", "config-ების backup"),
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
            InlineKeyboardButton("💾 Backup", callback_data="backup"),
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
            InlineKeyboardButton("❓ მაგალითები", callback_data="help"),
            InlineKeyboardButton("🔄 თავიდან", callback_data="reset"),
        ],
    ]
)

QUICK_QUESTIONS = {
    "all_ips": "ყველა მოწყობილობიდან ამოიღე ინტერფეისების IP მისამართები და გამიგზავნე Excel ფაილად "
    "(სვეტები: მოწყობილობა, ინტერფეისი, IP, სტატუსი). ჩატში მხოლოდ მოკლე შეჯამება.",
    "versions": "ყველა მოწყობილობის მოდელი, OS ვერსია და uptime ცხრილად.",
    "down_ports": "ყველა მოწყობილობაზე იპოვე ინტერფეისები, რომლებიც down-ია (administratively down ცალკე "
    "აღნიშნე). მოკლედ, მოწყობილობების მიხედვით დაჯგუფებული.",
    "neighbors": "ყველა მოწყობილობის CDP/LLDP neighbor-ები: ვინ ვისთანაა მიერთებული და რომელი პორტებით.",
}

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
}


def _describe_tool(name: str, args: dict[str, Any]) -> str:
    template = _TOOL_LABELS.get(name, f"🔧 {name}")
    filter_s = f" ({args['filter']})" if args.get("filter") else ""
    try:
        return template.format(filter_s=filter_s, **args)
    except (KeyError, IndexError, ValueError):
        return f"🔧 {name}"


agent: NetAgent  # created in main() so importing this module needs no API key
monitor = ReachabilityMonitor()


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


async def _broadcast(app: Application, text: str) -> None:
    for uid in settings.telegram_allowed_users:
        for chunk in split_markdown(text):
            try:
                await app.bot.send_message(uid, markdown_to_telegram_html(chunk), parse_mode=ParseMode.HTML)
            except Exception:  # noqa: BLE001 - user may have never started the bot
                log.warning("could not message user %s", uid)


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


async def _ask_agent(update: Update, context: ContextTypes.DEFAULT_TYPE, content: Any) -> None:
    message = update.effective_message
    chat_id = update.effective_chat.id
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
    await send_markdown(message, reply.text)
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
        lines.append(f"{mark} {r.device:<14} {r.host:<15} {extra}")
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

    return build_report(agent.inventory())


_ACTIONS = {
    "status": ("🩺 ვამოწმებ მოწყობილობებს...", _format_status),
    "devices": (None, _format_devices),
    "backup": ("💾 ვიღებ backup-ს...", _run_backup),
    "report": ("📊 ვამზადებ რეპორტს...", _run_report),
}


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
    await update.effective_message.reply_text("🔄 საუბარი თავიდან დაიწყო.")


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
    await query.answer()
    data = query.data or ""
    if data in _ACTIONS:
        await _run_action(query.message, data)
    elif data == "help":
        await query.message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML)
    elif data == "reset":
        agent.reset(f"tg:{update.effective_chat.id}")
        await query.message.reply_text("🔄 საუბარი თავიდან დაიწყო.")
    elif data.startswith("ask:") and data[4:] in QUICK_QUESTIONS:
        await _ask_agent(update, context, QUICK_QUESTIONS[data[4:]])


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    await _ask_agent(update, context, update.effective_message.text)


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    message = update.effective_message
    doc = message.document
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

def _format_duration(seconds: float | None) -> str:
    if not seconds:
        return ""
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes} წთ"
    return f"{minutes // 60} სთ {minutes % 60} წთ"


async def job_monitor(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        inv = agent.inventory()
        results = await asyncio.to_thread(check_many, list(inv.devices.values()))
    except Exception:  # noqa: BLE001
        log.exception("monitor check failed")
        return
    downtimes = {r.device: monitor.down_duration(r.device) for r in results if r.up}
    changes = monitor.update(results)
    if not changes:
        return
    lines = []
    for r, state in changes:
        if state == "down":
            lines.append(f"🔴 **{r.device}** ({r.host}) მიუწვდომელია — {r.reason}")
        else:
            took = _format_duration(downtimes.get(r.device))
            lines.append(f"🟢 **{r.device}** ({r.host}) ისევ ხელმისაწვდომია" + (f" (გათიშული იყო {took})" if took else ""))
    await _broadcast(context.application, "🚨 **ალერტი**\n" + "\n".join(lines))


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
        log.info("monitoring every %s min", settings.monitor_interval)
    hhmm = _parse_hhmm(settings.daily_report_time) if settings.daily_report_time else None
    if hhmm:
        tz = ZoneInfo(settings.timezone)
        jq.run_daily(job_daily_report, time=dtime(hhmm[0], hhmm[1], tzinfo=tz), name="daily_report")
        log.info("daily report at %02d:%02d %s", hhmm[0], hhmm[1], settings.timezone)


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

    global agent
    agent = NetAgent()

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
    for action in _ACTIONS:
        app.add_handler(CommandHandler(action, _action_command(action)))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    log.info("NetAgent Telegram bot started (model=%s)", settings.model)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
