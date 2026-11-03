"""Telegram interface.

Run:  python -m netagent.telegram_bot
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.error import BadRequest
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from .agent import NetAgent
from .config import settings
from .formatting import markdown_to_telegram_html, split_markdown
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
• <code>ყველა მოწყობილობის OS ვერსია</code>
• <code>BGP neighbor-ები R2-ზე</code>
• <code>10.0.0.0/22 დაყავი /26-ებად</code>

📄 ატვირთე config ან log ფაილი და ამოვიღებ IP-ებს, VLAN-ებს, ინტერფეისებს.

ბრძანებები:
/devices — მოწყობილობების სია
/reset — საუბრის თავიდან დაწყება
/id — შენი Telegram ID
/help — ეს ტექსტი"""

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
}


def _describe_tool(name: str, args: dict[str, Any]) -> str:
    template = _TOOL_LABELS.get(name, f"🔧 {name}")
    filter_s = f" ({args['filter']})" if args.get("filter") else ""
    try:
        return template.format(filter_s=filter_s, **args)
    except (KeyError, IndexError):
        return f"🔧 {name}"


agent: NetAgent  # created in main() so importing this module needs no API key


def _is_allowed(update: Update) -> bool:
    user = update.effective_user
    return bool(user and user.id in settings.telegram_allowed_users)


async def _deny(update: Update) -> None:
    user = update.effective_user
    if update.message and user:
        await update.message.reply_text(
            f"⛔ წვდომა არ გაქვს.\nშენი Telegram ID: {user.id}\n"
            "ადმინისტრატორმა უნდა დაამატოს ის TELEGRAM_ALLOWED_USERS-ში (.env)."
        )
    log.warning("denied user %s", user.id if user else "?")


async def _send_answer(update: Update, text: str) -> None:
    for chunk in split_markdown(text):
        if not chunk.strip():
            continue
        try:
            await update.message.reply_text(markdown_to_telegram_html(chunk), parse_mode=ParseMode.HTML)
        except BadRequest:
            # Malformed HTML for some reason - fall back to plain text.
            await update.message.reply_text(chunk)


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
    chat_id = update.effective_chat.id
    loop = asyncio.get_running_loop()
    status = await update.message.reply_text("⏳ ვამუშავებ...")
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
        answer = await asyncio.to_thread(
            agent.chat,
            f"tg:{chat_id}",
            content,
            user=f"telegram:{update.effective_user.id}",
            channel="telegram",
            on_tool=on_tool,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("agent failure")
        answer = f"⚠️ შიდა შეცდომა: {type(exc).__name__}"
    finally:
        stop.set()
        await typing_task

    try:
        await status.delete()
    except Exception:  # noqa: BLE001
        pass
    await _send_answer(update, answer)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML)


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(f"შენი Telegram ID: {update.effective_user.id}")


async def cmd_reset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    agent.reset(f"tg:{update.effective_chat.id}")
    await update.message.reply_text("🔄 საუბარი თავიდან დაიწყო.")


async def cmd_devices(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    try:
        inv = agent.inventory()
    except Exception as exc:  # noqa: BLE001
        return await update.message.reply_text(f"⚠️ {exc}")
    if not inv.devices:
        return await update.message.reply_text("inventory ცარიელია.")
    lines = [f"{d.name:<14} {d.host:<15} {d.device_type}" for d in inv.devices.values()]
    text = "```\n" + "\n".join(lines) + "\n```"
    await _send_answer(update, f"📋 მოწყობილობები ({len(lines)}):\n{text}")


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    await _ask_agent(update, context, update.message.text)


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return await _deny(update)
    doc = update.message.document
    if doc.file_size and doc.file_size > MAX_UPLOAD_BYTES:
        return await update.message.reply_text("⚠️ ფაილი ძალიან დიდია (მაქს. 2 MB).")
    tg_file = await doc.get_file()
    raw = bytes(await tg_file.download_as_bytearray())
    if raw.count(b"\x00") > 10:
        return await update.message.reply_text("⚠️ ეს ტექსტური ფაილი არ არის (config, log, txt, csv...).")
    text = mask_secrets(raw.decode("utf-8", errors="replace"))
    extracted = extract_network_data(text)
    question = update.message.caption or "გააანალიზე ეს ფაილი: ამოიღე IP მისამართები, ქსელები, VLAN-ები, ინტერფეისები და აღნიშნე პრობლემები."
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

    app = Application.builder().token(settings.telegram_token).concurrent_updates(True).build()
    app.add_handler(CommandHandler(["start", "help"], cmd_start))
    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(CommandHandler("reset", cmd_reset))
    app.add_handler(CommandHandler("devices", cmd_devices))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    log.info("NetAgent Telegram bot started (model=%s)", settings.model)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
