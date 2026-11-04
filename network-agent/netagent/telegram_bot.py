"""Telegram interface.

Standalone:          python -m netagent.telegram_bot
Together with app:   python -m netagent.server   (starts Telegram too when a token is set)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Message, Update
from telegram.constants import ChatAction, ParseMode
from telegram.error import BadRequest
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

from . import commands
from .agent import Reply
from .commands import Button, Result, mute_buttons
from .config import settings
from .content import IMAGE_TYPES, MAX_IMAGE_BYTES, UploadError, build_content
from .formatting import describe_tool, markdown_to_telegram_html, split_markdown
from .monitoring import Alert, MonitoringService, parse_hhmm

log = logging.getLogger("netagent.telegram")

HELP_TEXT = """\
🤖 <b>NetAgent</b> — ქსელის ასისტენტი (მხოლოდ წაკითხვის რეჟიმი)

უბრალოდ მომწერე, მაგალითად:
• <code>R1-ის ინტერფეისების IP-ები მაჩვენე</code>
• <code>192.168.1.57 სადაა ჩართული?</code>
• <code>რომელი IP-ებია თავისუფალი 192.168.10.0/24-ში?</code>
• <code>ყველა მოწყობილობის OS ვერსია Excel-ში</code>
• <code>რა შეიცვალა SW-Core-1-ის კონფიგში?</code>
• <code>რამდენად უსაფრთხოა ქსელი?</code>

📄 ატვირთე config ან log ფაილი და ამოვიღებ IP-ებს, VLAN-ებს, ინტერფეისებს.
📸 გამომიგზავნე ფოტო (ეკრანი, შეცდომა, ტოპოლოგია, rack) და გავაანალიზებ.

<b>სწრაფი ბრძანებები (AI-ს გარეშე, უფასო):</b>
/menu — ღილაკები
/status — რომელი მოწყობილობაა ჩართული/გათიშული
/health R1 — ინტერფეისები, BGP, OSPF, CPU
/graph R1 — latency გრაფიკი (ბოლო 24 სთ)
/cmd R1 show ip route — ბრძანება პირდაპირ მოწყობილობაზე
/cmd all show clock — ყველა მოწყობილობაზე
/audit — უსაფრთხოების აუდიტი
/backup — config-ების backup
/map — ქსელის რუკა · /logs R1 — ლოგები
/runbook internet — „ინტერნეტი არ მუშაობს“ · /newdevices · /mac
/report — ქსელის რეპორტი
/discover 10.0.0.0/24 — ახალი მოწყობილობების ძებნა
/mute R1 2h — ალერტების დადუმება (/mute all 30m) · /unmute R1
/note R1 ISP: Magti, ID 12345 — შენიშვნა · /notes R1 · /delnote R1 2
/usage — AI ხარჯი
/devices — მოწყობილობების სია
/reset — საუბრის თავიდან დაწყება"""

BOT_COMMANDS = [
    BotCommand("menu", "ღილაკების მენიუ"),
    BotCommand("status", "მოწყობილობების სტატუსი (up/down)"),
    BotCommand("health", "მოწყობილობის მდგომარეობა: /health R1"),
    BotCommand("graph", "latency გრაფიკი: /graph R1"),
    BotCommand("cmd", "show ბრძანება: /cmd R1 show ip route"),
    BotCommand("runbook", "დიაგნოსტიკა: /runbook internet"),
    BotCommand("newdevices", "ახალი მოწყობილობები ქსელში"),
    BotCommand("mac", "MAC-ის მწარმოებელი: /mac aa:bb:cc:dd:ee:ff"),
    BotCommand("map", "ქსელის რუკა (CDP/LLDP)"),
    BotCommand("logs", "ლოგები: /logs R1"),
    BotCommand("audit", "უსაფრთხოების აუდიტი"),
    BotCommand("report", "ქსელის რეპორტი"),
    BotCommand("backup", "config-ების backup"),
    BotCommand("discover", "მოწყობილობების ძებნა: /discover 10.0.0.0/24"),
    BotCommand("mute", "ალერტების დადუმება: /mute R1 2h"),
    BotCommand("unmute", "დადუმების მოხსნა: /unmute R1"),
    BotCommand("note", "შენიშვნა: /note R1 ტექსტი"),
    BotCommand("notes", "შენიშვნები: /notes R1"),
    BotCommand("usage", "AI ხარჯი"),
    BotCommand("devices", "მოწყობილობების სია"),
    BotCommand("reset", "საუბრის თავიდან დაწყება"),
    BotCommand("help", "დახმარება და მაგალითები"),
    BotCommand("id", "ჩემი Telegram ID"),
]

MENU = InlineKeyboardMarkup([
    [InlineKeyboardButton("🩺 სტატუსი", callback_data="c:/status"),
     InlineKeyboardButton("📋 მოწყობილობები", callback_data="c:/devices")],
    [InlineKeyboardButton("📊 რეპორტი", callback_data="c:/report"),
     InlineKeyboardButton("🛡 აუდიტი", callback_data="c:/audit")],
    [InlineKeyboardButton("💾 Backup", callback_data="c:/backup"),
     InlineKeyboardButton("💰 ხარჯი", callback_data="c:/usage")],
    [InlineKeyboardButton("🌐 ყველა IP → Excel", callback_data="ask:all_ips"),
     InlineKeyboardButton("🖥 OS ვერსიები", callback_data="ask:versions")],
    [InlineKeyboardButton("🔴 გათიშული პორტები", callback_data="ask:down_ports"),
     InlineKeyboardButton("🔗 Neighbors", callback_data="ask:neighbors")],
    [InlineKeyboardButton("🔕 დადუმებული", callback_data="c:/mutes"),
     InlineKeyboardButton("📝 შენიშვნები", callback_data="c:/notes"),
     InlineKeyboardButton("🔄 თავიდან", callback_data="reset")],
])

FOLLOWUP = InlineKeyboardMarkup([[
    InlineKeyboardButton("🔄 განახლება", callback_data="fu:refresh"),
    InlineKeyboardButton("📊 Excel-ად", callback_data="fu:excel"),
]])

QUICK_QUESTIONS = {
    "all_ips": "ყველა მოწყობილობიდან ამოიღე ინტერფეისების IP მისამართები და გამიგზავნე Excel ფაილად "
    "(სვეტები: მოწყობილობა, ინტერფეისი, IP, სტატუსი). ჩატში მხოლოდ მოკლე შეჯამება.",
    "versions": "ყველა მოწყობილობის მოდელი, OS ვერსია და uptime ცხრილად.",
    "down_ports": "ყველა მოწყობილობაზე იპოვე ინტერფეისები, რომლებიც down-ია (administratively down ცალკე "
    "აღნიშნე). მოკლედ, მოწყობილობების მიხედვით დაჯგუფებული.",
    "neighbors": "ყველა მოწყობილობის CDP/LLDP neighbor-ები: ვინ ვისთანაა მიერთებული და რომელი პორტებით.",
}
EXCEL_FOLLOWUP = "წინა პასუხის მონაცემები გამომიგზავნე Excel ფაილად (export_excel). ჩატში მხოლოდ მოკლე შეჯამება."

# Commands that take a while get a "working..." note first.
SLOW_COMMANDS = {
    "status": "🩺 ვამოწმებ მოწყობილობებს...", "backup": "💾 ვიღებ backup-ს...", "report": "📊 ვამზადებ რეპორტს...",
    "audit": "🛡 ვამოწმებ კონფიგურაციებს...", "health": "🩺 ვამოწმებ...", "cmd": "💻 ვასრულებ...",
    "discover": "🔍 ვასკანერებ (შეიძლება 1-2 წუთი დასჭირდეს)...", "graph": "📈 ვხატავ გრაფიკს...",
    "map": "🗺 ვაგროვებ CDP/LLDP-ს და ვხატავ რუკას...",
    "runbook": "📚 ვასრულებ შემოწმებებს...", "mac": "🔎 ვეძებ...",
}

class TelegramBot:
    def __init__(self, services, monitoring: MonitoringService) -> None:
        self.s = services
        self.monitoring = monitoring
        self.app: Application | None = None
        self.last_question: dict[int, Any] = {}
        self._long_callbacks: dict[str, str] = {}

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def is_allowed(update: Update) -> bool:
        user = update.effective_user
        return bool(user and user.id in settings.telegram_allowed_users)

    @staticmethod
    async def deny(update: Update) -> None:
        user, msg = update.effective_user, update.effective_message
        if msg and user:
            await msg.reply_text(
                f"⛔ წვდომა არ გაქვს.\nშენი Telegram ID: {user.id}\n"
                "ადმინისტრატორმა უნდა დაამატოს ის TELEGRAM_ALLOWED_USERS-ში (.env)."
            )
        log.warning("denied user %s", user.id if user else "?")

    def markup(self, buttons: list[Button]) -> InlineKeyboardMarkup | None:
        rows = []
        for b in buttons:
            data = f"c:{b.command}"
            if len(data.encode()) > 64:  # Telegram callback_data limit
                key = str(len(self._long_callbacks))
                self._long_callbacks[key] = b.command
                data = f"l:{key}"
            rows.append([InlineKeyboardButton(b.label, callback_data=data)])
        return InlineKeyboardMarkup(rows) if rows else None

    @staticmethod
    async def send_markdown(message: Message, text: str, reply_markup=None) -> None:
        chunks = [c for c in split_markdown(text) if c.strip()] or ["(ცარიელი)"]
        for i, chunk in enumerate(chunks):
            markup = reply_markup if i == len(chunks) - 1 else None
            try:
                await message.reply_text(markdown_to_telegram_html(chunk), parse_mode=ParseMode.HTML, reply_markup=markup)
            except BadRequest:
                await message.reply_text(chunk, reply_markup=markup)

    async def send_result(self, message: Message, result: Result) -> None:
        markup = self.markup(result.buttons)
        if result.image:
            with result.image.open("rb") as fh:
                await message.reply_photo(fh, caption=result.text[:1000] or None, reply_markup=markup)
        elif result.text:
            await self.send_markdown(message, result.text, reply_markup=markup)
        await self.send_files(message, result.files)

    @staticmethod
    async def send_files(message: Message, files) -> None:
        for path in files:
            try:
                with path.open("rb") as fh:
                    await message.reply_document(fh, filename=path.name)
            except Exception as exc:  # noqa: BLE001
                log.exception("failed to send %s", path)
                await message.reply_text(f"⚠️ ფაილის გაგზავნა ვერ მოხერხდა: {path.name} ({exc})")

    async def run_command(self, message: Message, line: str, user: str) -> None:
        parsed = commands.parse(line)
        waiting = SLOW_COMMANDS.get(parsed[0]) if parsed else None
        note = await message.reply_text(waiting) if waiting else None
        try:
            result = await asyncio.to_thread(commands.run, self.s, line, user)
        except Exception as exc:  # noqa: BLE001
            log.exception("command failed: %s", line)
            result = Result(f"⚠️ {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}")
        if note:
            try:
                await note.delete()
            except Exception:  # noqa: BLE001
                pass
        await self.send_result(message, result or Result("უცნობი ბრძანება. /help"))

    async def _typing(self, context, chat_id: int, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await context.bot.send_chat_action(chat_id, ChatAction.TYPING)
            except Exception:  # noqa: BLE001
                pass
            try:
                await asyncio.wait_for(stop.wait(), timeout=4.5)
            except asyncio.TimeoutError:
                pass

    async def ask_agent(self, update: Update, context, content: Any, remember: bool = True) -> None:
        message = update.effective_message
        chat_id = update.effective_chat.id
        if remember:
            self.last_question[chat_id] = content
        loop = asyncio.get_running_loop()
        status = await message.reply_text("⏳ ვამუშავებ...")
        steps: list[str] = []

        def on_tool(name: str, args: dict[str, Any]) -> None:
            steps.append(describe_tool(name, args))
            body = "⏳ ვამუშავებ...\n" + "\n".join(steps[-10:])
            fut = asyncio.run_coroutine_threadsafe(status.edit_text(body[:4000]), loop)
            fut.add_done_callback(lambda f: f.exception())  # swallow "message is not modified"

        stop = asyncio.Event()
        typing_task = asyncio.create_task(self._typing(context, chat_id, stop))
        try:
            reply: Reply = await asyncio.to_thread(
                self.s.agent.chat, f"tg:{chat_id}", content,
                user=f"telegram:{update.effective_user.id}", channel="telegram", on_tool=on_tool)
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
        followup = FOLLOWUP if steps and not reply.files and not reply.text.startswith(("⚠️", "💰")) else None
        await self.send_markdown(message, reply.text, reply_markup=followup)
        await self.send_files(message, reply.files)

    # -- handlers ------------------------------------------------------------
    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_allowed(update):
            return await self.deny(update)
        await update.effective_message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML, reply_markup=MENU)

    async def cmd_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_allowed(update):
            return await self.deny(update)
        await update.effective_message.reply_text("აირჩიე:", reply_markup=MENU)

    async def cmd_id(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.effective_message.reply_text(f"შენი Telegram ID: {update.effective_user.id}")

    async def cmd_reset(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_allowed(update):
            return await self.deny(update)
        self.s.agent.reset(f"tg:{update.effective_chat.id}")
        self.last_question.pop(update.effective_chat.id, None)
        await update.effective_message.reply_text("🔄 საუბარი თავიდან დაიწყო.")

    async def cmd_shared(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """All deterministic commands from commands.py."""
        if not self.is_allowed(update):
            return await self.deny(update)
        await self.run_command(update.effective_message, update.effective_message.text or "",
                               f"telegram:{update.effective_user.id}")

    async def on_button(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        if not self.is_allowed(update):
            await query.answer("⛔ წვდომა არ გაქვს", show_alert=True)
            return
        await query.answer()
        data = query.data or ""
        chat_id = update.effective_chat.id
        user = f"telegram:{update.effective_user.id}"
        if data.startswith("c:"):
            await self.run_command(query.message, data[2:], user)
        elif data.startswith("l:") and data[2:] in self._long_callbacks:
            await self.run_command(query.message, self._long_callbacks[data[2:]], user)
        elif data == "reset":
            self.s.agent.reset(f"tg:{chat_id}")
            self.last_question.pop(chat_id, None)
            await query.message.reply_text("🔄 საუბარი თავიდან დაიწყო.")
        elif data.startswith("ask:") and data[4:] in QUICK_QUESTIONS:
            await self.ask_agent(update, context, QUICK_QUESTIONS[data[4:]])
        elif data == "fu:refresh":
            if chat_id not in self.last_question:
                await query.message.reply_text("გასამეორებელი კითხვა არ მაქვს.")
            else:
                await self.ask_agent(update, context, self.last_question[chat_id])
        elif data == "fu:excel":
            await self.ask_agent(update, context, EXCEL_FOLLOWUP, remember=False)

    async def on_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_allowed(update):
            return await self.deny(update)
        await self.ask_agent(update, context, update.effective_message.text)

    async def _ask_with_upload(self, update, context, name: str, media_type: str, size: int | None, tg_file_getter) -> None:
        message = update.effective_message
        limit = MAX_IMAGE_BYTES if media_type in IMAGE_TYPES else 2 * 1024 * 1024
        if size and size > limit:
            return await message.reply_text(f"⚠️ ფაილი ძალიან დიდია (მაქს. {limit // (1024 * 1024)} MB).")
        data = bytes(await (await tg_file_getter()).download_as_bytearray())
        try:
            content = build_content(message.caption or "", [(name, media_type, data)])
        except UploadError as exc:
            return await message.reply_text(f"⚠️ {exc}")
        await self.ask_agent(update, context, content)

    async def on_photo(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_allowed(update):
            return await self.deny(update)
        photo = update.effective_message.photo[-1]  # largest size
        await self._ask_with_upload(update, context, "photo.jpg", "image/jpeg", photo.file_size, photo.get_file)

    async def on_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_allowed(update):
            return await self.deny(update)
        doc = update.effective_message.document
        await self._ask_with_upload(update, context, doc.file_name or "file.txt", (doc.mime_type or "").lower(),
                                    doc.file_size, doc.get_file)

    # -- alerts ----------------------------------------------------------------
    async def notify(self, alert: Alert) -> None:
        if self.app is None:
            return
        header = "🚨 **ალერტი**\n" if alert.kind in {"down", "up", "watch", "syslog"} else ""
        text = header + alert.text
        markup = self.markup(mute_buttons(alert.devices)) if alert.mutable and alert.devices else None
        chunks = split_markdown(text)
        for uid in settings.telegram_allowed_users:
            for i, chunk in enumerate(chunks):
                try:
                    await self.app.bot.send_message(
                        uid, markdown_to_telegram_html(chunk), parse_mode=ParseMode.HTML,
                        reply_markup=markup if i == len(chunks) - 1 else None)
                except Exception:  # noqa: BLE001 - user may have never started the bot
                    log.warning("could not message user %s", uid)

    # -- application -----------------------------------------------------------
    async def post_init(self, app: Application) -> None:
        try:
            await app.bot.set_my_commands(BOT_COMMANDS)
        except Exception:  # noqa: BLE001
            log.warning("could not set bot commands")

    def _schedule_jobs(self, app: Application) -> None:
        from datetime import time as dtime
        from zoneinfo import ZoneInfo

        jq = app.job_queue
        if jq is None:
            log.warning("JobQueue მიუწვდომელია: pip install 'python-telegram-bot[job-queue]' — მონიტორინგი გამორთულია")
            return
        m = self.monitoring

        def job(fn):
            async def run(context: ContextTypes.DEFAULT_TYPE) -> None:
                try:
                    await fn()
                except Exception:  # noqa: BLE001
                    log.exception("job failed")
            return run

        if settings.monitor_interval > 0:
            jq.run_repeating(job(m.check_reachability), interval=settings.monitor_interval * 60, first=20, name="monitor")
        if settings.deep_monitor_interval > 0:
            jq.run_repeating(job(m.check_deep), interval=settings.deep_monitor_interval * 60, first=45, name="deep_monitor")
        if settings.new_device_interval > 0:
            jq.run_repeating(job(m.check_new_devices), interval=settings.new_device_interval * 60, first=60,
                             name="new_devices")
        if settings.config_watch_interval > 0:
            jq.run_repeating(job(m.check_config_changes), interval=settings.config_watch_interval * 60, first=90,
                             name="config_watch")
        hhmm = parse_hhmm(settings.daily_report_time) if settings.daily_report_time else None
        if hhmm:
            jq.run_daily(job(m.daily_report), time=dtime(hhmm[0], hhmm[1], tzinfo=ZoneInfo(settings.timezone)),
                         name="daily_report")

    def build_application(self, schedule_jobs: bool = True) -> Application:
        if not settings.telegram_allowed_users:
            log.warning("TELEGRAM_ALLOWED_USERS ცარიელია — ბოტი ყველას უარს ეტყვის. "
                        "მიწერე ბოტს /id, შემდეგ ჩაწერე ID .env-ში და გადატვირთე.")
        app = (Application.builder().token(settings.telegram_token).concurrent_updates(True)
               .post_init(self.post_init).build())
        app.add_handler(CommandHandler(["start", "help"], self.cmd_start))
        app.add_handler(CommandHandler("menu", self.cmd_menu))
        app.add_handler(CommandHandler("id", self.cmd_id))
        app.add_handler(CommandHandler("reset", self.cmd_reset))
        shared = [n for n in commands.COMMANDS if n != "help" and "-" not in n]
        app.add_handler(CommandHandler(shared, self.cmd_shared))
        app.add_handler(CallbackQueryHandler(self.on_button))
        app.add_handler(MessageHandler(filters.PHOTO, self.on_photo))
        app.add_handler(MessageHandler(filters.Document.ALL, self.on_document))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.on_text))
        if schedule_jobs:
            self._schedule_jobs(app)
        self.app = app
        return app


def main() -> None:
    from .services import Services

    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if not settings.telegram_token:
        raise SystemExit("TELEGRAM_BOT_TOKEN არ არის მითითებული .env ფაილში")
    services = Services.create()
    monitoring = MonitoringService(services)
    bot = TelegramBot(services, monitoring)
    monitoring.add_notifier(bot.notify)
    app = bot.build_application(schedule_jobs=True)
    log.info("NetAgent Telegram bot started (model=%s)", settings.model)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
