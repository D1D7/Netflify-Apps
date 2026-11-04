"""NetAgent server: the app (web/PWA) + background monitoring + optional Telegram, in one process.

Run:  python -m netagent.server
"""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
import re
import sys

import uvicorn

from .config import settings
from .monitoring import Alert, MonitoringService, start_scheduler
from .services import Services
from .web.app import create_app
from .web.auth import WebAuth
from .web.push import PushSender, VapidKeys

log = logging.getLogger("netagent.server")


def plain_text(markdown: str) -> str:
    """Markdown-ish alert text -> plain text for a phone notification."""
    text = re.sub(r"```.*?\n", "", markdown)
    text = text.replace("```", "").replace("**", "").replace("`", "")
    return re.sub(r"\n{2,}", "\n", text).strip()


async def amain() -> None:
    services = Services.create()
    monitoring = MonitoringService(services)
    auth = WebAuth(settings.data_dir / "web_auth.json", env_password=os.getenv("NETAGENT_WEB_PASSWORD", ""))
    if not auth.configured:
        log.warning("აპის პაროლი ჯერ არ არის დაყენებული — გაუშვი: python -m netagent web-setup")
    push = PushSender(services.state, VapidKeys(settings.data_dir / "vapid.pem"))

    async def push_notify(alert: Alert) -> None:
        if push.subscriptions():
            await push.send(alert.title, plain_text(alert.text), tag=alert.kind)

    monitoring.add_notifier(push_notify)

    telegram_app = None
    if settings.telegram_token and os.getenv("NETAGENT_TELEGRAM", "on").lower() not in {"off", "0", "false", "no"}:
        from telegram import Update

        from .telegram_bot import TelegramBot

        bot = TelegramBot(services, monitoring)
        telegram_app = bot.build_application(schedule_jobs=False)  # the server schedules monitoring itself
        monitoring.add_notifier(bot.notify)
        await telegram_app.initialize()
        await bot.post_init(telegram_app)
        await telegram_app.start()
        await telegram_app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        log.info("Telegram bot started")

    tasks = start_scheduler(monitoring)
    services.vendors.ensure()  # download the MAC vendor list once, in the background

    syslog_transport = None
    if settings.syslog_port > 0:
        from .syslogd import start_syslog

        hosts = {d.host: d.name for d in services.inventory().devices.values()}

        def resolve(ip: str) -> str:
            try:
                return {d.host: d.name for d in services.inventory().devices.values()}.get(ip, ip)
            except Exception:  # noqa: BLE001
                return hosts.get(ip, ip)

        def on_alert(device: str, text: str) -> None:
            if not services.mutes.is_muted(device):
                asyncio.create_task(monitoring.emit(Alert("syslog", text, [device])))

        try:
            syslog_transport, _ = await start_syslog(settings.syslog_host, settings.syslog_port,
                                                     services.syslog, resolve, on_alert)
        except OSError as exc:
            log.warning("syslog udp/%s ვერ გაიხსნა (%s) — ლოგების მიღება გამორთულია. "
                        "შეცვალე NETAGENT_SYSLOG_PORT ან გაუშვი ადმინისტრატორად.", settings.syslog_port, exc)

    app = create_app(services, monitoring, auth, push)
    config = uvicorn.Config(app, host=settings.web_host, port=settings.web_port, proxy_headers=True,
                            forwarded_allow_ips="127.0.0.1", log_level="info", access_log=False)
    log.info("NetAgent app: http://%s:%s (model=%s)", settings.web_host, settings.web_port, settings.model)
    try:
        await uvicorn.Server(config).serve()
    finally:
        for t in tasks:
            t.cancel()
        if syslog_transport is not None:
            syslog_transport.close()
        if telegram_app is not None:
            await telegram_app.updater.stop()
            await telegram_app.stop()
            await telegram_app.shutdown()


def setup_logging(log_file: str | None = None) -> None:
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    if log_file or sys.stderr is None:  # pythonw.exe (Windows autostart) has no console
        path = log_file or os.path.join(str(settings.data_dir.parent), "logs", "netagent.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        logging.basicConfig(format=fmt, level=logging.INFO, handlers=[handler])
        # stray prints go to a separate file: Windows can't rotate a file that is held open twice
        console_path = os.path.splitext(path)[0] + "-console.log"
        stream = open(console_path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115 - lives for the process
        if sys.stdout is None:
            sys.stdout = stream
        if sys.stderr is None:
            sys.stderr = stream
    else:
        logging.basicConfig(format=fmt, level=logging.INFO)


def main(log_file: str | None = None) -> None:
    setup_logging(log_file)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    asyncio.run(amain())


if __name__ == "__main__":
    main()
