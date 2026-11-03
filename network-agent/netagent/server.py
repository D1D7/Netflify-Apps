"""NetAgent server: the app (web/PWA) + background monitoring + optional Telegram, in one process.

Run:  python -m netagent.server
"""

from __future__ import annotations

import asyncio
import logging
import os
import re

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
    app = create_app(services, monitoring, auth, push)
    config = uvicorn.Config(app, host=settings.web_host, port=settings.web_port, proxy_headers=True,
                            forwarded_allow_ips="127.0.0.1", log_level="info", access_log=False)
    log.info("NetAgent app: http://%s:%s (model=%s)", settings.web_host, settings.web_port, settings.model)
    try:
        await uvicorn.Server(config).serve()
    finally:
        for t in tasks:
            t.cancel()
        if telegram_app is not None:
            await telegram_app.updater.stop()
            await telegram_app.stop()
            await telegram_app.shutdown()


def main() -> None:
    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    asyncio.run(amain())


if __name__ == "__main__":
    main()
