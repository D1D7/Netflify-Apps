"""Extra alert channels: e-mail (SMTP), Discord and Slack webhooks. Configured only in .env.

    NETAGENT_SMTP_HOST=smtp.gmail.com  NETAGENT_SMTP_PORT=587
    NETAGENT_SMTP_USER=me@gmail.com    NETAGENT_SMTP_PASS=<app password>
    NETAGENT_EMAIL_TO=me@gmail.com     NETAGENT_EMAIL_KINDS=down,escalation,isp,site,report
    NETAGENT_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
    NETAGENT_SLACK_WEBHOOK=https://hooks.slack.com/services/...
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import smtplib
import ssl
from email.message import EmailMessage

from ..result import CommandError, Result

log = logging.getLogger("netagent.notify")
DEFAULT_EMAIL_KINDS = "down,escalation,isp,site,syslog,newdevice,report,scheduled,watch,config"


def plain(text: str) -> str:
    text = re.sub(r"```.*?\n", "", text).replace("```", "").replace("**", "").replace("`", "")
    return re.sub(r"\n{2,}", "\n", text).strip()


def email_config() -> dict | None:
    host, to = os.getenv("NETAGENT_SMTP_HOST", "").strip(), os.getenv("NETAGENT_EMAIL_TO", "").strip()
    if not host or not to:
        return None
    user = os.getenv("NETAGENT_SMTP_USER", "").strip()
    return {"host": host, "port": int(os.getenv("NETAGENT_SMTP_PORT", "587") or 587), "user": user,
            "password": os.getenv("NETAGENT_SMTP_PASS", ""), "from": os.getenv("NETAGENT_SMTP_FROM", user or to).strip(),
            "to": [x.strip() for x in to.split(",") if x.strip()],
            "kinds": {k.strip() for k in os.getenv("NETAGENT_EMAIL_KINDS", DEFAULT_EMAIL_KINDS).split(",") if k.strip()}}


def send_email(cfg: dict, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg["from"], ", ".join(cfg["to"])
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if cfg["port"] == 465:
        with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ctx, timeout=30) as smtp:
            if cfg["user"]:
                smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as smtp:
            smtp.starttls(context=ctx)
            if cfg["user"]:
                smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(msg)


async def post_webhook(url: str, payload: dict) -> None:
    import httpx

    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, json=payload)
        r.raise_for_status()


def channels() -> dict[str, bool]:
    return {"email": email_config() is not None, "discord": bool(os.getenv("NETAGENT_DISCORD_WEBHOOK", "").strip()),
            "slack": bool(os.getenv("NETAGENT_SLACK_WEBHOOK", "").strip())}


async def deliver(title: str, text: str, kind: str = "test") -> list[str]:
    """Send to every configured channel; returns the names that worked."""
    ok = []
    body = plain(text)
    cfg = email_config()
    if cfg and (kind == "test" or kind in cfg["kinds"]):
        try:
            await asyncio.to_thread(send_email, cfg, f"NetAgent: {title}", body)
            ok.append("email")
        except Exception as exc:  # noqa: BLE001
            log.warning("email failed: %s", type(exc).__name__)
    for name, env, key in (("discord", "NETAGENT_DISCORD_WEBHOOK", "content"), ("slack", "NETAGENT_SLACK_WEBHOOK", "text")):
        url = os.getenv(env, "").strip()
        if url:
            try:
                await post_webhook(url, {key: f"**{title}**\n{body}"[:1900] if name == "discord" else f"*{title}*\n{body}"})
                ok.append(name)
            except Exception as exc:  # noqa: BLE001
                log.warning("%s webhook failed: %s", name, type(exc).__name__)
    return ok


def notifiers(services):
    if not any(channels().values()):
        return []

    async def send(alert) -> None:
        if alert.kind == "up" and not os.getenv("NETAGENT_NOTIFY_UP"):
            return
        await deliver(alert.title, alert.text, alert.kind)

    return [send]


def notify_cmd(s, args, user) -> Result:
    ch = channels()
    if args and args[0].lower() == "test":
        if not any(ch.values()):
            raise CommandError("არცერთი არხი არ არის მითითებული .env-ში (იხ. README → შეტყობინებები)")
        ok = asyncio.run(deliver("ტესტი", "✅ NetAgent-ის სატესტო შეტყობინება"))
        failed = [k for k, v in ch.items() if v and k not in ok]
        return Result("📨 გაიგზავნა: " + (", ".join(ok) or "—") + (f"\n⚠️ ვერ გაიგზავნა: {', '.join(failed)} — შეამოწმე .env" if failed else ""))
    lines = ["📨 **შეტყობინებების არხები**",
             "• აპი (push) — ✅", "• Telegram — " + ("✅" if os.getenv("TELEGRAM_BOT_TOKEN") else "—")]
    lines += [f"• {k.capitalize()} — {'✅' if v else '— (.env-ში მიუთითე)'}" for k, v in ch.items()]
    lines.append("\nსატესტო შეტყობინება: /notify test")
    return Result("\n".join(lines))


COMMANDS = {"notify": notify_cmd}
HELP = ["/notify — შეტყობინებების არხები (email, Discord, Slack) · /notify test"]
