"""Operations: maintenance windows, escalation (repeat until acknowledged), scheduled tasks.

    /maintenance R1 22:00 1h გადატვირთვა     alerts for R1 stay quiet 22:00-23:00
    /maintenance all now 30m                  everything quiet for 30 min
    /ack R1                                   stop repeating "R1 is still down"
    /schedule mon 09:00 /report               every Monday 09:00
    /schedule daily 08:30 რა მოხდა ღამით?     AI question every day
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from ..alerts import ALL, format_duration, parse_duration
from ..config import settings
from ..result import Button, CommandError, Result
from . import env_int

log = logging.getLogger("netagent.ops")
DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
        "ორშ": 0, "სამ": 1, "ოთხ": 2, "ხუთ": 3, "პარ": 4, "შაბ": 5, "კვი": 6}
DAY_NAMES = ["ორშ", "სამ", "ოთხ", "ხუთ", "პარ", "შაბ", "კვი"]
QUIET_KINDS = {"down", "up", "watch", "config", "syslog", "newdevice", "escalation"}


def now_local() -> datetime:
    return datetime.now(ZoneInfo(settings.timezone)).replace(tzinfo=None)


# -- maintenance windows ------------------------------------------------------------------------
def parse_start(text: str, now: datetime) -> datetime:
    if text.lower() in {"now", "ახლა"}:
        return now
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", text)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise CommandError("დრო ასე მიუთითე: 22:00 ან now")
    start = now.replace(hour=int(m.group(1)), minute=int(m.group(2)), second=0, microsecond=0)
    return start if start > now - timedelta(minutes=1) else start + timedelta(days=1)


def windows(state, now: datetime | None = None) -> list[dict]:
    now = now or now_local()
    return [w for w in (state.get("maintenance") or []) if w["end"] > now.isoformat()]


def active_targets(state, now: datetime | None = None) -> set[str]:
    now = now or now_local()
    return {w["target"] for w in windows(state, now) if w["start"] <= now.isoformat()}


def suppress(s, alert) -> bool:
    if alert.kind not in QUIET_KINDS:
        return False
    targets = active_targets(s.state)
    if not targets:
        return False
    return ALL in targets or bool(alert.devices) and all(d in targets for d in alert.devices)


def maintenance_cmd(s, args, user) -> Result:
    now = now_local()
    if not args:
        items = windows(s.state, now)
        if not items:
            return Result("🛠 დაგეგმილი სამუშაოები არ არის.\nდამატება: /maintenance R1 22:00 1h აღწერა")
        lines = ["🛠 **სამუშაოები** (ამ დროს ალერტები ჩუმადაა):"]
        for i, w in enumerate(items, 1):
            state = "🟠 ახლა მიმდინარეობს" if w["start"] <= now.isoformat() else "🕒"
            who = "ყველა მოწყობილობა" if w["target"] == ALL else w["target"]
            lines.append(f"{i}. {state} **{who}** {w['start'][5:16].replace('T', ' ')} → {w['end'][11:16]}"
                         + (f" — {w['note']}" if w.get("note") else ""))
        return Result("\n".join(lines), buttons=[Button(f"❌ გაუქმება {i}", f"/maintenance cancel {i}")
                                                 for i in range(1, min(len(items), 4) + 1)])
    if args[0].lower() == "cancel":
        items = windows(s.state, now)
        try:
            w = items[int(args[1]) - 1]
        except (IndexError, ValueError):
            raise CommandError("გამოყენება: /maintenance cancel 1") from None
        s.state.update("maintenance", lambda v: [x for x in (v or []) if x != w])
        return Result("✅ გაუქმდა")
    if len(args) < 3:
        raise CommandError("გამოყენება: /maintenance R1 22:00 1h აღწერა · /maintenance all now 30m")
    target = ALL if args[0].lower() in {"all", "ყველა"} else args[0]
    if target != ALL and target not in s.inventory().devices:
        raise CommandError(f"მოწყობილობა '{target}' inventory-ში არ არის")
    start = parse_start(args[1], now)
    try:
        seconds = parse_duration(args[2])
    except ValueError as exc:
        raise CommandError(str(exc)) from None
    w = {"target": target, "start": start.isoformat(timespec="seconds"),
         "end": (start + timedelta(seconds=seconds)).isoformat(timespec="seconds"), "note": " ".join(args[3:])[:100],
         "by": user}
    s.state.update("maintenance", lambda v: [x for x in (v or []) if x["end"] > now.isoformat()] + [w])
    who = "ყველა მოწყობილობის" if target == ALL else f"{target}-ის"
    return Result(f"🛠 დაიგეგმა: {who} ალერტები ჩუმად იქნება {w['start'][5:16].replace('T', ' ')} → {w['end'][11:16]}"
                  f" ({format_duration(seconds)}). ალერტები მაინც ჩაიწერება ჟურნალში.")


# -- escalation ---------------------------------------------------------------------------------
def ack_cmd(s, args, user) -> Result:
    target = (args[0] if args else ALL)
    s.state.update("acked", lambda v: sorted(set(v or []) | {target}))
    who = "ყველა" if target in {ALL, "all"} else target
    return Result(f"✅ დადასტურდა: {who} — განმეორებითი შეხსენებები შეჩერდა, სანამ არ აღდგება.")


def escalation_due(down_minutes: float, every: int, already_sent: int) -> bool:
    """Remind at every, 2*every, ... minutes of downtime (max 6 reminders)."""
    return every > 0 and already_sent < 6 and down_minutes >= every * (already_sent + 1)


# -- schedules ----------------------------------------------------------------------------------
def parse_days(text: str) -> list[int]:
    t = text.lower()
    if t in {"daily", "ყოველდღე"}:
        return list(range(7))
    if t in {"weekdays", "სამუშაო"}:
        return [0, 1, 2, 3, 4]
    days = []
    for part in t.split(","):
        if part[:3] not in DAYS:
            raise CommandError("დღე: daily, weekdays ან mon,tue,... (ორშ,სამ,...)")
        days.append(DAYS[part[:3]])
    return sorted(set(days))


def schedule_cmd(s, args, user) -> Result:
    if len(args) < 3 or not re.fullmatch(r"\d{1,2}:\d{2}", args[1]):
        raise CommandError("გამოყენება: /schedule mon 09:00 /report · /schedule daily 08:30 /isp · "
                           "/schedule weekdays 18:00 რა მოხდა დღეს ქსელში?")
    days = parse_days(args[0])
    h, m = (int(x) for x in args[1].split(":"))
    if h > 23 or m > 59:
        raise CommandError("არასწორი დრო")
    line = " ".join(args[2:]).strip()
    if line.startswith("/schedule"):
        raise CommandError("ეს ბრძანება განრიგში ვერ ჩაჯდება")
    item = {"days": days, "time": f"{h:02d}:{m:02d}", "line": line, "by": user,
            "last_run": now_local().date().isoformat() if (h, m) <= (now_local().hour, now_local().minute) else ""}
    s.state.update("schedules", lambda v: (v or []) + [item])
    return Result(f"🗓 დაემატა: {describe_days(days)} {item['time']} → `{line}`")


def describe_days(days: list[int]) -> str:
    if days == list(range(7)):
        return "ყოველდღე"
    if days == [0, 1, 2, 3, 4]:
        return "სამუშაო დღეებში"
    return ",".join(DAY_NAMES[d] for d in days)


def schedules_cmd(s, args, user) -> Result:
    items = s.state.get("schedules") or []
    if not items:
        return Result("🗓 განრიგი ცარიელია. მაგ.: /schedule mon 09:00 /report")
    lines = ["🗓 **განრიგი:**"] + [f"{i}. {describe_days(x['days'])} {x['time']} → `{x['line']}`" for i, x in enumerate(items, 1)]
    return Result("\n".join(lines), buttons=[Button(f"🗑 {i}", f"/unschedule {i}") for i in range(1, min(len(items), 6) + 1)])


def unschedule_cmd(s, args, user) -> Result:
    items = s.state.get("schedules") or []
    try:
        removed = items.pop(int(args[0]) - 1)
    except (IndexError, ValueError):
        raise CommandError("გამოყენება: /unschedule 1 (ნომერი /schedules-დან)") from None
    s.state.set("schedules", items)
    return Result(f"🗑 წაიშალა: `{removed['line']}`")


def due_schedules(items: list[dict], now: datetime) -> list[int]:
    today = now.date().isoformat()
    hhmm = f"{now.hour:02d}:{now.minute:02d}"
    return [i for i, x in enumerate(items) if now.weekday() in x["days"] and x["time"] <= hhmm and x.get("last_run") != today]


def run_line(s, line: str) -> str:
    from .. import commands

    if line.startswith("/"):
        res = commands.run(s, line, "schedule")
        if res is None:
            return f"⚠️ უცნობი ბრძანება: {line}"
        extra = [p.name for p in res.files] + ([res.image.name] if res.image else [])
        return res.text + (f"\n\n📎 ფაილი აპში: {', '.join(extra)}" if extra else "")
    reply = s.agent.chat("schedule", line, user="schedule", channel="web")
    return reply.text


COMMANDS = {"maintenance": maintenance_cmd, "ack": ack_cmd, "schedule": schedule_cmd,
            "schedules": schedules_cmd, "unschedule": unschedule_cmd}
HELP = ["/maintenance R1 22:00 1h — სამუშაოების დრო, ალერტები ჩუმად · /maintenance — სია",
        "/ack R1 — „ჯერ კიდევ გათიშულია“ შეხსენებების შეჩერება",
        "/schedule mon 09:00 /report — განრიგი (ბრძანება ან AI კითხვა) · /schedules"]
BOT_COMMANDS = [("maintenance", "სამუშაოების დრო (ალერტები ჩუმად)"), ("schedules", "განრიგი")]


def jobs(monitoring):
    from ..monitoring import Alert

    s = monitoring.s
    every = env_int("NETAGENT_ESCALATE_MINUTES", 15)
    sent: dict[str, int] = {}

    async def escalate():
        state = getattr(s.monitor, "_state", {})
        acked = set(s.state.get("acked") or [])
        for device, up in list(state.items()):
            if up:
                sent.pop(device, None)
                if device in acked:
                    s.state.update("acked", lambda v, d=device: [x for x in (v or []) if x != d])
                continue
            dur = s.monitor.down_duration(device) or 0
            if device in acked or ALL in acked or s.mutes.is_muted(device):
                continue
            if escalation_due(dur / 60, every, sent.get(device, 0)):
                sent[device] = sent.get(device, 0) + 1
                await monitoring.emit(Alert("escalation", f"⏰ **{device}** ჯერ კიდევ მიუწვდომელია — {format_duration(dur)}",
                                            [device], buttons=[Button("✅ ვიცი, ვმუშაობ", f"/ack {device}")]))
        if acked and all(state.get(d, True) for d in acked if d != ALL) and all(state.values()):
            s.state.set("acked", [])

    async def scheduler():
        items = s.state.get("schedules") or []
        now = now_local()
        for i in due_schedules(items, now):
            items[i]["last_run"] = now.date().isoformat()
            s.state.set("schedules", items)
            try:
                text = await asyncio.to_thread(run_line, s, items[i]["line"])
            except Exception as exc:  # noqa: BLE001
                text = f"⚠️ ვერ შესრულდა: {exc}"
            await monitoring.emit(Alert("scheduled", f"🗓 **{items[i]['line']}**\n\n{text}", mutable=False))

    out = [("schedules", 30, 20, scheduler)]
    if every > 0:
        out.append(("escalation", 60, 90, escalate))
    return out
