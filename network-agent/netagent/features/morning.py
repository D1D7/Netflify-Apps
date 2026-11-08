"""Morning summary push: how the night went, in one message.

  /morning   the summary now
Every day at NETAGENT_MORNING (default 08:00, "off" disables) it arrives as a push / Telegram message: internet
outages and ping overnight, the latest speed, devices online now, new and unknown devices since last evening,
Wi-Fi signal, DNS blocks. If the PC was asleep at that time, it comes when it wakes up (until noon).
"""

from __future__ import annotations

import os
import statistics
import time
from datetime import datetime, timedelta

from ..result import Button, Result

SENT_KEY = "morning_last"


def morning_time() -> tuple[int, int] | None:
    from ..monitoring import parse_hhmm

    raw = os.getenv("NETAGENT_MORNING", "08:00").strip().lower()
    return None if raw in {"", "off", "0", "no", "false"} else parse_hhmm(raw)


def due(now: datetime, at: tuple[int, int] | None, last: str | None) -> bool:
    if at is None or last == now.date().isoformat():
        return False
    start = now.replace(hour=at[0], minute=at[1], second=0, microsecond=0)
    return start <= now < now.replace(hour=12, minute=0, second=0, microsecond=0) or (at[0] >= 12 and now >= start)


def _fmt_dur(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 60} წთ" if sec < 3600 else f"{sec // 3600} სთ {sec % 3600 // 60} წთ"


def build(s, hours: float = 12, now: datetime | None = None, live=None) -> str:
    now = now or datetime.now()
    since = now - timedelta(hours=hours)
    lines = [f"☀️ **დილა მშვიდობისა!** ღამის შეჯამება ({since:%H:%M}-დან)"]

    # internet
    try:
        from .isp import monitor_for

        sm = monitor_for(s).summary(hours / 24)
        if sm.get("down_now_since"):
            lines.append(f"🔴 **ინტერნეტი ახლა გათიშულია** ({sm['down_now_since'][11:16]}-დან)")
        elif sm.get("samples"):
            out = sm["outages"]
            txt = (f"🔴 {len(out)} გათიშვა, ჯამში {_fmt_dur(sm['outage_total_seconds'])}" if out else "🟢 გათიშვა არ ყოფილა")
            lat = f" · ping საშუალოდ {sm['latency_avg_ms']} ms" if sm.get("latency_avg_ms") is not None else ""
            lines.append(f"🌐 ინტერნეტი: {txt}{lat} (ხელმისაწვდომობა {sm['uptime_percent']}%)")
    except Exception:  # noqa: BLE001 - every part is optional
        pass
    tests = [t for t in (s.state.get("isp_speedtests") or []) if t.get("down_mbps") is not None]
    if tests:
        t = tests[-1]
        lines.append(f"⚡ ბოლო სიჩქარე ({t['ts'][5:16].replace('T', ' ')}): ჩამოტვირთვა (download) {t['down_mbps']} Mbps · "
                     f"ატვირთვა (upload) {t['up_mbps']} Mbps")
    bb = s.state.get("bufferbloat_tests") or []
    if bb and bb[-1].get("grade") not in {None, "?"}:
        lines.append(f"🌊 Bufferbloat (ბოლო ტესტი): {bb[-1]['grade']}")

    # devices
    if live is None:
        from . import livedevices

        live = livedevices.ENGINE
    if live is not None:
        try:
            snap = live.snapshot()
            rows = snap["devices"]
            cutoff = time.time() - hours * 3600
            new = [e for e in live.events if e["event"] == "new" and e["ts"] >= cutoff]
            unknown = [r for r in rows if r["online"] and not r["trusted"] and not r["self"]]
            lines.append(f"📡 ქსელში ახლა: **{snap['online']}** მოწყობილობა ონლაინ (სულ {len(rows)})")
            if new:
                lines.append(f"🆕 ღამით შემოვიდა {len(new)} ახალი: " + ", ".join(e["hostname"] or e["vendor"] or e["ip"] for e in new[:6]))
            if unknown:
                lines.append(f"🚨 ონლაინაა {len(unknown)} უცნობი: " + ", ".join(r["label"] or r["hostname"] or r["vendor"] or r["ip"] for r in unknown[:6]))
        except Exception:  # noqa: BLE001
            pass

    # Wi-Fi
    try:
        from .quality import signal_history

        sig = [v for _, v in signal_history(hours)]
        if sig:
            lines.append(f"📶 Wi-Fi სიგნალი: საშუალოდ {round(statistics.mean(sig))}% (მინ. {min(sig)}%)")
    except Exception:  # noqa: BLE001
        pass

    # DNS
    try:
        from .dnsfilter import RUNNING, STATS

        if RUNNING:
            d = STATS.as_dict()
            lines.append(f"🛡 DNS: დღეს {d['total']:,} მოთხოვნა, დაიბლოკა {d['blocked']:,}")
    except Exception:  # noqa: BLE001
        pass

    if len(lines) == 1:
        lines.append("ჯერ მონაცემი არ დაგროვდა — ხვალ დილით უკვე სრული შეჯამება მოვა.")
    return "\n".join(lines)


def morning_cmd(s, args, user) -> Result:
    return Result(build(s), buttons=[Button("📡 Live", "/live"), Button("⚡ სიჩქარე", "/speedtest")])


COMMANDS = {"morning": morning_cmd}
HELP = ["/morning — დილის შეჯამება (ღამის გათიშვები, სიჩქარე, ახალი/უცნობი მოწყობილობები, Wi-Fi); "
        "ავტომატურად ყოველ დილით NETAGENT_MORNING=08:00-ზე"]
BOT_COMMANDS = [("morning", "დილის შეჯამება")]


def jobs(monitoring):
    at = morning_time()
    if at is None:
        return []

    async def check():
        import asyncio

        from ..monitoring import Alert

        state = monitoring.s.state
        now = datetime.now()
        if not due(now, at, state.get(SENT_KEY)):
            return
        state.set(SENT_KEY, now.date().isoformat())
        text = await asyncio.to_thread(build, monitoring.s)
        await monitoring.emit(Alert("morning", text, mutable=False, buttons=[Button("📡 Live", "/live")]))

    return [("morning", 60, 120, check)]
