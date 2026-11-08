"""Network score 0-100: one number for security + internet + Wi-Fi, and what to do to raise it.

  /score   the score, where points were lost, the 3 most useful fixes, and the change since last week

Everything comes from what NetAgent already measures (IoT check, Live Devices, ISP monitor, bufferbloat,
Wi-Fi signal log, room tests); missing measurements cost nothing, they only add a "measure this" tip.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..result import Button, Result

HISTORY_KEY = "score_history"
AREAS = {"security": ("🔐 უსაფრთხოება", 40), "internet": ("🌐 ინტერნეტი", 30), "wifi": ("📶 Wi-Fi", 30)}
SEVERITY_COST = {"high": 8, "medium": 4, "low": 1}


@dataclass
class Score:
    lost: dict = field(default_factory=lambda: {a: 0.0 for a in AREAS})
    items: list = field(default_factory=list)   # (points, area, text, command)
    tips: list = field(default_factory=list)    # things not measured yet

    def take(self, area: str, points: float, text: str, cmd: str = "") -> None:
        cap = AREAS[area][1]
        points = min(points, cap - self.lost[area])
        if points > 0:
            self.lost[area] += points
            self.items.append((round(points), area, text, cmd))

    @property
    def value(self) -> int:
        return max(0, round(100 - sum(self.lost.values())))

    def area(self, a: str) -> int:
        cap = AREAS[a][1]
        return round(100 * (cap - self.lost[a]) / cap)


def compute(state, *, live_rows=None, isp_summary=None, wifi_now=None, wifi_hist=None, wifi_adv=None) -> Score:
    sc = Score()

    # --- security ----------------------------------------------------------------------------------
    iot = (state.get("iot_last") or {}).get("devices") or {}
    if not iot:
        sc.tips.append(("IoT უსაფრთხოება ჯერ არ შემოწმებულა", "/iot"))
    for ip, findings in iot.items():
        for f in findings:
            cost = SEVERITY_COST.get(f.get("severity"), 0)
            if cost:
                sc.take("security", cost, f"{ip}: {f.get('title', '')}", "/iot")
    if live_rows is not None:
        unknown = [r for r in live_rows if r.get("online") and not r.get("trusted") and not r.get("self")]
        for r in unknown[:3]:
            sc.take("security", 3, f"უცნობი მოწყობილობა ონლაინ: {r.get('label') or r.get('hostname') or r.get('vendor') or r['ip']}", "/live")

    # --- internet ----------------------------------------------------------------------------------
    s = isp_summary or {}
    up = s.get("uptime_percent")
    if up is not None and up < 99.5:
        sc.take("internet", min(12, (100 - up) * 3), f"ინტერნეტი 24 სთ-ში {up}% იყო ხელმისაწვდომი", "/isp")
    if s.get("down_now_since"):
        sc.take("internet", 12, "ინტერნეტი ახლა გათიშულია", "/diagnose")
    lat = s.get("latency_avg_ms")
    if lat is not None and lat > 60:
        sc.take("internet", 4, f"ping საშუალოდ {lat} ms (მაღალია)", "/diagnose")
    bb = [t for t in (state.get("bufferbloat_tests") or []) if t.get("grade") not in {None, "?"}]
    if not bb:
        sc.tips.append(("Bufferbloat ჯერ არ გაზომილა", "/bufferbloat"))
    else:
        cost = {"B": 3, "C": 7, "D": 10, "F": 14}.get(bb[-1]["grade"], 0)
        sc.take("internet", cost, f"Bufferbloat: {bb[-1]['grade']} — დატვირთვისას ping {bb[-1].get('worst_increase_ms')} ms-ით იზრდება", "/bufferbloat")
    tests = [t for t in (state.get("isp_speedtests") or []) if t.get("down_mbps") is not None][-5:]
    if not tests:
        sc.tips.append(("სიჩქარე ჯერ არ გაზომილა", "/speedtest"))
    else:
        down = statistics.median(t["down_mbps"] for t in tests)
        if down < 10:
            sc.take("internet", 8, f"ჩამოტვირთვა (download) მედიანა {down:.0f} Mbps — ძალიან ნელია", "/speedhistory")
        elif down < 25:
            sc.take("internet", 4, f"ჩამოტვირთვა (download) მედიანა {down:.0f} Mbps", "/speedhistory")

    # --- Wi-Fi -------------------------------------------------------------------------------------
    sig = [v for _, v in (wifi_hist or [])]
    if sig:
        avg = statistics.mean(sig)
        if avg < 50:
            sc.take("wifi", 10, f"ამ კომპიუტერის Wi-Fi სიგნალი საშუალოდ {avg:.0f}%", "/diagnose wifi")
        elif avg < 65:
            sc.take("wifi", 5, f"ამ კომპიუტერის Wi-Fi სიგნალი საშუალოდ {avg:.0f}%", "/diagnose wifi")
    if wifi_adv and wifi_adv.get("best") not in {None, wifi_adv.get("current")} and wifi_adv.get("gain", 0) >= 0.15:
        sc.take("wifi", 5, f"როუტერის არხი {wifi_adv['current']} გადატვირთულია — უკეთესია {wifi_adv['best']}", "/wifiscan")
    ch = str((wifi_now or {}).get("channel") or "")
    if ch.isdigit() and int(ch) <= 14:
        sc.take("wifi", 3, "კომპიუტერი 2.4 GHz-ზეა (5 GHz უფრო სწრაფია, თუ როუტერს აქვს)", "/wifiscan")
    from .rooms import summary as rooms_summary

    rooms = rooms_summary(state)
    if not rooms:
        sc.tips.append(("Wi-Fi ოთახებში ჯერ არ გაზომილა (ტელეფონით, „ქსელი“ ჩანართი)", "/rooms"))
    else:
        worst = min(rooms, key=lambda r: r["down"] or 0)
        if (worst["down"] or 0) < 15:
            sc.take("wifi", 8, f"{worst['room']}: Wi-Fi მხოლოდ {worst['down']} Mbps", "/rooms")
        elif (worst["down"] or 0) < 40:
            sc.take("wifi", 4, f"{worst['room']}: Wi-Fi {worst['down']} Mbps", "/rooms")
    sc.items.sort(key=lambda x: -x[0])
    return sc


def gather(s) -> Score:
    """Collect the inputs from the running services (each one optional)."""
    kw: dict = {}
    try:
        from .livedevices import ENGINE

        if ENGINE is not None:
            kw["live_rows"] = ENGINE.snapshot()["devices"]
    except Exception:  # noqa: BLE001
        pass
    try:
        from .isp import monitor_for

        kw["isp_summary"] = monitor_for(s).summary(1)
    except Exception:  # noqa: BLE001
        pass
    try:
        from . import quality
        from .morebooks import _windows_wifi

        kw["wifi_hist"] = quality.signal_history(24)
        if quality.IS_WINDOWS:
            kw["wifi_now"] = _windows_wifi() or {}
            nets = quality.scan_networks(fresh=False) or []
            kw["wifi_adv"] = quality.advise(nets, kw["wifi_now"])
    except Exception:  # noqa: BLE001
        pass
    return compute(s.state, **kw)


def remember(state, value: int, now: datetime | None = None) -> int | None:
    """Keep one score per day; return the score from about a week ago (or the oldest one) for comparison."""
    now = now or datetime.now()
    day = now.date().isoformat()

    def fn(v):
        v = dict(v or {})
        v[day] = value
        return dict(sorted(v.items())[-60:])

    hist = state.update(HISTORY_KEY, fn)
    week = (now - timedelta(days=7)).date().isoformat()
    older = [(d, x) for d, x in hist.items() if d <= week] or [(d, x) for d, x in hist.items() if d < day]
    return older[-1][1] if older else None


def label(v: int) -> str:
    return "🏆 შესანიშნავი" if v >= 90 else "🟢 კარგი" if v >= 75 else "🟡 საშუალო" if v >= 55 else "🔴 სუსტი"


def bar(pct: int) -> str:
    n = round(pct / 10)
    return "█" * n + "░" * (10 - n)


def format_score(sc: Score, before: int | None = None) -> str:
    v = sc.value
    trend = ""
    if before is not None and before != v:
        trend = f" ({'▲' if v > before else '▼'} {abs(v - before)} წინა გაზომვასთან)"
    lines = [f"**ქსელის ქულა: {v}/100** — {label(v)}{trend}", ""]
    for a, (name, _) in AREAS.items():
        lines.append(f"{name}: `{bar(sc.area(a))}` {sc.area(a)}%")
    if sc.items:
        lines.append("\n**რა გააკეთო ქულის გასაზრდელად:**")
        for pts, _, text, cmd in sc.items[:5]:
            lines.append(f"• +{pts} — {text}" + (f" → {cmd}" if cmd else ""))
    else:
        lines.append("\n✅ ყველაფერი რიგზეა, რაც გაზომილია.")
    if sc.tips:
        lines.append("\n**ჯერ არ გაზომილა** (ქულა უფრო ზუსტი იქნება):")
        lines += [f"• {t} → {c}" for t, c in sc.tips]
    return "\n".join(lines)


def score_cmd(s, args, user) -> Result:
    sc = gather(s)
    before = remember(s.state, sc.value)
    btns = [Button(f"🔧 {cmd}", cmd) for _, _, _, cmd in sc.items[:3] if cmd]
    return Result(format_score(sc, before), buttons=list({b.command: b for b in btns}.values()))


COMMANDS = {"score": score_cmd}
HELP = ["/score — ქსელის ქულა 0-100 (უსაფრთხოება, ინტერნეტი, Wi-Fi) და რა გააკეთო მის გასაზრდელად"]
BOT_COMMANDS = [("score", "ქსელის ქულა 0-100")]
TOOLS = [
    ({"name": "network_score", "description": "Overall home network score 0-100 (security, internet, Wi-Fi) with the "
                                              "deductions and the most useful fixes.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: (lambda sc: {"score": sc.value, "areas": {a: sc.area(a) for a in AREAS}, "deductions": sc.items,
                              "not_measured": sc.tips})(gather(ctx.services))),
]
