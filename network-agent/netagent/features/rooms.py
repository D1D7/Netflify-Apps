"""Wi-Fi room by room: walk around with the phone, press "measure here" in each room, compare.

The phone measures against this PC over the home network (ping, download, upload: /api/lantest/*), so the
number shows the Wi-Fi in that spot, not the internet. Results are kept per room (last 10 each).

  /rooms         the comparison and what to do about the weak spots
  /rooms clear   start over
"""

from __future__ import annotations

import re
from datetime import datetime

from ..result import Button, CommandError, Result

KEY = "room_tests"
MAX_PER_ROOM = 10
MAX_ROOMS = 30
MAX_TEST_MB = 64


def clean_room(name: str) -> str:
    name = re.sub(r"\s+", " ", str(name or "")).strip()[:40]
    if not name:
        raise CommandError("მიუთითე ოთახის სახელი (მაგ. სამზარეულო).")
    return name


def _num(v, lo=0.0, hi=100000.0):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    return round(min(max(v, lo), hi), 1)


def save(state, room: str, res: dict, who: str = "") -> dict:
    room = clean_room(room)
    entry = {"ts": datetime.now().isoformat(timespec="seconds"), "down": _num(res.get("down")), "up": _num(res.get("up")),
             "ping": _num(res.get("ping"), 0, 10000), "jitter": _num(res.get("jitter"), 0, 10000), "who": who[:40]}
    if entry["down"] is None and entry["ping"] is None:
        raise CommandError("გაზომვის შედეგი ცარიელია.")

    def fn(v):
        v = v or {}
        v.setdefault(room, []).append(entry)
        v[room] = v[room][-MAX_PER_ROOM:]
        if len(v) > MAX_ROOMS:  # forget the room measured longest ago
            oldest = min(v, key=lambda r: v[r][-1]["ts"])
            v.pop(oldest)
        return v

    state.update(KEY, fn)
    return entry


def summary(state) -> list[dict]:
    """One row per room: the latest measurement and the median of the last ones, best first."""
    import statistics

    rows = []
    for room, tests in (state.get(KEY) or {}).items():
        downs = [t["down"] for t in tests if t.get("down") is not None]
        rows.append({"room": room, "last": tests[-1], "count": len(tests),
                     "down": round(statistics.median(downs), 1) if downs else None,
                     "up": tests[-1].get("up"), "ping": tests[-1].get("ping"), "jitter": tests[-1].get("jitter")})
    rows.sort(key=lambda r: -(r["down"] or 0))
    return rows


def grade(down: float | None, ping: float | None) -> str:
    if down is None:
        return "bad"
    if down >= 100 and (ping or 0) < 15:
        return "great"
    if down >= 40 and (ping or 0) < 30:
        return "good"
    if down >= 15:
        return "ok"
    return "bad"


GRADE_ICON = {"great": "🟢", "good": "🟢", "ok": "🟡", "bad": "🔴"}


def advice(rows: list[dict]) -> list[str]:
    if not rows:
        return []
    out = []
    best = rows[0]
    weak = [r for r in rows if r["down"] is not None and best["down"] and r["down"] < best["down"] * 0.35]
    if weak:
        out.append(f"📉 სუსტი წერტილი: **{', '.join(r['room'] for r in weak)}** — {best['room']}-ზე 3-ჯერ და მეტად ნელია. "
                   "გამოსავალი: როუტერი სახლის შუაში და მაღლა (არა კარადაში / იატაკზე), ან mesh / Wi-Fi repeater ამ ოთახსა და როუტერს შორის.")
    jittery = [r for r in rows if (r["jitter"] or 0) > 30]
    if jittery:
        out.append(f"〰️ არასტაბილური: {', '.join(r['room'] for r in jittery)} — ping „ხტის“, ვიდეოზარი შეიძლება ფერხდებოდეს. "
                   "ხშირი მიზეზი: მიკროტალღური, სქელი კედელი, მეზობლების ქსელები (/wifiscan).")
    if all(grade(r["down"], r["ping"]) in {"great", "good"} for r in rows):
        out.append("✅ Wi-Fi ყველა გაზომილ ოთახში კარგია.")
    if best["down"] and best["down"] < 60:
        out.append("💡 საუკეთესო ოთახშიც კი ნელია — თუ ტელეფონი 2.4 GHz-ზეა, სცადე 5 GHz ქსელი (თუ როუტერს აქვს).")
    return out


def format_rooms(rows: list[dict]) -> str:
    if not rows:
        return ("📍 **Wi-Fi ოთახებში** — ჯერ არაფერი გაზომილა.\nტელეფონით გახსენი აპი → „ქსელი“ → **Wi-Fi ოთახებში**, "
                "ჩაწერე ოთახის სახელი და დააჭირე „გაზომე აქ“. ასე გაიარე ყველა ოთახი.")
    lines = ["📍 **Wi-Fi ოთახებში** (ტელეფონიდან ამ კომპიუტერამდე, სახლის ქსელში)"]
    for r in rows:
        g = grade(r["down"], r["ping"])
        lines.append(f"{GRADE_ICON[g]} **{r['room']}** — ჩამოტვირთვა (download) {r['down']} Mbps · ატვირთვა (upload) {r['up']} Mbps · "
                     f"ping {r['ping']} ms" + (f" · {r['count']} გაზომვა" if r["count"] > 1 else ""))
    adv = advice(rows)
    if adv:
        lines.append("")
        lines += adv
    return "\n".join(lines)


def rooms_cmd(s, args, user) -> Result:
    if args and args[0].lower() == "clear":
        s.state.set(KEY, {})
        return Result("🧹 ოთახების გაზომვები წაიშალა.")
    return Result(format_rooms(summary(s.state)), buttons=[Button("📶 Wi-Fi არხები", "/wifiscan")])


COMMANDS = {"rooms": rooms_cmd}
HELP = ["/rooms — Wi-Fi ოთახების მიხედვით (ტელეფონით გაზომე „ქსელი“ ჩანართიდან) · /rooms clear"]
BOT_COMMANDS = [("rooms", "Wi-Fi ოთახების მიხედვით")]
TOOLS = [
    ({"name": "wifi_rooms", "description": "Wi-Fi measured room by room from the user's phone to this PC (download/upload "
                                           "Mbps, ping, jitter per room). Use for 'where is Wi-Fi weak at home'.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: summary(ctx.services.state)),
]
