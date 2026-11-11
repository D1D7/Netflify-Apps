"""Wi-Fi dead zones: where at home the Wi-Fi is too weak or drops.

Two ways, both from the phone (Network tab → "Wi-Fi dead zones"):
  map   the home as a grid (e.g. 6×4 squares): stand somewhere, tap that square → a 5-second test
        (ping with loss, download to this PC); the grid turns into a heat map, dead squares in red
  walk  walk around with the phone: it pings this PC twice a second, shows the quality live and
        vibrates where the connection gets bad; "mark this spot" saves it with a name

A phone that fell back from Wi-Fi to mobile data (Android reports it) counts as a dead spot.
  /deadzones         dead and weak places (grid squares, marked spots, measured rooms) + what to do
  /deadzones clear   start over
"""

from __future__ import annotations

import re
from datetime import datetime

from ..result import Button, CommandError, Result

KEY = "wifi_map"
MAX_SPOTS = 50
MIN_SIZE, MAX_SIZE = 2, 10


def blank(cols: int = 6, rows: int = 4) -> dict:
    return {"cols": cols, "rows": rows, "cells": {}, "spots": [], "router": None}


def load(state) -> dict:
    v = state.get(KEY) or {}
    out = blank()
    out.update({k: v[k] for k in ("cols", "rows", "cells", "spots", "router") if k in v})
    return out


def _num(v, lo=0.0, hi=100000.0):
    try:
        return round(min(max(float(v), lo), hi), 1)
    except (TypeError, ValueError):
        return None


def measurement(res: dict) -> dict:
    net = str(res.get("net") or "")[:12].lower()
    return {"ts": datetime.now().isoformat(timespec="seconds"), "down": _num(res.get("down")),
            "ping": _num(res.get("ping"), 0, 10000), "loss": _num(res.get("loss"), 0, 100),
            "jitter": _num(res.get("jitter"), 0, 10000), "net": net if re.fullmatch(r"[a-z0-9_-]*", net) else ""}


def classify(m: dict) -> str:
    """'dead', 'weak', 'ok' or 'good'."""
    loss, down, ping = m.get("loss") or 0, m.get("down"), m.get("ping")
    if m.get("net") == "cellular" or loss >= 30 or (ping is None and down is None) or (down is not None and down < 5):
        return "dead"
    if loss >= 5 or (down is not None and down < 20) or (ping or 0) > 100:  # over Tailscale+HTTP 20-50 ms is normal
        return "weak"
    if (down is None or down >= 80) and (ping or 0) < 30 and loss == 0:
        return "good"
    return "ok"


def set_size(state, cols: int, rows: int) -> dict:
    try:
        cols, rows = int(cols), int(rows)
    except (TypeError, ValueError):
        raise CommandError("ბადის ზომა რიცხვებით მიუთითე") from None
    if not (MIN_SIZE <= cols <= MAX_SIZE and MIN_SIZE <= rows <= MAX_SIZE):
        raise CommandError(f"ბადე {MIN_SIZE}-დან {MAX_SIZE}-მდე უჯრა თითო მხარეს")

    def fn(v):
        v = v or blank()
        v["cols"], v["rows"] = cols, rows
        v["cells"] = {k: c for k, c in (v.get("cells") or {}).items()
                      if int(k.split(",")[0]) < rows and int(k.split(",")[1]) < cols}  # squares outside the new grid go
        return v

    return state.update(KEY, fn)


def save_cell(state, row, col, res: dict) -> dict:
    m = measurement(res)
    m["class"] = classify(m)

    def fn(v):
        v = v or blank()
        r, c = int(row), int(col)
        if not (0 <= r < v.get("rows", 4) and 0 <= c < v.get("cols", 6)):
            raise CommandError("ეს უჯრა ბადის გარეთაა")
        v.setdefault("cells", {})[f"{r},{c}"] = m
        return v

    try:
        state.update(KEY, fn)
    except (TypeError, ValueError):
        raise CommandError("უჯრის ნომერი არასწორია") from None
    return m


def set_router(state, row, col) -> dict:
    """Mark the router's square (the same square again clears it)."""
    def fn(v):
        v = v or blank()
        r, c = int(row), int(col)
        if not (0 <= r < v.get("rows", 4) and 0 <= c < v.get("cols", 6)):
            raise CommandError("ეს უჯრა ბადის გარეთაა")
        v["router"] = None if v.get("router") == f"{r},{c}" else f"{r},{c}"
        return v

    try:
        return state.update(KEY, fn)
    except (TypeError, ValueError):
        raise CommandError("უჯრის ნომერი არასწორია") from None


def _rc(key: str) -> tuple[int, int]:
    r, c = key.split(",")
    return int(r), int(c)


def _line_dist(p, a, b) -> float:
    """Distance of square p from the straight line a→b (in squares)."""
    (pr, pc), (ar, ac), (br, bc) = p, a, b
    dr, dc = br - ar, bc - ac
    n = (dr * dr + dc * dc) ** 0.5 or 1.0
    return abs(dr * (ac - pc) - dc * (ar - pr)) / n


def mesh_advice(m: dict) -> dict:
    """Where a mesh point / repeater helps: for each dead or weak square, the measured good/OK square on the way from
    the router that is closest to the problem (a repeater needs good signal itself). Plus a router move when the router
    stands far from the middle of the measured home."""
    out = {"mesh": [], "move_router": None, "need_router": False}
    cells = m.get("cells") or {}
    bad = [k for k, c in cells.items() if c.get("class") in {"dead", "weak"}]
    if not m.get("router"):
        out["need_router"] = bool(bad)
        return out
    router = _rc(m["router"])
    good = {k: c for k, c in cells.items() if c.get("class") in {"good", "ok"}}
    for k in sorted(bad, key=lambda k: (cells[k]["class"] != "dead", k)):
        target = _rc(k)
        dist_rt = ((target[0] - router[0]) ** 2 + (target[1] - router[1]) ** 2) ** 0.5
        best = None
        for g in good:
            p = _rc(g)
            d_r = ((p[0] - router[0]) ** 2 + (p[1] - router[1]) ** 2) ** 0.5
            d_t = ((p[0] - target[0]) ** 2 + (p[1] - target[1]) ** 2) ** 0.5
            if d_r < dist_rt and d_t < dist_rt and _line_dist(p, router, target) <= 1.01:
                score = (d_t, -d_r)  # as close to the problem as possible while the signal is still good
                if best is None or score < best[0]:
                    best = (score, g)
        if best:
            out["mesh"].append({"for": cell_name(k), "at": cell_name(best[1]), "measured": True})
        else:  # nothing measured on the way: suggest the middle of the way, to be measured first
            mid = (round((router[0] + target[0]) / 2), round((router[1] + target[1]) / 2))
            if mid != router and mid != target:
                out["mesh"].append({"for": cell_name(k), "at": cell_name(f"{mid[0]},{mid[1]}"), "measured": False})
    tested = [_rc(k) for k in cells]
    if len(tested) >= 4 and bad:
        cr = sum(r for r, _ in tested) / len(tested)
        cc = sum(c for _, c in tested) / len(tested)
        if ((router[0] - cr) ** 2 + (router[1] - cc) ** 2) ** 0.5 >= 1.5:
            out["move_router"] = cell_name(f"{round(cr)},{round(cc)}")
    # one mesh point often covers several problems: group by suggested square
    grouped: dict[str, dict] = {}
    for x in out["mesh"]:
        g = grouped.setdefault(x["at"], {"at": x["at"], "for": [], "measured": x["measured"]})
        g["for"].append(x["for"])
    out["mesh"] = sorted(grouped.values(), key=lambda g: -len(g["for"]))
    return out


def save_spot(state, name: str, res: dict) -> dict:
    name = re.sub(r"\s+", " ", str(name or "")).strip()[:40] or datetime.now().strftime("ადგილი %H:%M")
    m = measurement(res)
    m.update(name=name, **{"class": classify(m)})

    def fn(v):
        v = v or blank()
        v["spots"] = ((v.get("spots") or []) + [m])[-MAX_SPOTS:]
        return v

    state.update(KEY, fn)
    return m


def problems(state) -> dict:
    """Everything dead or weak: grid squares, marked spots and measured rooms."""
    from .rooms import summary as rooms_summary

    v = load(state)
    cells = [(k, c) for k, c in v["cells"].items() if c.get("class") in {"dead", "weak"}]
    spots = [s for s in v["spots"] if s.get("class") in {"dead", "weak"}]
    rooms = []
    for r in rooms_summary(state):
        cls = classify({"down": r["down"], "ping": r["ping"], "loss": 0})
        if cls in {"dead", "weak"}:
            rooms.append({**r, "class": cls})
    return {"map": v, "cells": cells, "spots": spots, "rooms": rooms}


def cell_name(key: str) -> str:
    r, c = (int(x) for x in key.split(","))
    return f"{chr(ord('A') + c)}{r + 1}"  # like a chessboard: column letter, row number


def format_deadzones(p: dict) -> str:
    v = p["map"]
    tested = len(v["cells"]) + len(v["spots"])
    if not tested and not p["rooms"]:
        return ("📵 **Wi-Fi მკვდარი ზონები** — ჯერ არაფერი გაზომილა.\nტელეფონით: „ქსელი“ → **Wi-Fi მკვდარი ზონები** → "
                "„რუკა“ (დადექი, დააჭირე შენს უჯრას) ან „სიარული“ (იარე სახლში — სადაც ტელეფონი აზუზუნდება, იქ ცუდია).")
    dead = [cell_name(k) for k, c in p["cells"] if c["class"] == "dead"] + [s["name"] for s in p["spots"] if s["class"] == "dead"] \
        + [r["room"] for r in p["rooms"] if r["class"] == "dead"]
    weak = [cell_name(k) for k, c in p["cells"] if c["class"] == "weak"] + [s["name"] for s in p["spots"] if s["class"] == "weak"] \
        + [r["room"] for r in p["rooms"] if r["class"] == "weak"]
    lines = [f"📵 **Wi-Fi მკვდარი ზონები** — გაზომილია {len(v['cells'])} უჯრა ({v['cols']}×{v['rows']} ბადე), "
             f"{len(v['spots'])} მონიშნული ადგილი"]
    if dead:
        lines.append(f"☠️ **მკვდარი:** {', '.join(dead)} — კავშირი წყდება ან ძალიან ნელია")
    if weak:
        lines.append(f"🟠 **სუსტი:** {', '.join(weak)}")
    cell_cell = [c for _, c in p["cells"]] + p["spots"]
    if any(c.get("net") == "cellular" for c in cell_cell):
        lines.append("📱 ზოგან ტელეფონი Wi-Fi-დან მობილურ ინტერნეტზე გადავიდა — იქ Wi-Fi საერთოდ არ წვდება.")
    adv = mesh_advice(v)
    if adv["need_router"]:
        lines.append("📡 რუკაზე მონიშნე, სად დგას როუტერი („📡 როუტერი“ ღილაკი) — მაშინ გეტყვი, სად დადგა mesh / repeater.")
    for g in adv["mesh"]:
        lines.append(f"📶 **mesh / repeater → {g['at']}** — დაფარავს: {', '.join(g['for'])}"
                     + ("" if g["measured"] else " (ეს უჯრა ჯერ გაზომე: იქ სიგნალი კარგი უნდა იყოს)"))
    if adv["move_router"]:
        lines.append(f"↔️ როუტერი სახლის კიდეშია — თუ შესაძლებელია, გადაიტანე **{adv['move_router']}**-ის ახლოს (გაზომილი სახლის შუა).")
    if not dead and not weak:
        lines.append("✅ მკვდარი ზონა ვერ ვიპოვე — ყველგან, სადაც გაზომე, Wi-Fi ნორმალურია.")
    else:
        lines.append("\n🔧 **რა ეშველება:**\n• როუტერი სახლის შუაში, მაღლა, ღიად (არა კარადაში, ტელევიზორის უკან, იატაკზე)\n"
                     "• მკვდარ ზონასა და როუტერს შორის — **mesh** წერტილი ან Wi-Fi repeater (შუა გზაზე, სადაც სიგნალი ჯერ კიდევ კარგია)\n"
                     "• შორს მყოფ ოთახში — 2.4 GHz უკეთ გადის კედლებში, ვიდრე 5 GHz\n"
                     "• თუ კაბელის გაყვანა შეიძლება — მეორე წვდომის წერტილი კაბელით (ყველაზე სანდოა)")
    return "\n".join(lines)


def deadzones_cmd(s, args, user) -> Result:
    if args and args[0].lower() == "clear":
        v = load(s.state)
        s.state.set(KEY, blank(v["cols"], v["rows"]))
        return Result("🧹 მკვდარი ზონების რუკა გასუფთავდა.")
    return Result(format_deadzones(problems(s.state)), buttons=[Button("📍 ოთახები", "/rooms"), Button("📶 არხები", "/wifiscan")])


COMMANDS = {"deadzones": deadzones_cmd}
HELP = ["/deadzones — Wi-Fi მკვდარი ზონები (ტელეფონით: სახლის ბადე-რუკა ან „სიარულის“ რეჟიმი) · /deadzones clear"]
BOT_COMMANDS = [("deadzones", "Wi-Fi მკვდარი ზონები")]
TOOLS = [
    ({"name": "wifi_dead_zones", "description": "Wi-Fi dead and weak zones at home measured from the phone: grid squares "
                                                "(A1, B3...), named spots from walk mode, weak rooms.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: (lambda p: {"grid": f"{p['map']['cols']}x{p['map']['rows']}",
                             "dead_or_weak_cells": {cell_name(k): c for k, c in p["cells"]},
                             "spots": p["spots"], "rooms": p["rooms"]})(problems(ctx.services.state))),
]
