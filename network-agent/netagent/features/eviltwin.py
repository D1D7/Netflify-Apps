"""Fake copy of your Wi-Fi ("evil twin"): a nearby access point broadcasting your network's name.

Attackers set up a network with the same name (often open, or with a weaker security) so phones join it and
their traffic or the Wi-Fi password can be captured. Every 15 minutes this PC scans the air:
  - your network's access points are learned the first time (trust on first use) and whenever this PC is
    actually connected to one of them;
  - a NEW access point with your network's name is suspicious when its security differs (e.g. open instead of
    WPA2) - high - or its hardware address is unrelated to yours (another maker, not a neighbouring address
    as dual-band routers and mesh points use) - medium.
One alert per suspicious access point, with a "it's mine (mesh)" button.

  /eviltwin                status: your network, its known access points, suspicious ones
  /eviltwin trust <BSSID>  it is yours (a mesh point / second router)
"""

from __future__ import annotations

import re
from datetime import datetime

from ..result import Button, CommandError, Result

KEY = "wifi_twins"   # {"ssid": {"known": {bssid: {...}}, "alerted": [bssid]}}
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _bytes(mac: str) -> list[int]:
    return [int(x, 16) for x in mac.split(":")]


def related(a: str, b: str) -> bool:
    """Same router family: same maker (locally-administered bit ignored) or at most two bytes apart in the address."""
    x, y = _bytes(a), _bytes(b)
    if [x[0] & ~0x02, x[1], x[2]] == [y[0] & ~0x02, y[1], y[2]]:
        return True
    return sum(p != q for p, q in zip(x, y)) <= 2


def sec_level(auth: str) -> int:
    a = (auth or "").lower()
    return 0 if not a or "open" in a else 1 if "wep" in a else 2 if "wpa2" in a or a.startswith("wpa-") else 3 if "wpa3" in a else 2


def check(state, networks: list[dict], current: dict | None, now: str | None = None) -> list[dict]:
    """Learn your access points, return new suspicious ones: [{bssid, ssid, signal, channel, auth, level, why}]."""
    now = now or datetime.now().isoformat(timespec="seconds")
    if not current or not current.get("ssid"):
        return []
    ssid = current["ssid"]
    data = state.get(KEY) or {}
    mine = data.get(ssid) or {"known": {}, "alerted": []}
    known = mine["known"]
    same = [n for n in networks if n.get("ssid") == ssid and MAC.match(n.get("bssid", ""))]
    cur_b = (current.get("bssid") or "").lower()
    if MAC.match(cur_b) and cur_b not in known:  # connected to it = it is ours
        known[cur_b] = {"auth": current.get("auth", ""), "first": now, "how": "connected"}
    if len(known) <= (1 if cur_b in known else 0) and not mine.get("learned"):
        for n in same:  # first look: what is on the air now is yours (trust on first use)
            known.setdefault(n["bssid"], {"auth": n.get("auth", ""), "first": now, "how": "first scan"})
        mine["learned"] = now
    suspects = []
    known_auth = {v.get("auth", "") for v in known.values() if v.get("auth")}
    for n in same:
        b = n["bssid"]
        if b in known:
            continue
        weaker = known_auth and sec_level(n.get("auth", "")) < min(sec_level(a) for a in known_auth)
        unrelated = known and not any(related(b, k) for k in known)
        if not weaker and not unrelated:
            known[b] = {"auth": n.get("auth", ""), "first": now, "how": "same router family"}  # a second band / mesh
            continue
        why = []
        if weaker:
            why.append(f"უსაფრთხოება სუსტია: {n.get('auth') or 'ღია'} (შენი: {', '.join(sorted(known_auth))})")
        if unrelated:
            why.append("სხვა მოწყობილობაა (მისამართი შენს როუტერს არ ეკუთვნის)")
        suspects.append({"bssid": b, "ssid": ssid, "signal": n.get("signal"), "channel": n.get("channel"),
                         "auth": n.get("auth", ""), "level": "high" if weaker else "medium", "why": why})
    new = [s for s in suspects if s["bssid"] not in mine["alerted"]]
    mine["alerted"] = sorted(set(mine["alerted"]) | {s["bssid"] for s in new})[-50:]
    mine["suspects"] = suspects
    mine["checked"] = now
    data[ssid] = mine
    state.set(KEY, data)
    return new


def trust(state, bssid: str) -> str:
    b = bssid.strip().lower().replace("-", ":")
    if not MAC.match(b):
        raise CommandError("BSSID ასე უნდა იყოს: aa:bb:cc:dd:ee:ff")
    data = state.get(KEY) or {}
    for ssid, mine in data.items():
        if any(s["bssid"] == b for s in mine.get("suspects", [])) or b in mine.get("alerted", []):
            mine["known"][b] = {"auth": "", "first": datetime.now().isoformat(timespec="seconds"), "how": "trusted by you"}
            mine["suspects"] = [s for s in mine.get("suspects", []) if s["bssid"] != b]
            state.set(KEY, data)
            return ssid
    raise CommandError(f"{b} საეჭვოთა სიაში არ არის.")


def scan_and_check(state) -> list[dict]:
    from . import quality
    from .morebooks import _windows_wifi

    current = _windows_wifi() if quality.IS_WINDOWS else None
    nets = quality.scan_networks() or []
    return check(state, nets, current)


def alert_text(s: dict) -> str:
    icon = "🔴" if s["level"] == "high" else "🟠"
    return (f"{icon} **შენი Wi-Fi-ის („{s['ssid']}“) ყალბი ასლი ჩანს?**\n"
            f"წვდომის წერტილი {s['bssid']} · სიგნალი {s['signal']}% · არხი {s['channel']}\n" + "\n".join(f"• {w}" for w in s["why"])
            + "\nთუ ეს შენი mesh / მეორე როუტერი არ არის — ტელეფონებზე „Forget“ და ხელახლა შეუერთდი; ნუ შეიყვან პაროლს უცნაურ გვერდზე.")


def format_status(state) -> str:
    data = state.get(KEY) or {}
    if not data:
        return "🛡 **ყალბი Wi-Fi (evil twin)** — ჯერ არ შემოწმებულა (ყოველ 15 წუთში მოწმდება; ახლავე: /eviltwin scan)."
    lines = ["🛡 **ყალბი Wi-Fi (evil twin)**"]
    for ssid, mine in data.items():
        lines.append(f"\n**{ssid}** — შენი წვდომის წერტილები: {len(mine['known'])} · ბოლო შემოწმება {str(mine.get('checked', ''))[11:16]}")
        for b, k in mine["known"].items():
            lines.append(f"• ✅ {b} ({k.get('how', '')})")
        for s in mine.get("suspects", []):
            lines.append(f"• {'🔴' if s['level'] == 'high' else '🟠'} {s['bssid']} — {'; '.join(s['why'])}")
        if not mine.get("suspects"):
            lines.append("✅ ყალბი ასლი არ ჩანს.")
    return "\n".join(lines)


def eviltwin_cmd(s, args, user) -> Result:
    from ..permissions import DENIED, is_viewer

    sub = args[0].lower() if args else ""
    if sub == "trust":
        if is_viewer(user):
            raise CommandError(DENIED)
        ssid = trust(s.state, args[1] if len(args) > 1 else "")
        return Result(f"✅ {args[1].lower()} — შენი ქსელის ({ssid}) წვდომის წერტილად ჩაიწერა.")
    if sub == "scan":
        scan_and_check(s.state)
    return Result(format_status(s.state), buttons=[Button("🔄 ახლავე შემოწმება", "/eviltwin scan")])


COMMANDS = {"eviltwin": eviltwin_cmd}
HELP = ["/eviltwin — შენი Wi-Fi-ის ყალბი ასლის (evil twin) აღმოჩენა · /eviltwin trust <BSSID> — ეს ჩემია (mesh)"]
TOOLS = [
    ({"name": "wifi_evil_twin", "description": "Is a fake copy of the user's Wi-Fi (same name, other device or weaker security) "
                                               "nearby? Known access points and suspicious ones.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: ctx.services.state.get(KEY) or {}),
]


def jobs(monitoring):
    import os

    from . import env_int

    every = env_int("NETAGENT_EVILTWIN_INTERVAL", 15)
    if every <= 0 or os.name != "nt":
        return []

    async def run():
        import asyncio

        from ..monitoring import Alert

        for sus in await asyncio.to_thread(scan_and_check, monitoring.s.state):
            await monitoring.emit(Alert("security", alert_text(sus), mutable=False,
                                        buttons=[Button("✓ ჩემია (mesh)", f"/eviltwin trust {sus['bssid']}"),
                                                 Button("🛡 დეტალები", "/eviltwin")]))

    return [("eviltwin", every * 60, 180, run)]
