"""Who is home: named devices (see /name) are checked every minute with ARP; a phone arriving or leaving
sends a notification.

  /home              who is home now (🟢 since / ⚪ away since)
  /home დედას ტელეფონი  last arrivals/departures of one device

Phones put Wi-Fi to sleep, so "left" is announced only after NETAGENT_PRESENCE_AWAY minutes without an answer
(default 15). Settings (.env):  NETAGENT_PRESENCE_INTERVAL=60 (seconds, 0 = off) · NETAGENT_PRESENCE_NOTIFY=on|off
"""

from __future__ import annotations

import os
import platform
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from ..newdevices import canonical_mac
from ..result import Button, Result
from . import env_int, homenet

STATE_KEY = "presence"
LOG_KEY = "presence_log"
MAX_LOG = 300
IS_WINDOWS = platform.system() == "Windows"


# -- is it there? ---------------------------------------------------------------------------------
def _sendarp(ip: str) -> str:
    """Windows: ask the device itself for its MAC (ARP request; answered even by a sleeping phone)."""
    import ctypes

    dest = struct.unpack("<I", socket.inet_aton(ip))[0]
    buf = ctypes.create_string_buffer(8)
    size = ctypes.c_ulong(6)
    if ctypes.windll.Iphlpapi.SendARP(dest, 0, buf, ctypes.byref(size)) != 0:  # type: ignore[attr-defined]
        return ""
    return canonical_mac(buf.raw[: size.value].hex())


def _proc_arp(ip: str) -> str:
    """Linux: poke the address (creates an ARP request), then read only *complete* entries (flags 0x2)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"", (ip, 9))
    except OSError:
        pass
    time.sleep(1.0)
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) >= 4 and f[0] == ip and f[2] == "0x2":
                return canonical_mac(f[3])
    except OSError:
        pass
    return ""


def arp_resolve(ip: str) -> str:
    try:
        return _sendarp(ip) if IS_WINDOWS else _proc_arp(ip)
    except (OSError, ValueError, AttributeError):
        return ""


def _targets(state) -> dict[str, tuple[str, str]]:
    """{name key: (name, last known IP)} for every named device."""
    from .lan import _ip_of

    out = {}
    for key, name in homenet.device_names(state).items():
        ip = key[3:] if key.startswith("ip:") else _ip_of(state, key)
        out[key] = (name, ip)
    return out


def check_all(state) -> dict[str, bool]:
    """{key: present?}. MAC-named devices must answer with that MAC (an IP can move to someone else)."""
    targets = _targets(state)
    if not targets:
        return {}
    arp_table: dict[str, str] | None = None

    def one(item):
        nonlocal arp_table
        key, (_, ip) = item
        if ip:
            mac = arp_resolve(ip)
            if mac and (key.startswith("ip:") or mac == key):
                return key, True
        if key.startswith("ip:"):
            return key, False
        # the phone may have a new IP (DHCP): find its MAC in the ARP table, then confirm at that address
        table = arp_table if arp_table is not None else homenet.read_arp()
        arp_table = table
        new_ip = next((i for i, m in table.items() if m == key), "")
        return key, bool(new_ip and new_ip != ip and arp_resolve(new_ip) == key)

    with ThreadPoolExecutor(max_workers=16) as pool:
        return dict(pool.map(one, targets.items()))


# -- state machine ----------------------------------------------------------------------------------
def update(state, present: dict[str, bool], now: float | None = None, away_minutes: int = 15) -> list[dict]:
    """Returns events [{"key", "event": "arrived"|"left", "ts"}]. The very first look is a silent baseline."""
    now = now or time.time()
    current = dict(state.get(STATE_KEY) or {})
    events = []
    for key, here in present.items():
        rec = current.get(key)
        if rec is None:  # first time we look at this device: no notification
            current[key] = {"home": here, "since": now, "last_seen": now if here else 0}
            continue
        if here:
            rec["last_seen"] = now
            if not rec["home"]:
                rec.update(home=True, since=now)
                events.append({"key": key, "event": "arrived", "ts": now})
        elif rec["home"] and now - (rec.get("last_seen") or rec["since"]) >= away_minutes * 60:
            rec.update(home=False, since=rec.get("last_seen") or now)
            events.append({"key": key, "event": "left", "ts": rec["since"]})
    for key in [k for k in current if k not in present]:
        current.pop(key)  # name was removed
    state.set(STATE_KEY, current)
    if events:
        log = (state.get(LOG_KEY) or []) + events
        state.set(LOG_KEY, log[-MAX_LOG:])
    return events


def _hm(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M")


def format_event(name: str, ev: dict) -> str:
    if ev["event"] == "arrived":
        return f"🏠 **{name}** სახლშია ({_hm(ev['ts'])})"
    return f"🚶 **{name}** წავიდა (ბოლოს ჩანდა {_hm(ev['ts'])})"


# -- command / job ------------------------------------------------------------------------------------
def home_cmd(s, args, user) -> Result:
    names = homenet.device_names(s.state)
    if not names:
        return Result("ჯერ არცერთ მოწყობილობას არ აქვს სახელი. ჯერ /scan, მერე: `/name 192.168.1.5 დედას ტელეფონი`",
                      buttons=[Button("🔍 სკანი", "/scan")])
    if args:
        wanted = " ".join(args).lower()
        key = next((k for k, n in names.items() if n.lower() == wanted), None)
        if key is None:
            return Result(f"'{' '.join(args)}' — ასეთი სახელი არ არის (/names)")
        log = [e for e in (s.state.get(LOG_KEY) or []) if e["key"] == key][-15:][::-1]
        if not log:
            return Result(f"**{names[key]}** — ჯერ არაფერი მომხდარა (მოსვლა/წასვლა ჩაიწერება)")
        lines = [f"📅 **{names[key]}** — ბოლო მოსვლა/წასვლა"]
        lines += [("🏠 მოვიდა " if e["event"] == "arrived" else "🚶 წავიდა ")
                  + datetime.fromtimestamp(e["ts"]).strftime("%m-%d %H:%M") for e in log]
        return Result("\n".join(lines))
    current = s.state.get(STATE_KEY) or {}
    lines = ["🏠 **ვინ არის სახლში**"]
    for key, name in sorted(names.items(), key=lambda kv: (not (current.get(kv[0]) or {}).get("home"), kv[1].lower())):
        rec = current.get(key)
        if rec is None:
            lines.append(f"❔ **{name}** — ჯერ არ შემიმოწმებია (≈1 წუთში)")
        elif rec["home"]:
            lines.append(f"🟢 **{name}** — სახლშია {datetime.fromtimestamp(rec['since']).strftime('%H:%M')}-დან")
        else:
            when = datetime.fromtimestamp(rec["since"]).strftime("%m-%d %H:%M") if rec.get("since") else "?"
            lines.append(f"⚪ **{name}** — არ არის (ბოლოს: {when})")
    if env_int("NETAGENT_PRESENCE_INTERVAL", 60) <= 0:
        lines.append("\n⚠️ შემოწმება გამორთულია (.env: NETAGENT_PRESENCE_INTERVAL)")
    return Result("\n".join(lines), buttons=[Button("🏷️ სახელები", "/names")])


def jobs(monitoring):
    every = env_int("NETAGENT_PRESENCE_INTERVAL", 60)
    if every <= 0:
        return []

    async def run():
        import asyncio

        from ..monitoring import Alert

        s = monitoring.s
        if not homenet.device_names(s.state):
            return
        present = await asyncio.to_thread(check_all, s.state)
        events = update(s.state, present, away_minutes=env_int("NETAGENT_PRESENCE_AWAY", 15))
        if events and os.getenv("NETAGENT_PRESENCE_NOTIFY", "on").lower() not in {"off", "0", "no", "false"}:
            names = homenet.device_names(s.state)
            text = "\n".join(format_event(names.get(e["key"], e["key"]), e) for e in events)
            await monitoring.emit(Alert("presence", text, [], mutable=False, buttons=[Button("🏠 ვინ არის სახლში", "/home")]))

    return [("presence", max(30, every), 45, run)]


COMMANDS = {"home": home_cmd}
HELP = ["/home — ვინ არის სახლში (სახელიანი ტელეფონები) · /home დედას ტელეფონი — მოსვლა/წასვლის ისტორია"]
BOT_COMMANDS = [("home", "ვინ არის სახლში")]
