"""Managed devices appear by themselves: plug a router / switch into the network and NetAgent adds it.

Every minute it looks at what Live Devices sees. A device that looks like network equipment (the gateway, a
MikroTik / Cisco / TP-Link / Ubiquiti... vendor, or MikroTik's Winbox port) with SSH open, and not yet in
inventory/devices.yaml, is logged into with the credentials profiles from devices.yaml (NET_USER / NET_PASS,
MIKROTIK_USER / MIKROTIK_PASS...). If the platform is recognised it is written into devices.yaml and a
notification says so; from then on it shows on the Network tab, in /status, the map, monitoring...

Credentials are only ever sent to devices that look like network equipment, never to phones or PCs. SSH closed:
looked at again after 30 minutes; a failed login is retried after 6 hours (/autoinventory retry = now). Off: NETAGENT_AUTO_INVENTORY=off
"""

from __future__ import annotations

import logging
import os
import socket
import time

from ..result import Button, Result

log = logging.getLogger("netagent.autoinventory")
TRIED_KEY = "autoinv_tried"
RETRY_SECONDS = 6 * 3600        # after a failed login (do not lock the account)
SSH_RETRY_SECONDS = 30 * 60     # SSH closed: cheap to look again
CLOSED = "SSH დახურულია"
NETWORK_KINDS = {"router", "network"}


def enabled() -> bool:
    return os.getenv("NETAGENT_AUTO_INVENTORY", "on").strip().lower() not in {"off", "0", "false", "no"}


def ssh_open(ip: str, port: int = 22, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def profiles(inv, row: dict) -> list[str]:
    """Credentials profiles to try, only those whose username variable is actually set in .env."""
    refs = getattr(inv, "_credential_refs", None) or {"default": {"username_env": "NET_USER"}}
    usable = [n for n, c in refs.items() if isinstance(c, dict) and c.get("username_env") and os.getenv(c["username_env"])]
    vendor = (row.get("vendor") or "").lower()
    mt = "mikrotik" in vendor or "routerboard" in vendor or 8291 in (row.get("ports") or [])
    # the vendor's own profile first (a MikroTik with the MikroTik login), then the default
    usable.sort(key=lambda n: (not (mt and "mikrotik" in n.lower()), n != "default"))
    return usable


def candidates(rows: list[dict], inv, tried: dict, now: float) -> list[dict]:
    known = {d.host for d in inv.devices.values()}
    out = []
    for r in rows:
        if not r.get("online") or r.get("self") or r["ip"] in known:
            continue
        if r.get("kind") not in NETWORK_KINDS and not r.get("gateway"):
            continue
        last = tried.get(r["ip"]) or {}
        wait = SSH_RETRY_SECONDS if last.get("result") == CLOSED else RETRY_SECONDS
        if last and now - last.get("ts", 0) < wait:
            continue
        out.append(r)
    return out


def check(s, live=None, detect=None, add=None, probe=ssh_open, now: float | None = None) -> list[dict]:
    """One pass. Returns [{ip, name, device_type}] of the devices added."""
    from ..config import settings
    from ..discovery import add_to_inventory
    from ..discovery import detect as ssh_detect

    if live is None:
        from . import livedevices

        live = livedevices.ENGINE
    if live is None:
        return []
    now = time.time() if now is None else now
    detect, add = detect or ssh_detect, add or add_to_inventory
    inv = s.inventory()
    tried = s.state.get(TRIED_KEY) or {}
    added = []
    for r in candidates(live.snapshot()["devices"], inv, tried, now):
        note = {"ts": now, "result": ""}
        if not probe(r["ip"]):
            note["result"] = CLOSED
        else:
            for prof in profiles(inv, r) or []:
                c = detect(inv, r["ip"], 22, prof)
                if c.device_type:
                    names = add(settings.inventory_path, [c], prof, site="")
                    if names:
                        added.append({"ip": r["ip"], "name": names[0], "device_type": c.device_type, "profile": prof})
                        note["result"] = f"დაემატა: {names[0]}"
                    break
                note["result"] = c.error or "ვერ ამოვიცანი"
            else:
                note["result"] = note["result"] or "credentials არ არის მითითებული (.env)"
        tried[r["ip"]] = note
        log.info("auto-inventory %s: %s", r["ip"], note["result"])
    s.state.set(TRIED_KEY, tried)
    return added


def autoinv_cmd(s, args, user) -> Result:
    tried = s.state.get(TRIED_KEY) or {}
    lines = ["🔌 **მოწყობილობების ავტომატური დამატება** — " + ("ჩართულია" if enabled() else "გამორთულია (NETAGENT_AUTO_INVENTORY)"),
             "როცა მართვად როუტერს/switch-ს ქსელში შეაერთებ, NetAgent SSH-ით შედის (devices.yaml-ის credentials-ით), "
             "ამოიცნობს და „ქსელი“ ჩანართზე თავისით ჩნდება."]
    if args and args[0].lower() == "retry":
        s.state.set(TRIED_KEY, {})
        return Result("🔄 ყველა ქსელური მოწყობილობა ხელახლა შემოწმდება 1 წუთში.")
    if tried:
        lines.append("\n**ბოლო მცდელობები:**")
        for ip, n in sorted(tried.items(), key=lambda x: -x[1].get("ts", 0))[:10]:
            lines.append(f"• {ip} — {n.get('result') or '...'} ({time.strftime('%d.%m %H:%M', time.localtime(n.get('ts', 0)))})")
    return Result("\n".join(lines), buttons=[Button("🔄 ხელახლა სცადე", "/autoinventory retry"), Button("📡 Live", "/live")])


COMMANDS = {"autoinventory": autoinv_cmd}
HELP = ["/autoinventory — შეერთებული როუტერები/switch-ები ავტომატურად ემატება (SSH + devices.yaml credentials)"]


def jobs(monitoring):
    if not enabled():
        return []

    async def run():
        import asyncio

        from ..monitoring import Alert

        added = await asyncio.to_thread(check, monitoring.s)
        for a in added:
            await monitoring.emit(Alert("newdevice", f"🔌 **ქსელს დაემატა მართვადი მოწყობილობა: {a['name']}**\n"
                                                     f"{a['ip']} · {a['device_type']} — ახლა ჩანს „ქსელი“ ჩანართზე და მონიტორინგშია.",
                                        [a["name"]], mutable=False, buttons=[Button("🩺 სტატუსი", f"/status {a['name']}")]))

    return [("autoinventory", 60, 40, run)]
