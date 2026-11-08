"""Security watch for the local network: signs of an attack, checked in the background.

  ARP spoofing   the router's MAC changes, or another IP answers with the router's MAC
                 (a man-in-the-middle tells everyone "I am the router")
  rogue DHCP     a second DHCP server hands out addresses (a forgotten router, or an attacker
                 who gives everyone a fake gateway/DNS)
  new open port  a device that was already known suddenly opens remote access or file sharing
                 (RDP, SSH, Telnet, SMB, Winbox...), compared with every earlier /scan

  /security          status and recent findings
  /security check    run the ARP and DHCP checks now
  /security reset    forget the learned baseline (admin only), e.g. after replacing the router

Nothing is blocked or changed; findings arrive as "🔐 უსაფრთხოება" alerts. The DHCP check sends one
DHCPDISCOVER with a random made-up MAC (no lease is taken) every 30 minutes.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from datetime import datetime

from ..result import Button, CommandError, Result
from . import env_int, homenet

KEY = "secwatch"
MAX_EVENTS = 50
DHCP_REALERT = 6 * 3600
WATCH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 139: "NetBIOS", 445: "SMB", 1883: "MQTT", 3389: "RDP",
               5900: "VNC", 8080: "HTTP-alt", 8291: "Winbox", 8728: "MikroTik API"}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _special(mac: str) -> bool:
    """Broadcast / multicast MACs (first octet odd) are never a device."""
    try:
        return int(mac[:2], 16) & 1 == 1
    except ValueError:
        return True


def load(state) -> dict:
    return dict(state.get(KEY) or {})


def _event(w: dict, text: str) -> None:
    w["events"] = ((w.get("events") or []) + [{"ts": _now(), "text": text}])[-MAX_EVENTS:]


# -- ARP -------------------------------------------------------------------------------------------------
def check_arp(w: dict, gw: str | None, arp: dict[str, str], vendor=lambda mac: "") -> list[str]:
    """Compare the ARP table with the learned router MAC. Mutates w; returns alert lines."""
    if not gw or not arp.get(gw):
        return []
    mac = arp[gw]
    out = []
    if w.get("gateway") != gw or not w.get("gw_mac"):
        # first run, or this PC is now in another network: learn, don't alarm
        w.update(gateway=gw, gw_mac=mac, gw_since=_now(), pending_mac=None, shared_seen=[], dhcp_known=[])
    elif mac != w["gw_mac"]:
        if w.get("pending_mac") == mac:  # seen twice in a row: not a one-off glitch
            v = vendor(mac)
            out.append(f"🔴 **როუტერის ({gw}) MAC შეიცვალა:** `{w['gw_mac']}` → `{mac}`" + (f" ({v})" if v else "")
                       + "\nთუ როუტერი არ შეგიცვლიათ, ეს შეიძლება იყოს **ARP spoofing**: სხვა მოწყობილობა თავს როუტერად აცხადებს "
                       "და ტრაფიკს თავისკენ მიმართავს.")
            w.update(gw_mac=mac, gw_since=_now(), pending_mac=None)
        else:
            w["pending_mac"] = mac
    else:
        w["pending_mac"] = None
    seen = set(w.get("shared_seen") or [])
    for ip, m in sorted(arp.items()):
        if ip == gw or m != w["gw_mac"] or _special(m) or f"{ip}|{m}" in seen:
            continue
        seen.add(f"{ip}|{m}")
        out.append(f"🟠 **{ip} როუტერის MAC-ს იყენებს** (`{m}`) — ARP spoofing-ის კლასიკური ნიშანი. "
                   "თუ როუტერს მეორე მისამართი არ აქვს, მოძებნე ეს მოწყობილობა (/scan) და გათიშე.")
    w["shared_seen"] = sorted(seen)
    return out


# -- DHCP ------------------------------------------------------------------------------------------------
def _discover_packet(mac: bytes, xid: bytes) -> bytes:
    head = struct.pack("!BBBB4sHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                       b"\0" * 4, mac + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    return head + b"\x63\x82\x53\x63" + bytes([53, 1, 1, 55, 3, 1, 3, 6, 255])


def parse_offer(data: bytes, xid: bytes) -> dict | None:
    if len(data) < 240 or data[0] != 2 or data[4:8] != xid or data[236:240] != b"\x63\x82\x53\x63":
        return None
    opts, i, res = data[240:], 0, {"offered": socket.inet_ntoa(data[16:20])}
    while i + 1 < len(opts) and opts[i] != 255:
        if opts[i] == 0:
            i += 1
            continue
        code, ln = opts[i], opts[i + 1]
        val = opts[i + 2:i + 2 + ln]
        if code == 54 and ln == 4:
            res["server"] = socket.inet_ntoa(val)
        elif code == 3 and ln >= 4:
            res["router"] = socket.inet_ntoa(val[:4])
        elif code == 6 and ln >= 4:
            res["dns"] = socket.inet_ntoa(val[:4])
        i += 2 + ln
    return res


def dhcp_probe(timeout: float = 4.0) -> list[dict] | None:
    """Ask "who is a DHCP server?" once. Returns the offers, or None when this PC cannot check."""
    ip = homenet.local_ip()
    if not ip or ip.startswith(("127.", "169.254.")):
        return None
    xid, mac = os.urandom(4), bytes([0x02]) + os.urandom(5)  # random locally administered MAC: no real client
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return None
    offers: dict[str, dict] = {}
    with sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind((ip, 68))  # the LAN address, so the broadcast leaves through the right adapter
            sock.settimeout(0.5)
            sock.sendto(_discover_packet(mac, xid), ("255.255.255.255", 67))
        except OSError:
            return None
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, addr = sock.recvfrom(2048)
            except TimeoutError:
                continue
            except OSError:
                break
            offer = parse_offer(data, xid)
            if offer:
                offer["from"] = addr[0]
                offers[offer.get("server") or addr[0]] = offer
    return list(offers.values())


def check_dhcp(w: dict, offers: list[dict] | None, now: float | None = None) -> list[str]:
    """Compare DHCP servers that answered with the learned ones. Mutates w; returns alert lines."""
    if offers is None:
        return []
    now = now or time.time()
    servers = {o.get("server") or o["from"]: o for o in offers}
    w["dhcp_last"] = {"ts": _now(), "servers": sorted(servers)}
    known = set(w.get("dhcp_known") or [])
    if not known:
        w["dhcp_known"] = sorted(servers)
        if len(servers) <= 1:
            return []
        known = set()
    out = []
    alerted = dict(w.get("dhcp_alerted") or {})
    for sid, o in sorted(servers.items()):
        if sid in known or (sid in alerted and now - alerted[sid] < DHCP_REALERT):
            continue
        alerted[sid] = now
        extra = ", ".join(x for x in (f"IP-ს აძლევს: {o.get('offered')}" if o.get("offered") else "",
                                       f"gateway: {o['router']}" if o.get("router") else "",
                                       f"DNS: {o['dns']}" if o.get("dns") else "") if x)
        out.append(f"🔴 **უცხო DHCP სერვერი ქსელში: {sid}**" + (f" ({extra})" if extra else "")
                   + "\nმოწყობილობებმა შეიძლება მისგან მიიღონ არასწორი gateway/DNS — ანუ ინტერნეტი გაუფუჭდეთ ან ტრაფიკი "
                   "უცხოსთან წავიდეს. ხშირად ეს მეორე როუტერია, რომელიც LAN პორტით არის შეერთებული: მასზე DHCP გამორთე.")
    w["dhcp_alerted"] = alerted
    return out


# -- open ports (compares every home scan with the ports ever seen before) -------------------------------
def check_ports(w: dict, scan: dict | None, names: dict[str, str] | None = None) -> list[str]:
    if not scan or not scan.get("devices") or scan.get("scanned_at") == w.get("scan_at"):
        return []
    w["scan_at"] = scan.get("scanned_at")
    names = names or {}
    seen = dict(w.get("ports") or {})
    out = []
    for e in scan["devices"]:
        if e.get("self"):
            continue
        key = e.get("mac") or f"ip:{e['ip']}"
        ports = set(e.get("ports") or [])
        if key not in seen:
            seen[key] = sorted(ports)  # first time: learn
            continue
        new = sorted((ports - set(seen[key])) & set(WATCH_PORTS))
        seen[key] = sorted(set(seen[key]) | ports)  # "ever open", so a sleeping device does not cause repeats
        if new:
            who = names.get(e.get("mac", "")) or names.get(f"ip:{e['ip']}") or e.get("name") or e.get("vendor") or ""
            svc = ", ".join(f"{p} {WATCH_PORTS[p]}" for p in new)
            out.append(f"🟠 **ახალი ღია პორტი:** {e['ip']}" + (f" ({who})" if who else "") + f" — {svc}\n"
                       "თუ ეს თქვენ არ ჩართეთ, შეამოწმეთ ეს მოწყობილობა: დისტანციური წვდომა ან ფაილების გაზიარება "
                       "უცნობის მიერ შეიძლება იყოს ჩართული.")
    w["ports"] = seen
    return out


# -- running the checks ----------------------------------------------------------------------------------
def run_checks(s, dhcp: bool, probe=None) -> list[str]:
    w = load(s.state)
    vendor = (lambda mac: s.vendors.lookup(mac) or "") if getattr(s, "vendors", None) else (lambda mac: "")
    found = check_arp(w, homenet.default_gateway(), homenet.read_arp(), vendor)
    if dhcp:
        found += check_dhcp(w, (probe or dhcp_probe)())  # looked up at call time (tests replace it)
    found += check_ports(w, s.state.get("home_last_scan"), homenet.device_names(s.state))
    for f in found:
        _event(w, f.splitlines()[0])
    w["checked_at"] = _now()
    s.state.set(KEY, w)
    return found


def jobs(monitoring):
    import asyncio

    from ..monitoring import Alert

    every = env_int("NETAGENT_SECWATCH_INTERVAL", 5)
    if every <= 0:
        return []
    dhcp_every = max(every, env_int("NETAGENT_DHCP_CHECK_INTERVAL", 30))
    last_dhcp: dict = {"t": None}

    async def check():
        dhcp = last_dhcp["t"] is None or time.monotonic() - last_dhcp["t"] >= dhcp_every * 60
        if dhcp:
            last_dhcp["t"] = time.monotonic()
        found = await asyncio.to_thread(run_checks, monitoring.s, dhcp)
        if found:
            await monitoring.emit(Alert("security", "\n\n".join(found), [], mutable=False,
                                        buttons=[Button("🔐 დაცვის სტატუსი", "/security")]))

    return [("secwatch", every * 60, 90, check)]


# -- /security -------------------------------------------------------------------------------------------
def _ago(ts: str | None) -> str:
    return ts[5:16].replace("T", " ") if ts else "ჯერ არა"


def format_status(w: dict, s) -> str:
    lines = ["🔐 **ქსელის დაცვა**"]
    if w.get("gw_mac"):
        v = s.vendors.lookup(w["gw_mac"]) if getattr(s, "vendors", None) else ""
        lines.append(f"✅ როუტერი {w['gateway']} · `{w['gw_mac']}`" + (f" ({v})" if v else "") + f" — ცნობილია {_ago(w.get('gw_since'))}-დან")
        lines.append("✅ ARP: როუტერის MAC-ს სხვა არავინ იყენებს" if not w.get("shared_seen") else
                     f"⚠️ ARP: როუტერის MAC-ით სხვა მისამართებიც ჩანდა: {', '.join(x.split('|')[0] for x in w['shared_seen'])}")
    else:
        lines.append("⏳ როუტერი ჯერ არ შემოწმებულა")
    d = w.get("dhcp_last")
    if d is None:
        lines.append("⏳ DHCP ჯერ არ შემოწმებულა")
    else:
        extra = [x for x in d["servers"] if x not in (w.get("dhcp_known") or [])]
        lines.append((f"⚠️ DHCP: უცხო სერვერი {', '.join(extra)}" if extra else
                      f"✅ DHCP: მხოლოდ {', '.join(d['servers']) or '—'}") + f" (შემოწმდა {_ago(d['ts'])})")
    known = len(w.get("ports") or {})
    lines.append(f"✅ ღია პორტები: {known} მოწყობილობას ვადევნებ თვალს (ბოლო სკანი {_ago(w.get('scan_at'))})"
                 if known else "⏳ პორტები: პირველი სკანის შემდეგ დავიწყებ (/scan)")
    ev = (w.get("events") or [])[-6:]
    if ev:
        lines += ["", "**ბოლო მიგნებები**"] + [f"• {e['ts'][5:16].replace('T', ' ')} {e['text']}" for e in reversed(ev)]
    lines.append("\n_ARP — ყოველ 5 წთ-ში, DHCP — 30 წთ-ში, პორტები — ყოველი სკანის შემდეგ. არაფერს ვბლოკავ, მხოლოდ გატყობინებთ._")
    return "\n".join(lines)


def security_cmd(s, args, user) -> Result:
    from ..permissions import DENIED, is_viewer

    sub = args[0].lower() if args else ""
    buttons = [Button("🔍 შემოწმება ახლა", "/security check"), Button("🛡️ როუტერი", "/routercheck")]
    if sub == "reset":
        if is_viewer(user):
            return Result(DENIED)
        s.state.set(KEY, None)
        return Result("🔐 ნასწავლი მდგომარეობა წაიშალა — შემდეგი შემოწმება ახლიდან ისწავლის როუტერს, DHCP-ს და პორტებს.",
                      buttons=buttons[:1])
    if sub == "check":
        found = run_checks(s, dhcp=True)
        head = "\n\n".join(found) + "\n\n" if found else "✅ ახალი საფრთხე ვერ ვიპოვე.\n\n"
        return Result(head + format_status(load(s.state), s), buttons=buttons[1:])
    if sub:
        raise CommandError("გამოყენება: /security · /security check · /security reset")
    return Result(format_status(load(s.state), s), buttons=buttons)


COMMANDS = {"security": security_cmd}
HELP = ["/security — ქსელის დაცვა: ARP spoofing, უცხო DHCP სერვერი, ახალი ღია პორტები (/security check — ახლავე)"]
BOT_COMMANDS = [("security", "ქსელის დაცვა: ARP, DHCP, ღია პორტები")]
