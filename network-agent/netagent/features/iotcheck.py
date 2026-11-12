"""IoT security check: well-known risky services on cameras, smart plugs, TV boxes, printers, routers.

  /iot                 every device Live Devices currently sees (except this PC)
  /iot 192.168.1.50    one device

Each check is one harmless request. NO passwords are ever tried:
  Telnet 23/2323, FTP 21, Android debug (ADB) 5555 open
  RTSP 554/8554   DESCRIBE without credentials: "200" means the video stream is open to anyone on the network
  MQTT 1883       CONNECT without credentials: accepted means anyone can read/control the smart-home devices
  vendor ports    34567 XMEye/Sofia, 37777 Dahua, 8000 Hikvision SDK, 9999 TP-Link Kasa (local control w/o login)
  HTTP 80/8080    embedded web servers known from old firmware (Server header); admin panel only over plain HTTP
"""

from __future__ import annotations

import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from ..result import Button, CommandError, Result
from . import homenet

KEY = "iot_last"
PORTS = (21, 23, 80, 443, 554, 1883, 2323, 5555, 8000, 8080, 8443, 8554, 9999, 34567, 37777)
RANK = {"high": 0, "medium": 1, "low": 2, "ok": 3}
OLD_SERVERS = [  # embedded HTTP servers that mean very old, rarely patched firmware
    (r"^Boa/0\.9", "Boa 0.9x (განვითარება 2005 წელს შეწყდა)"),
    (r"GoAhead", "GoAhead (ბევრ ძველ კამერაზე/როუტერზე — ცნობილი CVE-ები)"),
    (r"mini_httpd/1\.(1\d|2[0-9])\b", "mini_httpd (ძველი ვერსია)"),
    (r"^thttpd", "thttpd (ძველი)"),
    (r"lighttpd/1\.4\.([0-2]\d|3[0-4])\b", "lighttpd 1.4 (ძველი ვერსია)"),
    (r"uc-httpd", "uc-httpd (XMEye კამერები — ცნობილი სისუსტე)"),
    (r"(DNVRS|App|Hikvision)-Webs", "Hikvision-ის ძველი firmware"),
    (r"Allegro-Software-RomPager", "RomPager („Misfortune Cookie“ სისუსტე)"),
    (r"micro_httpd|Microsoft-IIS/[5-7]\.", "ძალიან ძველი ვებ-სერვერი"),
]


def _open(ip: str, port: int, timeout: float = 0.8) -> bool:
    return homenet._probe(ip, port, timeout)  # noqa: SLF001


def _talk(ip: str, port: int, data: bytes, timeout: float = 2.0, size: int = 2048) -> bytes:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(data)
            return s.recv(size)
    except OSError:
        return b""


def rtsp_status(ip: str, port: int = 554) -> int | None:
    """Status of an unauthenticated DESCRIBE (200 = open stream, 401 = password required)."""
    req = (f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n"
           "User-Agent: NetAgent-IoT-check\r\n\r\n").encode()
    m = re.match(rb"RTSP/1\.\d (\d{3})", _talk(ip, port, req))
    return int(m.group(1)) if m else None


def mqtt_connect_packet(client_id: str = "netagent-check") -> bytes:
    cid = client_id.encode()
    variable = b"\x00\x04MQTT" + b"\x04" + b"\x02" + struct.pack("!H", 10)  # MQTT 3.1.1, clean session, keepalive 10
    payload = struct.pack("!H", len(cid)) + cid
    rest = variable + payload
    return b"\x10" + bytes([len(rest)]) + rest


def mqtt_anonymous(ip: str, port: int = 1883) -> bool | None:
    """True: the broker accepted a connection without credentials. None: no MQTT answer."""
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.settimeout(2)
            s.sendall(mqtt_connect_packet())
            r = s.recv(4)
            try:
                s.sendall(b"\xe0\x00")  # DISCONNECT
            except OSError:
                pass
    except OSError:
        return None
    if len(r) >= 4 and r[0] == 0x20:
        return r[3] == 0
    return None


def adb_packet(cmd: bytes = b"CNXN", arg0: int = 0x01000000, arg1: int = 4096, data: bytes = b"host::\x00") -> bytes:
    c = struct.unpack("<I", cmd)[0]
    return struct.pack("<6I", c, arg0, arg1, len(data), sum(data) & 0xFFFFFFFF, c ^ 0xFFFFFFFF) + data


def adb_status(ip: str, port: int = 5555) -> str:
    """'open' (ADB answered CNXN: no authorization), 'auth' (ADB asks for a key), '' (not ADB at all)."""
    head = _talk(ip, port, adb_packet(), timeout=2.0, size=24)[:4]
    return "open" if head == b"CNXN" else "auth" if head == b"AUTH" else ""


def http_server(ip: str, port: int) -> str:
    raw = _talk(ip, port, f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetAgent-IoT-check\r\n\r\n".encode(), size=4096)
    m = re.search(rb"(?im)^server:\s*([^\r\n]+)", raw)
    return m.group(1).decode("latin-1").strip()[:80] if m else ""


def old_server(server: str) -> str:
    for rx, why in OLD_SERVERS:
        if re.search(rx, server, re.I):
            return why
    return ""


def finding(sev: str, title: str, advice: str, port: int | None = None) -> dict:
    return {"severity": sev, "title": title, "advice": advice, "port": port}


def check_device(ip: str, vendor: str = "", kind: str = "", probe=None) -> list[dict]:
    probe = probe or {}
    is_open = probe.get("open") or _open
    rtsp = probe.get("rtsp") or rtsp_status
    mqtt = probe.get("mqtt") or mqtt_anonymous
    server = probe.get("http") or http_server
    adb = probe.get("adb") or adb_status
    with ThreadPoolExecutor(max_workers=len(PORTS)) as pool:
        ports = {p for p, ok in zip(PORTS, pool.map(lambda p: is_open(ip, p), PORTS)) if ok}
    out: list[dict] = []
    for p in sorted(ports & {23, 2323}):
        out.append(finding("high", f"Telnet ღიაა (პორტი {p})",
                           "Telnet პაროლს დაუშიფრავად გადასცემს და ბოტნეტების (Mirai) მთავარი სამიზნეა. გამორთე მოწყობილობის "
                           "პარამეტრებში; თუ არ ითიშება — განაახლე firmware ან გამოყავი ცალკე (სტუმრის) ქსელში.", p))
    adb_state = adb(ip, 5555) if 5555 in ports else ""  # port 5555 is only ADB if it speaks ADB
    if adb_state == "open":
        out.append(finding("high", "Android debug (ADB) ღიაა პაროლის გარეშე — 5555",
                           "ADB ქსელით = მოწყობილობის სრული მართვა. TV box/ტელეფონზე: Developer options → "
                           "ADB debugging / Network debugging გამორთე.", 5555))
    elif adb_state == "auth":
        out.append(finding("medium", "Android debug (ADB) ქსელით ჩართულია — 5555",
                           "ითხოვს ავტორიზაციას, მაგრამ თუ არ იყენებ, Developer options-ში გამორთე.", 5555))
    if 21 in ports:
        out.append(finding("medium", "FTP ღიაა — 21", "FTP დაუშიფრავია. თუ ფაილების გაზიარება არ გჭირდება, გამორთე.", 21))
    for p in sorted(ports & {554, 8554}):
        st = rtsp(ip, p)
        if st == 200:
            out.append(finding("high", f"კამერის ვიდეო პაროლის გარეშე ჩანს (RTSP {p})",
                               "ქსელში ნებისმიერს შეუძლია ნახოს. კამერის პარამეტრებში ჩართე RTSP authentication და დააყენე "
                               "ძლიერი პაროლი.", p))
        elif st == 401:
            out.append(finding("ok", f"RTSP {p} პაროლითაა დაცული", "კარგია. დარწმუნდი, რომ ქარხნული პაროლი შეცვლილია.", p))
        else:
            out.append(finding("low", f"RTSP ვიდეო-სერვისი ღიაა ({p})", "ვერ დავადგინე, პაროლს თუ ითხოვს — შეამოწმე კამერის პარამეტრები.", p))
    if 1883 in ports:
        anon = mqtt(ip, 1883)
        if anon:
            out.append(finding("high", "MQTT პაროლის გარეშე იღებს კავშირს — 1883",
                               "ქსელში ნებისმიერს შეუძლია წაიკითხოს და მართოს ჭკვიანი სახლის მოწყობილობები. ჩართე "
                               "მომხმარებელი/პაროლი (Mosquitto: allow_anonymous false).", 1883))
        elif anon is False:
            out.append(finding("low", "MQTT პაროლით, მაგრამ დაუშიფრავად — 1883", "თუ შესაძლებელია, გამოიყენე 8883 (TLS).", 1883))
    if 34567 in ports:
        out.append(finding("high", "XMEye/Sofia კამერის პორტი ღიაა — 34567",
                           "იაფი კამერების ეს სერვისი ცნობილია უამრავი სისუსტით (CVE-2017-7577 და სხვ.). დაბლოკე ან გამოყავი "
                           "კამერა ცალკე ქსელში, ჩართე მხოლოდ საჭირო სერვისები.", 34567))
    if 37777 in ports:
        out.append(finding("medium", "Dahua-ს სერვისის პორტი ღიაა — 37777",
                           "ძველ firmware-ზე ცნობილი სისუსტეებია. განაახლე firmware და შეცვალე ქარხნული პაროლი.", 37777))
    if 8000 in ports and (ports & {554, 8554} or re.search(r"hikvision|ezviz", vendor, re.I)):
        out.append(finding("medium", "Hikvision SDK პორტი ღიაა — 8000",
                           "განაახლე firmware (ძველ ვერსიებზე CVE-2017-7921, CVE-2021-36260).", 8000))
    if 9999 in ports and re.search(r"tp-?link", vendor, re.I):
        out.append(finding("medium", "TP-Link Kasa ადგილობრივი მართვა ღიაა — 9999",
                           "ეს პროტოკოლი პაროლს არ ითხოვს: ქსელში ნებისმიერს შეუძლია ჩართოს/გამორთოს. განაახლე firmware.", 9999))
    for p in sorted(ports & {80, 8080}):
        srv = server(ip, p)
        why = old_server(srv)
        if why:
            out.append(finding("medium", f"ძველი ვებ-სერვერი: {srv}", f"{why}. firmware სავარაუდოდ დიდი ხანია არ "
                                                                      "განახლებულა — შეამოწმე მწარმოებლის საიტზე.", p))
    if ports & {80, 8080} and not ports & {443, 8443} and kind in {"camera", "router", "nas", "printer", "iot", "network"}:
        out.append(finding("low", "ადმინ-პანელი მხოლოდ HTTP-ით (დაუშიფრავად)",
                           "მისი პაროლი ქსელში ღიად გადაიცემა. შედი მხოლოდ სახლის ქსელიდან; თუ შესაძლებელია, ჩართე HTTPS.",
                           80 if 80 in ports else 8080))
    if not [f for f in out if f["severity"] != "ok"]:
        out.append(finding("ok", "ცნობილი სახიფათო სერვისი ვერ ვიპოვე", "ქარხნული პაროლის შეცვლა და firmware-ის განახლება "
                                                                     "მაინც შეამოწმე ხელით."))
    out.sort(key=lambda f: RANK[f["severity"]])
    return out


def run_check(s, only_ip: str = "", probe=None, devices: list[dict] | None = None) -> dict:
    """Check devices (from Live Devices, or the last /scan) and keep the result for the app."""
    if devices is None:
        from . import livedevices

        if livedevices.ENGINE is not None:
            devices = [r for r in livedevices.ENGINE.snapshot()["devices"] if r["online"] and not r["self"]]
        else:
            devices = [{"ip": e["ip"], "vendor": e.get("vendor", ""), "kind": ""}
                       for e in (s.state.get("home_last_scan") or {}).get("devices", []) if not e.get("self")]
    if only_ip:
        devices = [d for d in devices if d["ip"] == only_ip] or [{"ip": only_ip, "vendor": "", "kind": ""}]
    if not devices:
        raise CommandError("შესამოწმებელი მოწყობილობა ვერ ვიპოვე — გახსენი Live ჩანართი ან გაუშვი /scan")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(zip([d["ip"] for d in devices],
                           pool.map(lambda d: check_device(d["ip"], d.get("vendor", ""), d.get("kind", ""), probe), devices)))
    meta = {d["ip"]: {"name": d.get("label") or d.get("hostname") or d.get("kind_label") or d.get("vendor") or ""} for d in devices}
    data = {"ts": datetime.now().isoformat(timespec="seconds"),
            "devices": {**((s.state.get(KEY) or {}).get("devices", {}) if only_ip else {}), **results}, "meta": meta}
    s.state.set(KEY, data)
    return {"ts": data["ts"], "results": results, "meta": meta}


def format_report(r: dict) -> str:
    icons = {"high": "🔴", "medium": "🟠", "low": "🟡", "ok": "✅"}
    bad = sum(1 for fs in r["results"].values() for f in fs if f["severity"] in {"high", "medium"})
    lines = [f"🛡 **IoT უსაფრთხოება** — {len(r['results'])} მოწყობილობა, " + (f"{bad} სერიოზული მიგნება" if bad else "სერიოზული პრობლემა არ არის")]
    order = sorted(r["results"].items(), key=lambda kv: min(RANK[f["severity"]] for f in kv[1]))
    for ip, fs in order:
        name = r["meta"].get(ip, {}).get("name", "")
        lines.append(f"\n**{ip}**" + (f" · {name}" if name else ""))
        for f in fs:
            lines.append(f"{icons[f['severity']]} {f['title']}" + (f" — {f['advice']}" if f["severity"] in {"high", "medium"} else ""))
    lines.append("\n_პაროლებს არ ვცდი — მხოლოდ ვამოწმებ, რომელი სერვისია ღია და ითხოვს თუ არა პაროლს._")
    return "\n".join(lines)


def iot_cmd(s, args, user) -> Result:
    ip = args[0] if args else ""
    if ip and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        raise CommandError("გამოყენება: /iot · /iot 192.168.1.50")
    return Result(format_report(run_check(s, ip)), buttons=[Button("📡 Live", "/live"), Button("🛡️ როუტერი", "/routercheck")])


COMMANDS = {"iot": iot_cmd}
HELP = ["/iot — IoT უსაფრთხოება: კამერები, ჭკვიანი სახლი, TV box (Telnet, ღია ვიდეო, MQTT, ADB, ძველი firmware) · /iot 192.168.1.50"]
BOT_COMMANDS = [("iot", "IoT მოწყობილობების უსაფრთხოება")]
TOOLS = [
    ({"name": "iot_security_check",
      "description": "Check LAN devices (cameras, smart plugs, TV boxes, printers, router) for well-known risky services: "
                     "Telnet, open RTSP video without password, MQTT without password, Android ADB, vendor P2P ports, old "
                     "embedded web servers. No passwords are tried. Optional ip for one device.",
      "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": []}},
     lambda ctx, ip="": run_check(ctx.services, ip)),
]
