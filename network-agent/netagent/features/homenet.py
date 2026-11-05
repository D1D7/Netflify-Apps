"""Home / office LAN scanner run from this PC: who is on the network, vendor, open ports.

No SSH devices needed. Discovery = a TCP probe to every address (this also makes the OS
resolve ARP), then the OS ARP table gives the MAC of everything that answered, even
phones with no open ports. Only private address ranges are allowed.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path

from ..newdevices import NewDeviceTracker, canonical_mac
from ..result import Button, CommandError, Result
from . import env_int

IS_WINDOWS = platform.system() == "Windows"
PORTS = {
    22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 631: "IPP", 1883: "MQTT", 3389: "RDP", 5000: "NAS/UPnP", 5001: "NAS",
    7000: "AirPlay", 8008: "Cast", 8009: "Cast", 8080: "HTTP-alt", 8291: "Winbox", 8443: "HTTPS-alt",
    9100: "Printer", 32400: "Plex", 62078: "iOS",
}
EXTRA_PORTS = {21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP", 161: "SNMP?", 389: "LDAP", 515: "LPD",
               548: "AFP", 1433: "MSSQL", 1900: "UPnP", 2000: "MikroTik bw-test", 3000: "Web app",
               3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-alt",
               8081: "HTTP-alt", 8728: "MikroTik API", 8729: "MikroTik API-SSL", 9000: "Web/Portainer",
               10000: "Webmin", 49152: "UPnP"}
SITE = "🏠 ლოკალური ქსელი"


class HomeTracker(NewDeviceTracker):
    KEY = "home_known_macs"


# -- local facts -------------------------------------------------------------------------
def local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # UDP connect sends nothing; it just picks the route
            return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def default_gateway() -> str | None:
    try:
        if IS_WINDOWS:
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True,
                                 timeout=10, errors="replace").stdout
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
            return m.group(1) if m else None
        route = Path("/proc/net/route")
        if route.exists():
            for line in route.read_text().splitlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[1] == "00000000":
                    return socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
        out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"gateway:\s*(\S+)", out)
        return m.group(1) if m else None
    except Exception:  # noqa: BLE001
        return None


_MAC = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"


def parse_arp_table(text: str) -> dict[str, str]:
    """Windows `arp -a`, Linux /proc/net/arp, macOS `arp -an` -> {ip: mac}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac = re.search(_MAC, line)
        if not ip or not mac or " 0x0 " in line:
            continue
        m = canonical_mac(mac.group(0))
        if not m or m in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"} or int(m[:2], 16) & 1:
            continue  # broadcast / multicast
        out[ip.group(1)] = m
    return out


def read_arp() -> dict[str, str]:
    p = Path("/proc/net/arp")
    if p.exists():
        return parse_arp_table(p.read_text())
    args = ["arp", "-a"] if IS_WINDOWS else ["arp", "-an"]
    try:
        return parse_arp_table(subprocess.run(args, capture_output=True, text=True, timeout=15, errors="replace").stdout)
    except Exception:  # noqa: BLE001
        return {}


def check_private(network: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        raise CommandError(f"არასწორი ქსელი: {network}") from exc
    if net.version != 4 or not (net.is_private or net in ipaddress.ip_network("100.64.0.0/10")):
        raise CommandError("სკანირება მხოლოდ შიდა (private) ქსელებშია დაშვებული: 10.x, 172.16-31.x, 192.168.x")
    if net.num_addresses > 1024:
        raise CommandError("ქსელი ძალიან დიდია (მაქს. /22 — 1024 მისამართი)")
    return net


# -- scanning -----------------------------------------------------------------------------
def _probe(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except OSError:
        return ""


def guess_kind(entry: dict, gateway: str | None) -> str:
    ports = set(entry.get("ports", []))
    vendor = (entry.get("vendor") or "").lower()
    if entry["ip"] == gateway:
        return "როუტერი (gateway)"
    if entry.get("self"):
        return "ეს კომპიუტერი"
    if 554 in ports:
        return "კამერა / NVR"
    if ports & {9100, 631, 515}:
        return "პრინტერი"
    if 8291 in ports or "mikrotik" in vendor:
        return "MikroTik"
    if 62078 in ports:
        return "iPhone / iPad"
    if ports & {8008, 8009} or any(v in vendor for v in ("google", "chromecast", "roku", "lg electronics", "sony")):
        return "ტელევიზორი / მედია"
    if ports & {5000, 5001} or "synology" in vendor or "qnap" in vendor:
        return "NAS"
    if ports & {445, 3389, 139}:
        return "Windows კომპიუტერი"
    if "raspberry" in vendor:
        return "Raspberry Pi"
    if "apple" in vendor:
        return "Apple მოწყობილობა"
    if any(v in vendor for v in ("samsung", "xiaomi", "huawei", "oppo", "vivo", "oneplus", "motorola")):
        return "ტელეფონი / პლანშეტი"
    if "შემთხვევითი" in vendor:
        return "ტელეფონი/ლეპტოპი (privacy MAC)"
    if any(v in vendor for v in ("tp-link", "ubiquiti", "netgear", "d-link", "zyxel", "asus")):
        return "ქსელური მოწყობილობა"
    if any(v in vendor for v in ("espressif", "tuya", "philips", "nest", "amazon")):
        return "ჭკვიანი სახლი (IoT)"
    if ports & {80, 443}:
        return "ვებ-ინტერფეისიანი მოწყობილობა"
    return ""


def scan(network: str = "", vendors=None, ports: dict[int, str] | None = None, timeout: float = 0.5) -> dict:
    me = local_ip()
    net = check_private(network or f"{me}/24")
    hosts = [str(h) for h in net.hosts()] if net.num_addresses > 2 else [str(net.network_address)]
    ports = ports or PORTS
    open_ports: dict[str, list[int]] = {}
    with ThreadPoolExecutor(max_workers=128) as pool:
        # pass 1: one probe per address (wakes ARP); pass 2: all ports on whoever is there
        first = {pool.submit(_probe, ip, 80, timeout): ip for ip in hosts if ip != me}
        wait(first)
        alive = {first[f] for f in first if f.result()}
        arp = read_arp()
        hostset = set(hosts)
        present = sorted(alive | (set(arp) & hostset) | ({me} & hostset),
                         key=lambda x: tuple(int(p) for p in x.split(".")))
        jobs = {pool.submit(_probe, ip, p, timeout): (ip, p) for ip in present for p in ports}
        names = {ip: pool.submit(_name, ip) for ip in present}
        wait(jobs)
        for f, (ip, p) in jobs.items():
            if f.result():
                open_ports.setdefault(ip, []).append(p)
        wait(names.values(), timeout=8)
    gateway = default_gateway()
    entries = []
    for ip in present:
        mac = arp.get(ip, "")
        e = {"ip": ip, "mac": mac, "vendor": (vendors.lookup(mac) if vendors and mac else "") or "",
             "name": names[ip].result() if names[ip].done() else "", "ports": sorted(open_ports.get(ip, []))}
        if ip == me:
            e["self"] = True
        e["kind"] = guess_kind(e, gateway)
        entries.append(e)
    return {"network": str(net), "this_pc": me, "gateway": gateway, "devices": entries,
            "scanned_at": datetime.now().isoformat(timespec="seconds")}


def format_scan(res: dict, ports: dict[int, str] | None = None) -> str:
    ports = ports or {**PORTS, **EXTRA_PORTS}
    lines = [f"🏠 **ქსელი {res['network']}** — {len(res['devices'])} მოწყობილობა"]
    for e in res["devices"]:
        label = " · ".join(x for x in (e.get("kind"), e.get("vendor"), e.get("name")) if x)
        svc = ", ".join(ports.get(p, str(p)) for p in e["ports"])
        lines.append(f"• **{e['ip']}**" + (f" — {label}" if label else "") + (f"\n  `{e['mac']}`" if e["mac"] else "")
                     + (f" · 🔓 {svc}" if svc else ""))
    risky = [e for e in res["devices"] if set(e["ports"]) & {23, 3389, 445, 5900, 21} and not e.get("self")]
    if risky:
        lines.append("\n⚠️ ყურადღება: " + ", ".join(
            f"{e['ip']} ({', '.join(ports[p] for p in e['ports'] if p in {23, 3389, 445, 5900, 21})})" for e in risky)
            + " — ეს სერვისები ინტერნეტში არ უნდა იყოს გახსნილი")
    return "\n".join(lines)


def scan_host(ip: str, vendors=None) -> dict:
    check_private(ip + "/32")
    allports = {**PORTS, **EXTRA_PORTS}
    with ThreadPoolExecutor(max_workers=64) as pool:
        res = dict(zip(allports, pool.map(lambda p: _probe(ip, p, 1.0), allports)))
    mac = read_arp().get(ip, "")
    return {"ip": ip, "mac": mac, "vendor": (vendors.lookup(mac) if vendors and mac else "") or "",
            "name": _name(ip), "open_ports": {p: allports[p] for p, ok in res.items() if ok}}


# -- commands / tools / jobs -----------------------------------------------------------------
def scan_cmd(s, args, user) -> Result:
    if args and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", args[0]):
        r = scan_host(args[0], s.vendors)
        svc = "\n".join(f"• {p} — {n}" for p, n in r["open_ports"].items()) or "ღია პორტი ვერ ვიპოვე"
        who = " · ".join(x for x in (r["vendor"], r["name"], r["mac"]) if x)
        return Result(f"🔍 **{r['ip']}**" + (f" — {who}" if who else "") + f"\n{svc}")
    res = scan(args[0] if args else "", s.vendors)
    s.state.set("home_last_scan", res)
    HomeTracker(s.state, s.vendors).process({SITE: [(e["ip"], e["mac"]) for e in res["devices"] if e["mac"]]})
    return Result(format_scan(res), buttons=[Button("🔄 თავიდან", "/scan")])


def _tool_scan(ctx, network: str = "", host: str = "") -> dict:
    s = ctx.services
    vendors = s.vendors if s else None
    try:
        return scan_host(host, vendors) if host else scan(network, vendors)
    except CommandError as exc:
        raise ValueError(str(exc)) from None


COMMANDS = {"scan": scan_cmd}
HELP = ["/scan — ლოკალური ქსელის სკანირება (ვინ არის Wi-Fi-ზე) · /scan 192.168.1.50 — ერთი მოწყობილობის პორტები"]
BOT_COMMANDS = [("scan", "ლოკალური ქსელის სკანირება")]
TOOLS = [({
    "name": "scan_local_network",
    "description": "Scan the LAN of the PC NetAgent runs on (home/office Wi-Fi): every device with IP, MAC, vendor, "
                   "hostname, open ports and a guessed type (router, phone, camera, printer...). Works without any "
                   "SSH device in the inventory. Give `host` to scan more ports of a single address. Private ranges only.",
    "input_schema": {"type": "object", "properties": {
        "network": {"type": "string", "description": "CIDR, e.g. 192.168.1.0/24. Empty = this PC's /24."},
        "host": {"type": "string", "description": "single IP for a detailed port scan"}}, "required": []},
}, _tool_scan)]


def jobs(monitoring):
    minutes = env_int("NETAGENT_HOME_SCAN_INTERVAL", 30)
    if minutes <= 0:
        return []

    async def run():
        import asyncio

        from ..monitoring import Alert
        from ..newdevices import format_new

        s = monitoring.s
        res = await asyncio.to_thread(scan, "", s.vendors)
        s.state.set("home_last_scan", res)
        new = HomeTracker(s.state, s.vendors).process({SITE: [(e["ip"], e["mac"]) for e in res["devices"] if e["mac"]]})
        if new:
            kinds = {e["ip"]: e["kind"] for e in res["devices"]}
            for n in new:
                n["vendor"] = " · ".join(x for x in (kinds.get(n["ip"]), n.get("vendor")) if x)
            await monitoring.emit(Alert("newdevice", format_new(new), [], mutable=False))

    return [("homescan", minutes * 60, 120, run)]
