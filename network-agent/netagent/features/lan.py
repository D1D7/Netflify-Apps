"""Home network extras: names for devices, a router security check, Wake-on-LAN.

  /name 192.168.1.5 დედას ტელეფონი   name a device (kept by MAC, so it survives an IP change)
  /name 192.168.1.5 -                 remove the name
  /names                              all names with IP and MAC
  /routercheck                        what the router exposes on the LAN (Telnet, FTP, UPnP, TR-069...) + advice
  /wake <name | IP | MAC>             Wake-on-LAN magic packet
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from ..newdevices import canonical_mac
from ..result import Button, CommandError, Result
from . import homenet

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
MAX_NAME = 40


# -- where a device is -------------------------------------------------------------------------------
def _last_seen(state) -> dict[str, str]:
    """{ip: mac} from the last scan plus the known-devices list (newest wins)."""
    out: dict[str, str] = {}
    for mac, e in (homenet.HomeTracker(state).known() or {}).items():
        if e.get("ip"):
            out[e["ip"]] = mac
    for e in (state.get("home_last_scan") or {}).get("devices", []):
        if e.get("mac"):
            out[e["ip"]] = e["mac"]
    return out


def _ip_of(state, mac: str) -> str:
    for ip, m in _last_seen(state).items():
        if m == mac:
            return ip
    return ""


def _is_random(mac: str) -> bool:
    return bool(mac) and int(mac[:2], 16) & 0x02 != 0  # locally administered = privacy / random MAC


def resolve(state, target: str) -> tuple[str, str]:
    """name / IP / MAC -> (ip, mac). Either may be empty when unknown."""
    target = target.strip()
    if _MAC_RE.match(target):
        mac = canonical_mac(target)
        return _ip_of(state, mac), mac
    if _IP_RE.match(target):
        mac = _last_seen(state).get(target) or homenet.read_arp().get(target, "")
        return target, mac
    wanted = target.lower()
    for key, name in homenet.device_names(state).items():
        if name.lower() == wanted:
            if key.startswith("ip:"):
                ip = key[3:]
                return ip, _last_seen(state).get(ip, "")
            return _ip_of(state, key), key
    raise CommandError(f"'{target}' ვერ ვიპოვე — მიუთითე IP, MAC ან სახელი (/names)")


# -- /name, /names -----------------------------------------------------------------------------------
def name_cmd(s, args, user) -> Result:
    if len(args) < 2:
        raise CommandError("გამოყენება: /name 192.168.1.5 დედას ტელეფონი   ·   წაშლა: /name 192.168.1.5 -")
    target, text = args[0], " ".join(args[1:]).strip()
    if not (_IP_RE.match(target) or _MAC_RE.match(target)):
        raise CommandError("პირველი უნდა იყოს IP ან MAC, მაგ. /name 192.168.1.5 დედას ტელეფონი")
    ip, mac = resolve(s.state, target)
    key = homenet.name_key(ip, mac)
    names = dict(homenet.device_names(s.state))
    if text in {"-", "--delete", "წაშლა"}:
        old = names.pop(key, None) or names.pop(f"ip:{ip}", None)
        s.state.set(homenet.NAMES_KEY, names)
        return Result(f"🗑️ სახელი წაიშალა: {old}" if old else "ამ მოწყობილობას სახელი არ ჰქონდა")
    clean = re.sub(r"[`*_\[\]<>|\\]", "", text)[:MAX_NAME].strip()
    if not clean:
        raise CommandError("სახელი ცარიელია")
    taken = [k for k, v in names.items() if v.lower() == clean.lower() and k != key]
    if taken:
        raise CommandError(f"სახელი „{clean}“ უკვე სხვა მოწყობილობას აქვს — აირჩიე სხვა")
    names[key] = clean
    if mac:
        names.pop(f"ip:{ip}", None)  # an older IP-only name for the same device
    s.state.set(homenet.NAMES_KEY, names)
    where = f"**{ip or '?'}**" + (f" · `{mac}`" if mac else "")
    note = ""
    if not mac:
        note = "\nℹ️ MAC ვერ ვნახე (ჯერ /scan) — სახელი IP-ზეა მიბმული და IP-ის შეცვლისას დაიკარგება."
    elif _is_random(mac):
        note = ("\nℹ️ privacy MAC: ტელეფონი ამ Wi-Fi-სთვის ჩვეულებრივ ერთსა და იმავეს იყენებს. თუ ტელეფონში "
                "„Private/Random address“ ყოველდღე იცვლება, სახელი ახალ MAC-ს ვერ მიჰყვება.")
    return Result(f"🏷️ {where} → **{clean}**{note}", buttons=[Button("🏷️ ყველა სახელი", "/names")])


def names_cmd(s, args, user) -> Result:
    names = homenet.device_names(s.state)
    if not names:
        return Result("სახელები ჯერ არ არის. ჯერ /scan, მერე: `/name 192.168.1.5 დედას ტელეფონი`",
                      buttons=[Button("🔍 სკანი", "/scan")])
    seen = _last_seen(s.state)
    online = {e["ip"] for e in (s.state.get("home_last_scan") or {}).get("devices", [])}
    lines = [f"🏷️ **მოწყობილობების სახელები** ({len(names)})"]
    for key, name in sorted(names.items(), key=lambda kv: kv[1].lower()):
        if key.startswith("ip:"):
            ip, mac = key[3:], seen.get(key[3:], "")
        else:
            ip, mac = _ip_of(s.state, key), key
        dot = "🟢" if ip and ip in online else "⚪"
        extra = " · privacy MAC" if _is_random(mac) else ""
        lines.append(f"{dot} **{name}** — {ip or 'IP უცნობია'}" + (f" · `{mac}`{extra}" if mac else ""))
    lines.append("\n🟢 ბოლო სკანში ჩანდა · ⚪ არ ჩანდა")
    return Result("\n".join(lines), buttons=[Button("🔍 სკანი", "/scan")])


# -- /routercheck ------------------------------------------------------------------------------------
ROUTER_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS", 7547: "TR-069",
                8080: "HTTP-alt", 8443: "HTTPS-alt", 8291: "Winbox", 8728: "MikroTik API"}
_SSDP = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
         "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()


def upnp_enabled(gateway: str, timeout: float = 3.0) -> bool:
    """Does the router answer an SSDP search for an Internet Gateway Device (UPnP port mapping)?"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.settimeout(0.5)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            for dest in (("239.255.255.250", 1900), (gateway, 1900)):
                try:
                    sock.sendto(_SSDP, dest)
                except OSError:
                    continue
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    data, addr = sock.recvfrom(4096)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if addr[0] == gateway and (b"InternetGatewayDevice" in data or b"WANIPConnection" in data):
                    return True
    except OSError:
        pass
    return False


def router_check(state=None, vendors=None) -> dict:
    gw = homenet.default_gateway()
    if not gw:
        raise CommandError("როუტერი (default gateway) ვერ ვიპოვე — კომპიუტერი ქსელშია?")
    with ThreadPoolExecutor(max_workers=16) as pool:
        upnp = pool.submit(upnp_enabled, gw)
        found = dict(zip(ROUTER_PORTS, pool.map(lambda p: homenet._probe(gw, p, 1.5), ROUTER_PORTS)))  # noqa: SLF001
        is_upnp = upnp.result()
    mac = homenet.read_arp().get(gw, "")
    vendor = (vendors.lookup(mac) if vendors and mac else "") or ""
    return {"gateway": gw, "mac": mac, "vendor": vendor, "open": sorted(p for p, ok in found.items() if ok), "upnp": is_upnp}


def format_router_check(r: dict) -> str:
    gw, open_ = r["gateway"], set(r["open"])
    head = f"🛡️ **როუტერის შემოწმება — {gw}**" + (f" · {r['vendor']}" if r["vendor"] else "")
    bad, warn, info = [], [], []
    if 23 in open_:
        bad.append("🔴 **Telnet ღიაა** — პაროლს დაუშიფრავად გადასცემს. გამორთე: Management / Security / Service Control → Telnet → Disable.")
    if 21 in open_:
        bad.append("🔴 **FTP ღიაა** — დაუშიფრავია. თუ USB დისკს არ აზიარებ, გამორთე.")
    if r["upnp"]:
        warn.append("🟠 **UPnP ჩართულია** — პროგრამებს (და ვირუსებს) შეუძლიათ ინტერნეტიდან პორტები თავად გახსნან. "
                    "თუ კონსოლი/ონლაინ თამაშები არ გჭირდება, გამორთე (Advanced / NAT / UPnP).")
    if 80 in open_ and 443 not in open_ and 8443 not in open_:
        warn.append("🟡 ადმინ-პანელი მხოლოდ **HTTP**-ით იხსნება (დაუშიფრავი) — შედი მხოლოდ სახლის ქსელიდან, "
                    "საჯარო Wi-Fi-ზე მისი პაროლი არ აკრიფო.")
    if 7547 in open_:
        info.append("ℹ️ TR-069 (7547) — პროვაიდერის დისტანციური მართვა. ნორმალურია, თუ როუტერი პროვაიდერისაა.")
    if open_ & {8291, 8728}:
        info.append("ℹ️ MikroTik Winbox/API ღიაა — დატოვე მხოლოდ LAN-ზე (/ip service → available-from).")
    if 22 in open_:
        info.append("✅ SSH ღიაა — დაშიფრულია. თუ არ იყენებ, შეგიძლია გამორთო.")
    if not bad and not warn:
        info.insert(0, "✅ ქსელიდან სახიფათო სერვისი (Telnet, FTP, UPnP) არ ჩანს.")
    manual = ["❔ ადმინის **ქარხნული პაროლი** შეცვლილია? (admin/admin, სტიკერზე დაწერილი...)",
              "❔ **WPS** გამორთულია? (ღილაკით/PIN-ით შეერთება — ადვილად ტყდება)",
              "❔ Wi-Fi: **WPA2** ან **WPA3** (არა WEP/Open), ძლიერი პაროლით?",
              "❔ **Remote management** (ინტერნეტიდან მართვა / WAN access) გამორთულია?",
              "❔ firmware განახლებულია? (ბოლო 1-2 წელი)"]
    svc = ", ".join(f"{p} {ROUTER_PORTS[p]}" for p in r["open"]) or "არცერთი"
    parts = [head, f"ღია პორტები: {svc}", ""] + bad + warn + info
    parts += ["", "**ხელით შესამოწმებელი** (ქსელიდან არ ჩანს) — ადმინ-პანელი: " + f"http://{gw}"] + manual
    return "\n".join(parts)


def routercheck_cmd(s, args, user) -> Result:
    return Result(format_router_check(router_check(s.state, s.vendors)), buttons=[Button("🔍 სკანი", "/scan")])


# -- /wake -------------------------------------------------------------------------------------------
def magic_packet(mac: str) -> bytes:
    return b"\xff" * 6 + bytes.fromhex(canonical_mac(mac).replace(":", "")) * 16


def send_wol(mac: str) -> list[str]:
    packet = magic_packet(mac)
    targets = {"255.255.255.255"}
    try:
        targets.add(str(ipaddress.ip_network(f"{homenet.local_ip()}/24", strict=False).broadcast_address))
    except ValueError:
        pass
    sent = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for t in sorted(targets):
            for port in (9, 7):
                try:
                    sock.sendto(packet, (t, port))
                    sent.append(f"{t}:{port}")
                except OSError:
                    continue
    return sent


def wake_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /wake <სახელი | IP | MAC>, მაგ. /wake სამუშაო კომპიუტერი")
    target = " ".join(args)
    ip, mac = resolve(s.state, target)
    if not mac:
        raise CommandError(f"{target}: MAC ვერ ვიპოვე. მოწყობილობა ერთხელ ჩართული უნდა იყოს /scan-ის დროს, ან მიუთითე MAC.")
    if not send_wol(mac):
        raise CommandError("magic packet ვერ გაიგზავნა (ქსელის შეცდომა)")
    name = homenet.device_names(s.state).get(mac, "")
    return Result(f"⏰ **Wake-on-LAN გაიგზავნა** → {name or target} (`{mac}`{', ' + ip if ip else ''})\n"
                  "~30-60 წამში უნდა ჩაირთოს. თუ არ ჩაირთო: BIOS-ში **Wake on LAN**, Windows-ში ქსელის ბარათზე "
                  "**Wake on Magic Packet**, და კომპიუტერი **კაბელით** უნდა იყოს მიერთებული (Wi-Fi-ზე იშვიათად მუშაობს).",
                  buttons=[Button("🔍 ჩაირთო?", f"/scan {ip}")] if ip else [])


COMMANDS = {"name": name_cmd, "names": names_cmd, "routercheck": routercheck_cmd, "wake": wake_cmd}
HELP = ["/name 192.168.1.5 დედას ტელეფონი — მოწყობილობის სახელი · /names — ყველა სახელი",
        "/routercheck — როუტერის უსაფრთხოების შემოწმება (Telnet, UPnP...) · /wake <სახელი> — კომპიუტერის ჩართვა (Wake-on-LAN)"]
BOT_COMMANDS = [("names", "მოწყობილობების სახელები"), ("routercheck", "როუტერის შემოწმება")]
