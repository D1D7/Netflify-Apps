"""NetFlow v5 / v9 / IPFIX collector: who uses the bandwidth, to where, with which app.

Routers export flows to this PC (UDP NETAGENT_FLOW_PORT, default 2055):
  MikroTik:  /ip traffic-flow set enabled=yes interfaces=all
             /ip traffic-flow target add dst-address=<NetAgent PC> port=2055 version=9
  Cisco:     flow exporter NA / destination <PC> / transport udp 2055 / export-protocol netflow-v9
             flow monitor NA / exporter NA / record netflow ipv4 original-input
             interface Gi0/0 / ip flow monitor NA input
/top shows the busiest local hosts (download/upload), remote endpoints and applications.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

from ..result import Button, CommandError, Result
from . import env_int

FIELDS = {1: "bytes", 2: "packets", 4: "proto", 7: "sport", 8: "src", 11: "dport", 12: "dst", 23: "out_bytes",
          24: "out_packets", 27: "src6", 28: "dst6", 85: "bytes", 86: "packets"}
SERVICES = {443: "HTTPS", 80: "HTTP", 53: "DNS", 22: "SSH", 3389: "RDP", 25: "SMTP", 587: "SMTP", 993: "IMAP",
            123: "NTP", 1935: "RTMP (ვიდეო)", 3478: "Teams/STUN", 3479: "Teams", 3480: "Teams", 8801: "Zoom",
            5228: "Google Play", 5222: "WhatsApp", 1194: "OpenVPN", 51820: "WireGuard", 500: "IPsec", 4500: "IPsec",
            445: "SMB", 554: "RTSP (კამერა)", 6881: "BitTorrent", 51413: "BitTorrent", 27015: "Steam", 3074: "Xbox",
            9308: "PlayStation", 8080: "HTTP-alt", 853: "DNS-over-TLS", 5060: "SIP (ტელეფონი)", 10000: "RTP/ვიდეო"}
NAME_HINTS = [("googlevideo", "YouTube"), ("youtube", "YouTube"), ("1e100.net", "Google"), ("nflxvideo", "Netflix"),
              ("netflix", "Netflix"), ("fbcdn", "Facebook/Instagram"), ("facebook", "Facebook"), ("whatsapp", "WhatsApp"),
              ("tiktok", "TikTok"), ("byteoversea", "TikTok"), ("akamai", "Akamai CDN"), ("cloudfront", "Amazon CDN"),
              ("amazonaws", "AWS"), ("windowsupdate", "Windows Update"), ("microsoft", "Microsoft"), ("msedge", "Microsoft"),
              ("apple.com", "Apple"), ("icloud", "iCloud"), ("telegram", "Telegram"), ("cloudflare", "Cloudflare"),
              ("steam", "Steam"), ("spotify", "Spotify"), ("zoom", "Zoom"), ("discord", "Discord")]


def _ip(b: bytes) -> str:
    return str(ipaddress.ip_address(b))


def parse_v5(data: bytes) -> list[dict]:
    count = struct.unpack("!H", data[2:4])[0]
    out = []
    for i in range(count):
        r = data[24 + 48 * i: 72 + 48 * i]
        if len(r) < 48:
            break
        pkts, octets = struct.unpack("!II", r[16:24])
        sport, dport = struct.unpack("!HH", r[32:36])
        out.append({"src": _ip(r[0:4]), "dst": _ip(r[4:8]), "packets": pkts, "bytes": octets,
                    "sport": sport, "dport": dport, "proto": r[38]})
    return out


MAX_TEMPLATES = 1000  # real exporters send a handful; spoofed senders must not grow this forever


class TemplateCache:
    def __init__(self) -> None:
        self.t: dict[tuple, list[tuple[int, int]]] = {}

    def parse(self, data: bytes, exporter: str) -> list[dict]:
        version = struct.unpack("!H", data[:2])[0]
        if version == 5:
            return parse_v5(data)
        if version == 9:
            domain, pos = struct.unpack("!I", data[16:20])[0], 20
            tmpl_set = (0,)  # 1 = options templates (ignored)
        elif version == 10:
            domain, pos = struct.unpack("!I", data[12:16])[0], 16
            tmpl_set = (2,)  # 3 = options templates (ignored)
        else:
            return []
        flows = []
        while pos + 4 <= len(data):
            set_id, length = struct.unpack("!HH", data[pos:pos + 4])
            if length < 4:
                break
            body = data[pos + 4: pos + length]
            if set_id in tmpl_set:
                self._templates(body, exporter, domain, version)
            elif set_id >= 256:
                fmt = self.t.get((exporter, domain, set_id))
                if fmt:
                    flows += self._records(body, fmt)
            pos += length
        return flows

    def _templates(self, body: bytes, exporter: str, domain: int, version: int) -> None:
        p = 0
        while p + 4 <= len(body):
            tid, n = struct.unpack("!HH", body[p:p + 4])
            p += 4
            fields = []
            for _ in range(n):
                ftype, flen = struct.unpack("!HH", body[p:p + 4])
                p += 4
                if version == 10 and ftype & 0x8000:  # enterprise field: 4-byte PEN follows
                    p += 4
                    ftype = -1
                fields.append((ftype, flen))
            key = (exporter, domain, tid)
            if tid >= 256 and (key in self.t or len(self.t) < MAX_TEMPLATES):
                self.t[key] = fields

    @staticmethod
    def _records(body: bytes, fmt: list[tuple[int, int]]) -> list[dict]:
        size = sum(f[1] for f in fmt)
        if size == 0 or any(f[1] == 65535 for f in fmt):
            return []
        out = []
        for start in range(0, len(body) - size + 1, size):
            rec, p = {}, start
            for ftype, flen in fmt:
                raw = body[p:p + flen]
                p += flen
                name = FIELDS.get(ftype)
                if not name:
                    continue
                if name in {"src", "dst", "src6", "dst6"}:
                    rec[name.rstrip("6")] = _ip(raw)
                else:
                    rec[name] = int.from_bytes(raw, "big")
            if "src" in rec and "dst" in rec:
                rec["bytes"] = rec.get("bytes", 0) + rec.pop("out_bytes", 0)
                out.append(rec)
        return out


_PUBLIC_DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_local(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if any(a in n for n in _PUBLIC_DOC if a.version == 4):  # documentation ranges behave like the internet here
        return False
    return a.is_private or (a.version == 4 and a in _CGNAT)


MAX_KEYS = 1_000_000  # memory guard: anyone on the LAN can send (spoofed) flow packets with random IPs


class _Budget:
    def __init__(self, limit: int) -> None:
        self.limit, self.total = limit, 0


class _CappedCounter(Counter):
    """Counter that stops taking NEW keys when the shared budget is spent (existing keys still count up)."""

    def __init__(self, budget: _Budget) -> None:
        super().__init__()
        self._budget = budget

    def __setitem__(self, key, value) -> None:
        if key not in self:
            if self._budget.total >= self._budget.limit:
                return
            self._budget.total += 1
        super().__setitem__(key, value)


class FlowStats:
    """Per-minute counters for the last 24 hours (in memory)."""

    def __init__(self, max_keys: int = MAX_KEYS) -> None:
        self.lock = threading.Lock()
        self.minutes: dict[int, dict[str, Counter]] = {}
        self.exporters: Counter = Counter()
        self.budget = _Budget(max_keys)

    def add(self, flows: list[dict], exporter: str = "", now: float | None = None) -> None:
        minute = int((now or time.time()) // 60)
        with self.lock:
            # drop data older than 24 h first, so its memory budget is free for the new minute
            for old in [m for m in self.minutes if m < minute - 24 * 60]:
                self.budget.total -= sum(len(c) for c in self.minutes.pop(old).values())
            b = self.minutes.get(minute)
            if b is None:
                b = self.minutes[minute] = defaultdict(lambda: _CappedCounter(self.budget))
            for f in flows:
                n = f.get("bytes", 0)
                src, dst = f["src"], f["dst"]
                ls, ld = is_local(src), is_local(dst)
                if ld and not ls:
                    b["down"][dst] += n
                    b["remote"][src] += n
                    port = f.get("sport", 0)
                elif ls and not ld:
                    b["up"][src] += n
                    b["remote"][dst] += n
                    port = f.get("dport", 0)
                else:
                    b["lan"][src] += n
                    b["lan"][dst] += n
                    port = min(f.get("sport", 0) or 65535, f.get("dport", 0) or 65535)
                proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(f.get("proto", 0), str(f.get("proto", "")))
                b["app"][f"{proto}/{port}"] += n
                b["total"]["all"] += n
                if ls or ld:
                    b["pair"][f"{dst if ld and not ls else src}>{src if ld and not ls else dst}"] += n
            self.exporters[exporter] += len(flows)

    def window(self, minutes: int, now: float | None = None) -> dict[str, Counter]:
        end = int((now or time.time()) // 60)
        acc: dict[str, Counter] = defaultdict(Counter)
        covered = 0
        with self.lock:
            for m, b in self.minutes.items():
                if m > end - minutes:
                    covered += 1
                    for k, c in b.items():
                        acc[k].update(c)
        acc["_meta"]["minutes"] = covered
        return acc


STATS = FlowStats()
_RDNS: dict[str, str] = {}


def remote_name(ip: str) -> str:
    if ip in _RDNS:
        return _RDNS[ip]
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
    except OSError:
        host = ""
    label = next((name for hint, name in NAME_HINTS if hint in host), host)
    _RDNS[ip] = label
    return label


def app_name(key: str) -> str:
    proto, _, port = key.partition("/")
    p = int(port) if port.isdigit() else 0
    return SERVICES.get(p, f"{proto} {port}")


def human(n: float) -> str:
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{int(n)} B"


def top(s, minutes: int = 15, limit: int = 10) -> dict:
    w = STATS.window(minutes)
    names = {}
    try:
        from .ipam import seen

        known = seen(s)
        from .ipam import data as ipam_data

        assigned = ipam_data(s.state)["addresses"]
        for ip, e in known.items():
            names[ip] = assigned.get(ip, {}).get("name") or e.get("hostname") or e.get("kind") or e.get("vendor") or ""
        for ip, e in assigned.items():
            names[ip] = e.get("name", "")
    except Exception:  # noqa: BLE001
        pass
    hosts = Counter()
    for k in ("down", "up", "lan"):
        hosts.update(w.get(k, {}))
    secs = max(60, w["_meta"].get("minutes", 0) * 60)
    host_rows = [{"ip": ip, "name": names.get(ip, ""), "down": w["down"].get(ip, 0), "up": w["up"].get(ip, 0),
                  "lan": w["lan"].get(ip, 0), "avg_mbps": round((w["down"].get(ip, 0) + w["up"].get(ip, 0)) * 8 / secs / 1e6, 2)}
                 for ip, _ in hosts.most_common(limit)]
    remotes = w.get("remote", Counter()).most_common(limit)
    with ThreadPoolExecutor(max_workers=8) as pool:
        labels = list(pool.map(remote_name, [ip for ip, _ in remotes]))
    return {"minutes": minutes, "total_bytes": w.get("total", {}).get("all", 0), "hosts": host_rows,
            "remotes": [{"ip": ip, "name": lab, "bytes": n} for (ip, n), lab in zip(remotes, labels)],
            "apps": [{"app": app_name(k), "bytes": n} for k, n in w.get("app", Counter()).most_common(limit)],
            "exporters": dict(STATS.exporters)}


def format_top(t: dict) -> str:
    if not t["total_bytes"]:
        return ("📊 NetFlow მონაცემები ჯერ არ მოსულა.\nროუტერზე ჩართე flow export ამ კომპიუტერის IP-ზე, UDP "
                f"{env_int('NETAGENT_FLOW_PORT', 2055)} (MikroTik: /ip traffic-flow, Cisco: flow exporter) — იხ. README.")
    lines = [f"📊 **ტრაფიკი — ბოლო {t['minutes']} წთ** (სულ {human(t['total_bytes'])})", "", "**ვინ:**"]
    for h in t["hosts"]:
        label = f" ({h['name']})" if h["name"] else ""
        lines.append(f"• **{h['ip']}**{label} — ⬇ {human(h['down'])} ⬆ {human(h['up'])}"
                     + (f" · LAN {human(h['lan'])}" if h["lan"] else "") + f" · ~{h['avg_mbps']} Mbit/s")
    if t["remotes"]:
        lines += ["", "**სად:**"] + [f"• {r['name'] or r['ip']} ({r['ip']}) — {human(r['bytes'])}" for r in t["remotes"][:6]]
    if t["apps"]:
        lines += ["", "**რა:** " + ", ".join(f"{a['app']} {human(a['bytes'])}" for a in t["apps"][:6])]
    return "\n".join(lines)


def top_cmd(s, args, user) -> Result:
    try:
        minutes = int(args[0]) if args else 15
    except ValueError:
        raise CommandError("გამოყენება: /top · /top 60 (წუთები)") from None
    minutes = max(1, min(minutes, 24 * 60))
    return Result(format_top(top(s, minutes)), buttons=[Button("5 წთ", "/top 5"), Button("1 სთ", "/top 60"), Button("24 სთ", "/top 1440")])


COMMANDS = {"top": top_cmd}
HELP = ["/top — ვინ ტვირთავს ინტერნეტს (NetFlow): ჰოსტები, მიმართულებები, აპები · /top 60"]
BOT_COMMANDS = [("top", "ვინ ტვირთავს ინტერნეტს")]
TOOLS = [({
    "name": "top_talkers",
    "description": "Bandwidth usage from NetFlow/IPFIX exported by routers: busiest local hosts with download/upload, "
                   "top remote endpoints (with reverse-DNS service names like YouTube) and applications by port, over "
                   "the last N minutes. Use for 'who is using the internet', 'why is it slow', 'what is 192.168.1.21 doing'.",
    "input_schema": {"type": "object", "properties": {"minutes": {"type": "integer", "description": "1-1440, default 15"}},
                     "required": []},
}, lambda ctx, minutes=15: top(ctx.services, max(1, min(minutes, 1440))))]


class _Collector(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.templates = TemplateCache()

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            flows = self.templates.parse(data, addr[0])
        except (struct.error, ValueError, IndexError):
            return
        if flows:
            STATS.add(flows, addr[0])


async def start(services, monitoring):
    port = env_int("NETAGENT_FLOW_PORT", 2055)
    if port <= 0:
        return []
    import os

    host = os.getenv("NETAGENT_FLOW_HOST", "0.0.0.0")
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(_Collector, local_addr=(host, port))
    return [transport]
