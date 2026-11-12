"""NetAgent DNS: ad / tracker / malware blocking for the whole home and per-device DNS statistics.

Off by default. NETAGENT_DNS=on starts a DNS server on this PC (UDP+TCP, port NETAGENT_DNS_PORT=53). Then, in the
router's DHCP settings, set the DNS server to this PC's IP (or set it on single devices). Every device then asks
NetAgent; blocked names get 0.0.0.0, everything else is forwarded to NETAGENT_DNS_UPSTREAM (1.1.1.1, 8.8.8.8).

  /dns                  status, today's numbers, top blocked, per-device
  /dns block|allow X    your own block / allow lists (allow wins) · /dns unblock X
  /dns pause 15 · /dns resume · /dns log [IP] · /dns test X · /dns update (re-download the block lists)

Only clients with private (LAN) addresses get answers, so it is never an open resolver on the internet.
If the PC is off, devices lose DNS: in the router keep a second DNS (e.g. 1.1.1.1) as a fallback.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct
import threading
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

from ..config import settings
from ..result import Button, CommandError, Result
from . import env_int

log = logging.getLogger("netagent.dns")

DEFAULT_LISTS = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
LISTS_KEY = "dns_lists"          # {"block": [...], "allow": [...]}
STATS_KEY = "dns_stats"
PAUSE_KEY = "dns_pause_until"
REFRESH_HOURS = 24


def enabled() -> bool:
    return os.getenv("NETAGENT_DNS", "off").strip().lower() in {"on", "1", "true", "yes"}


def upstreams() -> list[str]:
    raw = os.getenv("NETAGENT_DNS_UPSTREAM", "1.1.1.1,8.8.8.8")
    return [x.strip() for x in raw.split(",") if x.strip()]


def norm(name: str) -> str:
    return name.strip().strip(".").lower()


def parse_list(text: str) -> set[str]:
    """hosts files ("0.0.0.0 ads.example.com") and plain domain lists ("ads.example.com", "||ads.example.com^")."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        parts = line.split()
        name = parts[1] if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"} else parts[0]
        name = norm(name.removeprefix("||").removesuffix("^"))
        if "." in name and name not in {"localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0"}:
            out.add(name)
    return out


def suffixes(name: str):
    parts = name.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])


# =========================================================================================================
class Filter:
    """Decides block / allow. Lists: downloaded (data/dns/blocklist.txt) + the user's own (state)."""

    def __init__(self, state, root: Path | None = None):
        self.state = state
        self.root = root or settings.data_dir / "dns"
        self.lists: set[str] = set()
        self.loaded = 0.0
        self.lock = threading.Lock()

    @property
    def cache(self) -> Path:
        return self.root / "blocklist.txt"

    def load(self) -> int:
        try:
            names = parse_list(self.cache.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            names = set()
        with self.lock:
            self.lists = names
            self.loaded = self.cache.stat().st_mtime if self.cache.exists() else 0.0
        return len(names)

    def download(self, fetch=None) -> int:
        """Re-download the block lists (NETAGENT_DNS_LISTS, comma separated). Keeps the old file on failure."""
        urls = [u.strip() for u in os.getenv("NETAGENT_DNS_LISTS", DEFAULT_LISTS).split(",") if u.strip()]
        if fetch is None:
            import httpx

            def fetch(url):
                r = httpx.get(url, timeout=60, follow_redirects=True, headers={"User-Agent": "NetAgent"})
                r.raise_for_status()
                return r.text

        texts = []
        for u in urls:
            try:
                texts.append(fetch(u))
            except Exception as exc:  # noqa: BLE001 - one dead list must not stop the others
                log.warning("dns list %s: %s", u, exc)
        if not texts:
            raise CommandError("სიების ჩამოტვირთვა ვერ მოხერხდა (ინტერნეტი? NETAGENT_DNS_LISTS?).")
        names = set().union(*(parse_list(t) for t in texts))
        from ..osutil import atomic_write

        self.root.mkdir(parents=True, exist_ok=True)
        atomic_write(self.cache, "\n".join(sorted(names)) + "\n")
        return self.load()

    def own(self) -> dict:
        v = self.state.get(LISTS_KEY) or {}
        return {"block": set(v.get("block", [])), "allow": set(v.get("allow", []))}

    def paused(self) -> bool:
        return (self.state.get(PAUSE_KEY) or 0) > time.time()

    def verdict(self, name: str, own: dict | None = None) -> str:
        """'allow' (your allow list), 'block' (your block list), 'list' (downloaded list) or ''."""
        name = norm(name)
        own = own or self.own()
        sfx = list(suffixes(name))
        if any(x in own["allow"] for x in sfx):
            return "allow"
        if any(x in own["block"] for x in sfx):
            return "block"
        with self.lock:
            if any(x in self.lists for x in sfx):
                return "list"
        return ""

    def blocked(self, name: str, own: dict | None = None) -> bool:
        return not self.paused() and self.verdict(name, own) in {"block", "list"}


# =========================================================================================================
class Stats:
    def __init__(self):
        self.day = datetime.now().date().isoformat()
        self.total = 0
        self.blocked = 0
        self.clients: dict[str, list[int]] = {}   # ip -> [queries, blocked]
        self.top = Counter()
        self.top_blocked = Counter()
        self.client_top: dict[str, Counter] = {}
        self.recent: deque = deque(maxlen=300)
        self.lock = threading.Lock()

    def add(self, client: str, name: str, qtype: str, blocked: bool, ms: float | None) -> None:
        with self.lock:
            today = datetime.now().date().isoformat()
            if today != self.day:
                self.__init__()
            self.total += 1
            c = self.clients.setdefault(client, [0, 0])
            c[0] += 1
            if blocked:
                self.blocked += 1
                c[1] += 1
                self.top_blocked[name] += 1
            else:
                self.top[name] += 1
            ct = self.client_top.setdefault(client, Counter())
            ct[name] += 1
            if len(ct) > 2000:  # keep memory bounded on chatty devices
                self.client_top[client] = Counter(dict(ct.most_common(1000)))
            if len(self.top) > 20000:
                self.top = Counter(dict(self.top.most_common(5000)))
            self.recent.appendleft({"ts": datetime.now().strftime("%H:%M:%S"), "client": client, "name": name,
                                    "type": qtype, "blocked": blocked, "ms": ms})

    def as_dict(self) -> dict:
        with self.lock:
            return {"day": self.day, "total": self.total, "blocked": self.blocked,
                    "clients": {k: list(v) for k, v in self.clients.items()},
                    "top": self.top.most_common(20), "top_blocked": self.top_blocked.most_common(20),
                    "client_top": {k: v.most_common(10) for k, v in self.client_top.items()}}

    def restore(self, d: dict | None) -> None:
        if not d or d.get("day") != self.day:
            return
        with self.lock:
            self.total, self.blocked = d.get("total", 0), d.get("blocked", 0)
            self.clients = {k: list(v) for k, v in (d.get("clients") or {}).items()}
            self.top = Counter(dict(d.get("top") or []))
            self.top_blocked = Counter(dict(d.get("top_blocked") or []))
            self.client_top = {k: Counter(dict(v)) for k, v in (d.get("client_top") or {}).items()}


# =========================================================================================================
def lan_client(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


def blocked_answer(query):
    """0.0.0.0 / :: for A / AAAA (apps fail fast instead of waiting), NXDOMAIN-free empty answer otherwise."""
    import dns.message
    import dns.rdatatype
    import dns.rrset

    r = dns.message.make_response(query)
    q = query.question[0]
    if q.rdtype == dns.rdatatype.A:
        r.answer.append(dns.rrset.from_text(q.name, 60, "IN", "A", "0.0.0.0"))
    elif q.rdtype == dns.rdatatype.AAAA:
        r.answer.append(dns.rrset.from_text(q.name, 60, "IN", "AAAA", "::"))
    return r.to_wire()


class Resolver:
    """Forwards to upstream servers (UDP, TCP when asked) after the filter's decision."""

    def __init__(self, flt: Filter, stats: Stats, upstream: list[str] | None = None, timeout: float = 2.0):
        self.filter, self.stats = flt, stats
        self.upstream = upstream or upstreams()
        self.timeout = timeout

    async def handle(self, wire: bytes, client: str, tcp: bool = False) -> bytes | None:
        import dns.message
        import dns.rdatatype

        if not lan_client(client):
            return None
        try:
            q = dns.message.from_wire(wire)
            question = q.question[0]
        except Exception:  # noqa: BLE001 - garbage in, nothing out
            return None
        name = norm(question.name.to_text())
        qtype = dns.rdatatype.to_text(question.rdtype)
        if self.filter.blocked(name):
            self.stats.add(client, name, qtype, True, 0.0)
            return blocked_answer(q)
        t0 = time.monotonic()
        for server in self.upstream:
            try:
                ans = await (self._tcp(wire, server) if tcp else self._udp(wire, server))
            except (OSError, asyncio.TimeoutError):
                continue
            if ans:
                self.stats.add(client, name, qtype, False, round((time.monotonic() - t0) * 1000, 1))
                return ans
        self.stats.add(client, name, qtype, False, None)
        r = dns.message.make_response(q)
        r.set_rcode(2)  # SERVFAIL: every upstream failed
        return r.to_wire()

    async def _udp(self, wire: bytes, server: str) -> bytes:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        class P(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not fut.done():
                    fut.set_result(data)

            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        transport, _ = await loop.create_datagram_endpoint(P, remote_addr=(server, 53))
        try:
            transport.sendto(wire)
            return await asyncio.wait_for(fut, self.timeout)
        finally:
            transport.close()

    async def _tcp(self, wire: bytes, server: str) -> bytes:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 53), self.timeout)
        try:
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            n = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), self.timeout))[0]
            return await asyncio.wait_for(reader.readexactly(n), self.timeout)
        finally:
            writer.close()


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, resolver: Resolver):
        self.resolver = resolver
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self._answer(data, addr))

    async def _answer(self, data, addr):
        ans = await self.resolver.handle(data, addr[0])
        if ans and self.transport is not None:
            self.transport.sendto(ans, addr)


async def serve(resolver: Resolver, host: str, port: int) -> list:
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(lambda: _Udp(resolver), local_addr=(host, port))

    async def on_tcp(reader, writer):
        try:
            while True:
                n = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 10))[0]
                ans = await resolver.handle(await reader.readexactly(n), writer.get_extra_info("peername")[0], tcp=True)
                if not ans:
                    break
                writer.write(struct.pack("!H", len(ans)) + ans)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            pass
        finally:
            writer.close()

    tcp = await asyncio.start_server(on_tcp, host, port)
    return [udp, tcp]


# =========================================================================================================
# plug-in
# =========================================================================================================
FILTER: Filter | None = None
STATS = Stats()
RUNNING: dict = {}
FAILED: dict = {}


async def start(services, monitoring) -> list:
    global FILTER
    FILTER = Filter(services.state)
    STATS.restore(services.state.get(STATS_KEY))
    if not enabled():
        return []
    n = await asyncio.to_thread(FILTER.load)
    if not n:
        try:
            n = await asyncio.to_thread(FILTER.download)
        except CommandError as exc:
            log.warning("dns: %s", exc)
    host, port = os.getenv("NETAGENT_DNS_HOST", "0.0.0.0"), env_int("NETAGENT_DNS_PORT", 53)
    try:
        out = await serve(Resolver(FILTER, STATS), host, port)
    except OSError as exc:
        FAILED["error"] = f"{host}:{port} — {exc.strerror or exc}"
        log.warning("dns: could not listen on %s:%s (%s)", host, port, exc)
        return []
    RUNNING.update(host=host, port=port, since=datetime.now().isoformat(timespec="seconds"))
    log.info("dns: listening on %s:%s, %d blocked names", host, port, n)
    return out


def _filter(s) -> Filter:
    global FILTER
    if FILTER is None:
        FILTER = Filter(s.state)
        FILTER.load()
    return FILTER


def _names(s) -> dict[str, str]:
    """ip -> what the user knows the device as (name, hostname, vendor) from Live Devices."""
    try:
        from .livedevices import ENGINE

        if ENGINE is None:
            return {}
        return {r["ip"]: (r["label"] or r["hostname"] or r["vendor"] or "") for r in ENGINE.snapshot()["devices"]}
    except Exception:  # noqa: BLE001
        return {}


def _domain(arg: str) -> str:
    d = norm(arg.removeprefix("https://").removeprefix("http://").split("/", 1)[0])
    if "." not in d or " " in d:
        raise CommandError(f"„{arg}“ დომენს არ ჰგავს (მაგ. ads.example.com).")
    return d


def _edit(s, which: str, add: str | None = None, remove: str | None = None) -> None:
    def fn(v):
        v = v or {}
        cur = set(v.get(which, []))
        if add:
            cur.add(add)
        if remove:
            cur.discard(remove)
        v[which] = sorted(cur)
        return v

    s.state.update(LISTS_KEY, fn)


def status_text(s) -> str:
    f = _filter(s)
    d = STATS.as_dict()
    own = f.own()
    if RUNNING:
        head = f"🛡 **NetAgent DNS ჩართულია** — {RUNNING['host']}:{RUNNING['port']}, ბლოკ-სიაში {len(f.lists):,} დომენი"
    elif enabled():
        head = ("🛡 **NetAgent DNS** ჩართულია პარამეტრებში, მაგრამ სერვერი არ გაეშვა"
                + (f": {FAILED['error']}" if FAILED else "") + ".\nხშირი მიზეზი Windows-ზე: პორტ 53-ს იკავებს "
                "„Internet Connection Sharing“ (SharedAccess) ან Mobile hotspot — გამორთე hotspot, ან services.msc-ში "
                "SharedAccess → Disabled, შემდეგ გადატვირთე NetAgent.")
    else:
        return ("🛡 **NetAgent DNS** (რეკლამის / ტრეკერების / მავნე საიტების ბლოკი მთელ სახლში) **გამორთულია**.\n\n"
                "ჩართვა:\n1. `.env`-ში: `NETAGENT_DNS=on` და გადატვირთე NetAgent (start.bat).\n"
                "2. Windows Firewall-ის კითხვაზე — Allow (Private network).\n"
                "3. როუტერის ადმინ-პანელში → LAN / DHCP → DNS server 1 = ამ კომპიუტერის IP, DNS 2 = 1.1.1.1 "
                "(რომ კომპიუტერის გამორთვისას ინტერნეტი არ გაითიშოს).\n"
                "4. მოწყობილობებმა Wi-Fi ხელახლა რომ დაუკავშირდნენ — ახალ DNS-ს მიიღებენ.\n\n"
                "ცალკე მოწყობილობაზე სატესტოდ: მის Wi-Fi პარამეტრებში DNS ხელით მიუთითე ამ კომპიუტერის IP.")
    lines = [head]
    if f.paused():
        left = int(((s.state.get(PAUSE_KEY) or 0) - time.time()) // 60) + 1
        lines.append(f"⏸ ბლოკი შეჩერებულია კიდევ {left} წთ (`/dns resume`)")
    pct = round(100 * d["blocked"] / d["total"], 1) if d["total"] else 0
    lines.append(f"დღეს: **{d['total']:,}** მოთხოვნა, დაიბლოკა **{d['blocked']:,}** ({pct}%)")
    if own["block"] or own["allow"]:
        lines.append(f"შენი სიები: ბლოკი {len(own['block'])} · დაშვება {len(own['allow'])}")
    if d["top_blocked"]:
        lines.append("\n**ყველაზე ხშირად დაბლოკილი:**")
        lines += [f"• {n} — {c}" for n, c in d["top_blocked"][:8]]
    if d["clients"]:
        names = _names(s)
        lines.append("\n**მოწყობილობები:**")
        for ip, (q, b) in sorted(d["clients"].items(), key=lambda x: -x[1][0])[:12]:
            top = ", ".join(n for n, _ in d["client_top"].get(ip, [])[:3])
            who = f"{names[ip]} ({ip})" if names.get(ip) else ip
            lines.append(f"• {who}: {q} მოთხ., დაბლ. {b}" + (f" · {top}" if top else ""))
    return "\n".join(lines)


def dns_cmd(s, args, user) -> Result:
    f = _filter(s)
    sub = args[0].lower() if args else ""
    btns = [Button("📜 ლოგი", "/dns log"), Button("⏸ 15 წთ", "/dns pause 15")]
    if sub in {"block", "allow", "unblock", "test"} and len(args) < 2:
        raise CommandError(f"მიუთითე დომენი: /dns {sub} example.com")
    if sub == "block":
        d = _domain(args[1])
        _edit(s, "block", add=d)
        _edit(s, "allow", remove=d)
        return Result(f"⛔ {d} (და მისი ქვედომენები) დაიბლოკება.")
    if sub == "allow":
        d = _domain(args[1])
        _edit(s, "allow", add=d)
        _edit(s, "block", remove=d)
        return Result(f"✅ {d} ყოველთვის დაშვებულია (ბლოკ-სიაშიც რომ იყოს).")
    if sub == "unblock":
        d = _domain(args[1])
        _edit(s, "block", remove=d)
        _edit(s, "allow", remove=d)
        msg = f"{d} შენი სიებიდან ამოიღო."
        if f.verdict(d) == "list":
            msg += f" ის ჩამოტვირთულ ბლოკ-სიაშიცაა — სრულად დასაშვებად: /dns allow {d}"
        return Result(msg)
    if sub == "test":
        d = _domain(args[1])
        v = f.verdict(d)
        text = {"allow": "დაშვებულია (შენი დაშვების სია)", "block": "დაიბლოკება (შენი ბლოკ-სია)",
                "list": "დაიბლოკება (ჩამოტვირთული სია)", "": "არ იბლოკება"}[v]
        return Result(f"🔎 {d}: {text}" + (" — მაგრამ ბლოკი ახლა შეჩერებულია" if f.paused() and v in {"block", "list"} else ""))
    if sub == "pause":
        mins = int(args[1]) if len(args) > 1 and args[1].isdigit() else 15
        s.state.set(PAUSE_KEY, time.time() + mins * 60)
        return Result(f"⏸ ბლოკი შეჩერდა {mins} წუთით.", buttons=[Button("▶️ გაგრძელება", "/dns resume")])
    if sub == "resume":
        s.state.set(PAUSE_KEY, 0)
        return Result("▶️ ბლოკი ისევ მუშაობს.")
    if sub == "update":
        n = f.download()
        return Result(f"🔄 ბლოკ-სია განახლდა: {n:,} დომენი.")
    if sub == "log":
        ip = args[1] if len(args) > 1 else ""
        rows = [r for r in STATS.recent if not ip or r["client"] == ip][:40]
        if not rows:
            return Result("ლოგი ცარიელია" + (f" {ip}-სთვის" if ip else "") + ".")
        names = _names(s)
        return Result("📜 **ბოლო DNS მოთხოვნები**\n" + "\n".join(
            f"{r['ts']} {'⛔' if r['blocked'] else '·'} {names.get(r['client']) or r['client']} → {r['name']} ({r['type']})" for r in rows))
    if sub:
        raise CommandError("გამოყენება: /dns · /dns block|allow|unblock|test <დომენი> · /dns pause 15 · /dns resume · /dns log [IP] · /dns update")
    return Result(status_text(s), buttons=btns if RUNNING else [])


COMMANDS = {"dns": dns_cmd}
HELP = ["/dns — NetAgent DNS: რეკლამის/ტრეკერების/მავნე საიტების ბლოკი მთელ სახლში + ვინ რას სტუმრობს "
        "(/dns block|allow|test X, /dns pause 15, /dns log) · ჩართვა: NETAGENT_DNS=on"]
BOT_COMMANDS = [("dns", "რეკლამის ბლოკი და DNS სტატისტიკა")]
TOOLS = [
    ({"name": "dns_stats", "description": "NetAgent DNS filter: whether it runs, today's query/blocked counts, top blocked "
                                          "domains and per-device query counts with their top domains.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: {"running": bool(RUNNING), "enabled": enabled(), **STATS.as_dict()}),
]


def jobs(monitoring):
    if not enabled():
        return []

    async def save():
        await asyncio.to_thread(monitoring.s.state.set, STATS_KEY, STATS.as_dict())

    async def refresh():
        f = FILTER
        if f is not None and time.time() - f.loaded > REFRESH_HOURS * 3600:
            try:
                await asyncio.to_thread(f.download)
            except CommandError as exc:
                log.warning("dns refresh: %s", exc)

    return [("dnsstats", 300, 300, save), ("dnslists", 3600, 600, refresh)]
