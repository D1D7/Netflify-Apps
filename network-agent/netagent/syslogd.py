"""Syslog receiver (UDP): stores device logs and raises alerts on important events.

Devices send to <this computer's IP>:514 (configurable). Messages are stored per day in
data/syslog/YYYY-MM-DD.jsonl (kept 14 days). Rules below turn some messages into alerts:
config changes (who and from where), interfaces going down, repeated failed logins,
and anything with severity critical or worse. Each rule is rate-limited per device.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Callable

log = logging.getLogger("netagent.syslog")

SEVERITY = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
KEEP_DAYS = 14
ALERT_COOLDOWN = 600          # seconds between alerts of the same kind for the same device
LOGIN_FAIL_THRESHOLD = 5      # failed logins ...
LOGIN_FAIL_WINDOW = 600       # ... within this many seconds


@dataclass
class LogEntry:
    ts: str
    host: str           # sender IP
    device: str         # inventory name, or the IP when unknown
    severity: int
    message: str

    def as_dict(self) -> dict:
        return {"ts": self.ts, "host": self.host, "device": self.device,
                "severity": SEVERITY[self.severity] if 0 <= self.severity < 8 else str(self.severity),
                "message": self.message}


_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.S)


def parse_message(data: bytes) -> tuple[int, str]:
    """Return (severity, message text). Handles RFC 3164 and RFC 5424 well enough for display."""
    text = data.decode("utf-8", errors="replace").strip().replace("\x00", "")
    m = _PRI.match(text)
    if not m:
        return 6, text
    pri, rest = int(m.group(1)), m.group(2).strip()
    rest = re.sub(r"^1 \S+ \S+ \S+ \S+ \S+ (?:\[.*?\]|-)\s*", "", rest)            # RFC 5424 header
    rest = re.sub(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(?:\S+\s+)?", "", rest)  # RFC 3164 timestamp + host
    rest = re.sub(r"^\d+:\s*(?:\*?[A-Z][a-z]{2}\s+\d+\s+[\d:.]+(?:\s+\w+)?:\s*)?", "", rest)  # Cisco seq + time
    return pri % 8, rest.strip()


# --------------------------------------------------------------------------- alert rules

_RULES: list[tuple[str, re.Pattern, Callable[[re.Match], str]]] = [
    ("config", re.compile(r"%SYS-5-CONFIG_I: Configured from (\S+) by (\S+)(?: on \S+ \(([\d.]+)\))?", re.I),
     lambda m: f"📝 config შეცვალა **{m.group(2)}**" + (f" ({m.group(3)})" if m.group(3) else f" ({m.group(1)})")),
    ("config", re.compile(r"UI_COMMIT: User '([^']+)' requested '(\w+)'", re.I),
     lambda m: f"📝 Junos {m.group(2)} — მომხმარებელი **{m.group(1)}**"),
    ("config", re.compile(r"config changed by (\S+)", re.I),
     lambda m: f"📝 config შეცვალა **{m.group(1)}**"),
    ("link", re.compile(r"%LINK-\d-UPDOWN: Interface (\S+), changed state to (down|administratively down)", re.I),
     lambda m: f"🔴 ინტერფეისი **{m.group(1).rstrip(',')}** ჩავარდა ({m.group(2)})"),
    ("link", re.compile(r"SNMP_TRAP_LINK_DOWN.*?ifName (\S+)", re.I),
     lambda m: f"🔴 ინტერფეისი **{m.group(1).rstrip(',')}** ჩავარდა"),
    ("link", re.compile(r"interface (\S+) link down", re.I),
     lambda m: f"🔴 ინტერფეისი **{m.group(1)}** ჩავარდა"),
    ("bgp", re.compile(r"%BGP-5-ADJCHANGE: neighbor (\S+) (?:vpn vrf \S+ )?Down(.*)", re.I),
     lambda m: f"🔴 BGP neighbor **{m.group(1)}** დაეცა{(' —' + m.group(2)) if m.group(2).strip() else ''}"),
    ("ospf", re.compile(r"%OSPF-5-ADJCHG: .*?Nbr (\S+) on (\S+) from FULL to (\S+)", re.I),
     lambda m: f"🔴 OSPF neighbor **{m.group(1)}** ({m.group(2)}) FULL → {m.group(3)}"),
]
_LOGIN_FAIL = re.compile(
    r"(LOGIN_FAILED|Login failed|login failure|authentication failure|Failed password|SSHD_LOGIN_FAILED)", re.I)
_LOGIN_USER_IP = re.compile(r"(?:user(?:name)?[: ]+'?\[?(\S+?)\]?'?[ ,].*?)?(?:from|source:?|\[Source:)\s*\[?([\d.]+)", re.I)


class SyslogStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = threading.Lock()
        self._last_prune: date | None = None

    def _file(self, d: date) -> Path:
        return self.root / f"{d.isoformat()}.jsonl"

    def append(self, entry: LogEntry) -> None:
        today = date.today()
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            with self._file(today).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.as_dict(), ensure_ascii=False) + "\n")
            if self._last_prune != today:
                self._last_prune = today
                cutoff = today - timedelta(days=KEEP_DAYS)
                for f in self.root.glob("*.jsonl"):
                    try:
                        if date.fromisoformat(f.stem) < cutoff:
                            f.unlink()
                    except ValueError:
                        continue

    def search(self, device: str = "", text: str = "", hours: float = 24, max_severity: int = 7,
               limit: int = 50) -> list[dict]:
        start = datetime.now() - timedelta(hours=hours)
        out: list[dict] = []
        d = start.date()
        needle = text.lower()
        while d <= date.today():
            f = self._file(d)
            if f.exists():
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if e["ts"] < start.isoformat(timespec="seconds"):
                        continue
                    if device and e["device"].lower() != device.lower() and e["host"] != device:
                        continue
                    sev = SEVERITY.index(e["severity"]) if e["severity"] in SEVERITY else 7
                    if sev > max_severity or (needle and needle not in e["message"].lower()):
                        continue
                    out.append(e)
            d += timedelta(days=1)
        return out[-limit:]


class SyslogAnalyzer:
    """Turns log entries into alert texts (with cooldown and login-failure counting)."""

    def __init__(self) -> None:
        self._last: dict[tuple[str, str], float] = {}
        self._fails: dict[str, deque] = defaultdict(deque)

    def _allowed(self, device: str, kind: str, now: float) -> bool:
        key = (device, kind)
        if key in self._last and now - self._last[key] < ALERT_COOLDOWN:
            return False
        self._last[key] = now
        return True

    def analyze(self, e: LogEntry, now: float | None = None) -> str | None:
        now = now if now is not None else time.time()
        for kind, rx, fmt in _RULES:
            m = rx.search(e.message)
            if m:
                if kind == "config" or self._allowed(e.device, f"{kind}:{m.group(1)}", now):
                    return f"**{e.device}**: {fmt(m)}"
                return None
        if _LOGIN_FAIL.search(e.message):
            q = self._fails[e.device]
            q.append(now)
            while q and now - q[0] > LOGIN_FAIL_WINDOW:
                q.popleft()
            if len(q) >= LOGIN_FAIL_THRESHOLD and self._allowed(e.device, "login", now):
                who = _LOGIN_USER_IP.search(e.message)
                src = f" (ბოლო: {who.group(2)})" if who and who.group(2) else ""
                return (f"**{e.device}**: 🔐 {len(q)} წარუმატებელი შესვლა "
                        f"{LOGIN_FAIL_WINDOW // 60} წუთში{src} — შესაძლო brute force")
            return None
        if e.severity <= 2 and self._allowed(e.device, "severe", now):
            return f"**{e.device}**: 🔥 {SEVERITY[e.severity].upper()}: {e.message[:200]}"
        return None


class SyslogServer(asyncio.DatagramProtocol):
    def __init__(self, store: SyslogStore, resolve: Callable[[str], str],
                 on_alert: Callable[[str, str], None]) -> None:
        self.store = store
        self.resolve = resolve
        self.on_alert = on_alert
        self.analyzer = SyslogAnalyzer()
        self.received = 0

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) > 8192:
            data = data[:8192]
        host = addr[0]
        severity, message = parse_message(data)
        entry = LogEntry(datetime.now().isoformat(timespec="seconds"), host, self.resolve(host), severity, message)
        self.received += 1
        try:
            self.store.append(entry)
        except OSError:
            log.exception("syslog write failed")
        alert = self.analyzer.analyze(entry)
        if alert:
            self.on_alert(entry.device, alert)


async def start_syslog(host: str, port: int, store: SyslogStore, resolve, on_alert):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogServer(store, resolve, on_alert), local_addr=(host, port))
    log.info("syslog listening on udp/%s:%s", host, port)
    return transport, protocol
