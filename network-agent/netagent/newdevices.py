"""Detect devices that appear on the network for the first time (new MAC in any ARP table).

The first scan only records a baseline. After that every unknown MAC raises one alert
(with IP, vendor and where it was seen). Known MACs are kept in the state file.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .inventory import Inventory
from .tools import device as dev

_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MAC = re.compile(r"\b((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4})\b", re.I)


def canonical_mac(mac: str) -> str:
    h = re.sub(r"[^0-9a-f]", "", mac.lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def parse_arp(text: str) -> list[tuple[str, str]]:
    """(ip, mac) pairs from any vendor's ARP / neighbor table."""
    out = []
    for line in text.splitlines():
        ip, mac = _IP.search(line), _MAC.search(line)
        if not ip or not mac:
            continue
        m = canonical_mac(mac.group(1))
        first = int(m[:2], 16)
        if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or first & 1:  # broadcast / multicast
            continue
        out.append((ip.group(1), m))
    return out


def collect_arp(inventory: Inventory) -> dict[str, list[tuple[str, str]]]:
    devices = [d for d in inventory.devices.values() if dev.commands_for(d, "arp")]

    def one(d):
        res = dev.run_commands(inventory, d, dev.commands_for(d, "arp"), parse=False, max_chars=None)
        return [pair for r in res for pair in parse_arp(r.get("output", ""))]

    results = dev.run_on_devices(inventory, devices, one)
    return {k: v for k, v in results.items() if isinstance(v, list)}


class NewDeviceTracker:
    KEY = "known_macs"

    def __init__(self, state, vendors=None) -> None:
        self.state = state
        self.vendors = vendors

    def known(self) -> dict[str, dict]:
        return self.state.get(self.KEY, {}) or {}

    def process(self, arp: dict[str, list[tuple[str, str]]], now: str | None = None) -> list[dict]:
        """Update the known set; return newly seen devices (empty on the first, baseline run)."""
        now = now or datetime.now().isoformat(timespec="seconds")
        known = self.known()
        baseline = not known
        new: list[dict] = []
        for device, pairs in arp.items():
            for ip, mac in pairs:
                if mac in known:
                    known[mac]["last_seen"] = now
                    known[mac]["ip"] = ip
                    continue
                vendor = self.vendors.lookup(mac) if self.vendors else None
                entry = {"ip": ip, "seen_on": device, "vendor": vendor or "", "first_seen": now, "last_seen": now}
                if baseline:
                    entry["baseline"] = True  # was already there when monitoring started
                known[mac] = entry
                if not baseline:
                    new.append({"mac": mac, **entry})
        if arp:
            self.state.set(self.KEY, known)
        return new

    def recent(self, since_iso: str) -> list[dict]:
        return sorted(({"mac": m, **e} for m, e in self.known().items()
                       if not e.get("baseline") and e.get("first_seen", "") >= since_iso),
                      key=lambda e: e["first_seen"], reverse=True)


def format_new(entries: list[dict[str, Any]]) -> str:
    lines = []
    for e in entries[:15]:
        vendor = f" · {e['vendor']}" if e.get("vendor") else ""
        lines.append(f"🆕 **{e['ip']}** `{e['mac']}`{vendor} — {e['seen_on']}")
    if len(entries) > 15:
        lines.append(f"… და კიდევ {len(entries) - 15}")
    return "\n".join(lines)
