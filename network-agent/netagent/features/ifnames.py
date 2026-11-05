"""Interface names of a device, for Tab completion in the app's terminal (GET /api/interfaces?device=R1).

One read-only command per device, cached for 10 minutes so Tab stays fast and the device isn't asked again and again.
"""

from __future__ import annotations

import re
import threading
import time

CACHE_SECONDS = 600
MAX_NAMES = 500
_cache: dict[str, tuple[float, list[str]]] = {}
_lock = threading.Lock()

# (device_type prefix, command, how to read the names)
_SOURCES = [
    ("mikrotik", "/interface print terse", "ros"),
    ("juniper", "show interfaces terse", "first"),
    ("huawei", "display interface brief", "first"),
    ("linux", "ip -br link", "linux"),
    ("", "show ip interface brief", "first"),  # Cisco IOS/XE/NX-OS, Arista and most others
]
_IFNAME = re.compile(r"^[A-Za-z][\w\-/.:]*\d[\w\-/.:]*$")
_HEADERS = {"interface", "port", "name", "admin", "physical"}


def parse_names(output: str, how: str) -> list[str]:
    names: list[str] = []
    for line in output.splitlines():
        if how == "ros":
            m = re.search(r"\bname=(\S+)", line)
            name = m.group(1).strip('"') if m else ""
        else:
            first = line.strip().split()[0] if line.strip() else ""
            name = first.split("@", 1)[0] if how == "linux" else first  # "eth0.10@eth0"
        if name and name.lower() not in _HEADERS and (how == "ros" or _IFNAME.match(name)) and name not in names:
            names.append(name)
    return names[:MAX_NAMES]


def interface_names(services, device: str) -> list[str]:
    from ..tools.device import run_commands

    inv = services.inventory()
    d = inv.devices.get(device)
    if d is None:
        return []
    with _lock:
        hit = _cache.get(device)
        if hit and time.time() - hit[0] < CACHE_SECONDS:
            return hit[1]
    dtype = d.device_type.lower()
    _, command, how = next(src for src in _SOURCES if dtype.startswith(src[0]))
    try:
        result = run_commands(inv, d, [command], parse=False, max_chars=None)
    except Exception:  # noqa: BLE001 - SSH refused / timeout / no credentials
        result = []
    if not result or "error" in result[0]:
        with _lock:  # remember the failure for a minute only (an unreachable device must not slow every Tab)
            _cache[device] = (time.time() - CACHE_SECONDS + 60, [])
        return []
    names = parse_names(result[0].get("output", ""), how)
    with _lock:
        _cache[device] = (time.time(), names)
    return names
