"""Reachability checks (TCP connect to each device's management port) and change tracking."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .config import settings
from .inventory import Device


@dataclass(frozen=True)
class Reachability:
    device: str
    host: str
    port: int
    up: bool
    latency_ms: float | None = None
    reason: str = ""

    def as_dict(self) -> dict:
        d = {"device": self.device, "host": self.host, "port": self.port, "up": self.up}
        if self.latency_ms is not None:
            d["latency_ms"] = self.latency_ms
        if self.reason:
            d["reason"] = self.reason
        return d


def check_one(device: Device, timeout: float = 3.0) -> Reachability:
    if device.device_type == "snmp":  # no SSH: ask over SNMP instead of a TCP port
        from .features.snmp import probe_device

        up, ms, reason = probe_device(device)
        return Reachability(device.name, device.host, device.port if device.port != 22 else 161, up, ms, reason)
    if device.is_serial:  # console cable: plugged in = reachable (opening the port would take it from the user)
        up = serial_present(device.host)
        return Reachability(device.name, device.host, 0, up, None, "" if up else f"{device.host} არ არის მიერთებული")
    start = time.monotonic()
    try:
        with socket.create_connection((device.host, device.port), timeout=timeout):
            ms = round((time.monotonic() - start) * 1000, 1)
            return Reachability(device.name, device.host, device.port, True, ms)
    except socket.timeout:
        reason = "timeout"
    except ConnectionRefusedError:
        reason = "connection refused"
    except OSError as exc:
        reason = exc.strerror or str(exc)
    return Reachability(device.name, device.host, device.port, False, reason=reason)


def serial_present(port: str) -> bool:
    try:
        from serial.tools import list_ports

        return any(p.device.upper() == port.upper() for p in list_ports.comports())
    except Exception:  # noqa: BLE001
        return False


def check_many(devices: list[Device], timeout: float = 3.0, retries: int = 1) -> list[Reachability]:
    """Check all devices in parallel. A device is retried before being declared down."""
    if not devices:
        return []

    def run(d: Device) -> Reachability:
        r = check_one(d, timeout)
        for _ in range(retries):
            if r.up:
                break
            r = check_one(d, timeout)
        return r

    with ThreadPoolExecutor(max_workers=max(1, min(32, settings.max_parallel_devices * 2))) as pool:
        return list(pool.map(run, devices))


class ReachabilityMonitor:
    """Remembers the last state of every device and reports transitions."""

    def __init__(self) -> None:
        self._state: dict[str, bool] = {}
        self._down_since: dict[str, float] = {}

    def update(self, results: list[Reachability]) -> list[tuple[Reachability, str]]:
        """Return (result, "down"|"up") for devices whose state changed since the last check.

        The very first observation of a device only sets the baseline, except that a
        device already down at startup is reported once so it is not silently missed.
        """
        changes: list[tuple[Reachability, str]] = []
        now = time.time()
        seen = set()
        for r in results:
            seen.add(r.device)
            prev = self._state.get(r.device)
            self._state[r.device] = r.up
            if prev is None:
                if not r.up:
                    self._down_since[r.device] = now
                    changes.append((r, "down"))
                continue
            if prev and not r.up:
                self._down_since[r.device] = now
                changes.append((r, "down"))
            elif not prev and r.up:
                changes.append((r, "up"))
        for name in list(self._state):
            if name not in seen:  # removed from inventory
                self._state.pop(name, None)
                self._down_since.pop(name, None)
        return changes

    def down_duration(self, device: str) -> float | None:
        since = self._down_since.get(device)
        return None if since is None else time.time() - since
