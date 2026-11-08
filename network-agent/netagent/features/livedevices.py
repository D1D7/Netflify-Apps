"""Live Devices: who is on the local network right now, refreshed every few seconds.

Discovery (every `scan_interval` seconds) over the selected interface's subnet:
  Windows      an ARP request to every address with ResolveIpNetEntry2 (always a fresh request, the ARP cache
               is not trusted) + an ICMP echo with IcmpSendEcho. Both are iphlpapi.dll calls: no admin rights,
               no Npcap, no console windows.
  Linux/macOS  ICMP echo (unprivileged ICMP socket, else the `ping` command) + a UDP "poke" that makes the
               kernel send an ARP request; MACs are then read from the ARP table. No root needed.
  always       the system ARP table is merged in as a fallback.
Liveness (every `ping_interval` seconds): ICMP echo to every known device; if it does not answer, a fresh ARP
request (phones in Wi-Fi sleep and Windows PCs that block ping still answer ARP). A device turns Offline only
after `offline_after` checks in a row without any answer, and stays in the list (last seen) for a week.
Names: reverse DNS, NetBIOS (UDP 137) and mDNS (UDP 5353), resolved in the background and cached.
MAC addresses exist only inside the same layer-2 subnet: anything else gets "N/A".
Join/leave events are appended to logs/live-devices.log; the list exports as CSV.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import os
import random
import re
import socket
import struct
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..newdevices import canonical_mac
from ..result import Button, Result
from . import env_int, homenet

log = logging.getLogger("netagent.live")

IS_WINDOWS = os.name == "nt"
SETTINGS_KEY = "live_settings"
KNOWN_KEY = "live_known"
DEFAULTS = {"interface": "", "ping_interval": 3, "scan_interval": 60, "offline_after": 3}
LIMITS = {"ping_interval": (1, 60), "scan_interval": (15, 3600), "offline_after": (1, 20)}
MAX_HOSTS = 1024          # bigger subnets: only the /24 around this PC is swept
HISTORY = 600             # ping samples kept per device (30 min at 3 s)
NEW_SECONDS = 600         # a newly joined device is highlighted for 10 minutes
OFFLINE_MIN_SECONDS = 20  # ...and Offline needs this long without any answer (phones in Wi-Fi power save)
NAME_REFRESH = 30 * 60    # re-resolve host names every 30 minutes
EVENTS = 100
LOG_MAX_BYTES = 5_000_000
VIRTUAL = re.compile(r"vEthernet|VMware|VirtualBox|Hyper-V|WSL|Tailscale|ZeroTier|TAP-|Loopback|docker|veth|br-|virbr|utun",
                     re.I)


# =========================================================================================================
# probing: ICMP echo and ARP request per platform
# =========================================================================================================
class Prober:
    """ping(ip) -> latency ms or None · arp(ip) -> MAC or "" · arp_many(ips) -> {ip: mac}."""

    name = "none"
    notices: list[str] = []

    def ping(self, ip: str, timeout: float = 1.0) -> float | None:
        raise NotImplementedError

    def arp(self, ip: str) -> str:
        raise NotImplementedError

    def arp_many(self, ips: list[str], pool: ThreadPoolExecutor) -> dict[str, str]:
        return {ip: mac for ip, mac in zip(ips, pool.map(self.arp, ips)) if mac}


class WindowsProber(Prober):
    name = "ARP (ResolveIpNetEntry2) + ICMP (IcmpSendEcho)"

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ct = ctypes
        lib = ctypes.WinDLL("iphlpapi.dll")

        class SOCKADDR_INET(ctypes.Structure):  # IPv4 view of the 28-byte union
            _fields_ = [("family", ctypes.c_ushort), ("port", ctypes.c_ushort), ("addr", ctypes.c_ubyte * 4),
                        ("zero", ctypes.c_ubyte * 20)]

        class MIB_IPNET_ROW2(ctypes.Structure):
            _fields_ = [("Address", SOCKADDR_INET), ("InterfaceIndex", ctypes.c_ulong),
                        ("InterfaceLuid", ctypes.c_ulonglong), ("PhysicalAddress", ctypes.c_ubyte * 32),
                        ("PhysicalAddressLength", ctypes.c_ulong), ("State", ctypes.c_int), ("Flags", ctypes.c_ubyte),
                        ("ReachabilityTime", ctypes.c_ulong)]

        class IP_OPTION_INFORMATION(ctypes.Structure):
            _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                        ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

        class ICMP_ECHO_REPLY(ctypes.Structure):
            _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong),
                        ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                        ("Options", IP_OPTION_INFORMATION)]

        assert ctypes.sizeof(MIB_IPNET_ROW2) == 88, "MIB_IPNET_ROW2 layout"
        self.Row, self.Reply = MIB_IPNET_ROW2, ICMP_ECHO_REPLY
        lib.ResolveIpNetEntry2.argtypes = [ctypes.POINTER(MIB_IPNET_ROW2), ctypes.c_void_p]
        lib.ResolveIpNetEntry2.restype = ctypes.c_ulong
        lib.GetBestInterface.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        lib.GetBestInterface.restype = ctypes.c_ulong
        lib.IcmpCreateFile.restype = wintypes.HANDLE
        lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        lib.IcmpSendEcho.restype = ctypes.c_ulong
        self.lib = lib

    @staticmethod
    def _addr(ip: str) -> int:
        return struct.unpack("<I", socket.inet_aton(ip))[0]

    def ping(self, ip: str, timeout: float = 1.0) -> float | None:
        ct = self.ct
        handle = self.lib.IcmpCreateFile()
        if not handle or handle == ct.c_void_p(-1).value:
            return None
        try:
            payload = b"NetAgent-live-00"
            buf = ct.create_string_buffer(ct.sizeof(self.Reply) + len(payload) + 8)
            t0 = time.perf_counter()
            n = self.lib.IcmpSendEcho(handle, self._addr(ip), payload, len(payload), None, buf, len(buf),
                                      int(timeout * 1000))
            ms = (time.perf_counter() - t0) * 1000
            reply = self.Reply.from_buffer(buf)
            if n == 0 or reply.Status != 0 or reply.Address != self._addr(ip):
                return None  # timeout, or "destination unreachable" sent by someone else
            return round(max(ms, 0.05), 2)  # wall clock: RoundTripTime is whole milliseconds only
        finally:
            self.lib.IcmpCloseHandle(handle)

    def arp(self, ip: str) -> str:
        ct = self.ct
        index = ct.c_ulong()
        if self.lib.GetBestInterface(self._addr(ip), ct.byref(index)) != 0:
            return ""
        row = self.Row()
        row.Address.family = socket.AF_INET
        row.Address.addr[:] = socket.inet_aton(ip)
        row.InterfaceIndex = index.value
        if self.lib.ResolveIpNetEntry2(ct.byref(row), None) != 0:  # 67 = nobody answered (after ~3 s)
            return ""
        raw = bytes(row.PhysicalAddress[: row.PhysicalAddressLength])
        return canonical_mac(raw.hex()) if len(raw) == 6 and any(raw) else ""


class PosixProber(Prober):
    """Linux/macOS without root: unprivileged ICMP socket if allowed, else `ping`; ARP via the kernel cache."""

    def __init__(self) -> None:
        self.notices = []
        self.dgram = self._dgram_allowed()
        if self.dgram:
            self.name = "ICMP (socket) + ARP-ცხრილი"
        else:
            import shutil

            self.name = "ICMP (ping ბრძანება) + ARP-ცხრილი"
            if not shutil.which("ping"):
                self.notices.append("ping შეუძლებელია: ICMP socket ამ მომხმარებლისთვის დაკეტილია და `ping` ბრძანებაც არ არის. "
                                    "გაუშვი root-ით, ან: sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'")
            else:
                self.notices.append("ICMP socket დაკეტილია, ping-ისთვის `ping` ბრძანებას ვიყენებ (უფრო ნელია). დასაჩქარებლად: "
                                    "sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'")

    @staticmethod
    def _dgram_allowed() -> bool:
        try:
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP).close()
            return True
        except OSError:
            return False

    def ping(self, ip: str, timeout: float = 1.0) -> float | None:
        if self.dgram:
            return icmp_dgram(ip, timeout)
        from ..tools import network as net

        r = net.ping(ip, 1)
        return round(r["avg_rtt_ms"], 2) if r.get("reachable") and r.get("avg_rtt_ms") is not None else None

    def arp(self, ip: str) -> str:
        return self.arp_many([ip], None).get(ip, "")

    def arp_many(self, ips: list[str], pool) -> dict[str, str]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for ip in ips:  # any packet to a LAN address makes the kernel ARP for it
                try:
                    s.sendto(b"", (ip, 9))
                except OSError:
                    pass
        time.sleep(1.5)
        table = homenet.read_arp()
        return {ip: table[ip] for ip in ips if table.get(ip)}


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_dgram(ip: str, timeout: float = 1.0) -> float | None:
    """Echo over an unprivileged ICMP socket (Linux ping_group_range, macOS)."""
    seq = random.randint(1, 0xFFFF)
    payload = b"NetAgent-live-00"
    header = struct.pack("!BBHHH", 8, 0, 0, 0, seq)
    packet = struct.pack("!BBHHH", 8, 0, _checksum(header + payload), 0, seq) + payload
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as s:
            s.settimeout(timeout)
            t0 = time.perf_counter()
            s.sendto(packet, (ip, 0))
            while True:
                left = timeout - (time.perf_counter() - t0)
                if left <= 0:
                    return None
                s.settimeout(left)
                data, addr = s.recvfrom(1024)
                if data and data[0] >> 4 == 4:  # macOS hands over the IP header too
                    data = data[(data[0] & 0x0F) * 4:]
                if addr[0] == ip and len(data) >= 8 and data[0] == 0 and struct.unpack("!H", data[6:8])[0] == seq:
                    return round((time.perf_counter() - t0) * 1000, 2)
    except OSError:
        return None


def make_prober() -> Prober:
    if IS_WINDOWS:
        try:
            return WindowsProber()
        except (OSError, AttributeError, AssertionError) as exc:
            log.warning("iphlpapi unavailable (%s), falling back to ping/arp commands", exc)
            p = PosixProber.__new__(PosixProber)
            p.dgram, p.notices = False, ["Windows-ის ქსელის API ვერ ჩაიტვირთა — ვიყენებ ping/arp ბრძანებებს (ნელია)."]
            p.name = "ICMP (ping ბრძანება) + ARP-ცხრილი"
            return p
    return PosixProber()


# =========================================================================================================
# host names: reverse DNS, NetBIOS, mDNS
# =========================================================================================================
def _dns_name(msg: bytes, pos: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, position after it in the original place)."""
    labels, jumped, end, hops = [], False, pos, 0
    while pos < len(msg):
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(msg) or hops > 20:
                raise ValueError("bad pointer")
            if not jumped:
                end = pos + 2
            pos, jumped, hops = ((n & 0x3F) << 8) | msg[pos + 1], True, hops + 1
            continue
        labels.append(msg[pos + 1:pos + 1 + n].decode("utf-8", errors="replace"))
        pos += 1 + n
    return ".".join(labels), (end if jumped else pos)


def ptr_query(ip: str, tid: int = 0, qu: bool = True) -> bytes:
    name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + q + struct.pack("!HH", 12, 0x8001 if qu else 1)


def parse_ptr(msg: bytes) -> str:
    """First PTR answer of a DNS/mDNS response ("iPhone.local." -> "iPhone.local")."""
    if len(msg) < 12:
        return ""
    qd, an = struct.unpack("!HH", msg[4:8])
    pos = 12
    try:
        for _ in range(qd):
            _, pos = _dns_name(msg, pos)
            pos += 4
        for _ in range(an):
            _, pos = _dns_name(msg, pos)
            rtype, _, _, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
            pos += 10
            if rtype == 12:
                return _dns_name(msg, pos)[0].rstrip(".")
            pos += rdlen
    except (ValueError, struct.error, IndexError):
        return ""
    return ""


def nbstat_query(tid: int) -> bytes:
    encoded = b"CK" + b"A" * 30  # "*" padded with NULs, NetBIOS first-level encoding
    return struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20" + encoded + b"\0" + struct.pack("!HH", 0x21, 1)


def parse_nbstat(msg: bytes) -> str:
    """Workstation name (suffix 0x00, unique) from a NetBIOS node status response."""
    try:
        pos = 12
        _, pos = _dns_name(msg, pos)
        pos += 10  # type, class, ttl, rdlength
        count = msg[pos]
        pos += 1
        for i in range(count):
            entry = msg[pos + i * 18: pos + i * 18 + 18]
            if len(entry) < 18:
                break
            name, suffix, flags = entry[:15], entry[15], struct.unpack("!H", entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000:
                return name.decode("ascii", errors="replace").strip()
    except (ValueError, IndexError, struct.error):
        return ""
    return ""


def _udp_ask(ip: str, port: int, packet: bytes, parse, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, port))
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                s.settimeout(max(end - time.monotonic(), 0.05))
                data, addr = s.recvfrom(2048)
                if addr[0] == ip:
                    return parse(data)
    except OSError:
        return ""
    return ""


def netbios_name(ip: str, timeout: float = 1.0) -> str:
    tid = random.randint(1, 0xFFFF)
    return _udp_ask(ip, 137, nbstat_query(tid), parse_nbstat, timeout)


def mdns_name(ip: str, timeout: float = 1.0) -> str:
    """Unicast ("legacy") mDNS query sent straight to the device: Apple, Android, printers, Chromecasts answer."""
    return _udp_ask(ip, 5353, ptr_query(ip, random.randint(1, 0xFFFF)), parse_ptr, timeout)


def reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""
    return "" if name == ip else name.rstrip(".")


def resolve_name(ip: str) -> tuple[str, str]:
    """(name, source). Tries mDNS and NetBIOS first: on a home LAN they give the device's own name,
    while the router's reverse DNS often only knows a DHCP placeholder."""
    for source, fn in (("mDNS", mdns_name), ("NetBIOS", netbios_name), ("DNS", reverse_dns)):
        name = fn(ip)
        if name and not re.fullmatch(r"[\d.\-]+(\.in-addr\.arpa)?", name):
            return name, source
    return "", ""


# =========================================================================================================
# interfaces
# =========================================================================================================
def list_interfaces() -> list[dict]:
    """IPv4 interfaces that can have neighbours (no loopback, link-local, point-to-point /31-/32, or down)."""
    try:
        import psutil
    except ImportError:
        ip = homenet.local_ip()
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return [{"name": "default", "ip": ip, "netmask": "255.255.255.0", "network": str(net), "prefix": 24,
                 "mac": "", "up": True, "virtual": False}]
    stats = psutil.net_if_stats()
    out = []
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), "")
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            try:
                iface = ipaddress.ip_interface(f"{a.address}/{a.netmask}")
            except ValueError:
                continue
            if iface.ip.is_loopback or iface.ip.is_link_local or iface.network.prefixlen >= 31 or not (st and st.isup):
                continue
            out.append({"name": name, "ip": str(iface.ip), "netmask": a.netmask, "network": str(iface.network),
                        "prefix": iface.network.prefixlen, "mac": canonical_mac(mac) if mac else "", "up": True,
                        "virtual": bool(VIRTUAL.search(name))})
    return out


def pick_interface(interfaces: list[dict], wanted: str = "", local_ip: str = "") -> dict | None:
    """The chosen one, else the interface that carries the default route (this PC's "real" LAN address)."""
    if wanted:
        for i in interfaces:
            if i["name"] == wanted:
                return i
    for i in interfaces:
        if i["ip"] == local_ip:
            return i
    real = [i for i in interfaces if not i["virtual"]]
    return (real or interfaces or [None])[0]


def scan_targets(iface: dict) -> tuple[list[str], str]:
    """Addresses to sweep, plus a note when the subnet was too big and only the /24 around us is swept."""
    net = ipaddress.ip_network(iface["network"], strict=False)
    note = ""
    if net.num_addresses - 2 > MAX_HOSTS:
        net = ipaddress.ip_network(f"{iface['ip']}/24", strict=False)
        note = (f"ქსელი {iface['network']} დიდია ({ipaddress.ip_network(iface['network']).num_addresses} მისამართი) — "
                f"ვამოწმებ მხოლოდ {net}-ს ამ კომპიუტერის გარშემო.")
    return [str(h) for h in net.hosts()], note


# =========================================================================================================
# the engine
# =========================================================================================================
@dataclass
class Device:
    key: str
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    hostname_source: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    online: bool = False
    misses: int = 0
    latency_ms: float | None = None
    icmp: bool = False                 # has ever answered ping (some PCs only answer ARP)
    new_until: float = 0.0
    names_at: float = 0.0
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY))

    def stats(self) -> dict:
        vals = [v for _, v in self.history]
        got = [v for v in vals if v is not None]
        return {"samples": len(vals), "loss_pct": round(100 * (len(vals) - len(got)) / len(vals), 1) if vals else None,
                "min_ms": min(got) if got else None, "avg_ms": round(sum(got) / len(got), 2) if got else None,
                "max_ms": max(got) if got else None}


class LiveEngine:
    def __init__(self, state, vendors=None, prober: Prober | None = None, names=resolve_name,
                 interfaces=list_interfaces, local_ip=homenet.local_ip, gateway=homenet.default_gateway,
                 arp_table=homenet.read_arp, labels=None, log_path: Path | None = None, clock=time.time) -> None:
        self.state, self.vendors = state, vendors
        self.prober = prober or make_prober()
        self.names, self.interfaces_fn, self.local_ip_fn = names, interfaces, local_ip
        self.gateway_fn, self.arp_table_fn = gateway, arp_table
        self.labels = labels or (lambda: homenet.device_names(state))
        self.log_path, self.clock = log_path, clock
        self.devices: dict[str, Device] = {}
        self.events: deque = deque(maxlen=EVENTS)
        self.lock = threading.RLock()
        self.iface: dict | None = None
        self.notices: list[str] = []
        self.last_scan = 0.0
        self.scanning = False
        self.baseline = True           # the first sweep only learns: no "new" badges for what is already there
        self._restarted = False        # devices loaded from the last run: their first sweep is not "came online"
        self._gen = 0                  # bumped when the interface changes
        self.gateway = ""
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._scan_now = True
        self._inflight: set[str] = set()
        self._ping_pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="live-ping")
        self._scan_pool = ThreadPoolExecutor(max_workers=128, thread_name_prefix="live-scan")
        self._name_pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="live-name")
        self._thread: threading.Thread | None = None
        self._load_known()

    # -- settings ------------------------------------------------------------------------------------
    def settings(self) -> dict:
        s = {**DEFAULTS, **(self.state.get(SETTINGS_KEY) or {})}
        for k, (lo, hi) in LIMITS.items():
            try:
                s[k] = min(max(int(s[k]), lo), hi)
            except (TypeError, ValueError):
                s[k] = DEFAULTS[k]
        return s

    def update_settings(self, changes: dict) -> dict:
        s = self.settings()
        for k in DEFAULTS:
            if k in changes and changes[k] is not None:
                s[k] = str(changes[k])[:80] if k == "interface" else changes[k]
        self.state.set(SETTINGS_KEY, s)
        s = self.settings()
        if "interface" in changes:
            with self.lock:  # devices of the old subnet stay remembered (the list only shows the watched one)
                self._gen += 1  # a sweep still running for the old interface must not write into the new list
            self._scan_now = True
        self._wake.set()
        return s

    def request_scan(self) -> None:
        self._scan_now = True
        self._wake.set()

    # -- persistence of first/last seen ----------------------------------------------------------------
    def _load_known(self) -> None:
        keep = env_int("NETAGENT_LIVE_RETENTION_DAYS", 7) * 86400
        now = self.clock()
        for key, r in (self.state.get(KNOWN_KEY) or {}).items():
            if now - r.get("last_seen", 0) > keep:
                continue
            self.devices[key] = Device(key=key, ip=r.get("ip", ""), mac=r.get("mac", ""), vendor=r.get("vendor", ""),
                                       hostname=r.get("hostname", ""), hostname_source=r.get("hostname_source", ""),
                                       first_seen=r.get("first_seen", now), last_seen=r.get("last_seen", 0),
                                       icmp=r.get("icmp", False), names_at=0.0)
        if self.devices:
            self.baseline = False  # we have seen this network before: real newcomers get the badge
            self._restarted = True

    def _save_known(self) -> None:
        with self.lock:
            data = {d.key: {"ip": d.ip, "mac": d.mac, "vendor": d.vendor, "hostname": d.hostname,
                            "hostname_source": d.hostname_source, "first_seen": d.first_seen,
                            "last_seen": d.last_seen, "icmp": d.icmp} for d in self.devices.values() if d.last_seen}
        self.state.set(KNOWN_KEY, data)

    # -- events ----------------------------------------------------------------------------------------
    def _event(self, kind: str, d: Device) -> None:
        ev = {"ts": self.clock(), "event": kind, "ip": d.ip, "mac": d.mac or "N/A", "vendor": d.vendor,
              "hostname": d.hostname}
        self.events.appendleft(ev)
        if not self.log_path:
            return
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if self.log_path.exists() and self.log_path.stat().st_size > LOG_MAX_BYTES:
                os.replace(self.log_path, self.log_path.with_suffix(".log.1"))
            line = "\t".join([datetime.fromtimestamp(ev["ts"]).isoformat(timespec="seconds"), kind, d.ip,
                              d.mac or "N/A", d.vendor or "", d.hostname or ""])
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as exc:
            log.warning("live-devices log: %s", exc)

    # -- one discovery sweep ---------------------------------------------------------------------------
    def _in_subnet(self, ip: str) -> bool:
        if not self.iface:
            return False
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(self.iface["network"], strict=False)
        except ValueError:
            return False

    def _choose_interface(self) -> None:
        s = self.settings()
        ifaces = self.interfaces_fn()
        iface = pick_interface(ifaces, s["interface"], self.local_ip_fn())
        notices = list(self.prober.notices)
        if s["interface"] and (not iface or iface["name"] != s["interface"]):
            notices.append(f"ინტერფეისი „{s['interface']}“ ახლა არ ჩანს — ავტომატურად ავირჩიე სხვა.")
        if not iface:
            notices.append("აქტიური ქსელის ინტერფეისი ვერ ვიპოვე — კომპიუტერი ქსელშია?")
        self.iface, self.notices = iface, notices

    def sweep(self) -> None:
        gen = self._gen
        self._choose_interface()
        if not self.iface:
            return
        self.scanning = True
        try:
            targets, note = scan_targets(self.iface)
            if note:
                self.notices.append(note)
            me = self.iface["ip"]
            try:
                self.gateway = self.gateway_fn() or ""
            except Exception:  # noqa: BLE001
                self.gateway = ""
            others = [ip for ip in targets if ip != me]
            ping_f = {ip: self._scan_pool.submit(self.prober.ping, ip, 1.0) for ip in others}
            macs = self.prober.arp_many(others, self._scan_pool)  # ARP answers even when ICMP is blocked
            wait(list(ping_f.values()))
            pings = {ip: f.result() for ip, f in ping_f.items() if not f.exception()}
            # answered ping but missed its ARP reply (phones in Wi-Fi power save): it is awake now, ask again
            missing = [ip for ip, ms in pings.items() if ms is not None and not macs.get(ip)]
            if missing:
                macs.update(self.prober.arp_many(missing, self._scan_pool))
            try:  # fallback: whatever the OS already knows about this subnet
                for ip, mac in (self.arp_table_fn() or {}).items():
                    if self._in_subnet(ip) and ip not in macs and not mac.startswith(("ff:", "01:00:5e")):
                        macs.setdefault(ip, mac)
            except Exception:  # noqa: BLE001
                pass
            found = {ip for ip in others if pings.get(ip) is not None or macs.get(ip)}
            now = self.clock()
            with self.lock:
                if gen != self._gen:  # the interface was switched while this sweep ran: its results are stale
                    return
                # first look at this subnet (new install, or another interface): learn silently, no "new" badges
                self.baseline = not any(self._in_subnet(d.ip) and d.last_seen for d in self.devices.values())
                mine = self._upsert(me, canonical_mac(self.iface.get("mac") or "") if self.iface.get("mac") else "", 0.05, now)
                # this PC: its own name (reverse DNS can return entries like Docker's "host.docker.internal")
                mine.hostname, mine.hostname_source, mine.names_at = socket.gethostname(), "ეს კომპიუტერი", float("inf")
                for ip in sorted(found, key=lambda x: ipaddress.ip_address(x)):
                    self._upsert(ip, macs.get(ip, ""), pings.get(ip), now)
                for d in self.devices.values():  # known but silent in this sweep
                    if d.online and d.ip != me and d.ip not in found and self._in_subnet(d.ip):
                        d.misses += 1
                        if self._gone(d, now):
                            d.online = False
                            if not self._restarted:
                                self._event("offline", d)
                self._restarted = False
            self.last_scan = now
            self._resolve_names()
            self._save_known()
        finally:
            self.scanning = False

    def _upsert(self, ip: str, mac: str, ms: float | None, now: float) -> Device:
        """Record an answer from ip (with mac if known). Caller holds the lock."""
        mac = mac if mac and self._in_subnet(ip) else ""
        key = mac or f"ip:{ip}"
        d = self.devices.get(key)
        if d is None and not mac:  # answered without a MAC (slept through ARP): same address = same known device
            d = next((x for x in self.devices.values() if x.ip == ip), None)
            key = d.key if d else key
        if d is None and mac and f"ip:{ip}" in self.devices:  # we now know its MAC: re-key
            d = self.devices.pop(f"ip:{ip}")
            d.key, d.mac = key, mac
            self.devices[key] = d
        is_new = d is None
        if is_new:
            for other in list(self.devices.values()):  # the address now belongs to someone else
                if other.ip == ip and other.key != key and other.online:
                    other.online, other.misses = False, LIMITS["offline_after"][1]
                    self._event("offline", other)
            d = Device(key=key, ip=ip, mac=mac, first_seen=now)
            self.devices[key] = d
        if d.ip != ip:
            d.ip, d.names_at = ip, 0.0  # DHCP gave it another address: names may differ too
        if mac and not d.vendor and self.vendors:
            d.vendor = self.vendors.lookup(mac) or ""
        was_online = d.online
        d.online, d.misses, d.last_seen = True, 0, now
        d.latency_ms = ms
        d.icmp = d.icmp or ms is not None
        d.history.append((now, ms))
        if is_new and not self.baseline:  # the first sweep on a network only learns what is already there
            d.new_until = now + NEW_SECONDS
            self._event("new", d)
        elif not is_new and not was_online and not self._restarted:
            self._event("online", d)
        return d

    # -- liveness pings --------------------------------------------------------------------------------
    def _check(self, key: str, ip: str) -> tuple[str, float | None, bool, str]:
        """(key, ping ms, alive, MAC learned now). No ping answer -> ask with ARP; a device that answers ping but
        whose MAC we never got (it slept through the sweep's ARP) is asked for it once it is awake."""
        try:
            ms = self.prober.ping(ip, 1.0)
            need_mac = key.startswith("ip:") and self._in_subnet(ip)
            if ms is not None:
                return key, ms, True, (self.prober.arp(ip) if need_mac else "")
            mac = self.prober.arp(ip) if self._in_subnet(ip) else ""
            return key, None, bool(mac), (mac if need_mac else "")
        finally:
            self._inflight.discard(key)

    def _gone(self, d: Device, now: float) -> bool:
        return d.misses >= self.settings()["offline_after"] and now - d.last_seen >= OFFLINE_MIN_SECONDS

    def tick(self, block: bool = False) -> None:
        """Ping every online device once (and ones that went quiet in the last 2 minutes); offline devices are
        re-checked by the sweep. Results are applied as each check finishes, so a slow ARP retry for one device
        never delays the others. block=True waits for all of them (tests)."""
        now = self.clock()
        with self.lock:
            me = self.iface["ip"] if self.iface else ""
            todo = [(d.key, d.ip) for d in self.devices.values()
                    if d.key not in self._inflight and d.ip != me and self._in_subnet(d.ip)
                    and (d.online or now - d.last_seen < 120)]
            for key, _ in todo:
                self._inflight.add(key)
            mine = next((d for d in self.devices.values() if d.ip == me), None)
            if mine:
                mine.online, mine.last_seen, mine.latency_ms = True, now, 0.05
                mine.history.append((now, 0.05))
        futures = []
        for key, ip in todo:
            f = self._ping_pool.submit(self._check, key, ip)
            f.add_done_callback(self._apply)
            futures.append(f)
        if block:
            wait(futures)

    def _apply(self, future) -> None:
        if future.cancelled() or future.exception():
            return
        key, ms, alive, mac = future.result()
        now = self.clock()
        changed = False
        with self.lock:
            d = self.devices.get(key)
            if d is None:
                return
            if mac and key.startswith("ip:"):  # MAC finally known: key it by MAC (merge with an older record)
                old = self.devices.pop(mac, None)
                self.devices.pop(key, None)
                d.key, d.mac = mac, mac
                if old:
                    d.first_seen, d.hostname = min(d.first_seen, old.first_seen), d.hostname or old.hostname
                if self.vendors:
                    d.vendor = self.vendors.lookup(mac) or ""
                self.devices[mac] = d
                changed = True
            d.history.append((now, ms))
            if alive:
                if not d.online:
                    d.online = True
                    if not self._restarted:  # pings run before the first sweep after a restart: not "came online"
                        self._event("online", d)
                    changed = True
                d.misses, d.last_seen, d.latency_ms = 0, now, ms
                d.icmp = d.icmp or ms is not None
            else:
                d.misses += 1
                d.latency_ms = None
                if d.online and self._gone(d, now):
                    d.online = False
                    self._event("offline", d)
                    changed = True
        if changed:
            self._save_known()

    # -- names -----------------------------------------------------------------------------------------
    def _resolve_names(self) -> None:
        now = self.clock()
        with self.lock:
            todo = [d for d in self.devices.values() if d.online and now - d.names_at > NAME_REFRESH]
            for d in todo:
                d.names_at = now
        for d in todo:
            self._name_pool.submit(self._name_one, d.key, d.ip)

    def _name_one(self, key: str, ip: str) -> None:
        try:
            name, source = self.names(ip)
        except Exception:  # noqa: BLE001
            return
        if name:
            with self.lock:
                d = self.devices.get(key)
                if d and d.ip == ip:
                    d.hostname, d.hostname_source = name, source

    # -- background thread -----------------------------------------------------------------------------
    def start(self) -> "LiveEngine":
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True, name="live-devices")
            self._thread.start()
        return self

    def _run(self) -> None:
        sweeper: threading.Thread | None = None
        while not self._stop.is_set():
            s = self.settings()
            due = self._scan_now or self.clock() - self.last_scan >= s["scan_interval"]
            if due and (sweeper is None or not sweeper.is_alive()):
                self._scan_now = False
                sweeper = threading.Thread(target=self._safe_sweep, daemon=True, name="live-sweep")
                sweeper.start()
            if self.iface:
                try:
                    self.tick()
                except Exception:  # noqa: BLE001 - one bad round must not stop the panel
                    log.exception("live tick failed")
            self._wake.wait(s["ping_interval"])
            self._wake.clear()

    def _safe_sweep(self) -> None:
        try:
            self.sweep()
        except Exception:  # noqa: BLE001
            log.exception("live sweep failed")

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        for pool in (self._ping_pool, self._scan_pool, self._name_pool):
            pool.shutdown(wait=False, cancel_futures=True)

    # -- views -----------------------------------------------------------------------------------------
    def _row(self, d: Device, labels: dict, now: float) -> dict:
        label = labels.get(d.mac) or labels.get(f"ip:{d.ip}") or ""
        return {"key": d.key, "ip": d.ip, "mac": d.mac or "N/A", "vendor": d.vendor, "hostname": d.hostname,
                "hostname_source": d.hostname_source, "label": label, "online": d.online,
                "status": "online" if d.online else "offline", "latency_ms": d.latency_ms, "icmp": d.icmp,
                "first_seen": d.first_seen, "last_seen": d.last_seen, "new": d.new_until > now,
                "self": bool(self.iface and d.ip == self.iface["ip"]), "gateway": d.ip == self.gateway,
                "misses": d.misses, "spark": [v for _, v in list(d.history)[-30:]]}

    def snapshot(self) -> dict:
        now = self.clock()
        try:
            labels = self.labels() or {}
        except Exception:  # noqa: BLE001
            labels = {}
        with self.lock:
            # only the subnet being watched (records from another interface stay saved for when you switch back)
            rows = [self._row(d, labels, now) for d in self.devices.values() if not self.iface or self._in_subnet(d.ip)]
            events = list(self.events)[:30]
        rows.sort(key=lambda r: ipaddress.ip_address(r["ip"]) if r["ip"] else ipaddress.ip_address("0.0.0.0"))
        return {"interface": self.iface, "interfaces": self.interfaces_fn(), "settings": self.settings(),
                "devices": rows, "online": sum(r["online"] for r in rows), "offline": sum(not r["online"] for r in rows),
                "method": self.prober.name, "notices": self.notices, "scanning": self.scanning,
                "last_scan": self.last_scan, "now": now, "events": events}

    def history(self, key: str) -> dict | None:
        with self.lock:
            d = self.devices.get(key)
            if d is None:
                return None
            return {"key": key, "ip": d.ip, "points": [[t, v] for t, v in d.history], **d.stats()}

    def export_csv(self) -> str:
        snap = self.snapshot()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["status", "ip", "mac", "vendor", "hostname", "name", "ping_ms", "first_seen", "last_seen"])
        fmt = lambda t: datetime.fromtimestamp(t).isoformat(sep=" ", timespec="seconds") if t else ""  # noqa: E731
        for r in snap["devices"]:
            w.writerow([r["status"], r["ip"], r["mac"], r["vendor"], r["hostname"], r["label"],
                        "" if r["latency_ms"] is None else r["latency_ms"], fmt(r["first_seen"]), fmt(r["last_seen"])])
        return buf.getvalue()


# =========================================================================================================
# plug-in: background engine for the server, /live command, AI tool
# =========================================================================================================
ENGINE: LiveEngine | None = None


async def start(services, monitoring) -> list:
    """Started by the server only (not by the CLI or tests). NETAGENT_LIVE=off disables it."""
    global ENGINE
    if os.getenv("NETAGENT_LIVE", "on").strip().lower() in {"off", "0", "false", "no"}:
        return []
    from ..config import settings

    ENGINE = LiveEngine(services.state, services.vendors, log_path=settings.audit_log_path.parent / "live-devices.log")
    ENGINE.start()
    log.info("live devices: %s", ENGINE.prober.name)
    return [ENGINE]


def _ago(ts: float, now: float) -> str:
    s = int(now - ts)
    return f"{s} წმ" if s < 60 else f"{s // 60} წთ" if s < 3600 else f"{s // 3600} სთ"


def live_cmd(s, args, user) -> Result:
    if ENGINE is None:
        return Result("Live Devices გამორთულია (NETAGENT_LIVE=off) ან სერვერი არ არის გაშვებული.")
    snap = ENGINE.snapshot()
    iface = snap["interface"] or {}
    lines = [f"📡 **Live Devices** — {snap['online']} ონლაინ, {snap['offline']} ოფლაინ · {iface.get('network', '?')}"]
    for r in snap["devices"]:
        name = r["label"] or r["hostname"] or r["vendor"] or ""
        ms = "—" if r["latency_ms"] is None else f"{r['latency_ms']:.1f} ms"
        dot = "🟢" if r["online"] else "🔴"
        lines.append(f"{dot} {r['ip']} · {r['mac']} · {ms}" + (f" · {name}" if name else "")
                     + (" · 🆕" if r["new"] else "") + ("" if r["online"] else f" · ბოლოს {_ago(r['last_seen'], snap['now'])} წინ"))
    return Result("\n".join(lines[:60]), buttons=[Button("🔍 სკანი", "/scan")])


COMMANDS = {"live": live_cmd}
HELP = ["/live — Live Devices: ვინ არის ქსელში ახლა (IP, MAC, ping) · აპში ცალკე ჩანართი „Live“"]
TOOLS = [
    ({"name": "live_devices",
      "description": "Devices on the local network right now, measured every few seconds by NetAgent: IP, MAC, vendor, "
                     "host name, ping latency, online/offline, first/last seen, recent join/leave events.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: ENGINE.snapshot() if ENGINE else {"error": "Live Devices is not running"}),
]
