"""PC menu, part 1: system information and live load of this PC.

Static facts (Windows edition/version/build, install date, computer/user/domain, CPU, GPU, network adapters)
come from one PowerShell/CIM call and are cached for 10 minutes. Live values (CPU total and per core, RAM,
GPU engine load and video memory, partitions) are sampled every 2 seconds by a background thread:
psutil for CPU/RAM/partitions, the Windows PDH API (performance counters, via ctypes) for the GPU, so no
process is started for every sample. The last 10 minutes are kept for the graphs. No admin rights needed.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from collections import deque
from datetime import datetime

from ..osutil import NO_WINDOW

log = logging.getLogger("netagent.sysinfo")
IS_WINDOWS = os.name == "nt"
SAMPLE_EVERY = 2.0
HISTORY = 300  # samples: 10 minutes at 2 s

PS_STATIC = r"""
$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$cpu = @(Get-CimInstance Win32_Processor)
$vram = @{}
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue |
  ForEach-Object { $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($p.DriverDesc -and $p.'HardwareInformation.qwMemorySize') { $vram[$p.DriverDesc] = [int64]$p.'HardwareInformation.qwMemorySize' } }
$gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object { [pscustomobject]@{ name=$_.Name; driver=$_.DriverVersion;
  driver_date="$($_.DriverDate)"; vram=$(if ($vram[$_.Name]) { $vram[$_.Name] } else { [int64]$_.AdapterRAM }) } })
$ips = @{}; Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $ips[[int]$_.InterfaceIndex] += @("$($_.IPAddress)/$($_.PrefixLength)") }
$gw = @{}; Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | ForEach-Object { if (-not $gw[[int]$_.InterfaceIndex]) { $gw[[int]$_.InterfaceIndex] = "$($_.NextHop)" } }
$dns = @{}; Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $dns[[int]$_.InterfaceIndex] = @($_.ServerAddresses) }
$dhcp = @{}; Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $dhcp[$_.InterfaceIndex] = "$($_.Dhcp)" }
$ad = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { $i = [int]$_.ifIndex
  [pscustomobject]@{ index=$_.ifIndex; name=$_.Name; description=$_.InterfaceDescription; status="$($_.Status)"; mac=$_.MacAddress;
    speed=[int64]$_.ReceiveLinkSpeed;
    link=$_.LinkSpeed; virtual=[bool]($_.Virtual -or $_.InterfaceDescription -match 'Virtual|Hyper-V|VMware|TAP|Loopback|WAN Miniport|Tailscale|Bluetooth');
    ipv4=@($ips[$i]); gateway="$($gw[$i])"; dns=@($dns[$i]); dhcp=$dhcp[$_.ifIndex] } })
[pscustomobject]@{
  os=[pscustomobject]@{ caption=$os.Caption; version=$os.Version; build=$os.BuildNumber; ubr=$cv.UBR; display=$cv.DisplayVersion;
    arch=$os.OSArchitecture; installed=$os.InstallDate.ToString('s'); boot=$os.LastBootUpTime.ToString('s') }
  computer=[pscustomobject]@{ name=$cs.Name; user=$cs.UserName; domain=$(if ($cs.PartOfDomain) { $cs.Domain } else { '' });
    workgroup=$cs.Workgroup; maker=$cs.Manufacturer; model=$cs.Model }
  cpu=@($cpu | ForEach-Object { [pscustomobject]@{ name=$_.Name.Trim(); cores=$_.NumberOfCores; threads=$_.NumberOfLogicalProcessors; mhz=$_.MaxClockSpeed } })
  gpu=$gpu; adapters=$ad } | ConvertTo-Json -Depth 5 -Compress
"""


def _list(v) -> list:
    return [] if v is None else v if isinstance(v, list) else [v]


def static_info(run=None) -> dict:
    if not IS_WINDOWS:
        import platform
        import socket

        return {"os": {"caption": f"{platform.system()} {platform.release()}", "version": platform.version(), "arch": platform.machine()},
                "computer": {"name": socket.gethostname()}, "cpu": [{"name": platform.processor()}], "gpu": [], "adapters": []}
    out = (run or _ps)(PS_STATIC)
    data = json.loads(out.strip() or "{}")
    for k in ("cpu", "gpu", "adapters"):
        data[k] = _list(data.get(k))
    for a in data["adapters"]:
        a["ipv4"], a["dns"] = _list(a.get("ipv4")), _list(a.get("dns"))
    os_ = data.get("os", {})
    os_["pretty"] = pretty_os(os_)
    return data


def pretty_os(o: dict) -> str:
    """'Windows 11 Pro 25H2 (build 26200.7019), 64-bit'."""
    name = (o.get("caption") or "").replace("Microsoft ", "")
    build = f"{o.get('build')}" + (f".{o['ubr']}" if o.get("ubr") else "")
    return f"{name} {o.get('display') or ''} (build {build}), {o.get('arch') or ''}".replace("  ", " ").strip()


def _ps(script: str) -> str:
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                          timeout=60, errors="replace", creationflags=NO_WINDOW).stdout


# =========================================================================================================
# GPU load through PDH (performance counters) without starting processes
# =========================================================================================================
class Pdh:
    """Wildcard counters summed over instances: GPU 3D/compute engine %, dedicated and shared video memory."""

    COUNTERS = {"gpu_pct": r"\GPU Engine(*engtype_3D)\Utilization Percentage",
                "gpu_compute_pct": r"\GPU Engine(*engtype_Compute)\Utilization Percentage",
                "vram_dedicated": r"\GPU Adapter Memory(*)\Dedicated Usage",
                "vram_shared": r"\GPU Adapter Memory(*)\Shared Usage"}

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self.ct, self.wt = ctypes, wintypes
        self.pdh = ctypes.WinDLL("pdh.dll")
        for fn in ("PdhOpenQueryW", "PdhAddEnglishCounterW", "PdhCollectQueryData", "PdhGetFormattedCounterArrayW"):
            getattr(self.pdh, fn).restype = ctypes.c_ulong  # PDH status codes are unsigned (0x800007D2 = more data)
        self.query = wintypes.HANDLE()
        if self.pdh.PdhOpenQueryW(None, None, ctypes.byref(self.query)) != 0:
            raise OSError("PdhOpenQuery failed")
        self.handles = {}
        for key, path in self.COUNTERS.items():
            h = wintypes.HANDLE()
            if self.pdh.PdhAddEnglishCounterW(self.query, path, None, ctypes.byref(h)) == 0:
                self.handles[key] = h
        self.pdh.PdhCollectQueryData(self.query)  # rate counters need two samples

    def read(self) -> dict:
        ct = self.ct

        class FMT(ct.Structure):
            _fields_ = [("status", ct.c_ulong), ("pad", ct.c_ulong), ("value", ct.c_double)]

        class ITEM(ct.Structure):
            _fields_ = [("name", ct.c_wchar_p), ("fmt", FMT)]

        if self.pdh.PdhCollectQueryData(self.query) != 0:
            return {}
        out = {}
        for key, h in self.handles.items():
            size, count = self.wt.DWORD(0), self.wt.DWORD(0)
            PDH_FMT_DOUBLE, MORE = 0x200, 0x800007D2
            rc = self.pdh.PdhGetFormattedCounterArrayW(h, PDH_FMT_DOUBLE, ct.byref(size), ct.byref(count), None)
            if rc != MORE or not size.value:
                continue
            buf = (ct.c_byte * size.value)()
            if self.pdh.PdhGetFormattedCounterArrayW(h, PDH_FMT_DOUBLE, ct.byref(size), ct.byref(count), buf) != 0:
                continue
            items = ct.cast(buf, ct.POINTER(ITEM))
            out[key] = sum(items[i].fmt.value for i in range(count.value) if items[i].fmt.status in (0, 1))
        return out


# =========================================================================================================
class Sampler:
    """Background sampling every SAMPLE_EVERY seconds; one per process."""

    def __init__(self, every: float = SAMPLE_EVERY):
        self.every = every
        self.lock = threading.Lock()
        self.last: dict = {}
        self.history: deque = deque(maxlen=HISTORY)
        self.pdh = None
        self.thread = None
        self.stopped = threading.Event()

    def start(self) -> "Sampler":
        if self.thread is None:
            self.thread = threading.Thread(target=self._run, name="sysinfo-sampler", daemon=True)
            self.thread.start()
        return self

    def stop(self) -> None:
        self.stopped.set()

    def _run(self) -> None:
        import psutil

        psutil.cpu_percent(percpu=True)
        if IS_WINDOWS:
            try:
                self.pdh = Pdh()
            except Exception as exc:  # noqa: BLE001 - GPU numbers are optional
                log.info("GPU counters unavailable: %s", exc)
        while not self.stopped.wait(self.every):
            try:
                self.sample()
            except Exception:  # noqa: BLE001 - a sampler must keep going
                log.exception("sysinfo sample failed")

    def sample(self) -> dict:
        import psutil

        cores = psutil.cpu_percent(percpu=True)
        vm = psutil.virtual_memory()
        s = {"ts": time.time(), "cpu": round(sum(cores) / max(len(cores), 1), 1), "cores": [round(c) for c in cores],
             "ram_pct": vm.percent, "ram_used": vm.total - vm.available, "ram_total": vm.total}
        try:
            f = psutil.cpu_freq()
            s["mhz"] = round(f.current) if f else None
        except Exception:  # noqa: BLE001
            pass
        if self.pdh is not None:
            g = self.pdh.read()
            if g:
                s["gpu"] = round(min(100.0, max(g.get("gpu_pct", 0), g.get("gpu_compute_pct", 0))), 1)
                s["vram_dedicated"] = int(g.get("vram_dedicated", 0))
                s["vram_shared"] = int(g.get("vram_shared", 0))
        with self.lock:
            self.last = s
            self.history.append((round(s["ts"]), s["cpu"], s["ram_pct"], s.get("gpu")))
        return s

    def snapshot(self) -> dict:
        with self.lock:
            return {"now": dict(self.last), "history": list(self.history)}


SAMPLER: Sampler | None = None
_STATIC: dict = {}


def sampler() -> Sampler:
    global SAMPLER
    if SAMPLER is None:
        SAMPLER = Sampler().start()
    return SAMPLER


def partitions() -> list[dict]:
    import psutil

    out = []
    for p in psutil.disk_partitions(all=False):
        if "cdrom" in p.opts or not p.fstype:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except OSError:
            continue
        out.append({"mount": p.mountpoint, "fs": p.fstype, "total": u.total, "used": u.used, "free": u.free, "pct": u.percent})
    return out


def info(refresh: bool = False, run=None) -> dict:
    """Everything for the PC menu's system section."""
    if refresh or not _STATIC or time.time() - _STATIC.get("at", 0) > 600:
        try:
            _STATIC.update(at=time.time(), data=static_info(run), error="")
        except Exception as exc:  # noqa: BLE001 - live values still work
            log.info("static info: %s", exc)
            _STATIC.update(at=time.time(), data=_STATIC.get("data") or {}, error=str(exc))
    snap = sampler().snapshot()
    if not snap["now"]:
        snap["now"] = sampler().sample()
    data = dict(_STATIC["data"])
    o = data.get("os") or {}
    if o.get("boot"):
        data["uptime_s"] = int((datetime.now() - datetime.fromisoformat(o["boot"])).total_seconds())
    return {**data, "live": snap["now"], "history": snap["history"], "partitions": partitions(),
            "ts": datetime.now().isoformat(timespec="seconds"), "static_error": _STATIC.get("error", "")}


def fmt_bytes(n: float | None) -> str:
    if n is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return "—"


def fmt_uptime(s: int) -> str:
    d, s = divmod(int(s), 86400)
    h, s = divmod(s, 3600)
    return (f"{d} დღე " if d else "") + f"{h} სთ {s // 60} წთ"


def format_info(d: dict) -> str:
    o, c, live = d.get("os") or {}, d.get("computer") or {}, d.get("live") or {}
    lines = ["🖥 **სისტემა**", f"• {o.get('pretty', '')}",
             f"• კომპიუტერი: **{c.get('name', '')}** · მომხმარებელი {c.get('user') or '—'} · "
             + (f"დომენი {c['domain']}" if c.get("domain") else f"სამუშაო ჯგუფი {c.get('workgroup') or '—'}")]
    if o.get("installed"):
        lines.append(f"• დაყენდა {o['installed'][:10]} · ჩართულია {fmt_uptime(d.get('uptime_s', 0))}")
    for cpu in d.get("cpu", []):
        lines.append(f"• CPU: {cpu.get('name')} — {cpu.get('cores')} ბირთვი / {cpu.get('threads')} ნაკადი · დატვირთვა **{live.get('cpu', '—')}%**")
    for g in d.get("gpu", []):
        lines.append(f"• GPU: {g.get('name')} · დრაივერი {g.get('driver')} · VRAM {fmt_bytes(g.get('vram'))}"
                     + (f" · დატვირთვა **{live['gpu']}%**" if live.get("gpu") is not None else ""))
    lines.append(f"• RAM: {fmt_bytes(live.get('ram_used'))} / {fmt_bytes(live.get('ram_total'))} (**{live.get('ram_pct', '—')}%**)")
    for p in d.get("partitions", []):
        lines.append(f"• {p['mount']} {fmt_bytes(p['used'])} / {fmt_bytes(p['total'])} ({p['pct']}%)")
    for a in d.get("adapters", []):
        if a.get("virtual") or a.get("status") != "Up":
            continue
        lines.append(f"• 🔌 {a['name']}: {', '.join(a['ipv4']) or '—'} · MAC {a.get('mac')} · {a.get('link') or ''}"
                     + (f" · gateway {a['gateway']}" if a.get("gateway") else ""))
    return "\n".join(lines)


def sysinfo_cmd(s, args, user):
    from ..result import Button, Result

    return Result(format_info(info(refresh=bool(args and args[0] == "refresh"))), buttons=[Button("💽 დისკები და RAM", "/pc")])


COMMANDS = {"sysinfo": sysinfo_cmd}
HELP = ["/sysinfo — სისტემის ინფორმაცია: Windows, CPU, GPU, RAM, დისკები, ქსელის ადაპტერები (ცოცხალი დატვირთვით)"]
TOOLS = [
    ({"name": "pc_system_info", "description": "This PC's Windows edition/version/build, uptime, computer/user/domain, CPU "
                                              "(load), GPU (load, VRAM), RAM use, partitions, network adapters (IP, MAC, gateway, DNS).",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: {k: v for k, v in info().items() if k != "history"}),
]


async def start(services, monitoring) -> list:
    """Start sampling with the server so the graphs already have data when the PC tab opens."""
    sampler()
    return []
