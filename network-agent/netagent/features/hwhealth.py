"""This PC's hardware health: disks (HDD / SATA SSD / M.2 NVMe) and RAM. "PC" tab in the app, /pc in chat.

Disks
  NVMe (M.2)  the drive's own health log (SMART): percentage of rated life used, spare blocks, temperature,
              power-on hours, data written, media errors, critical warnings. Read with
              IOCTL_STORAGE_QUERY_PROPERTY on a handle opened with no access rights: works WITHOUT admin.
  SATA SSD/HDD  ATA "Device Statistics" log through the same IOCTL (endurance used, hours, temperature,
              reallocated sectors) where Windows' driver allows it; otherwise Windows' own health status.
  every disk  Windows' HealthStatus / OperationalStatus (Get-PhysicalDisk) and the space on its volumes.
RAM
  RAM does not wear out like a disk: its "health" is whether errors were seen. Modules (maker, size, type,
  speed), memory use now, hardware memory errors (WHEA) and Windows Memory Diagnostic results from the
  System log.

A snapshot is kept once a day, so the disk's wear rate and the years left can be estimated after a week;
a background check (every 6 h) sends an alert when a disk or RAM turns bad or a disk overheats.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import subprocess
from datetime import datetime

from ..osutil import NO_WINDOW
from ..result import Button, Result

log = logging.getLogger("netagent.hwhealth")
IS_WINDOWS = os.name == "nt"
HISTORY_KEY = "hw_history"
ALERTED_KEY = "hw_alerted"

JEDEC = {"2C": "Micron", "CE": "Samsung", "AD": "SK hynix", "9B": "Crucial", "CB": "ADATA", "98": "Kingston",
         "9E": "Corsair", "CD": "G.Skill", "EF": "Team Group", "4F": "Transcend", "C1": "Infineon", "51": "Qimonda",
         "FE": "Elpida", "0B": "Nanya", "B3": "Kingmax", "45": "SanDisk", "94": "Mushkin", "C8": "Patriot"}
MEM_TYPES = {20: "DDR", 21: "DDR2", 24: "DDR3", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2", 29: "LPDDR3", 30: "LPDDR4",
             34: "DDR5", 35: "LPDDR5"}


def le(b: bytes) -> int:
    return int.from_bytes(b, "little")


# =========================================================================================================
# raw drive data (Windows, no admin)
# =========================================================================================================
def _query(disk: int, protocol: int, data_type: int, value: int, sub: int, length: int = 512) -> bytes | None:
    """IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceProtocolSpecificProperty -> the returned protocol data."""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                wintypes.DWORD, wintypes.HANDLE]
    k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k32.CreateFileW(rf"\\.\PhysicalDrive{int(disk)}", 0, 3, None, 3, 0, None)  # 0 = query rights only
    if h in (None, wintypes.HANDLE(-1).value):
        return None
    try:
        # STORAGE_PROPERTY_QUERY{PropertyId=50 ProtocolSpecific, QueryType=0} + STORAGE_PROTOCOL_SPECIFIC_DATA (40 bytes)
        inp = struct.pack("<II", 50, 0) + struct.pack("<10I", protocol, data_type, value, sub, 40, length, 0, 0, 0, 0)
        buf = ctypes.create_string_buffer(inp + bytes(length), len(inp) + length)
        got = wintypes.DWORD()
        if not k32.DeviceIoControl(h, 0x2D1400, buf, len(buf), buf, len(buf), ctypes.byref(got), None):
            return None
        # output: STORAGE_PROTOCOL_DATA_DESCRIPTOR{Version, Size} + the 40-byte block, data at its offset
        offset, size = struct.unpack_from("<II", buf.raw, 8 + 16)
        return buf.raw[8 + offset: 8 + offset + size] if size else None
    finally:
        k32.CloseHandle(h)


def parse_nvme_health(d: bytes) -> dict:
    """NVMe SMART / Health Information log page (02h)."""
    temp_k = le(d[1:3])
    return {"critical_warning": d[0], "temperature_c": temp_k - 273 if temp_k else None, "spare_pct": d[3],
            "spare_threshold_pct": d[4], "used_pct": d[5], "written_tb": round(le(d[48:64]) * 512000 / 1e12, 2),
            "read_tb": round(le(d[32:48]) * 512000 / 1e12, 2), "power_cycles": le(d[112:128]),
            "power_on_hours": le(d[128:144]), "unsafe_shutdowns": le(d[144:160]), "media_errors": le(d[160:176]),
            "error_log_entries": le(d[176:192])}


def _stat(page: bytes, off: int) -> int | None:
    """One ATA Device Statistics entry: bit 63 = supported, bit 62 = valid, value in the low 48 bits."""
    if len(page) < off + 8:
        return None
    q = le(page[off: off + 8])
    return q & 0xFFFFFFFFFFFF if q >> 63 & 1 and q >> 62 & 1 else None


def parse_ata_stats(pages: dict[int, bytes]) -> dict:
    """ATA Device Statistics log (04h): 1 general, 3 rotating media, 5 temperature, 7 solid state."""
    out: dict = {}
    if 1 in pages:
        out["power_on_hours"] = _stat(pages[1], 16)
        sectors = _stat(pages[1], 24)
        out["written_tb"] = round(sectors * 512 / 1e12, 2) if sectors is not None else None
    if 3 in pages:
        out["reallocated_sectors"] = _stat(pages[3], 32)
    if 5 in pages:
        t = _stat(pages[5], 8)
        out["temperature_c"] = (t & 0xFF) - 256 if t is not None and t & 0x80 else (t & 0xFF if t is not None else None)
    if 7 in pages:
        u = _stat(pages[7], 8)
        out["used_pct"] = u & 0xFF if u is not None else None
    return {k: v for k, v in out.items() if v is not None}


def drive_details(disk: int, bus: str) -> dict:
    if not IS_WINDOWS:
        return {}
    try:
        if bus.lower() == "nvme":
            d = _query(disk, 3, 2, 2, 0)  # NVMe, log page, health information
            return {"source": "NVMe SMART", **parse_nvme_health(d)} if d and len(d) >= 192 else {}
        pages = {}
        for p in (1, 3, 5, 7):
            d = _query(disk, 2, 2, 0x04, p)  # ATA, log page, Device Statistics, page p
            if d:
                pages[p] = d
        stats = parse_ata_stats(pages)
        return {"source": "ATA Device Statistics", **stats} if stats else {}
    except Exception as exc:  # noqa: BLE001 - details are a bonus over Windows' own status
        log.info("drive %s details: %s", disk, exc)
        return {}


# =========================================================================================================
# Windows inventory (PowerShell, no admin)
# =========================================================================================================
PS_DISKS = r"""
$d = Get-PhysicalDisk | ForEach-Object { [pscustomobject]@{ id=[int]$_.DeviceId; name=$_.FriendlyName; media="$($_.MediaType)";
  bus="$($_.BusType)"; health="$($_.HealthStatus)"; status="$($_.OperationalStatus)"; size=[int64]$_.Size } }
$v = Get-Partition | Where-Object DriveLetter | ForEach-Object { $vol = $_ | Get-Volume;
  [pscustomobject]@{ disk=[int]$_.DiskNumber; letter="$($_.DriveLetter)"; label=$vol.FileSystemLabel; size=[int64]$vol.Size;
  free=[int64]$vol.SizeRemaining } }
$m = Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [pscustomobject]@{ slot=$_.DeviceLocator; maker="$($_.Manufacturer)".Trim();
  part="$($_.PartNumber)".Trim(); size=[int64]$_.Capacity; speed=[int]$_.ConfiguredClockSpeed; type=[int]$_.SMBIOSMemoryType } }
$since = (Get-Date).AddDays(-30)
$whea = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$since} -ErrorAction SilentlyContinue)
$diag = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'} -MaxEvents 1 -ErrorAction SilentlyContinue)
$dev = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk','Ntfs','stornvme','storahci'; Level=1,2,3; StartTime=$since} -ErrorAction SilentlyContinue)
[pscustomobject]@{ disks=@($d); volumes=@($v); memory=@($m);
  whea=@($whea | ForEach-Object { [pscustomobject]@{ ts=$_.TimeCreated.ToString('s'); id=$_.Id; text=($_.Message -split "`n")[0] } });
  memdiag=@($diag | ForEach-Object { [pscustomobject]@{ ts=$_.TimeCreated.ToString('s'); id=$_.Id } });
  diskevents=@($dev | Select-Object -First 20 | ForEach-Object { [pscustomobject]@{ ts=$_.TimeCreated.ToString('s'); src=$_.ProviderName; id=$_.Id } }) } |
  ConvertTo-Json -Depth 4 -Compress
"""


def windows_inventory() -> dict:
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_DISKS], capture_output=True,
                         text=True, timeout=60, errors="replace", creationflags=NO_WINDOW).stdout
    data = json.loads(out.strip() or "{}")
    for k in ("disks", "volumes", "memory", "whea", "memdiag", "diskevents"):  # one item comes back as an object
        v = data.get(k)
        data[k] = [] if v is None else v if isinstance(v, list) else [v]
    return data


def ram_maker(code: str) -> str:
    c = (code or "").upper().strip()
    if not c or c in {"UNKNOWN", "0000"}:
        return ""
    if not all(ch in "0123456789ABCDEF" for ch in c):
        return code  # already a name
    # e.g. "802C0000802C" or "80CE": the JEDEC id is the byte after the bank's 0x80 marker
    for i in range(0, len(c) - 3, 2):
        if c[i:i + 2] == "80" and c[i + 2:i + 4] in JEDEC:
            return JEDEC[c[i + 2:i + 4]]
    return JEDEC.get(c[-2:], code)


# =========================================================================================================
# verdicts
# =========================================================================================================
def disk_kind(d: dict) -> str:
    bus, media = (d.get("bus") or "").lower(), (d.get("media") or "").upper()
    if bus == "nvme":
        return "M.2 NVMe SSD"
    if media == "HDD":
        return "HDD"
    if media == "SSD":
        return "SATA SSD" if bus in {"sata", "ata"} else f"SSD ({d.get('bus')})"
    return f"{d.get('bus') or ''} {d.get('media') or 'დისკი'}".strip()


def judge_disk(d: dict) -> dict:
    """status ok / warn / bad, life % (if known) and the reasons."""
    x = d.get("details") or {}
    why, status = [], "ok"

    def worse(s, text):
        nonlocal status
        why.append(text)
        if s == "bad" or (s == "warn" and status == "ok"):
            status = s

    health = (d.get("health") or "").lower()
    if health in {"unhealthy"}:
        worse("bad", "Windows: დისკი გაუმართავია (Unhealthy)")
    elif health == "warning":
        worse("warn", "Windows: გაფრთხილება (Warning)")
    if x.get("critical_warning"):
        worse("bad", f"დისკის კრიტიკული გაფრთხილება (კოდი {x['critical_warning']})")
    used = x.get("used_pct")
    life = max(0, 100 - used) if used is not None else None
    if used is not None:
        if used >= 100:
            worse("bad", f"რესურსი ამოწურულია ({used}% გამოყენებული)")
        elif used >= 80:
            worse("warn", f"რესურსის {used}% გამოყენებულია")
    if x.get("spare_threshold_pct") and x.get("spare_pct") is not None and x["spare_pct"] <= x["spare_threshold_pct"]:
        worse("bad", f"სათადარიგო ბლოკები ამოიწურა ({x['spare_pct']}%)")
    if x.get("media_errors"):
        worse("warn", f"მედიის შეცდომები: {x['media_errors']}")
    if x.get("reallocated_sectors"):
        worse("bad" if x["reallocated_sectors"] > 50 else "warn", f"გადატანილი (დაზიანებული) სექტორები: {x['reallocated_sectors']}")
    t = x.get("temperature_c")
    hot = 70 if "nvme" in (d.get("bus") or "").lower() else 55 if (d.get("media") or "").upper() == "HDD" else 65
    if t is not None and t >= hot:
        worse("warn", f"ცხელა: {t}°C")
    return {"status": status, "life_pct": life, "why": why}


def judge_ram(inv: dict, vm: dict) -> dict:
    why, status = [], "ok"
    mem_err = [e for e in inv.get("whea", []) if e.get("id") in {19, 47} or "memory" in (e.get("text") or "").lower()]
    if mem_err:
        status = "bad"
        why.append(f"აპარატურული მეხსიერების შეცდომები ბოლო 30 დღეში: {len(mem_err)} (WHEA)")
    elif inv.get("whea"):
        status = "warn"
        why.append(f"აპარატურული შეცდომები (WHEA) ბოლო 30 დღეში: {len(inv['whea'])} — შეიძლება არა RAM-ის")
    diag = inv.get("memdiag") or []
    if diag and diag[0].get("id") == 1202:
        status = "bad"
        why.append("Windows Memory Diagnostic-მა RAM-ში შეცდომა იპოვა")
    if vm.get("percent", 0) >= 90:
        status = "warn" if status == "ok" else status
        why.append(f"მეხსიერება თითქმის სავსეა ({vm['percent']}%)")
    return {"status": status, "why": why, "diag": diag[0] if diag else None}


# =========================================================================================================
# collect + history
# =========================================================================================================
def collect(inventory=None, details=drive_details) -> dict:
    import psutil

    if inventory is None:
        inventory = windows_inventory() if IS_WINDOWS else {}
    disks = []
    vols = inventory.get("volumes", [])
    for d in sorted(inventory.get("disks", []), key=lambda d: d.get("id", 0)):
        d = dict(d)
        d["kind"] = disk_kind(d)
        d["size_gb"] = round((d.get("size") or 0) / 1e9)
        d["details"] = details(d.get("id", 0), d.get("bus") or "")
        d["volumes"] = [{"letter": v["letter"], "label": v.get("label") or "", "size_gb": round(v["size"] / 1e9, 1),
                         "free_gb": round(v["free"] / 1e9, 1), "used_pct": round(100 * (1 - v["free"] / v["size"])) if v.get("size") else None}
                        for v in vols if v.get("disk") == d.get("id")]
        d.update(judge_disk(d))
        disks.append(d)
    vm = psutil.virtual_memory()
    vmd = {"total_gb": round(vm.total / 2**30, 1), "used_gb": round((vm.total - vm.available) / 2**30, 1), "percent": vm.percent}
    modules = [{"slot": m.get("slot") or "", "maker": ram_maker(m.get("maker", "")), "part": m.get("part") or "",
                "size_gb": round((m.get("size") or 0) / 2**30), "speed": m.get("speed") or None,
                "type": MEM_TYPES.get(m.get("type") or 0, "")} for m in inventory.get("memory", [])]
    ram = {**vmd, "modules": modules, **judge_ram(inventory, vmd), "whea_30d": len(inventory.get("whea", []))}
    return {"ts": datetime.now().isoformat(timespec="seconds"), "disks": disks, "ram": ram,
            "disk_events_30d": inventory.get("diskevents", [])}


def remember(state, data: dict, now: datetime | None = None) -> dict:
    """One snapshot per disk per day: used % and TB written, for the wear rate."""
    day = (now or datetime.now()).date().isoformat()

    def fn(v):
        v = dict(v or {})
        for d in data["disks"]:
            x = d.get("details") or {}
            if x.get("used_pct") is None and x.get("written_tb") is None:
                continue
            key = f"{d.get('name')}#{d.get('id')}"
            days = dict(v.get(key) or {})
            days[day] = {"used": x.get("used_pct"), "tb": x.get("written_tb")}
            v[key] = dict(sorted(days.items())[-400:])
        return v

    return state.update(HISTORY_KEY, fn)


def forecast(history: dict, key: str) -> dict:
    """Wear and writes per day from the first to the last snapshot (needs a week), and years until 100 %."""
    days = sorted((history or {}).get(key, {}).items())
    if len(days) < 2:
        return {}
    (d0, a), (d1, b) = days[0], days[-1]
    span = (datetime.fromisoformat(d1) - datetime.fromisoformat(d0)).days
    if span < 7:
        return {"wait_days": 7 - span}
    out = {"days": span}
    if a.get("tb") is not None and b.get("tb") is not None:
        out["tb_per_day"] = round((b["tb"] - a["tb"]) / span, 3)
    if a.get("used") is not None and b.get("used") is not None and b["used"] > a["used"]:
        per_day = (b["used"] - a["used"]) / span
        out["years_left"] = round((100 - b["used"]) / per_day / 365, 1)
    return out


# =========================================================================================================
# text
# =========================================================================================================
ICON = {"ok": "🟢", "warn": "🟠", "bad": "🔴"}
WORD = {"ok": "ჯანმრთელი", "warn": "ყურადღება", "bad": "პრობლემა"}


def format_pc(data: dict, history: dict | None = None) -> str:
    lines = ["🖥 **კომპიუტერის ჯანმრთელობა**", ""]
    for d in data["disks"]:
        x = d.get("details") or {}
        life = f" · სიცოცხლე **{d['life_pct']}%**" if d.get("life_pct") is not None else ""
        lines.append(f"{ICON[d['status']]} **{d['name']}** — {d['kind']}, {d['size_gb']} GB · {WORD[d['status']]}{life}")
        facts = []
        if x.get("temperature_c") is not None:
            facts.append(f"{x['temperature_c']}°C")
        if x.get("power_on_hours") is not None:
            facts.append(f"{x['power_on_hours']:,} სთ ჩართული")
        if x.get("written_tb") is not None:
            facts.append(f"ჩაწერილი {x['written_tb']} TB")
        if x.get("unsafe_shutdowns"):
            facts.append(f"უეცარი გათიშვა {x['unsafe_shutdowns']}")
        if facts:
            lines.append("   " + " · ".join(facts))
        fc = forecast(history or {}, f"{d.get('name')}#{d.get('id')}")
        if fc.get("years_left") is not None:
            lines.append(f"   ⏳ ამ ტემპით რესურსი დაახლოებით **{fc['years_left']} წელი** ეყოფა ({fc['tb_per_day']} TB/დღეში)")
        for w in d["why"]:
            lines.append(f"   ⚠️ {w}")
        for v in d["volumes"]:
            lines.append(f"   💾 {v['letter']}: {v['free_gb']} GB თავისუფალი {v['size_gb']}-დან ({v['used_pct']}% სავსე)")
        if not x:
            lines.append("   ℹ️ დეტალური SMART ამ დისკზე Windows-მა ადმინის გარეშე არ მოგვცა — ჩანს მხოლოდ Windows-ის სტატუსი.")
    r = data["ram"]
    lines.append("")
    lines.append(f"{ICON[r['status']]} **RAM** — {r['total_gb']} GB · {WORD[r['status']]} · ახლა გამოყენებულია {r['percent']}%")
    for m in r["modules"]:
        lines.append(f"   🧩 {m['slot']}: {m['size_gb']} GB {m['type']}-{m['speed'] or '?'} · {m['maker'] or '?'} {m['part']}".rstrip())
    for w in r["why"]:
        lines.append(f"   ⚠️ {w}")
    if r["status"] == "ok":
        lines.append("   ✅ აპარატურული მეხსიერების შეცდომა ბოლო 30 დღეში არ ყოფილა (RAM-ს „ცვეთა“ არ აქვს — მთავარია შეცდომები).")
    if not r.get("diag"):
        lines.append("   💡 RAM-ის სრული ტესტი: Start → „Windows Memory Diagnostic“ (კომპიუტერი გადაიტვირთება, ~15 წთ).")
    return "\n".join(lines)


def pc_cmd(s, args, user) -> Result:
    data = collect()
    hist = remember(s.state, data)
    return Result(format_pc(data, hist), buttons=[Button("🔄 განახლება", "/pc")])


COMMANDS = {"pc": pc_cmd}
HELP = ["/pc — კომპიუტერის ჯანმრთელობა: დისკები (HDD / SSD / M.2 NVMe — სიცოცხლე %, ტემპერატურა, საათები) და RAM"]
BOT_COMMANDS = [("pc", "კომპიუტერის დისკები და RAM")]
TOOLS = [
    ({"name": "pc_hardware_health", "description": "Health of THIS computer's disks (HDD/SATA SSD/M.2 NVMe: life %, "
                                                   "temperature, hours, TB written, errors) and RAM (modules, errors).",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: collect()),
]


def jobs(monitoring):
    from . import env_int

    every = env_int("NETAGENT_HW_INTERVAL", 360)  # minutes
    if every <= 0 or not IS_WINDOWS:
        return []

    async def check():
        import asyncio

        from ..monitoring import Alert

        state = monitoring.s.state
        data = await asyncio.to_thread(collect)
        await asyncio.to_thread(remember, state, data)
        bad = {f"disk:{d['name']}": (d["status"], d["why"]) for d in data["disks"] if d["status"] != "ok"}
        if data["ram"]["status"] != "ok":
            bad["ram"] = (data["ram"]["status"], data["ram"]["why"])
        before = state.get(ALERTED_KEY) or {}
        new = {k: v for k, v in bad.items() if before.get(k) != v[0]}  # alert once per new state
        state.set(ALERTED_KEY, {k: v[0] for k, v in bad.items()})
        if new:
            text = "🖥 **კომპიუტერის აპარატურა**\n" + "\n".join(
                f"{ICON[st]} {k.split(':', 1)[-1].replace('ram', 'RAM')}: " + "; ".join(why) for k, (st, why) in new.items())
            await monitoring.emit(Alert("hardware", text, mutable=False, buttons=[Button("🖥 PC", "/pc")]))

    return [("hwhealth", every * 60, 90, check)]
