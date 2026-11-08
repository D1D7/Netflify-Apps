"""Internet quality: Wi-Fi channel advisor, bufferbloat test, latency to popular services.

  /wifiscan     nearby Wi-Fi networks, how crowded each channel is, which channel to move to; signal history
  /bufferbloat  how much the ping grows while the line is busy (download/upload) -> grade A+..F
  /services     latency to Google, YouTube, Facebook, Zoom, Steam... (is one service slow, or everything?)

Wi-Fi: Windows asks the adapter for a fresh scan (WlanScan, no admin) and reads `netsh wlan show networks`;
Linux reads `nmcli dev wifi list`. The signal of this PC's connection is recorded every 5 minutes.
"""

from __future__ import annotations

import csv
import os
import re
import socket
import statistics
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from ..config import settings
from ..osutil import NO_WINDOW
from ..result import Button, CommandError, Result
from . import env_int

IS_WINDOWS = os.name == "nt"


# =========================================================================================================
# Wi-Fi channel advisor
# =========================================================================================================
def trigger_scan(wait: float = 4.0) -> bool:
    """Windows: ask every Wi-Fi adapter for a fresh scan (the netsh list is otherwise an old cached one)."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        class INFO(ctypes.Structure):
            _fields_ = [("guid", GUID), ("desc", ctypes.c_wchar * 256), ("state", ctypes.c_int)]

        class LIST(ctypes.Structure):
            _fields_ = [("n", wintypes.DWORD), ("i", wintypes.DWORD), ("items", INFO * 1)]

        wlan = ctypes.WinDLL("wlanapi.dll")
        h, ver = wintypes.HANDLE(), wintypes.DWORD()
        if wlan.WlanOpenHandle(2, None, ctypes.byref(ver), ctypes.byref(h)) != 0:
            return False
        try:
            lst = ctypes.POINTER(LIST)()
            if wlan.WlanEnumInterfaces(h, None, ctypes.byref(lst)) != 0:
                return False
            items = ctypes.cast(ctypes.addressof(lst.contents.items), ctypes.POINTER(INFO))
            ok = any(wlan.WlanScan(h, ctypes.byref(items[i].guid), None, None, None) == 0 for i in range(lst.contents.n))
            wlan.WlanFreeMemory(lst)
        finally:
            wlan.WlanCloseHandle(h, None)
    except (OSError, AttributeError):
        return False
    if ok:
        time.sleep(wait)
    return ok


def parse_netsh_networks(text: str) -> list[dict]:
    """`netsh wlan show networks mode=bssid` -> one dict per access point (BSSID)."""
    out, ssid, cur = [], "", None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^SSID \d+\s*:\s*(.*)$", line)
        if m:
            ssid = m.group(1).strip()
            continue
        m = re.match(r"^BSSID \d+\s*:\s*([0-9a-fA-F:]{17})", line)
        if m:
            cur = {"ssid": ssid or "(დამალული)", "bssid": m.group(1).lower(), "signal": 0, "channel": 0, "band": "", "util": None}
            out.append(cur)
            continue
        if cur is None or ":" not in line:
            continue
        key, _, val = (x.strip() for x in line.partition(":"))
        k = key.lower()
        if k == "signal":
            cur["signal"] = int(re.sub(r"\D", "", val) or 0)
        elif k == "channel":
            cur["channel"] = int(re.sub(r"\D", "", val) or 0)
        elif k == "band":
            cur["band"] = val
        elif k.startswith("channel utilization"):
            m = re.search(r"\((\d+)\s*%\)", val)
            cur["util"] = int(m.group(1)) if m else None
    for n in out:
        if not n["band"] and n["channel"]:
            n["band"] = "2.4 GHz" if n["channel"] <= 14 else "5 GHz"
    return out


def parse_nmcli(text: str) -> list[dict]:
    """`nmcli -t -f SSID,BSSID,CHAN,SIGNAL dev wifi list` (BSSID colons are escaped as \\:)."""
    out = []
    for line in text.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 4:
            ch = int(parts[2] or 0) if parts[2].isdigit() else 0
            out.append({"ssid": parts[0] or "(დამალული)", "bssid": parts[1].replace("\\:", ":").lower(), "channel": ch,
                        "signal": int(parts[3] or 0) if parts[3].isdigit() else 0, "band": "2.4 GHz" if ch <= 14 else "5 GHz",
                        "util": None})
    return out


def scan_networks(fresh: bool = True) -> list[dict] | None:
    """Nearby access points, or None when this computer has no Wi-Fi (or it is not allowed to scan)."""
    try:
        if IS_WINDOWS:
            if fresh:
                trigger_scan()
            out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True,
                                 timeout=15, errors="replace", creationflags=NO_WINDOW).stdout
            if "location" in out.lower() and "permission" in out.lower():
                raise CommandError("Windows-მა Wi-Fi-ის სკანირებაზე ნებართვა არ მისცა: Settings → Privacy & security → "
                                   "Location → ჩართე „Let desktop apps access your location“.")
            return parse_netsh_networks(out)
        out = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL", "dev", "wifi", "list"], capture_output=True,
                             text=True, timeout=20, errors="replace", creationflags=NO_WINDOW).stdout
        return parse_nmcli(out)
    except (OSError, subprocess.SubprocessError):
        return None


def channel_load(networks: list[dict], channel: int, exclude: set[str] = frozenset()) -> float:
    """How busy a channel is for us: overlapping 2.4 GHz neighbours count by signal and distance (±4 channels)."""
    load = 0.0
    for n in networks:
        if n["bssid"] in exclude or not n["channel"]:
            continue
        if channel <= 14 and n["channel"] <= 14:
            d = abs(n["channel"] - channel)
            if d < 5:
                load += n["signal"] / 100 * (1 - d / 5)
        elif channel > 14 and n["channel"] == channel:
            load += n["signal"] / 100
    return round(load, 2)


def advise(networks: list[dict], current: dict | None) -> dict:
    """Best channel for our own access point(s)."""
    mine = {n["bssid"] for n in networks if current and n["ssid"] == current.get("ssid")}
    cur_ch = int(current.get("channel") or 0) if current and str(current.get("channel", "")).isdigit() else 0
    res = {"current": cur_ch, "mine": sorted(mine), "options": {}}
    if not cur_ch:
        return res
    if cur_ch <= 14:
        cands = sorted({1, 6, 11, cur_ch})
    else:
        cands = sorted({n["channel"] for n in networks if n["channel"] > 14} | {36, 40, 44, 48, 149, 153, 157, 161, cur_ch})
    res["options"] = {c: channel_load(networks, c, mine) for c in cands}
    best = min(cands, key=lambda c: (res["options"][c], c != cur_ch))
    res["best"] = best
    res["gain"] = round(res["options"][cur_ch] - res["options"][best], 2)
    return res


def wifi_dir() -> Path:
    p = settings.data_dir / "wifi"
    p.mkdir(parents=True, exist_ok=True)
    return p


def record_signal(info: dict, when: datetime | None = None, root: Path | None = None) -> None:
    when = when or datetime.now()
    root = root or wifi_dir()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{when.date().isoformat()}.csv"
    new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["ts", "ssid", "signal", "channel", "rx", "tx"])
        sig = int(re.sub(r"\D", "", str(info.get("signal") or "0")) or 0)
        w.writerow([when.isoformat(timespec="seconds"), info.get("ssid", ""), sig, info.get("channel", ""), info.get("rx", ""), info.get("tx", "")])
    cutoff = (when - timedelta(days=14)).date().isoformat()
    for f in root.glob("*.csv"):
        if f.stem < cutoff:
            f.unlink(missing_ok=True)


def signal_history(hours: float = 24, root: Path | None = None) -> list[tuple[datetime, int]]:
    root = root or wifi_dir()
    since = datetime.now() - timedelta(hours=hours)
    rows = []
    for f in sorted(root.glob("*.csv")):
        if f.stem < since.date().isoformat():
            continue
        with f.open(encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                ts = datetime.fromisoformat(r["ts"])
                if ts >= since:
                    rows.append((ts, int(r["signal"] or 0)))
    return rows


def format_wifi(networks: list[dict], current: dict | None, adv: dict, hist: list) -> str:
    if current is None:
        return "📶 Wi-Fi-ის სკანირება მხოლოდ Wi-Fi ადაპტერიან კომპიუტერზეა შესაძლებელი."
    if not current:
        head = "📶 **Wi-Fi** — ეს კომპიუტერი კაბელითაა მიერთებული; ქვემოთ — ახლომდებარე ქსელები."
    else:
        head = (f"📶 **Wi-Fi: {current.get('ssid')}** — არხი {current.get('channel')} ({current.get('band') or current.get('radio') or ''}), "
                f"სიგნალი {current.get('signal')}, სიჩქარე როუტერთან {current.get('rx')} Mbps")
    lines = [head, ""]
    by_band: dict[str, list] = {}
    for n in sorted(networks, key=lambda n: (-n["signal"])):
        by_band.setdefault(n["band"] or "?", []).append(n)
    for band, items in sorted(by_band.items()):
        lines.append(f"**{band}** — {len(items)} წვდომის წერტილი")
        for n in items[:12]:
            me = " ← შენი" if n["bssid"] in adv.get("mine", []) else ""
            util = f", დატვირთვა {n['util']}%" if n.get("util") is not None else ""
            lines.append(f"• არხი {n['channel']:>3} · {n['signal']:>3}% · {n['ssid'][:24]}{util}{me}")
    if adv.get("options"):
        lines.append("")
        lines.append("**არხების დატვირთვა** (მეზობლების გავლენა; ნაკლები = უკეთესი): "
                     + " · ".join(f"{c}: {v}" for c, v in adv["options"].items()))
        if adv["best"] != adv["current"] and adv["gain"] >= 0.15:
            lines.append(f"🎯 **რჩევა: როუტერზე არხი {adv['current']} → {adv['best']}** "
                         f"(შენს არხზე მეზობლების გავლენა {adv['options'][adv['current']]}, {adv['best']}-ზე — {adv['options'][adv['best']]}). "
                         "როუტერის ადმინ-პანელი → Wireless → Channel.")
        else:
            lines.append(f"✅ არხი {adv['current']} ახლა კარგი არჩევანია — შეცვლა მნიშვნელოვნად არ გააუმჯობესებს.")
        if adv["current"] <= 14:
            lines.append("💡 თუ როუტერს 5 GHz აქვს, მასზე გადასვლა (თუ კედლები ბევრი არაა) ჩვეულებრივ 2-5-ჯერ სწრაფია და "
                         "მეზობლების ხმაური თითქმის არ აქვს.")
    if hist:
        sig = [s for _, s in hist]
        lines.append(f"\n📈 სიგნალი ბოლო 24 სთ: საშუალო {round(statistics.mean(sig))}%, მინ. {min(sig)}%, მაქს. {max(sig)}% ({len(sig)} გაზომვა)")
    return "\n".join(lines)


def wifiscan_cmd(s, args, user) -> Result:
    from .morebooks import _windows_wifi

    networks = scan_networks()
    if networks is None:
        raise CommandError("Wi-Fi-ის სიის წაკითხვა ვერ მოხერხდა (netsh / nmcli).")
    current = _windows_wifi() if IS_WINDOWS else {}
    adv = advise(networks, current)
    return Result(format_wifi(networks, current, adv, signal_history(24)),
                  buttons=[Button("📶 Wi-Fi დიაგნოსტიკა", "/diagnose wifi"), Button("🌊 Bufferbloat", "/bufferbloat")])


def _wifi_tool() -> dict:
    from .morebooks import _windows_wifi

    nets = scan_networks() or []
    cur = _windows_wifi() if IS_WINDOWS else {}
    return {"current": cur, "networks": nets, "advice": advise(nets, cur), "signal_24h": [(t.isoformat(), s) for t, s in signal_history(24)]}


# =========================================================================================================
# bufferbloat
# =========================================================================================================
GRADES = [(5, "A+"), (30, "A"), (60, "B"), (200, "C"), (400, "D")]


def grade(increase_ms: float) -> str:
    for limit, g in GRADES:
        if increase_ms < limit:
            return g
    return "F"


def _median(xs: list[float]) -> float | None:
    return round(statistics.median(xs), 1) if xs else None


def measure_bufferbloat(rtt=None, load_down=None, load_up=None, seconds: float = 7.0, every: float = 0.25) -> dict:
    """Idle latency, then latency while the line downloads / uploads as fast as it can."""
    from .isp import tcp_rtt_sampler

    rtt = rtt or tcp_rtt_sampler()
    load_down = load_down or _download_load
    load_up = load_up or _upload_load

    def sample_during(load) -> tuple[list[float], float]:
        stop = threading.Event()
        result = {"mbps": 0.0}
        t = threading.Thread(target=lambda: result.update(mbps=load(stop, seconds)), daemon=True)
        t.start()
        time.sleep(min(1.0, seconds / 4))  # let the transfer ramp up first
        got = []
        end = time.monotonic() + seconds - 1.0
        while time.monotonic() < end and t.is_alive():
            v = rtt()
            if v is not None:
                got.append(v)
            time.sleep(every)
        stop.set()
        t.join(timeout=seconds + 5)
        return got, result["mbps"]

    idle = [v for v in (rtt() for _ in range(10)) if v is not None]
    down, down_mbps = sample_during(load_down)
    up, up_mbps = sample_during(load_up)
    base = _median(idle)
    res = {"idle_ms": base, "down_ms": _median(down), "up_ms": _median(up), "down_mbps": round(down_mbps, 1), "up_mbps": round(up_mbps, 1)}
    if base is None:
        res.update(grade="?", worst_increase_ms=None)
        return res
    inc = max((res[k] or base) - base for k in ("down_ms", "up_ms"))
    res.update(worst_increase_ms=round(inc, 1), down_increase_ms=round((res["down_ms"] or base) - base, 1),
               up_increase_ms=round((res["up_ms"] or base) - base, 1), grade=grade(inc))
    return res


def _download_load(stop: threading.Event, seconds: float) -> float:
    import httpx

    from .isp import SPEED_HEADERS, SPEED_URL

    size, t0 = 0, time.monotonic()
    try:
        with httpx.Client(timeout=15, headers=SPEED_HEADERS) as c, c.stream("GET", f"{SPEED_URL}/__down?bytes=200000000") as r:
            for chunk in r.iter_bytes():
                size += len(chunk)
                if stop.is_set() or time.monotonic() - t0 > seconds:
                    break
    except Exception:  # noqa: BLE001 - a load generator: whatever it achieved is fine
        pass
    return size * 8 / max(time.monotonic() - t0, 0.001) / 1e6


def _upload_load(stop: threading.Event, seconds: float) -> float:
    import httpx

    from .isp import SPEED_HEADERS, SPEED_URL

    sent, t0 = [0], time.monotonic()
    block = os.urandom(256 * 1024)

    def body():
        while not stop.is_set() and time.monotonic() - t0 < seconds:
            sent[0] += len(block)
            yield block

    try:
        with httpx.Client(timeout=15, headers=SPEED_HEADERS) as c:
            c.post(f"{SPEED_URL}/__up", content=body())
    except Exception:  # noqa: BLE001
        pass
    return sent[0] * 8 / max(time.monotonic() - t0, 0.001) / 1e6


GRADE_TEXT = {
    "A+": "შესანიშნავი — დატვირთვისას ping თითქმის არ იცვლება. ზარები და თამაშები არ შეფერხდება.",
    "A": "კარგი — მცირე ზრდა, ზარებს/თამაშებს არ აწუხებს.",
    "B": "საშუალო — ვიდეოზარს შეიძლება ხანდახან შეეტყოს, როცა ვინმე დიდ ფაილს ტვირთავს.",
    "C": "ცუდი — როცა ვინმე ტვირთავს/ატვირთავს, ზარები და თამაშები შესამჩნევად ფერხდება.",
    "D": "ძალიან ცუდი — დატვირთვისას კავშირი პრაქტიკულად „იჭედება“.",
    "F": "კრიტიკული — დატვირთვისას ინტერნეტი თითქმის გამოუსადეგარია ინტერაქტიულისთვის.",
}


def format_bufferbloat(r: dict) -> str:
    if r.get("grade") == "?":
        return "🌊 Bufferbloat ვერ გაიზომა — ping არ მუშაობს (ინტერნეტი არის?)."
    lines = [f"🌊 **Bufferbloat: {r['grade']}** — {GRADE_TEXT[r['grade']]}",
             f"ping უმოქმედოდ: **{r['idle_ms']} ms**",
             f"ping ჩამოტვირთვისას: **{r['down_ms']} ms** (+{r['down_increase_ms']}) · ხაზი იტვირთებოდა {r['down_mbps']} Mbps-ით",
             f"ping ატვირთვისას: **{r['up_ms']} ms** (+{r['up_increase_ms']}) · {r['up_mbps']} Mbps"]
    if r["grade"] in {"B", "C", "D", "F"}:
        lines.append("\n🔧 **რა ეშველება:** როუტერზე ჩართე **SQM / QoS / Smart Queue** (ზოგჯერ „Bandwidth control“) და მიუთითე "
                     "სიჩქარე რეალურის ~90%; თუ როუტერი ამას არ უჭერს მხარს — პროვაიდერს სთხოვე როუტერის შეცვლა.")
    return "\n".join(lines)


def bufferbloat_cmd(s, args, user) -> Result:
    r = measure_bufferbloat()
    s.state.update("bufferbloat_tests", lambda v: ((v or []) + [{"ts": datetime.now().isoformat(timespec="seconds"), **r}])[-100:])
    return Result(format_bufferbloat(r), buttons=[Button("⚡ სიჩქარე", "/speedtest"), Button("🌐 სერვისები", "/services")])


# =========================================================================================================
# latency to popular services
# =========================================================================================================
SERVICES = [
    ("Google", "www.google.com"), ("YouTube", "www.youtube.com"), ("Facebook", "www.facebook.com"),
    ("Instagram", "www.instagram.com"), ("WhatsApp", "web.whatsapp.com"), ("Zoom", "zoom.us"),
    ("Microsoft Teams", "teams.microsoft.com"), ("Netflix", "www.netflix.com"), ("TikTok", "www.tiktok.com"),
    ("Discord", "discord.com"), ("Steam", "store.steampowered.com"), ("Cloudflare", "www.cloudflare.com"),
]


def tcp_ms(host: str, port: int = 443, tries: int = 3, timeout: float = 3.0) -> tuple[float | None, float | None, str]:
    """(DNS ms, median TCP connect ms, error)."""
    from .diagnose import os_resolve

    d = os_resolve(host, timeout=4)
    if not d.get("records"):
        return None, None, d.get("error", "DNS")
    ip = d["records"][0]
    got = []
    for _i in range(tries):
        t0 = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                got.append((time.monotonic() - t0) * 1000)
        except OSError as exc:
            err = type(exc).__name__
            if not got and _i == tries - 1:
                return d.get("time_ms"), None, err
    return d.get("time_ms"), _median(got), ""


def check_services(probe=tcp_ms) -> list[dict]:
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=8) as pool:
        res = list(pool.map(lambda x: (x, probe(x[1])), SERVICES))
    return [{"name": name, "host": host, "dns_ms": dns, "ms": ms, "error": err} for (name, host), (dns, ms, err) in res]


def format_services(rows: list[dict]) -> str:
    ok = [r for r in rows if r["ms"] is not None]
    lines = ["🌐 **სერვისები — დაყოვნება აქედან**"]
    for r in sorted(rows, key=lambda r: (r["ms"] is None, r["ms"] or 0)):
        if r["ms"] is None:
            lines.append(f"🔴 {r['name']}: არ პასუხობს ({r['error']})")
            continue
        icon = "🟢" if r["ms"] < 50 else "🟡" if r["ms"] < 150 else "🟠"
        lines.append(f"{icon} {r['name']}: **{r['ms']:.0f} ms**" + (f" · DNS {r['dns_ms']:.0f} ms" if r["dns_ms"] and r["dns_ms"] > 100 else ""))
    if ok:
        med = statistics.median(r["ms"] for r in ok)
        slow = [r["name"] for r in ok if r["ms"] > max(3 * med, med + 80)]
        bad = [r["name"] for r in rows if r["ms"] is None]
        if bad or slow:
            lines.append("\n⚠️ " + ("არ მუშაობს: " + ", ".join(bad) + ". " if bad else "")
                         + ("სხვებზე ბევრად ნელია: " + ", ".join(slow) + ". " if slow else "")
                         + "დანარჩენი ნორმალურია — ე.ი. პრობლემა ამ სერვისის მხარესაა (ან პროვაიდერის მარშრუტში), არა შენს ქსელში.")
        else:
            lines.append(f"\n✅ ყველა სერვისი ნორმალურად პასუხობს (მედიანა {med:.0f} ms).")
    return "\n".join(lines)


def services_cmd(s, args, user) -> Result:
    return Result(format_services(check_services()), buttons=[Button("🌊 Bufferbloat", "/bufferbloat"), Button("⚡ სიჩქარე", "/speedtest")])


# =========================================================================================================
COMMANDS = {"wifiscan": wifiscan_cmd, "bufferbloat": bufferbloat_cmd, "services": services_cmd}
HELP = ["/wifiscan — Wi-Fi: მეზობელი ქსელები, არხების დატვირთვა, რომელ არხზე გადახვიდე · /bufferbloat — ping დატვირთვისას (A+…F)",
        "/services — დაყოვნება Google-მდე, YouTube-მდე, Zoom-მდე, Steam-მდე... (ერთი სერვისია ნელი თუ ყველა?)"]
BOT_COMMANDS = [("wifiscan", "Wi-Fi არხების რჩევა"), ("bufferbloat", "ping დატვირთვისას (A+…F)"), ("services", "პოპულარული სერვისების დაყოვნება")]
TOOLS = [
    ({"name": "wifi_channels", "description": "Nearby Wi-Fi networks, channel congestion and the recommended channel for the "
                                              "user's router; this PC's signal history.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: _wifi_tool()),
    ({"name": "bufferbloat_test", "description": "Latency under load (download/upload) and an A+..F grade: explains calls/games "
                                                 "lagging while someone downloads. Takes ~20 s and some traffic.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: measure_bufferbloat()),
    ({"name": "service_latency", "description": "Latency from here to popular services (Google, YouTube, Facebook, Zoom, Teams, "
                                                "Netflix, Steam...). Use for 'is only X slow?'.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: check_services()),
]


def jobs(monitoring):
    every = env_int("NETAGENT_WIFI_LOG_INTERVAL", 5)
    if every <= 0 or not IS_WINDOWS:
        return []

    async def log_signal():
        import asyncio

        from .morebooks import _windows_wifi

        info = await asyncio.to_thread(_windows_wifi)
        if info:
            await asyncio.to_thread(record_signal, info)

    return [("wifilog", every * 60, 30, log_signal)]
