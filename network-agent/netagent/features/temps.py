"""PC menu, part 2: live temperatures (CPU package and cores, GPU, disks) with history, thresholds, alerts.

Sources, best first:
  LibreHardwareMonitor  its "Remote Web Server" (Options → Remote Web Server → Run, default port 8085) gives every
                        sensor as JSON on localhost. It reads CPU/GPU sensors through its own driver and must run as
                        administrator; NetAgent installs no kernel driver of its own. NETAGENT_LHM_URL to change it.
  disk SMART            NVMe / SATA temperature from the drive itself (works without admin, see hwhealth.py)
  ACPI thermal zone     WMI MSAcpi_ThermalZoneTemperature: admin only, often a motherboard value, used only if
                        nothing better exists and labelled as such.
Without a CPU source the app says so (and how to get one) instead of showing 0 °C.

Thresholds (yellow / red) per kind are editable in the app; a red value seen twice in a row sends one alert.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import deque

log = logging.getLogger("netagent.temps")
IS_WINDOWS = os.name == "nt"
THRESH_KEY = "temp_thresholds"
DEFAULT_THRESHOLDS = {"cpu": [75, 90], "gpu": [80, 92], "disk": [55, 70]}
SAMPLE_EVERY = 5.0
HISTORY = 180  # 15 minutes at 5 s


def lhm_url() -> str:
    return os.getenv("NETAGENT_LHM_URL", "http://127.0.0.1:8085/data.json")


def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------------------------------------
# LibreHardwareMonitor JSON
# ---------------------------------------------------------------------------------------------------------
NOT_A_READING = re.compile(r"distance to tjmax|warning temperature|critical temperature|\blimit\b|threshold|\btjmax\b|"
                           r"\bmax\b|\baverage\b", re.I)


def _kind(sensor_id: str, image: str) -> str:
    sid, img = (sensor_id or "").lower(), (image or "").lower()
    if re.match(r"/(intelcpu|amdcpu|cpu)", sid) or "cpu" in img:
        return "cpu"
    if sid.startswith("/gpu") or any(x in img for x in ("nvidia", "ati", "amd", "intel", "gpu")):
        return "gpu"
    if re.match(r"/(nvme|hdd|ssd|storage|ata)", sid) or "hdd" in img:
        return "disk"
    return "other"


def parse_lhm(data: dict) -> list[dict]:
    """Temperature sensors from LibreHardwareMonitor's data.json tree: [{kind, hw, name, value, max}]."""
    out = []

    def num(v):
        m = re.search(r"-?\d+(?:[.,]\d+)?", str(v or ""))
        return float(m.group(0).replace(",", ".")) if m else None

    def walk(node, hw="", image=""):
        img = node.get("ImageURL") or image
        children = node.get("Children") or []
        is_hw = any(c.get("Children") for c in children) and node.get("Text") not in {"Temperatures", "Sensor"}
        name = node.get("Text") or ""
        if node.get("Type") == "Temperature" or ("°C" in str(node.get("Value", "")) and not children):
            v = num(node.get("Value"))
            if NOT_A_READING.search(name):  # limits ("Warning/Critical Temperature") and deltas ("Distance to TjMax")
                return
            if v is not None and -20 < v < 150:
                out.append({"kind": _kind(node.get("SensorId", ""), img), "hw": hw, "name": name, "value": round(v, 1),
                            "max": num(node.get("Max"))})
            return
        for c in children:
            walk(c, name if (img != image or is_hw) and name not in {"Temperatures"} else hw, img)

    walk(data)
    return out


def fetch_lhm(get=None) -> list[dict] | None:
    """None when LibreHardwareMonitor's web server is not running."""
    try:
        if get is None:
            import httpx

            r = httpx.get(lhm_url(), timeout=2)
            r.raise_for_status()
            data = r.json()
        else:
            data = get(lhm_url())
    except Exception:  # noqa: BLE001 - not running is the normal case
        return None
    return parse_lhm(data)


_DISKS: dict = {"at": 0.0, "list": []}


def disk_temps() -> list[dict]:
    from . import hwhealth

    out = []
    if time.time() - _DISKS["at"] > 600:  # the disk list rarely changes: no PowerShell every 30 s
        try:
            _DISKS.update(at=time.time(), list=hwhealth.windows_inventory().get("disks", []) if IS_WINDOWS else [])
        except Exception:  # noqa: BLE001
            return out
    disks = _DISKS["list"]
    for d in disks:
        t = (hwhealth.drive_details(d.get("id", 0), d.get("bus") or "") or {}).get("temperature_c")
        if t is not None:
            out.append({"kind": "disk", "hw": d.get("name", ""), "name": "SMART", "value": float(t), "max": None})
    return out


def thermal_zone() -> list[dict]:
    if not IS_WINDOWS or not is_admin():
        return []
    import subprocess

    from ..osutil import NO_WINDOW

    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          "Get-CimInstance -Namespace root/wmi MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | "
                          "ForEach-Object { [math]::Round($_.CurrentTemperature / 10 - 273.15, 1) }"],
                         capture_output=True, text=True, timeout=20, creationflags=NO_WINDOW).stdout
    vals = [float(x) for x in out.split() if re.fullmatch(r"-?\d+(\.\d+)?", x)]
    return [{"kind": "board", "hw": "ACPI thermal zone", "name": f"zone {i}", "value": v, "max": None}
            for i, v in enumerate(vals) if 0 < v < 120]


# ---------------------------------------------------------------------------------------------------------
def summarize(sensors: list[dict]) -> dict:
    """The headline numbers: CPU package (or hottest core), GPU core, hottest disk."""
    def pick(kind, prefer):
        s = [x for x in sensors if x["kind"] == kind]
        for p in prefer:
            for x in s:
                if p in x["name"].lower():
                    return x["value"]
        return max((x["value"] for x in s), default=None)

    return {"cpu": pick("cpu", ("package", "tctl", "tdie", "core (tctl")), "gpu": pick("gpu", ("gpu core", "core", "hot spot")),
            "disk": max((x["value"] for x in sensors if x["kind"] == "disk"), default=None)}


def level(kind: str, value: float | None, thresholds: dict) -> str:
    if value is None:
        return ""
    y, r = thresholds.get(kind, DEFAULT_THRESHOLDS.get(kind, [80, 95]))
    return "red" if value >= r else "yellow" if value >= y else "green"


def thresholds(state) -> dict:
    t = dict(DEFAULT_THRESHOLDS)
    for k, v in (state.get(THRESH_KEY) or {}).items():
        if k in t and isinstance(v, list) and len(v) == 2:
            t[k] = v
    return t


def set_thresholds(state, new: dict) -> dict:
    from ..result import CommandError

    clean = {}
    for k, v in (new or {}).items():
        if k not in DEFAULT_THRESHOLDS:
            continue
        try:
            y, r = int(v[0]), int(v[1])
        except (TypeError, ValueError, IndexError):
            raise CommandError(f"{k}: ორი რიცხვი საჭიროა (ყვითელი, წითელი)") from None
        if not (20 <= y < r <= 120):
            raise CommandError(f"{k}: უნდა იყოს 20 ≤ ყვითელი < წითელი ≤ 120")
        clean[k] = [y, r]
    state.update(THRESH_KEY, lambda cur: {**(cur or {}), **clean})
    return thresholds(state)


class TempSampler:
    def __init__(self, every: float = SAMPLE_EVERY, lhm=fetch_lhm, disks=disk_temps, zone=thermal_zone):
        self.every, self.lhm, self.disks, self.zone = every, lhm, disks, zone
        self.lock = threading.Lock()
        self.last: dict = {"sensors": [], "sources": [], "ts": 0}
        self.history: deque = deque(maxlen=HISTORY)
        self.thread = None
        self._disk_cache = (0.0, [])

    def start(self) -> "TempSampler":
        if self.thread is None:
            self.thread = threading.Thread(target=self._run, name="temps-sampler", daemon=True)
            self.thread.start()
        return self

    def _run(self) -> None:
        while True:
            try:
                self.sample()
            except Exception:  # noqa: BLE001
                log.exception("temperature sample failed")
            time.sleep(self.every)

    def sample(self) -> dict:
        sensors, sources = [], []
        got = self.lhm()
        if got is not None:
            sources.append("LibreHardwareMonitor")
            sensors += got
        now = time.time()
        if not any(s["kind"] == "disk" for s in sensors):
            if now - self._disk_cache[0] > 30:  # SMART every 30 s is plenty
                self._disk_cache = (now, self.disks())
            if self._disk_cache[1]:
                sources.append("SMART")
                sensors += self._disk_cache[1]
        if not any(s["kind"] == "cpu" for s in sensors):
            z = self.zone()
            if z:
                sources.append("ACPI")
                sensors += z
        head = summarize(sensors)
        snap = {"ts": now, "sensors": sensors, "sources": sources, "summary": head}
        with self.lock:
            self.last = snap
            self.history.append((round(now), head["cpu"], head["gpu"], head["disk"]))
        return snap

    def snapshot(self) -> dict:
        with self.lock:
            return {**self.last, "history": list(self.history)}


SAMPLER: TempSampler | None = None


def sampler() -> TempSampler:
    global SAMPLER
    if SAMPLER is None:
        SAMPLER = TempSampler().start()
    return SAMPLER


HOW_TO = ("CPU/GPU-ის ტემპერატურას Windows ადმინისა და სპეციალური დრაივერის გარეშე არ იძლევა. ჩართვა: "
          "გადმოწერე LibreHardwareMonitor (github.com/LibreHardwareMonitor, უფასო), გაუშვი ადმინად → Options → "
          "Remote Web Server → Run (პორტი 8085). NetAgent მონაცემს იქიდან წაიკითხავს. დისკის ტემპერატურა ამის გარეშეც ჩანს.")


def report(state) -> dict:
    snap = sampler().snapshot()
    th = thresholds(state)
    head = snap.get("summary") or {}
    msg = ""
    if not any(s["kind"] == "cpu" for s in snap.get("sensors", [])):
        msg = HOW_TO
    return {**snap, "thresholds": th, "levels": {k: level(k, head.get(k), th) for k in ("cpu", "gpu", "disk")},
            "admin": is_admin(), "lhm_url": lhm_url(), "message": msg}


def format_temps(r: dict) -> str:
    head = r.get("summary") or {}
    icon = {"green": "🟢", "yellow": "🟡", "red": "🔴", "": "⚪"}
    lines = ["🌡 **ტემპერატურები**" + (f" (წყარო: {', '.join(r['sources'])})" if r.get("sources") else "")]
    names = {"cpu": "CPU", "gpu": "GPU", "disk": "დისკი"}
    for k in ("cpu", "gpu", "disk"):
        v = head.get(k)
        lines.append(f"{icon[r['levels'].get(k, '')]} {names[k]}: " + (f"**{v:.0f}°C**" if v is not None else "— (სენსორი მიუწვდომელია)"))
    cores = [s for s in r.get("sensors", []) if s["kind"] == "cpu" and "core" in s["name"].lower()]
    if cores:
        lines.append("ბირთვები: " + ", ".join(f"{s['value']:.0f}°" for s in cores[:16]))
    if r.get("message"):
        lines.append("\nℹ️ " + r["message"])
    return "\n".join(lines)


def temps_cmd(s, args, user):
    from ..result import Result

    return Result(format_temps(report(s.state)))


COMMANDS = {"temps": temps_cmd}
HELP = ["/temps — CPU/GPU/დისკის ტემპერატურა (CPU-სთვის საჭიროა LibreHardwareMonitor-ის Remote Web Server)"]
TOOLS = [
    ({"name": "pc_temperatures", "description": "This PC's CPU (package/cores), GPU and disk temperatures with thresholds; "
                                               "says when CPU sensors are not available.",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: {k: v for k, v in report(ctx.services.state).items() if k != "history"}),
]


async def start(services, monitoring) -> list:
    sampler()
    return []


def jobs(monitoring):
    hot: dict = {}

    async def check():
        from ..monitoring import Alert
        from ..result import Button

        r = report(monitoring.s.state)
        for k, lv in r["levels"].items():
            hot[k] = hot.get(k, 0) + 1 if lv == "red" else 0
            if hot[k] == 2:  # two checks in a row, then quiet until it cools down
                v = r["summary"][k]
                await monitoring.emit(Alert("hardware", f"🔥 **{ {'cpu': 'CPU', 'gpu': 'GPU', 'disk': 'დისკი'}[k] } გადახურდა: {v:.0f}°C** "
                                                        f"(ზღვარი {r['thresholds'][k][1]}°C)", mutable=False,
                                            buttons=[Button("🌡 ტემპერატურები", "/temps")]))

    return [("temps", 60, 120, check)]
