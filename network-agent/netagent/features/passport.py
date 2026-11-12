"""Device passport: model, serial number, OS version, uptime, plus lifecycle dates you keep.

Lifecycle (optional) goes into the inventory next to the device:

    R1:
      host: 10.0.0.1
      device_type: cisco_ios
      lifecycle: {purchased: 2021-03-01, warranty_until: 2026-03-01, eol: 2027-01-31, vendor_support: "SmartNet 123"}
"""

from __future__ import annotations

import re
from datetime import date, datetime

import yaml

from ..config import settings
from ..export import write_xlsx
from ..result import CommandError, Result
from ..tools import device as dev
from ..watch import family

EXTRA = {"ios": ["show version", "show inventory"], "nxos": ["show version", "show inventory"],
         "arista": ["show version"], "junos": ["show version", "show chassis hardware"],
         "mikrotik": ["/system resource print", "/system routerboard print"]}


def parse(fam: str, text: str) -> dict:
    p: dict = {}

    def grab(key, *patterns):
        for pat in patterns:
            m = re.search(pat, text, re.M | re.I)
            if m:
                p[key] = m.group(1).strip().strip('"')
                return

    if fam == "mikrotik":
        grab("model", r"^\s*model:\s*(.+)$", r"^\s*board-name:\s*(.+)$")
        grab("serial", r"^\s*serial-number:\s*(.+)$")
        grab("version", r"^\s*version:\s*(.+)$")
        grab("firmware", r"^\s*current-firmware:\s*(.+)$")
        grab("uptime", r"^\s*uptime:\s*(.+)$")
    else:
        grab("model", r'^PID:\s*([^,\s]+)', r"^cisco (\S+) .*processor", r"^Model:\s*(\S+)", r"Arista (\S+)")
        grab("serial", r"SN:\s*(\S+)", r"Processor board ID (\S+)", r"Serial number:\s*(\S+)", r"Chassis\s+\S+\s+(\S+)")
        grab("version", r"Version (\d[\w.()]+)", r"Junos:\s*(\S+)", r"Software image version:\s*(\S+)")
        grab("uptime", r"uptime is (.+)$", r"System uptime:\s*(.+)$")
    return p


def lifecycle() -> dict[str, dict]:
    try:
        data = yaml.safe_load(settings.inventory_path.read_text(encoding="utf-8")) or {}
    except OSError:
        return {}
    return {n: (v.get("lifecycle") or {}) for n, v in (data.get("devices") or {}).items() if isinstance(v, dict)}


def _days_left(value) -> int | None:
    if not value:
        return None
    try:
        d = value if isinstance(value, date) else datetime.fromisoformat(str(value)).date()
    except ValueError:
        return None
    return (d - date.today()).days


def collect(inventory, device) -> dict:
    fam = family(device.device_type)
    cmds = EXTRA.get(fam) or dev.commands_for(device, "version") or []
    res = dev.run_commands(inventory, device, cmds, parse=False, max_chars=None)
    text = "\n".join(r.get("output", "") for r in res)
    if not text.strip():
        return {"device": device.name, "error": "; ".join(r.get("error", "") for r in res) or "პასუხი არ არის"}
    return {"device": device.name, "host": device.host, "type": device.device_type, "site": device.site,
            **parse(fam, text), "collected": datetime.now().isoformat(timespec="minutes")}


def warnings(p: dict, life: dict) -> list[str]:
    out = []
    for key, label in (("warranty_until", "გარანტია"), ("eol", "მხარდაჭერის დასრულება (EoL)")):
        left = _days_left(life.get(key))
        if left is not None and left < 0:
            out.append(f"🔴 {label} დასრულდა ({life[key]})")
        elif left is not None and left <= 90:
            out.append(f"🟠 {label} {left} დღეში ({life[key]})")
    return out


def format_card(p: dict, life: dict) -> str:
    if "error" in p:
        return f"⚪ **{p['device']}** — {p['error']}"
    lines = [f"🪪 **{p['device']}** ({p['host']}{', ' + p['site'] if p.get('site') else ''})"]
    for key, label in (("model", "მოდელი"), ("serial", "სერიული"), ("version", "OS"), ("firmware", "firmware"),
                       ("uptime", "uptime")):
        if p.get(key):
            lines.append(f"  {label}: {p[key]}")
    for key, label in (("purchased", "შეძენა"), ("warranty_until", "გარანტია"), ("eol", "EoL"), ("vendor_support", "მხარდაჭერა")):
        if life.get(key):
            lines.append(f"  {label}: {life[key]}")
    lines += [f"  {w}" for w in warnings(p, life)]
    return "\n".join(lines)


def passport_cmd(s, args, user) -> Result:
    inv = s.inventory()
    excel = bool(args) and args[0].lower() in {"excel", "xlsx"}
    rest = args[1:] if excel else args
    devices = inv.filter(rest[0]) if rest else list(inv.devices.values())
    if not devices:
        raise CommandError("მოწყობილობა ვერ მოიძებნა")
    results = dev.run_on_devices(inv, devices, lambda d: collect(inv, d))
    life = lifecycle()
    cards = [r if isinstance(r, dict) else {"device": n, "error": str(r)} for n, r in results.items()]
    s.state.set("passports", {c["device"]: c for c in cards if "error" not in c})
    if excel:
        cols = ["device", "host", "site", "type", "model", "serial", "version", "uptime", "purchased", "warranty_until", "eol"]
        rows = [[c.get(k, "") if k not in {"purchased", "warranty_until", "eol"} else str(life.get(c["device"], {}).get(k, "") or "")
                 for k in cols] for c in cards]
        path = write_xlsx(settings.export_dir, "passport.xlsx", [{"name": "Devices", "columns": cols, "rows": rows}])
        return Result(f"🪪 მოწყობილობების პასპორტი: {len(cards)} მოწყობილობა", files=[path])
    return Result("\n\n".join(format_card(c, life.get(c["device"], {})) for c in cards))


COMMANDS = {"passport": passport_cmd}
HELP = ["/passport — მოდელი, სერიული, OS, გარანტია/EoL · /passport excel"]
BOT_COMMANDS = [("passport", "მოწყობილობების პასპორტი")]
TOOLS = [({
    "name": "device_passport",
    "description": "Hardware/software passport of devices: model, serial number, OS version, firmware, uptime and the "
                   "lifecycle dates from the inventory (purchased, warranty_until, eol). Use for asset questions, "
                   "'which devices are out of warranty', 'serial of R1'.",
    "input_schema": {"type": "object", "properties": {"filter": {"type": "string"}}, "required": []},
}, lambda ctx, filter="": [dict(collect(ctx.inventory, d), lifecycle=lifecycle().get(d.name, {}))
                           for d in ctx.inventory.filter(filter)])]
