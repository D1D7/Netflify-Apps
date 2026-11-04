"""Golden config: what every device of a kind must (and must not) have in its configuration.

Rules come from inventory/golden.yaml (see golden.example.yaml); without it built-in
defaults apply. Each rule is a regular expression searched line by line in the config.

    cisco_ios:                       # device_type (or "all", "role:access-switch", "site:HQ")
      required:
        - name: NTP
          pattern: '^ntp server '
      forbidden:
        - name: Telnet on VTY
          pattern: 'transport input .*telnet'
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..backup import BackupStore, fetch_config
from ..config import settings
from ..result import CommandError, Result
from ..tools import device as dev

DEFAULT_RULES = {
    "cisco_ios": {
        "required": [
            {"name": "NTP სერვერი", "pattern": r"^ntp server "},
            {"name": "გარე syslog", "pattern": r"^logging (host )?\d"},
            {"name": "service password-encryption", "pattern": r"^service password-encryption"},
            {"name": "SSH v2", "pattern": r"^ip ssh version 2"},
            {"name": "login banner", "pattern": r"^banner (login|motd)"},
            {"name": "VTY exec-timeout ან access-class", "pattern": r"^ (exec-timeout [1-9]|access-class )"},
        ],
        "forbidden": [
            {"name": "Telnet VTY-ზე", "pattern": r"transport input .*telnet"},
            {"name": "HTTP სერვერი", "pattern": r"^ip http server"},
            {"name": "SNMP public/private", "pattern": r"^snmp-server community (public|private)\b"},
            {"name": "enable password (არა secret)", "pattern": r"^enable password "},
        ],
    },
    "mikrotik_routeros": {
        "required": [
            {"name": "NTP კლიენტი", "pattern": r"^/system ntp client|^set enabled=yes.*servers=|ntp"},
            {"name": "გარე syslog", "pattern": r"target=remote|remote="},
        ],
        "forbidden": [
            {"name": "DNS გარე მოთხოვნებისთვის ღია", "pattern": r"allow-remote-requests=yes"},
        ],
    },
}


def load_rules(path: Path | None = None) -> dict:
    path = path or settings.inventory_path.parent / "golden.yaml"
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise CommandError("golden.yaml-ის ფორმატი არასწორია")
        return data
    return DEFAULT_RULES


def rules_for(device, rules: dict) -> list[tuple[str, dict]]:
    keys = ["all", device.device_type, f"role:{device.role}", f"site:{device.site}"]
    if device.device_type in {"cisco_xe", "cisco_ios_telnet"}:
        keys.append("cisco_ios")
    out = []
    for k in keys:
        section = rules.get(k) or {}
        for kind in ("required", "forbidden"):
            for r in section.get(kind, []) or []:
                rule = r if isinstance(r, dict) else {"name": str(r), "pattern": re.escape(str(r))}
                out.append((kind, rule))
    return out


def check_config(config: str, rules: list[tuple[str, dict]]) -> dict:
    missing, present = [], []
    for kind, rule in rules:
        try:
            found = re.search(rule["pattern"], config, re.M | re.I)
        except re.error as exc:
            raise CommandError(f"არასწორი regex '{rule['pattern']}': {exc}") from None
        if kind == "required" and not found:
            missing.append(rule["name"])
        elif kind == "forbidden" and found:
            present.append(f"{rule['name']} — `{found.group(0).strip()[:60]}`")
    total = len(rules)
    ok = total - len(missing) - len(present)
    return {"missing": missing, "forbidden": present, "score": round(100 * ok / total) if total else 100, "rules": total}


def check_device(inventory, device, use_backup: bool = True) -> dict:
    rules = rules_for(device, load_rules())
    if not rules:
        return {"device": device.name, "skipped": "ამ ტიპისთვის წესები არ არის (golden.yaml)"}
    store = BackupStore(settings.backup_dir)
    snap = store.latest(device.name) if use_backup else None
    config = snap.read() if snap else fetch_config(inventory, device)
    return {"device": device.name, "source": "backup" if snap else "live", **check_config(config, rules)}


def format_result(r: dict) -> str:
    if "skipped" in r:
        return f"⚪ **{r['device']}** — {r['skipped']}"
    if not r["missing"] and not r["forbidden"]:
        return f"✅ **{r['device']}** — სტანდარტს შეესაბამება ({r['rules']} წესი)"
    lines = [f"{'🟠' if r['score'] >= 70 else '🔴'} **{r['device']}** — {r['score']}%"]
    lines += [f"  ➕ აკლია: {m}" for m in r["missing"]]
    lines += [f"  ⛔ არ უნდა იყოს: {f}" for f in r["forbidden"]]
    return "\n".join(lines)


def golden_cmd(s, args, user) -> Result:
    inv = s.inventory()
    live = "live" in args
    args = [a for a in args if a != "live"]
    devices = inv.filter(args[0]) if args else list(inv.devices.values())
    if not devices:
        raise CommandError("მოწყობილობა ვერ მოიძებნა")
    results = dev.run_on_devices(inv, devices, lambda d: check_device(inv, d, use_backup=not live))
    parts = [format_result(r) if isinstance(r, dict) else f"⚪ **{n}** — {r}" for n, r in results.items()]
    src = "inventory/golden.yaml" if (settings.inventory_path.parent / "golden.yaml").exists() else "ნაგულისხმევი წესები"
    return Result(f"📐 **სტანდარტული კონფიგურაცია** ({src})\n\n" + "\n".join(parts)
                  + "\n\nგამოსასწორებელი ბრძანებებისთვის ჰკითხე AI-ს: „როგორ გავასწორო R1 golden-ის მიხედვით?“")


COMMANDS = {"golden": golden_cmd}
HELP = ["/golden — შეესაბამება თუ არა config-ები სტანდარტს (inventory/golden.yaml)"]
TOOLS = [({
    "name": "golden_config_check",
    "description": "Compare device configs with the organisation's standard (inventory/golden.yaml or built-in "
                   "defaults): which required lines are missing and which forbidden ones are present, with a score.",
    "input_schema": {"type": "object", "properties": {"filter": {"type": "string"}}, "required": []},
}, lambda ctx, filter="": [check_device(ctx.inventory, d) for d in ctx.inventory.filter(filter)])]
