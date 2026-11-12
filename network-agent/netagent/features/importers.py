"""Import devices into the inventory from NetBox or Zabbix (read-only API calls).

    .env:  NETBOX_URL=https://netbox.local   NETBOX_TOKEN=...
           ZABBIX_URL=https://zabbix.local/api_jsonrpc.php   ZABBIX_TOKEN=...
    /import netbox [credentials]   → preview, then ➕ add
    /import zabbix [credentials]
Devices whose platform cannot be mapped to a Netmiko type are listed and skipped.
"""

from __future__ import annotations

import os
import re
import secrets

from ..config import settings
from ..result import Button, CommandError, Result

PLATFORM_MAP = [
    (r"ios[-_ ]?xe|iosxe", "cisco_xe"), (r"nx[-_ ]?os|nexus", "cisco_nxos"), (r"ios[-_ ]?xr|iosxr", "cisco_xr"),
    (r"\basa\b", "cisco_asa"), (r"\bios\b|cisco", "cisco_ios"), (r"junos|juniper", "juniper_junos"),
    (r"eos|arista", "arista_eos"), (r"routeros|mikrotik", "mikrotik_routeros"), (r"fortios|fortinet|fortigate", "fortinet"),
    (r"pan[-_ ]?os|palo", "paloalto_panos"), (r"vyos", "vyos"), (r"edgeos|edgerouter", "ubiquiti_edgerouter"),
    (r"huawei|vrp", "huawei"), (r"comware|h3c", "hp_comware"), (r"procurve|arubaos[-_ ]?switch", "hp_procurve"),
    (r"aos[-_ ]?cx|aruba", "aruba_aoscx"), (r"os10|dell", "dell_os10"), (r"linux|ubuntu|debian", "linux"),
]
_PENDING: dict[str, tuple[list[dict], str]] = {}


def map_platform(text: str) -> str | None:
    t = (text or "").lower()
    for pat, dt in PLATFORM_MAP:
        if re.search(pat, t):
            return dt
    return None


def _name(n: str) -> str:
    return re.sub(r"[^\w.-]", "-", n.strip())[:60] or "device"


def from_netbox(fetch=None) -> tuple[list[dict], list[str]]:
    url, token = os.getenv("NETBOX_URL", "").rstrip("/"), os.getenv("NETBOX_TOKEN", "")
    if not url or not token:
        raise CommandError("NetBox: .env-ში მიუთითე NETBOX_URL და NETBOX_TOKEN (read-only token საკმარისია)")
    if fetch is None:
        import httpx

        def fetch(path):
            items, nxt = [], f"{url}{path}"
            while nxt:
                r = httpx.get(nxt, headers={"Authorization": f"Token {token}", "Accept": "application/json"}, timeout=30)
                r.raise_for_status()
                data = r.json()
                items += data.get("results", [])
                nxt = data.get("next")
            return items
    found, skipped = [], []
    for d in fetch("/api/dcim/devices/?limit=500&has_primary_ip=true"):
        ip = ((d.get("primary_ip4") or d.get("primary_ip") or {}).get("address") or "").split("/")[0]
        platform = d.get("platform") or {}
        dt = map_platform(f"{platform.get('slug', '')} {platform.get('name', '')}")
        name = _name(d.get("name") or ip)
        role = (d.get("role") or d.get("device_role") or {}).get("name", "")
        if not ip or not dt:
            skipped.append(f"{name} ({'IP არ არის' if not ip else 'platform: ' + (platform.get('name') or '—')})")
            continue
        found.append({"name": name, "host": ip, "device_type": dt, "site": (d.get("site") or {}).get("name", ""), "role": role})
    return found, skipped


def from_zabbix(rpc=None) -> tuple[list[dict], list[str]]:
    url, token = os.getenv("ZABBIX_URL", ""), os.getenv("ZABBIX_TOKEN", "")
    if not url or not token:
        raise CommandError("Zabbix: .env-ში მიუთითე ZABBIX_URL (…/api_jsonrpc.php) და ZABBIX_TOKEN")
    if rpc is None:
        import httpx

        def rpc(method, params):
            r = httpx.post(url, json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
                           headers={"Authorization": f"Bearer {token}"}, timeout=30)
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                raise CommandError(f"Zabbix: {data['error'].get('data') or data['error'].get('message')}")
            return data["result"]
    hosts = rpc("host.get", {"output": ["host", "name"], "selectInterfaces": ["ip", "main", "type"],
                             "selectInventory": ["os", "type", "hardware", "location"], "selectTags": "extend",
                             "selectHostGroups": ["name"]})
    found, skipped = [], []
    for h in hosts:
        ifs = [i for i in h.get("interfaces", []) if i.get("ip")]
        ip = next((i["ip"] for i in ifs if str(i.get("main")) == "1"), ifs[0]["ip"] if ifs else "")
        tags = {t.get("tag"): t.get("value") for t in h.get("tags", [])}
        inv = h.get("inventory") or {}
        dt = tags.get("netagent_type") or map_platform(" ".join([inv.get("os", ""), inv.get("type", ""), inv.get("hardware", "")]))
        name = _name(h.get("name") or h.get("host") or ip)
        if not ip or not dt:
            skipped.append(f"{name} ({'IP არ არის' if not ip else 'OS უცნობია — დაამატე tag netagent_type'})")
            continue
        groups = [g.get("name", "") for g in h.get("hostgroups", h.get("groups", []))]
        found.append({"name": name, "host": ip, "device_type": dt, "site": inv.get("location") or (groups[0] if groups else ""), "role": ""})
    return found, skipped


def add_devices(devices: list[dict], credentials: str) -> list[str]:
    import yaml

    path = settings.inventory_path
    text = path.read_text(encoding="utf-8") if path.exists() else "devices:\n"
    data = yaml.safe_load(text) or {}
    existing = data.get("devices") or {}
    taken = {n.lower() for n in existing}
    hosts = {str(v.get("host")) for v in existing.values() if isinstance(v, dict)}
    new = {}
    for d in devices:
        if d["host"] in hosts:
            continue
        name, i = d["name"], 2
        while name.lower() in taken:
            name, i = f"{d['name']}-{i}", i + 1
        taken.add(name.lower())
        entry = {"host": d["host"], "device_type": d["device_type"]}
        if credentials != "default":
            entry["credentials"] = credentials
        for k in ("site", "role"):
            if d.get(k):
                entry[k] = d[k]
        new[name] = entry
    if not new:
        return []
    if re.search(r"^devices:\s*\{\s*\}\s*$", text, re.M):
        text = re.sub(r"^devices:\s*\{\s*\}\s*$", "devices:", text, flags=re.M)
    keys = re.findall(r"^([A-Za-z_][\w-]*):", text, re.M)
    if keys and keys[-1] == "devices":
        dumped = yaml.safe_dump(new, allow_unicode=True, sort_keys=False)
        text = text.rstrip("\n") + "\n  # imported\n" + "".join(f"  {ln}\n" for ln in dumped.splitlines())
        path.write_text(text, encoding="utf-8")
    else:
        path.with_suffix(".yaml.bak").write_text(text, encoding="utf-8")
        data.setdefault("devices", {}).update(new)
        path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return list(new)


def import_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /import netbox · /import zabbix (არასავალდებულო: credentials პროფილი)")
    if args[0] == "add" and len(args) == 2:
        pending = _PENDING.pop(args[1], None)
        if not pending:
            raise CommandError("ეს სია ვადაგასულია — გაუშვი /import ხელახლა")
        added = add_devices(*pending)
        return Result(f"✅ inventory-ში დაემატა {len(added)}: " + ", ".join(added[:30]) if added else "ახალი არაფერია (ყველა უკვე არის)")
    if args[0] == "cancel" and len(args) == 2:
        _PENDING.pop(args[1], None)
        return Result("გაუქმდა")
    source = args[0].lower()
    cred = args[1] if len(args) > 1 else "default"
    if source not in {"netbox", "zabbix"}:
        raise CommandError("წყარო: netbox ან zabbix")
    try:
        found, skipped = from_netbox() if source == "netbox" else from_zabbix()
    except CommandError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise CommandError(f"{source}: {type(exc).__name__}: {str(exc)[:200]}") from None
    known = {d.host for d in s.inventory().devices.values()} if settings.inventory_path.exists() else set()
    fresh = [d for d in found if d["host"] not in known]
    lines = [f"📥 **{source}**: ნაპოვნია {len(found)}, ახალი {len(fresh)}"]
    lines += [f"• {d['name']} — {d['host']} · {d['device_type']}" + (f" · {d['site']}" if d["site"] else "") for d in fresh[:25]]
    if skipped:
        lines.append(f"\n⚪ გამოტოვებული ({len(skipped)}): " + ", ".join(skipped[:10]))
    if not fresh:
        return Result("\n".join(lines))
    token = secrets.token_hex(4)
    _PENDING[token] = (fresh, cred)
    lines.append(f"\ncredentials: `{cred}` (შეცვლა: /import {source} <პროფილი>)")
    return Result("\n".join(lines), buttons=[Button(f"➕ დამატება ({len(fresh)})", f"/import add {token}"),
                                             Button("❌ არა", f"/import cancel {token}")])


COMMANDS = {"import": import_cmd}
HELP = ["/import netbox · /import zabbix — მოწყობილობების შემოტანა inventory-ში"]
