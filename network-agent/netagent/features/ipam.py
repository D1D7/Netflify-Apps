"""IPAM: who owns which IP. Names/notes you assign + what NetAgent has seen (ARP, LAN scans, inventory).

    /ip 192.168.1.50                  what is this address
    /ip 192.168.1.50 პრინტერი 2 სართული   name it
    /ip 192.168.1.50 -                remove the name
    /ipam add 192.168.1.0/24 ოფისი vlan 10
    /ipam 192.168.1.0/24              used / free addresses
    /ipam excel
"""

from __future__ import annotations

import ipaddress
from datetime import datetime

from ..config import settings
from ..export import write_xlsx
from ..result import Button, CommandError, Result

KEY = "ipam"


def data(state) -> dict:
    d = state.get(KEY) or {}
    d.setdefault("addresses", {})
    d.setdefault("subnets", [])
    return d


def seen(s) -> dict[str, dict]:
    """Everything NetAgent knows about addresses without asking any device."""
    out: dict[str, dict] = {}
    for key in ("known_macs", "home_known_macs"):
        for mac, e in (s.state.get(key) or {}).items():
            ip = e.get("ip")
            if ip:
                out.setdefault(ip, {}).update(mac=mac, vendor=e.get("vendor", ""), seen_on=e.get("seen_on", ""),
                                              last_seen=e.get("last_seen", ""))
    scan = s.state.get("home_last_scan") or {}
    for e in scan.get("devices", []):
        out.setdefault(e["ip"], {}).update({k: e[k] for k in ("mac", "vendor", "kind") if e.get(k)},
                                           hostname=e.get("name", ""), last_seen=scan.get("scanned_at", ""))
    try:
        for d in s.inventory().devices.values():
            out.setdefault(d.host, {})["device"] = d.name
    except Exception:  # noqa: BLE001
        pass
    return out


def info(s, ip: str) -> dict:
    ipaddress.ip_address(ip)
    d = data(s.state)
    res = {"ip": ip, **seen(s).get(ip, {}), **d["addresses"].get(ip, {})}
    subnet = next((x for x in d["subnets"] if ipaddress.ip_address(ip) in ipaddress.ip_network(x["cidr"])), None)
    if subnet:
        res["subnet"] = subnet
    return res


def set_name(s, ip: str, name: str, note: str, user: str) -> None:
    ipaddress.ip_address(ip)

    def upd(v):
        v = v or {"addresses": {}, "subnets": []}
        v.setdefault("addresses", {})
        if name in {"-", ""}:
            v["addresses"].pop(ip, None)
        else:
            v["addresses"][ip] = {"name": name[:60], "note": note[:200], "updated": datetime.now().isoformat(timespec="minutes"), "by": user}
        return v

    s.state.update(KEY, upd)


def usage(s, cidr: str) -> dict:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > 4096:
        raise CommandError("ქსელი ძალიან დიდია (მაქს. /20)")
    known = seen(s)
    names = data(s.state)["addresses"]
    used = {}
    for ip in set(known) | set(names):
        try:
            if ipaddress.ip_address(ip) in net:
                used[ip] = {**known.get(ip, {}), **names.get(ip, {})}
        except ValueError:
            continue
    hosts = [str(h) for h in net.hosts()]
    free = [h for h in hosts if h not in used]
    return {"network": str(net), "total": len(hosts), "used": len(used), "free": len(free),
            "first_free": free[:10], "addresses": dict(sorted(used.items(), key=lambda kv: ipaddress.ip_address(kv[0])))}


def _describe(e: dict) -> str:
    bits = [e.get("name"), e.get("device") and f"📟 {e['device']}", e.get("kind"), e.get("vendor"), e.get("hostname")]
    return " · ".join(b for b in bits if b) or "—"


def ip_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /ip 192.168.1.50 · /ip 192.168.1.50 სახელი შენიშვნა · /ip 192.168.1.50 -")
    ip = args[0]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise CommandError("არასწორი IP მისამართი") from None
    if len(args) > 1:
        set_name(s, ip, args[1], " ".join(args[2:]), user)
        return Result(f"🏷 {ip} → {args[1]}" if args[1] != "-" else f"🗑 {ip}-ის სახელი წაიშალა")
    e = info(s, ip)
    lines = [f"🏷 **{ip}** — {_describe(e)}"]
    if e.get("note"):
        lines.append(f"📝 {e['note']}")
    if e.get("mac"):
        lines.append(f"MAC: `{e['mac']}`" + (f" · ნანახია: {e.get('seen_on')}" if e.get("seen_on") else ""))
    if e.get("last_seen"):
        lines.append(f"ბოლოს: {e['last_seen'][:16].replace('T', ' ')}")
    if e.get("subnet"):
        lines.append(f"ქსელი: {e['subnet']['cidr']} {e['subnet'].get('name', '')}")
    if len(lines) == 1 and "name" not in e:
        lines.append("NetAgent-ს ეს მისამართი ჯერ არ უნახავს. სცადე /scan ან ჰკითხე AI-ს „სადაა 192.168.1.50?“")
    return Result("\n".join(lines))


def ipam_cmd(s, args, user) -> Result:
    d = data(s.state)
    if args and args[0] == "add" and len(args) >= 2:
        net = ipaddress.ip_network(args[1], strict=False)
        rest = args[2:]
        vlan = rest[rest.index("vlan") + 1] if "vlan" in rest and rest.index("vlan") + 1 < len(rest) else ""
        name = " ".join(x for i, x in enumerate(rest) if x != "vlan" and not (i > 0 and rest[i - 1] == "vlan"))
        s.state.update(KEY, lambda v: {**data_from(v), "subnets": [x for x in data_from(v)["subnets"] if x["cidr"] != str(net)]
                                       + [{"cidr": str(net), "name": name, "vlan": vlan}]})
        return Result(f"✅ ქსელი დაემატა: {net} {name}" + (f" (VLAN {vlan})" if vlan else ""))
    if args and args[0] in {"del", "rm"} and len(args) == 2:
        s.state.update(KEY, lambda v: {**data_from(v), "subnets": [x for x in data_from(v)["subnets"] if x["cidr"] != args[1]]})
        return Result(f"🗑 {args[1]} წაიშალა")
    if args and args[0] in {"excel", "xlsx"}:
        sheets = []
        for sub in d["subnets"] or [{"cidr": "", "name": "ყველა"}]:
            u = usage(s, sub["cidr"]) if sub["cidr"] else {"addresses": {**seen(s), **d["addresses"]}}
            rows = [[ip, e.get("name", ""), e.get("note", ""), e.get("device", ""), e.get("mac", ""), e.get("vendor", ""),
                     e.get("kind", ""), e.get("last_seen", "")] for ip, e in u["addresses"].items()]
            sheets.append({"name": sub.get("name") or sub["cidr"].replace("/", "_"),
                           "columns": ["IP", "სახელი", "შენიშვნა", "მოწყობილობა", "MAC", "მწარმოებელი", "ტიპი", "ბოლოს"], "rows": rows})
        path = write_xlsx(settings.export_dir, "ipam.xlsx", sheets[:20])
        return Result("📑 IPAM ექსპორტი", files=[path])
    if args:
        u = usage(s, args[0])
        lines = [f"📑 **{u['network']}** — დაკავებული {u['used']} / {u['total']}, თავისუფალი {u['free']}"]
        lines += [f"• {ip} — {_describe(e)}" for ip, e in list(u["addresses"].items())[:40]]
        if u["first_free"]:
            lines.append("🆓 პირველი თავისუფალი: " + ", ".join(u["first_free"][:6]))
        lines.append("ℹ️ „დაკავებული“ = რაც NetAgent-მა ნახა (ARP, /scan) ან შენ დაარქვი სახელი.")
        return Result("\n".join(lines))
    if not d["subnets"]:
        return Result("📑 ქსელები ჯერ არ არის. დამატება: /ipam add 192.168.1.0/24 ოფისი vlan 10\nან ნახე: /ipam 192.168.1.0/24")
    lines = ["📑 **IPAM**"]
    for sub in d["subnets"]:
        u = usage(s, sub["cidr"])
        pct = round(100 * u["used"] / u["total"]) if u["total"] else 0
        lines.append(f"• {sub['cidr']} {sub.get('name', '')}" + (f" (VLAN {sub['vlan']})" if sub.get("vlan") else "")
                     + f" — {u['used']}/{u['total']} ({pct}%)")
    return Result("\n".join(lines), buttons=[Button(sub["cidr"], f"/ipam {sub['cidr']}") for sub in d["subnets"][:5]]
                  + [Button("📑 Excel", "/ipam excel")])


def data_from(v) -> dict:
    v = dict(v or {})
    v.setdefault("addresses", {})
    v.setdefault("subnets", [])
    return v


COMMANDS = {"ip": ip_cmd, "ipam": ipam_cmd}
HELP = ["/ip 192.168.1.50 — ვისია IP (/ip IP სახელი — დარქმევა) · /ipam — ქსელები და თავისუფალი IP-ები · /ipam excel"]
BOT_COMMANDS = [("ipam", "IP მისამართების მართვა")]
TOOLS = [
    ({"name": "ipam_lookup",
      "description": "IP address management: what NetAgent knows about an IP (assigned name/note, MAC, vendor, where it "
                     "was seen, inventory device) or, for a CIDR, which addresses are used/free. No device access.",
      "input_schema": {"type": "object", "properties": {"query": {"type": "string", "description": "IP or CIDR"}},
                       "required": ["query"]}},
     lambda ctx, query: usage(ctx.services, query) if "/" in query else info(ctx.services, query)),
    ({"name": "ipam_set",
      "description": "Give an IP address a name and note in IPAM (e.g. 'printer 2nd floor'). name '-' removes it. "
                     "Only when the user asks to name/record an address.",
      "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}, "name": {"type": "string"},
                                                        "note": {"type": "string"}}, "required": ["ip", "name"]}},
     lambda ctx, ip, name, note="": set_name(ctx.services, ip, name, note, ctx.user) or {"ok": True}),
]
