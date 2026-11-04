"""Path trace: which devices does traffic from A to B cross, and where does it stop?

Starts on the device whose connected network holds the source, then follows each hop's
forwarding decision (Cisco `show ip cef <dst>`, MikroTik `/ip route print where <dst> in
dst-address`, Junos `show route <dst> active-path`) to the device that owns the next hop.
Read-only, nothing is sent to the destination.
"""

from __future__ import annotations

import ipaddress
import re

from ..result import CommandError, Result
from ..tools import device as dev
from ..watch import family

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
MAX_HOPS = 12


def parse_cef(text: str) -> dict:
    prefix = re.search(rf"^({_IP}/\d+)", text, re.M)
    res = {"prefix": prefix.group(1) if prefix else None}
    if m := re.search(rf"nexthop ({_IP})\s+(\S+)", text):
        res.update(kind="nexthop", nexthop=m.group(1), interface=m.group(2))
    elif m := re.search(r"attached to (\S+)", text):
        res.update(kind="attached", interface=m.group(1))
    elif "receive" in text:
        res.update(kind="receive")
    else:
        res.update(kind="none")
    return res


def parse_mikrotik_routes(text: str, dst: str) -> dict:
    best = None
    for line in text.splitlines():
        m = re.match(rf"^\s*\d*\s*([A-Za-z+]*)\s+({_IP}/\d+)\s+(\S+)", line)
        if not m or "A" not in m.group(1):
            continue
        net = ipaddress.ip_network(m.group(2), strict=False)
        if ipaddress.ip_address(dst) in net and (best is None or net.prefixlen > best[0].prefixlen):
            best = (net, m.group(3))
    if best is None:
        return {"prefix": None, "kind": "none"}
    gw = best[1]
    if re.fullmatch(_IP, gw):
        return {"prefix": str(best[0]), "kind": "nexthop", "nexthop": gw}
    return {"prefix": str(best[0]), "kind": "attached", "interface": gw}


def parse_junos_route(text: str) -> dict:
    prefix = re.search(rf"({_IP}/\d+)", text)
    res = {"prefix": prefix.group(1) if prefix else None}
    if m := re.search(rf">\s*to ({_IP}) via (\S+)", text):
        res.update(kind="nexthop", nexthop=m.group(1), interface=m.group(2))
    elif m := re.search(r"(?:Direct|Local).*?via (\S+)", text, re.S):
        res.update(kind="attached", interface=m.group(1))
    else:
        res.update(kind="none")
    return res


def lookup(inventory, device, dst: str) -> dict:
    fam = family(device.device_type)
    if fam in {"ios", "arista"}:
        cmd, parser = f"show ip cef {dst}", parse_cef
    elif fam == "nxos":
        cmd, parser = f"show ip route {dst}", lambda t: parse_cef(t.replace("*via", "nexthop").replace(", ", " "))
    elif fam == "mikrotik":
        cmd, parser = f"/ip route print where {dst} in dst-address", lambda t: parse_mikrotik_routes(t, dst)
    elif fam == "junos":
        cmd, parser = f"show route {dst} active-path", parse_junos_route
    else:
        return {"kind": "unsupported"}
    r = dev.run_commands(inventory, device, [cmd], parse=False, max_chars=None)[0]
    if "error" in r and not r.get("output"):
        return {"kind": "error", "error": r["error"]}
    return parser(r.get("output", ""))


def owned_ips(inventory) -> dict[str, str]:
    """{interface IP: device name} for the whole inventory."""

    def one(d):
        cmds = dev.commands_for(d, "ip_addresses") or []
        res = dev.run_commands(inventory, d, cmds, parse=False, max_chars=None) if cmds else []
        text = "\n".join(r.get("output", "") for r in res)
        return [ip for ip in re.findall(rf"\b({_IP})(?:/\d+)?\b", text) if not ip.startswith(("255.", "0."))]

    out: dict[str, str] = {}
    for name, ips in dev.run_on_devices(inventory, list(inventory.devices.values()), one).items():
        if isinstance(ips, list):
            for ip in ips:
                out.setdefault(ip, name)
    for d in inventory.devices.values():
        out.setdefault(d.host, d.name)
    return out


def trace(inventory, source: str, destination: str) -> dict:
    try:
        ipaddress.ip_address(source)
        ipaddress.ip_address(destination)
    except ValueError:
        raise CommandError("source და destination უნდა იყოს IP მისამართები") from None
    owners = owned_ips(inventory)
    start = owners.get(source)
    if start is None:
        firsts = dev.run_on_devices(inventory, list(inventory.devices.values()), lambda d: lookup(inventory, d, source))
        start = next((n for n, r in firsts.items() if isinstance(r, dict) and r.get("kind") == "attached"), None)
    if start is None:
        return {"source": source, "destination": destination, "hops": [],
                "result": "ვერ ვიპოვე მოწყობილობა, რომელსაც source ქსელი პირდაპირ აქვს მიერთებული"}
    hops, seen, cur = [], set(), start
    result = ""
    while len(hops) < MAX_HOPS:
        seen.add(cur)
        r = lookup(inventory, inventory.get(cur), destination)
        hops.append({"device": cur, **r})
        if owners.get(destination) == cur or r["kind"] == "receive":
            result = f"✅ მიზანი თვითონ {cur}-ია"
            break
        if r["kind"] == "attached":
            result = f"✅ მიზანი პირდაპირ არის მიერთებული {cur}-ზე ({r.get('interface')})"
            break
        if r["kind"] != "nexthop":
            result = f"⛔ {cur}-ზე {destination}-მდე route არ არის" if r["kind"] == "none" else \
                f"⚠️ {cur}: {r.get('error') or 'ამ პლატფორმაზე ჯერ არ არის მხარდაჭერილი'}"
            break
        nxt = owners.get(r["nexthop"])
        if nxt is None:
            result = f"➡️ ტრაფიკი inventory-ს ტოვებს {cur}-იდან: next hop {r['nexthop']} ({r.get('interface', '')})" + \
                (" — ინტერნეტი/ISP" if r.get("prefix") == "0.0.0.0/0" else "")
            break
        if nxt in seen:
            hops.append({"device": nxt, "kind": "loop"})
            result = f"🔁 routing loop: {cur} → {nxt}"
            break
        cur = nxt
    return {"source": source, "destination": destination, "hops": hops, "result": result}


def format_trace(t: dict) -> str:
    lines = [f"🧭 **{t['source']} → {t['destination']}**"]
    for i, h in enumerate(t["hops"], 1):
        how = {"nexthop": f"via {h.get('nexthop')} {h.get('interface', '')}".rstrip(), "attached": f"attached {h.get('interface', '')}",
               "receive": "local", "none": "route არ არის", "loop": "loop!"}.get(h["kind"], h.get("error", h["kind"]))
        lines.append(f"{i}. **{h['device']}**" + (f" — {h['prefix']}" if h.get("prefix") else "") + f" → {how}")
    lines.append(t["result"])
    return "\n".join(lines)


def path_cmd(s, args, user) -> Result:
    if len(args) != 2:
        raise CommandError("გამოყენება: /path 192.168.10.21 8.8.8.8")
    return Result(format_trace(trace(s.inventory(), args[0], args[1])))


COMMANDS = {"path": path_cmd}
HELP = ["/path 192.168.10.21 8.8.8.8 — რომელ მოწყობილობებზე გადის ტრაფიკი"]
BOT_COMMANDS = [("path", "ტრაფიკის გზა A-დან B-მდე")]
TOOLS = [({
    "name": "path_trace",
    "description": "Follow the forwarding path from a source IP to a destination IP through the inventory devices "
                   "(hop by hop, using each router's forwarding table): which devices, which interfaces, and where it "
                   "stops (no route, loop, leaves to the ISP). Read-only.",
    "input_schema": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}},
                     "required": ["source", "destination"]},
}, lambda ctx, source, destination: trace(ctx.inventory, source, destination))]
