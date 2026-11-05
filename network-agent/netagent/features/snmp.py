"""SNMP v2c (read-only) for devices without SSH: printers, UPSes, cameras, NAS, old switches.

Inventory:
    credentials:
      snmp: {community_env: SNMP_COMMUNITY}
    devices:
      Printer-2F: {host: 192.168.1.40, device_type: snmp, credentials: snmp}
      UPS-1:      {host: 192.168.1.41, device_type: snmp, credentials: snmp}

/snmp Printer-2F (or /snmp 192.168.1.40) shows system info, interfaces, toner levels, UPS battery.
Reachability monitoring of `snmp` devices uses an SNMP query instead of a TCP port.
Alerts: toner/ink < 10 %, UPS on battery / battery low. Pure Python: no extra library.
"""

from __future__ import annotations

import os
import random
import socket
import time

import yaml

from ..config import settings
from ..result import CommandError, Result
from . import env_int

SYS = {"descr": "1.3.6.1.2.1.1.1.0", "uptime": "1.3.6.1.2.1.1.3.0", "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0"}
IF_DESCR, IF_OPER = "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.8"
PRT_DESC, PRT_MAX, PRT_LEVEL = "1.3.6.1.2.1.43.11.1.1.6", "1.3.6.1.2.1.43.11.1.1.8", "1.3.6.1.2.1.43.11.1.1.9"
UPS = {"battery_status": "1.3.6.1.2.1.33.1.2.1.0", "minutes_left": "1.3.6.1.2.1.33.1.2.3.0",
       "charge": "1.3.6.1.2.1.33.1.2.4.0", "output_source": "1.3.6.1.2.1.33.1.4.1.0"}
APC = {"charge": "1.3.6.1.4.1.318.1.1.1.2.2.1.0", "output_status": "1.3.6.1.4.1.318.1.1.1.4.1.1.0"}


# -- BER ---------------------------------------------------------------------------------------------
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _int(v: int) -> bytes:
    return _tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(chunk)
    return _tlv(0x06, out)


def encode_request(community: str, oids: list[str], request_id: int, pdu: int = 0xA0) -> bytes:
    varbinds = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
    body = _int(request_id) + _int(0) + _int(0) + _tlv(0x30, varbinds)
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + _tlv(pdu, body))


def _read(data: bytes, i: int) -> tuple[int, bytes, int]:
    tag = data[i]
    n = data[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(data[i:i + k], "big")
        i += k
    return tag, data[i:i + n], i + n


def _decode_oid(v: bytes) -> str:
    parts = [v[0] // 40, v[0] % 40]
    n = 0
    for b in v[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def _value(tag: int, v: bytes):
    if tag == 0x02:
        return int.from_bytes(v, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(v, "big")
    if tag == 0x04:
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex(":")
    if tag == 0x06:
        return _decode_oid(v)
    if tag == 0x40:
        return ".".join(str(b) for b in v)
    return None  # NULL, noSuchObject, noSuchInstance, endOfMibView


def decode_response(data: bytes) -> tuple[int, int, list[tuple[str, object, int]]]:
    _, msg, _ = _read(data, 0)
    _, _, i = _read(msg, 0)           # version
    _, _, i = _read(msg, i)           # community
    _, pdu, _ = _read(msg, i)
    _, rid, j = _read(pdu, 0)
    _, err, j = _read(pdu, j)
    _, _, j = _read(pdu, j)
    _, vbs, _ = _read(pdu, j)
    out, k = [], 0
    while k < len(vbs):
        _, vb, k = _read(vbs, k)
        _, oid, m = _read(vb, 0)
        tag, val, _ = _read(vb, m)
        out.append((_decode_oid(oid), _value(tag, val), tag))
    return int.from_bytes(rid, "big"), int.from_bytes(err, "big"), out


def request(host: str, community: str, oids: list[str], pdu: int = 0xA0, timeout: float = 2.0, retries: int = 1,
            port: int = 161) -> list[tuple[str, object, int]]:
    rid = random.randint(1, 2**31 - 1)
    packet = encode_request(community, oids, rid, pdu)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for _ in range(retries + 1):
            s.sendto(packet, (host, port))
            try:
                while True:
                    data, _ = s.recvfrom(65535)
                    got_id, err, vbs = decode_response(data)
                    if got_id == rid:
                        if err:
                            raise RuntimeError(f"SNMP error-status {err}")
                        return vbs
            except socket.timeout:
                continue
    raise TimeoutError("SNMP პასუხი არ მოვიდა (community, ACL ან UDP 161 შეამოწმე)")


def get(host: str, community: str, oids: list[str], **kw) -> dict[str, object]:
    return {o: v for o, v, tag in request(host, community, oids, **kw) if tag not in (0x80, 0x81, 0x82)}


def walk(host: str, community: str, base: str, limit: int = 300, **kw) -> dict[str, object]:
    out, cur = {}, base
    for _ in range(limit):
        vbs = request(host, community, [cur], pdu=0xA1, **kw)
        oid, val, tag = vbs[0]
        if tag == 0x82 or not oid.startswith(base + "."):
            break
        out[oid] = val
        cur = oid
    return out


# -- device level ------------------------------------------------------------------------------------
def community_for(device) -> str:
    try:
        data = yaml.safe_load(settings.inventory_path.read_text(encoding="utf-8")) or {}
        ref = (data.get("credentials") or {}).get(device.credentials) or {}
        env = ref.get("community_env")
        if env and os.getenv(env):
            return os.environ[env]
    except OSError:
        pass
    return os.getenv("SNMP_COMMUNITY", "public")


def ticks(v) -> str:
    from ..alerts import format_duration

    return format_duration(int(v) / 100) if isinstance(v, int) else "?"


def snmp_port(device) -> int:
    return device.port if device.port != 22 else 161


def query(host: str, community: str, port: int = 161) -> dict:
    kw = {"port": port}
    sysinfo = get(host, community, list(SYS.values()), **kw)
    res = {"host": host, **{k: sysinfo.get(o) for k, o in SYS.items()}}
    res["uptime"] = ticks(res["uptime"])
    try:
        descr = walk(host, community, IF_DESCR, limit=200, **kw)
        oper = walk(host, community, IF_OPER, limit=200, **kw)
        ifs = {}
        for oid, name in descr.items():
            idx = oid.rsplit(".", 1)[1]
            ifs[str(name)] = {1: "up", 2: "down"}.get(oper.get(f"{IF_OPER}.{idx}"), "other")
        res["interfaces"] = ifs
    except (TimeoutError, RuntimeError):
        res["interfaces"] = {}
    try:
        desc = walk(host, community, PRT_DESC, limit=30, **kw)
        if desc:
            mx = walk(host, community, PRT_MAX, limit=30, **kw)
            lv = walk(host, community, PRT_LEVEL, limit=30, **kw)
            supplies = []
            for oid, name in desc.items():
                suffix = oid[len(PRT_DESC):]
                m, level = mx.get(PRT_MAX + suffix), lv.get(PRT_LEVEL + suffix)
                pct = round(100 * level / m) if isinstance(m, int) and m > 0 and isinstance(level, int) and level >= 0 else None
                supplies.append({"name": str(name), "percent": pct})
            res["supplies"] = supplies
    except (TimeoutError, RuntimeError):
        pass
    ups = get(host, community, list(UPS.values()), **kw)
    if ups:
        res["ups"] = {k: ups.get(o) for k, o in UPS.items()}
        res["ups"]["on_battery"] = res["ups"].get("output_source") == 5
        res["ups"]["battery_low"] = res["ups"].get("battery_status") in (3, 4)
    else:
        apc = get(host, community, list(APC.values()), **kw)
        if apc:
            res["ups"] = {"charge": apc.get(APC["charge"]), "on_battery": apc.get(APC["output_status"]) == 3}
    return res


def format_query(name: str, r: dict) -> str:
    lines = [f"📟 **{name}** — {r.get('name') or r['host']}" + (f" · {r['location']}" if r.get("location") else "")]
    if r.get("descr"):
        lines.append(f"  {str(r['descr'])[:120]}")
    lines.append(f"  uptime: {r['uptime']}")
    if r.get("interfaces"):
        ups_ = [n for n, st in r["interfaces"].items() if st == "up"]
        lines.append(f"  ინტერფეისები: 🟢 {len(ups_)} up · 🔴 {sum(1 for s in r['interfaces'].values() if s == 'down')} down")
    for sup in r.get("supplies", []):
        p = sup["percent"]
        icon = "⚪" if p is None else "🔴" if p < 10 else "🟠" if p < 25 else "🟢"
        lines.append(f"  {icon} {sup['name']}: {'?' if p is None else str(p) + '%'}")
    if "ups" in r:
        u = r["ups"]
        lines.append(f"  🔋 UPS: {'⚡ ბატარეაზეა!' if u.get('on_battery') else 'ქსელიდან იკვებება'}"
                     + (f", დამუხტვა {u['charge']}%" if u.get("charge") is not None else "")
                     + (f", დარჩენილი ~{u['minutes_left']} წთ" if u.get("minutes_left") else "")
                     + (" — 🔴 ბატარეა დაბალია" if u.get("battery_low") else ""))
    return "\n".join(lines)


def probe_device(device) -> tuple[bool, float | None, str]:
    """Reachability for device_type: snmp (used by health.check_one)."""
    start = time.monotonic()
    try:
        get(device.host, community_for(device), [SYS["uptime"]], timeout=2.0, retries=1, port=snmp_port(device))
        return True, round((time.monotonic() - start) * 1000, 1), ""
    except Exception as exc:  # noqa: BLE001
        return False, None, str(exc)[:80] or type(exc).__name__


def snmp_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /snmp Printer-2F · /snmp 192.168.1.40 (community: SNMP_COMMUNITY .env-დან, ან public)")
    inv = s.inventory()
    if args[0] in inv.devices:
        d = inv.devices[args[0]]
        host, community, name, port = d.host, community_for(d), d.name, snmp_port(d)
    else:
        host, community, name, port = args[0], os.getenv("SNMP_COMMUNITY", "public"), args[0], 161
    try:
        r = query(host, community, port)
    except (TimeoutError, OSError, RuntimeError) as exc:
        raise CommandError(f"{name}: {exc}") from None
    return Result(format_query(name, r))


COMMANDS = {"snmp": snmp_cmd}
HELP = ["/snmp Printer-2F — SNMP: სისტემა, ინტერფეისები, ტონერი, UPS ბატარეა (SSH-ის გარეშე მოწყობილობებისთვის)"]
TOOLS = [({
    "name": "snmp_query",
    "description": "Read a device over SNMP v2c (read-only): sysDescr/name/uptime, interface up/down, printer "
                   "toner/ink levels, UPS battery and power source. For printers, UPSes, cameras and other devices "
                   "without SSH. `target` is an inventory name (device_type snmp) or an IP.",
    "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
}, lambda ctx, target: query(*((ctx.inventory.devices[target].host, community_for(ctx.inventory.devices[target]),
                                snmp_port(ctx.inventory.devices[target]))
                               if target in ctx.inventory.devices else (target, os.getenv("SNMP_COMMUNITY", "public")))))]


def jobs(monitoring):
    import asyncio

    from ..monitoring import Alert

    every = env_int("NETAGENT_SNMP_INTERVAL", 10)
    if every <= 0:
        return []
    sent: dict[str, float] = {}

    async def run():
        s = monitoring.s
        devices = [d for d in s.inventory().devices.values() if d.device_type == "snmp"]
        for d in devices:
            try:
                r = await asyncio.to_thread(query, d.host, community_for(d), snmp_port(d))
            except Exception:  # noqa: BLE001 - reachability alerts come from the normal monitor
                continue
            msgs = []
            for sup in r.get("supplies", []):
                if sup["percent"] is not None and sup["percent"] < 10:
                    msgs.append((f"{d.name}:{sup['name']}", f"🖨 **{d.name}**: {sup['name']} — {sup['percent']}% დარჩა", 86400))
            u = r.get("ups") or {}
            if u.get("on_battery"):
                msgs.append((f"{d.name}:battery", f"🔴 **{d.name}**: UPS ბატარეაზე გადავიდა — დენი არ არის"
                             + (f" (დარჩენილი ~{u['minutes_left']} წთ)" if u.get("minutes_left") else ""), 1800))
            elif sent.pop(f"{d.name}:battery", None):
                msgs.append((f"{d.name}:mains", f"🟢 **{d.name}**: დენი აღდგა, UPS ისევ ქსელიდან იკვებება", 0))
            if u.get("battery_low"):
                msgs.append((f"{d.name}:low", f"🔴 **{d.name}**: UPS-ის ბატარეა დაბალია", 3600))
            for key, text, cooldown in msgs:
                if time.time() - sent.get(key, 0) > cooldown:
                    sent[key] = time.time()
                    await monitoring.emit(Alert("watch", text, [d.name]))

    return [("snmp", every * 60, 110, run)]
