"""Who uses the internet: traffic per device, now and per day, named like in Live Devices.

Sources (any that exists):
  NetFlow / IPFIX  the router exports flows to this PC (see flows.py): download/upload per device, apps,
                   destinations. MikroTik, Cisco, OpenWrt (softflowd) and most business routers can.
  SNMP switch      a managed switch in devices.yaml with an SNMP community: bytes per port + its MAC table.
                   A port with exactly one device on it = that device's traffic (wired devices).
Usage is summed per device per day (31 days kept). A device using more than NETAGENT_HOG_GB_HOUR (default 5)
GB in an hour sends one alert a day.

  /bandwidth        the last 15 minutes      /bandwidth 60 · /bandwidth today · /bandwidth week
"""

from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict
from datetime import date

from ..result import Button, Result
from . import env_int

log = logging.getLogger("netagent.talkers")
DAILY_KEY = "usage_daily"   # {"2026-11-11": {"ip:192.168.1.5" | "mac:aa:bb..": [down, up]}}
KEEP_DAYS = 31

# SNMP (64-bit counters, names, bridge MAC table)
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_IN = "1.3.6.1.2.1.31.1.1.1.6"
IF_OUT = "1.3.6.1.2.1.31.1.1.1.10"
BRIDGE_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
QFDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"


# ---------------------------------------------------------------------------------------------------------
def live_names() -> dict:
    """ip -> {name, mac, icon, kind}, mac -> same; from Live Devices (empty if it is not running)."""
    out = {}
    try:
        from .livedevices import ENGINE

        if ENGINE is None:
            return out
        for r in ENGINE.snapshot()["devices"]:
            info = {"name": r["label"] or r["hostname"] or r["kind_label"] or r["vendor"] or r["ip"], "ip": r["ip"],
                    "mac": r["mac"] if r["mac"] != "N/A" else "", "icon": r["icon"], "self": r["self"]}
            out[f"ip:{r['ip']}"] = info
            if info["mac"]:
                out[f"mac:{info['mac'].lower()}"] = info
    except Exception:  # noqa: BLE001
        pass
    return out


def _mac_from_oid(suffix: str) -> str:
    parts = suffix.split(".")[-6:]
    return ":".join(f"{int(p):02x}" for p in parts) if len(parts) == 6 and all(p.isdigit() for p in parts) else ""


class SwitchPorts:
    """SNMP per-port byte counters and MAC table of managed switches; rates from the previous sample."""

    def __init__(self, walk=None):
        self.walk = walk
        self.prev: dict[str, tuple[float, dict]] = {}
        self.rates: dict[str, dict] = {}     # "mac:.." -> {"down": bps, "up": bps, "port": "SW1 Gi0/5"}
        self.deltas: dict[str, list] = {}    # bytes since the previous sample per device key: [down, up]

    def _walk(self, host, community, oid):
        if self.walk is not None:
            return self.walk(host, community, oid)
        from . import snmp

        return snmp.walk(host, community, oid, limit=2000)

    def sample(self, name: str, host: str, community: str, now: float | None = None) -> None:
        now = now or time.time()
        names = {k.rsplit(".", 1)[-1]: str(v) for k, v in self._walk(host, community, IF_NAME).items()}
        ins = {k.rsplit(".", 1)[-1]: int(v) for k, v in self._walk(host, community, IF_IN).items()}
        outs = {k.rsplit(".", 1)[-1]: int(v) for k, v in self._walk(host, community, IF_OUT).items()}
        bridge = {k.rsplit(".", 1)[-1]: str(v) for k, v in self._walk(host, community, BRIDGE_IFINDEX).items()}
        macs: dict[str, list[str]] = defaultdict(list)  # ifIndex -> MACs learned on it
        fdb = self._walk(host, community, FDB_PORT) or self._walk(host, community, QFDB_PORT)
        for oid, port in fdb.items():
            mac = _mac_from_oid(oid)
            ifx = bridge.get(str(port), str(port))
            if mac:
                macs[ifx].append(mac)
        last = self.prev.get(name)
        self.prev[name] = (now, {"in": ins, "out": outs})
        if not last:
            return
        dt = max(now - last[0], 1.0)
        for ifx, ms in macs.items():
            if len(ms) != 1:  # an uplink / a port with many devices: not one device's traffic
                continue
            d_in = ins.get(ifx, 0) - last[1]["in"].get(ifx, ins.get(ifx, 0))
            d_out = outs.get(ifx, 0) - last[1]["out"].get(ifx, outs.get(ifx, 0))
            if d_in < 0 or d_out < 0:  # counter reset
                continue
            key = f"mac:{ms[0]}"
            # switch "out" = towards the device = its download
            self.rates[key] = {"down": d_out * 8 / dt, "up": d_in * 8 / dt, "port": f"{name} {names.get(ifx, ifx)}", "ts": now}
            acc = self.deltas.setdefault(key, [0, 0])
            acc[0] += d_out
            acc[1] += d_in

    def take_deltas(self) -> dict:
        d, self.deltas = self.deltas, {}
        return d


PORTS = SwitchPorts()


def snmp_switches(inv) -> list[tuple[str, str, str]]:
    from . import snmp

    out = []
    for d in inv.devices.values():
        try:
            comm = snmp.community_for(d)
        except Exception:  # noqa: BLE001
            comm = ""
        if comm and ("switch" in (d.role or "").lower() or d.device_type == "snmp"):
            out.append((d.name, d.host, comm))
    return out


# ---------------------------------------------------------------------------------------------------------
def add_daily(state, per_device: dict, day: str | None = None) -> None:
    """per_device: {key: [down_bytes, up_bytes]} added to today's totals."""
    if not per_device:
        return
    day = day or date.today().isoformat()

    def fn(v):
        v = dict(v or {})
        today = dict(v.get(day) or {})
        for k, (dn, up) in per_device.items():
            cur = today.get(k) or [0, 0]
            today[k] = [cur[0] + int(dn), cur[1] + int(up)]
        v[day] = today
        for old in sorted(v)[:-KEEP_DAYS]:
            v.pop(old)
        return v

    state.update(DAILY_KEY, fn)


def flow_minute(minute: int) -> dict:
    """One finished minute of NetFlow as {ip:..: [down, up]}."""
    from .flows import STATS

    with STATS.lock:
        b = STATS.minutes.get(minute)
        if not b:
            return {}
        down, up = Counter(b.get("down", {})), Counter(b.get("up", {}))
    return {f"ip:{ip}": [down.get(ip, 0), up.get(ip, 0)] for ip in set(down) | set(up)}


def _name(key: str, names: dict) -> dict:
    info = names.get(key)
    if info:
        return info
    kind, _, val = key.partition(":")
    return {"name": val, "ip": val if kind == "ip" else "", "mac": val if kind == "mac" else "", "icon": "help", "self": False}


def report(state, period: str = "15", names: dict | None = None) -> dict:
    """Rows for the app: who, how much (bytes) and how fast (bps), with the source of the numbers."""
    from .flows import STATS, app_name

    names = live_names() if names is None else names
    rows: dict[str, dict] = {}

    def row(key):
        if key not in rows:
            info = _name(key, names)
            rows[key] = {"key": key, "name": info["name"], "ip": info["ip"], "mac": info["mac"], "icon": info.get("icon", "help"),
                         "self": info.get("self", False), "down": 0, "up": 0, "down_bps": 0.0, "up_bps": 0.0, "source": set()}
        return rows[key]

    apps: list = []
    if period in {"today", "week"}:
        days = 1 if period == "today" else 7
        daily = state.get(DAILY_KEY) or {}
        for d in sorted(daily)[-days:]:
            for k, (dn, up) in daily[d].items():
                r = row(k)
                r["down"] += dn
                r["up"] += up
                r["source"].add("daily")
    else:
        minutes = max(1, min(int(period) if str(period).isdigit() else 15, 24 * 60))
        w = STATS.window(minutes)
        secs = max(60, w["_meta"].get("minutes", 0) * 60)
        for ip, n in w.get("down", {}).items():
            r = row(f"ip:{ip}")
            r["down"] += n
            r["down_bps"] = n * 8 / secs
            r["source"].add("NetFlow")
        for ip, n in w.get("up", {}).items():
            r = row(f"ip:{ip}")
            r["up"] += n
            r["up_bps"] = n * 8 / secs
            r["source"].add("NetFlow")
        apps = [{"app": app_name(k), "bytes": n} for k, n in w.get("app", Counter()).most_common(6)]
        for key, rt in PORTS.rates.items():
            if time.time() - rt["ts"] < 300:
                r = row(key)
                r["down_bps"] = max(r["down_bps"], rt["down"])
                r["up_bps"] = max(r["up_bps"], rt["up"])
                r["port"] = rt["port"]
                r["source"].add("SNMP")
    # the same device seen by IP (NetFlow) and by MAC (switch): one row
    for key in [k for k in rows if k.startswith("mac:")]:
        ip = (names.get(key) or {}).get("ip")
        if ip and f"ip:{ip}" in rows:
            a, b = rows[f"ip:{ip}"], rows.pop(key)
            a["source"] |= b["source"]
            a["port"] = b.get("port", a.get("port"))
            if not a["down"] and not a["up"]:
                a["down"], a["up"] = b["down"], b["up"]
            a["down_bps"], a["up_bps"] = max(a["down_bps"], b["down_bps"]), max(a["up_bps"], b["up_bps"])
    out = sorted(rows.values(), key=lambda r: -(r["down"] + r["up"] + (r["down_bps"] + r["up_bps"]) / 8))
    for r in out:
        r["source"] = sorted(r["source"])
    sources = {"netflow": bool(STATS.exporters), "exporters": dict(STATS.exporters), "snmp": bool(PORTS.prev)}
    return {"period": period, "rows": out[:30], "apps": apps, "sources": sources,
            "total": sum(r["down"] + r["up"] for r in out), "hint": "" if sources["netflow"] or sources["snmp"] else setup_hint()}


def setup_hint() -> str:
    """How to get per-device numbers, for the router this network actually has."""
    vendor = ""
    try:
        from .livedevices import ENGINE

        if ENGINE is not None:
            gw = next((r for r in ENGINE.snapshot()["devices"] if r["gateway"]), None)
            vendor = (gw or {}).get("vendor", "").lower()
    except Exception:  # noqa: BLE001
        pass
    port = env_int("NETAGENT_FLOW_PORT", 2055)
    from .homenet import local_ip

    me = local_ip() or "<ამ კომპიუტერის IP>"
    if "mikrotik" in vendor or "routerboard" in vendor:
        return (f"შენი როუტერი MikroTik-ია — ჩართე Traffic Flow:\n/ip traffic-flow set enabled=yes interfaces=all\n"
                f"/ip traffic-flow target add dst-address={me} port={port} version=9")
    if "cisco" in vendor:
        return (f"შენი როუტერი Cisco-ა — ჩართე NetFlow v9 (flow exporter → destination {me}, transport udp {port}; "
                "flow monitor; ip flow monitor ... input გარე ინტერფეისზე).")
    return ("მოწყობილობების მიხედვით ტრაფიკს NetAgent როუტერისგან იღებს (NetFlow), ან მართვადი სვიჩისგან (SNMP). "
            "შენი ახლანდელი როუტერი (პროვაიდერის) ამას არ აგზავნის. ვარიანტები:\n"
            f"• MikroTik ან OpenWrt როუტერი — NetFlow ამ კომპიუტერზე ({me}, UDP {port});\n"
            "• მართვადი სვიჩი (მაგ. Cisco) SNMP-ით — devices.yaml-ში role: switch და snmp community;\n"
            "• ზოგ პროვაიდერის როუტერს ადმინ-პანელში აქვს „Traffic statistics“ — იქ ხელით ნახე.")


def human(n: float) -> str:
    for unit, div in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{int(n)} B"


def rate(bps: float) -> str:
    return f"{bps / 1e6:.1f} Mbps" if bps >= 1e5 else f"{bps / 1e3:.0f} kbps"


def format_usage(r: dict) -> str:
    title = {"today": "დღეს", "week": "ბოლო 7 დღე"}.get(r["period"], f"ბოლო {r['period']} წთ")
    if not r["rows"]:
        return f"📊 **ვინ ჭამს ინტერნეტს — {title}**\nმონაცემი ჯერ არ არის.\n\n{r['hint']}" if r["hint"] else \
            f"📊 **ვინ ჭამს ინტერნეტს — {title}**\nამ პერიოდში ტრაფიკი არ ჩანს."
    lines = [f"📊 **ვინ ჭამს ინტერნეტს — {title}** (სულ {human(r['total'])})"]
    for x in r["rows"][:12]:
        now = f" · ახლა ჩამოტვირთვა (download) {rate(x['down_bps'])}" if x["down_bps"] > 1e4 else ""
        lines.append(f"• **{x['name']}**" + (f" ({x['ip']})" if x["ip"] and x["ip"] != x["name"] else "")
                     + f" — ჩამოტვირთვა (download) {human(x['down'])} · ატვირთვა (upload) {human(x['up'])}{now}"
                     + (f" · პორტი {x['port']}" if x.get("port") else ""))
    if r["apps"]:
        lines.append("\n**რა:** " + ", ".join(f"{a['app']} {human(a['bytes'])}" for a in r["apps"]))
    return "\n".join(lines)


def bandwidth_cmd(s, args, user) -> Result:
    period = (args[0].lower() if args else "15")
    period = {"დღეს": "today", "კვირა": "week"}.get(period, period)
    if period not in {"today", "week"} and not period.isdigit():
        period = "15"
    return Result(format_usage(report(s.state, period)),
                  buttons=[Button("⏱ 1 სთ", "/bandwidth 60"), Button("📅 დღეს", "/bandwidth today"), Button("🗓 კვირა", "/bandwidth week")])


COMMANDS = {"bandwidth": bandwidth_cmd}
HELP = ["/bandwidth [15|60|today|week] — ვინ ჭამს ინტერნეტს: ტრაფიკი მოწყობილობების მიხედვით (NetFlow / SNMP სვიჩი)"]
BOT_COMMANDS = [("bandwidth", "ვინ ჭამს ინტერნეტს")]
TOOLS = [
    ({"name": "bandwidth_by_device", "description": "Who uses the internet: download/upload per device (named as in Live "
                                                    "Devices) for the last N minutes, today or this week; top apps.",
      "input_schema": {"type": "object", "properties": {"period": {"type": "string", "description": "15, 60, today or week"}},
                       "required": []}},
     lambda ctx, period="15": report(ctx.services.state, str(period))),
]


def jobs(monitoring):
    """Every minute: add the finished NetFlow minute and the switch-port deltas to today's totals; heavy users."""
    import asyncio

    last_minute = {"m": int(time.time() // 60) - 2}  # the minute in progress at startup is counted too
    hog_gb = env_int("NETAGENT_HOG_GB_HOUR", 5)

    async def tick():
        from ..monitoring import Alert

        s = monitoring.s
        now_min = int(time.time() // 60)
        per: dict[str, list] = defaultdict(lambda: [0, 0])
        for m in range(last_minute["m"] + 1, now_min):  # finished minutes only
            for k, (dn, up) in flow_minute(m).items():
                per[k][0] += dn
                per[k][1] += up
        last_minute["m"] = now_min - 1
        try:
            for name, host, comm in await asyncio.to_thread(snmp_switches, s.inventory()):
                await asyncio.to_thread(PORTS.sample, name, host, comm)
        except Exception as exc:  # noqa: BLE001 - one unreachable switch must not stop the rest
            log.info("switch counters: %s", exc)
        for k, (dn, up) in PORTS.take_deltas().items():
            per[k][0] += dn
            per[k][1] += up
        await asyncio.to_thread(add_daily, s.state, dict(per))
        if hog_gb > 0:
            r = await asyncio.to_thread(report, s.state, "60")
            alerted = s.state.get("usage_hog_alerted") or {}
            today = date.today().isoformat()
            for x in r["rows"]:
                if x["down"] + x["up"] >= hog_gb * 1e9 and alerted.get(x["key"]) != today:
                    alerted[x["key"]] = today
                    await monitoring.emit(Alert("isp", f"📊 **{x['name']} ბევრს იყენებს**: ბოლო საათში {human(x['down'] + x['up'])} "
                                                       f"(ჩამოტვირთვა (download) {human(x['down'])})", mutable=False,
                                                buttons=[Button("📊 ვინ ჭამს ინტერნეტს", "/bandwidth 60")]))
            s.state.set("usage_hog_alerted", alerted)

    return [("talkers", 60, 70, tick)]
