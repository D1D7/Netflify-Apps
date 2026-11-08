"""Interface counters: errors / CRC / drops / resets, traffic and utilization, memory.

Watched devices (those with `watch:` in the inventory) are sampled every
NETAGENT_TRAFFIC_INTERVAL minutes (default 5). Alerts:
  - error counters (input/CRC/output) grew by >= 10 since the last sample → bad cable/SFP/duplex
  - interface resets grew by >= 3 → flapping
  - utilization >= watch.utilization (default 90 %) of the interface bandwidth
  - memory >= watch.memory (default 90 %)
Traffic history is kept 14 days in data/traffic/ for /traffic charts.
"""

from __future__ import annotations

import csv
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

from ..config import settings
from ..result import Button, CommandError, Result
from ..tools import device as dev
from ..watch import family, ifname_matches
from . import env_int

COMMANDS_BY_FAMILY = {
    "ios": {"interfaces": "show interfaces", "memory": "show processes memory sorted | include Processor"},
    "nxos": {"interfaces": "show interface", "memory": "show system resources"},
    "arista": {"interfaces": "show interfaces"},
    "mikrotik": {"interfaces": "/interface print stats terse", "memory": "/system resource print"},
}
ERROR_STEP, RESET_STEP = 10, 3


def _num(text: str) -> int:
    return int(text.replace(",", "").replace(" ", ""))


def parse_ios_interfaces(text: str) -> dict[str, dict]:
    """`show interfaces` (IOS/IOS-XE/NX-OS/EOS style) -> {ifname: counters}."""
    out: dict[str, dict] = {}
    blocks = re.split(r"\n(?=\S)", "\n" + text)
    for block in blocks:
        m = re.match(r"\s*(\S+) is (administratively down|up|down)[^,\n]*(?:, line protocol is (\w+))?", block)
        if not m:
            continue
        d: dict = {"status": m.group(2), "protocol": m.group(3) or m.group(2)}

        def grab(pattern, key, conv=_num):
            g = re.search(pattern, block, re.I)
            if g:
                d[key] = conv(g.group(1))

        grab(r"Description:\s*(.+)", "description", str.strip)
        grab(r"\bBW (\d+) Kbit", "bw_bps", lambda v: int(v) * 1000)
        grab(r"input rate (\d[\d,]*) bits/sec", "in_bps")
        grab(r"output rate (\d[\d,]*) bits/sec", "out_bps")
        grab(r"(\d[\d,]*) input errors?", "in_errors")
        grab(r"(\d[\d,]*) CRC", "crc")
        grab(r"(\d[\d,]*) output errors?", "out_errors")
        grab(r"(\d[\d,]*) interface resets?", "resets")
        grab(r"Total output drops: (\d[\d,]*)", "out_drops")
        grab(r"(\d[\d,]*) (?:input )?packets input, (\d[\d,]*) bytes", "in_packets")
        out[m.group(1)] = d
    return out


def parse_mikrotik_stats(text: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for line in text.splitlines():
        kv = dict(re.findall(r"([\w-]+)=(\S+)", line))
        if "name" not in kv:
            continue
        d = {"status": "up" if re.match(r"^\s*\d+\s+[A-Z]*R", line) else "down"}
        for src, dst in (("rx-byte", "rx_bytes"), ("tx-byte", "tx_bytes"), ("rx-error", "in_errors"),
                         ("tx-error", "out_errors"), ("rx-drop", "in_drops"), ("tx-drop", "out_drops"),
                         ("link-downs", "resets")):
            if src in kv:
                try:
                    d[dst] = _num(kv[src])
                except ValueError:
                    pass
        d["protocol"] = d["status"]
        out[kv["name"]] = d
    return out


_UNITS = {"kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "k": 1024, "kb": 1000, "mb": 1000 ** 2}


def parse_memory(fam: str, text: str) -> float | None:
    if fam == "mikrotik":
        free = re.search(r"free-memory:\s*([\d.]+)\s*(\w+)", text)
        total = re.search(r"total-memory:\s*([\d.]+)\s*(\w+)", text)
        if free and total:
            f = float(free.group(1)) * _UNITS.get(free.group(2).lower(), 1)
            t = float(total.group(1)) * _UNITS.get(total.group(2).lower(), 1)
            return round(100 * (1 - f / t), 1) if t else None
        return None
    m = re.search(r"Processor Pool Total:\s*(\d+)\s*Used:\s*(\d+)", text)
    if m:
        return round(100 * int(m.group(2)) / int(m.group(1)), 1)
    m = re.search(r"Memory usage:\s*(\d+)K total,\s*(\d+)K used", text)  # NX-OS
    if m:
        return round(100 * int(m.group(2)) / int(m.group(1)), 1)
    return None


def collect(inventory, device) -> dict:
    fam = family(device.device_type)
    cmds = COMMANDS_BY_FAMILY.get(fam)
    if not cmds:
        return {"error": f"{device.device_type}-ისთვის ინტერფეისების მრიცხველები ჯერ არ არის მხარდაჭერილი"}
    res = dev.run_commands(inventory, device, list(cmds.values()), parse=False, max_chars=None)
    by_cmd = {r.get("command"): r for r in res}
    first = by_cmd.get(cmds["interfaces"]) or res[0]
    if "error" in first and not first.get("output"):
        return {"error": first["error"]}
    text = first.get("output", "")
    ifaces = parse_mikrotik_stats(text) if fam == "mikrotik" else parse_ios_interfaces(text)
    mem = None
    if "memory" in cmds:
        mres = by_cmd.get(cmds["memory"]) or (res[1] if len(res) > 1 else {})
        mem = parse_memory(fam, mres.get("output", ""))
    return {"ts": time.time(), "interfaces": ifaces, "memory_percent": mem}


class TrafficTracker:
    """Keeps the previous sample per device to compute deltas and MikroTik rates."""

    def __init__(self, root: Path | None = None) -> None:
        self.prev: dict[str, dict] = {}
        self.root = root

    def update(self, device: str, sample: dict) -> dict:
        prev = self.prev.get(device)
        self.prev[device] = sample
        if not prev:
            return {}
        dt = max(1.0, sample["ts"] - prev["ts"])
        deltas = {}
        for name, cur in sample["interfaces"].items():
            old = prev["interfaces"].get(name)
            if not old:
                continue
            d = {}
            for key in ("in_errors", "crc", "out_errors", "resets", "out_drops", "in_drops"):
                if key in cur and key in old and cur[key] >= old[key]:
                    d[key] = cur[key] - old[key]
            for key, rate in (("rx_bytes", "in_bps"), ("tx_bytes", "out_bps")):
                if key in cur and key in old and cur[key] >= old[key] and rate not in cur:
                    cur[rate] = int((cur[key] - old[key]) * 8 / dt)
            deltas[name] = d
        return deltas

    def record(self, device: str, sample: dict, when: datetime | None = None) -> None:
        root = self.root or settings.data_dir / "traffic"
        when = when or datetime.now()
        d = root / re.sub(r"[^\w.-]", "_", device)
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{when.date().isoformat()}.csv"
        new = not path.exists()
        with path.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["ts", "interface", "in_bps", "out_bps", "bw_bps"])
            for name, i in sample["interfaces"].items():
                if "in_bps" in i or "out_bps" in i:
                    w.writerow([when.isoformat(timespec="seconds"), name, i.get("in_bps", ""), i.get("out_bps", ""), i.get("bw_bps", "")])
        cutoff = (when - timedelta(days=14)).date().isoformat()
        for f in d.glob("*.csv"):
            if f.stem < cutoff:
                f.unlink(missing_ok=True)

    def history(self, device: str, interface: str, hours: float) -> list[tuple[datetime, float, float, float | None]]:
        root = self.root or settings.data_dir / "traffic"
        d = root / re.sub(r"[^\w.-]", "_", device)
        since = datetime.now() - timedelta(hours=hours)
        rows = []
        for f in sorted(d.glob("*.csv")) if d.exists() else []:
            if f.stem < since.date().isoformat():
                continue
            with f.open(encoding="utf-8") as fh:
                for r in csv.DictReader(fh):
                    ts = datetime.fromisoformat(r["ts"])
                    if ts >= since and ifname_matches(interface, r["interface"]):
                        rows.append((ts, float(r["in_bps"] or 0), float(r["out_bps"] or 0),
                                     float(r["bw_bps"]) if r["bw_bps"] else None))
        return rows


TRACKER = TrafficTracker()


def utilization(i: dict) -> float | None:
    bw = i.get("bw_bps")
    if not bw:
        return None
    return round(100 * max(i.get("in_bps", 0), i.get("out_bps", 0)) / bw, 1)


def human_bps(v: float | None) -> str:
    if v is None:
        return "—"
    for unit, div in (("Gbit/s", 1e9), ("Mbit/s", 1e6), ("kbit/s", 1e3)):
        if v >= div:
            return f"{v / div:.1f} {unit}"
    return f"{int(v)} bit/s"


def analyze(device, sample: dict, deltas: dict) -> list[str]:
    w = device.watch or {}
    util_limit = float(w.get("utilization", 90))
    mem_limit = float(w.get("memory", 90))
    alerts = []
    for name, d in deltas.items():
        errs = d.get("in_errors", 0) + d.get("out_errors", 0) + d.get("crc", 0)
        if errs >= ERROR_STEP:
            detail = ", ".join(f"{k.replace('_', ' ')} +{v}" for k, v in d.items() if v and k in {"in_errors", "crc", "out_errors"})
            alerts.append(f"⚡ **{device.name}** {name}: შეცდომები იზრდება ({detail}) — შეამოწმე კაბელი, SFP ან duplex")
        if d.get("resets", 0) >= RESET_STEP:
            alerts.append(f"🔁 **{device.name}** {name}: ინტერფეისი ხშირად ირთვება/ითიშება ({d['resets']} reset ბოლო შემოწმების შემდეგ)")
    for name, i in sample["interfaces"].items():
        u = utilization(i)
        if u is not None and u >= util_limit:
            alerts.append(f"📈 **{device.name}** {name}: დატვირთვა {u}% ({human_bps(max(i.get('in_bps', 0), i.get('out_bps', 0)))}"
                          f" / {human_bps(i['bw_bps'])})")
    mem = sample.get("memory_percent")
    if mem is not None and mem >= mem_limit:
        alerts.append(f"🧠 **{device.name}**: მეხსიერება {mem}% (ზღვარი {mem_limit:.0f}%)")
    return alerts


def format_traffic(name: str, sample: dict, only_errors: bool = False) -> str:
    rows = []
    for ifname, i in sample["interfaces"].items():
        if i.get("status") != "up" and not only_errors:
            continue
        errs = sum(i.get(k, 0) for k in ("in_errors", "out_errors"))
        if only_errors and not errs and not i.get("crc"):
            continue
        u = utilization(i)
        rows.append(f"{ifname[:22]:<22} in{human_bps(i.get('in_bps')):>12} out{human_bps(i.get('out_bps')):>12}"
                    + (f" {u:>5}%" if u is not None else "       ")
                    + (f"  err {errs} crc {i.get('crc', 0)}" if errs or i.get("crc") else ""))
    head = f"📶 **{name}** — " + ("ინტერფეისები შეცდომებით" if only_errors else "ტრაფიკი") + \
        (f" · მეხსიერება {sample['memory_percent']}%" if sample.get("memory_percent") is not None else "")
    if not rows:
        return head + "\n" + ("✅ შეცდომები არ არის" if only_errors else "აქტიური ინტერფეისი ვერ ვიპოვე")
    return head + "\n```\n" + "\n".join(rows) + "\n```"


def chart(name: str, interface: str, rows, path: Path) -> Path | None:
    if len(rows) < 2:
        return None
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(9, 3.4), dpi=130)
    xs = [r[0] for r in rows]
    ax.plot(xs, [r[1] / 1e6 for r in rows], color="#2a78d6", lw=1.4, label="⬇ in")
    ax.plot(xs, [r[2] / 1e6 for r in rows], color="#8e4ec6", lw=1.4, label="⬆ out")
    bw = next((r[3] for r in rows if r[3]), None)
    if bw:
        ax.axhline(bw / 1e6, color="#e5484d", lw=1, ls="--", label="სიჩქარე")
    ax.set_ylabel("Mbit/s")
    ax.set_title(f"{name} {interface} — ტრაფიკი", fontsize=10, loc="left")
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


# -- commands / tools / jobs -----------------------------------------------------------------
def _sample(s, d) -> dict:
    sample = collect(s.inventory(), d)
    if "error" in sample:
        raise CommandError(f"{d.name}: {sample['error']}")
    TRACKER.update(d.name, sample)
    return sample


def traffic_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /traffic R1 · /traffic R1 Gi0/0/0 24 (გრაფიკი, საათები)")
    d = s.inventory().get(args[0])
    if len(args) >= 2:
        hours = float(args[2]) if len(args) > 2 and args[2].replace(".", "").isdigit() else 24
        rows = TRACKER.history(d.name, args[1], hours)
        settings.export_dir.mkdir(parents=True, exist_ok=True)
        img = chart(d.name, args[1], rows, settings.export_dir / f"traffic-{d.name}-{datetime.now():%Y%m%d-%H%M%S}.png")
        if img is None:
            return Result(f"📶 {d.name} {args[1]}: ისტორია ჯერ არ არის. ის ყოველ "
                          f"{env_int('NETAGENT_TRAFFIC_INTERVAL', 5)} წუთში იწერება `watch`-იან მოწყობილობებზე.")
        peak = max(rows, key=lambda r: max(r[1], r[2]))
        return Result(f"📶 **{d.name} {args[1]}** — ბოლო {hours:g} სთ, პიკი {human_bps(max(peak[1], peak[2]))} "
                      f"({peak[0]:%m-%d %H:%M})", image=img)
    return Result(format_traffic(d.name, _sample(s, d)), buttons=[Button("⚡ შეცდომები", f"/errors {d.name}")])


def errors_cmd(s, args, user) -> Result:
    devices = [s.inventory().get(args[0])] if args else list(s.inventory().devices.values())
    if not devices:
        return Result("inventory ცარიელია")
    results = dev.run_on_devices(s.inventory(), devices, lambda d: collect(s.inventory(), d))
    parts = []
    for name, sample in results.items():
        if isinstance(sample, dict) and "interfaces" in sample:
            text = format_traffic(name, sample, only_errors=True)
            if args or "✅" not in text:
                parts.append(text)
    return Result("\n\n".join(parts) or "✅ არცერთ ინტერფეისზე შეცდომები არ ჩანს")


def _tool(ctx, device: str, interface: str = "", hours: int = 0) -> dict:
    d = ctx.inventory.get(device)
    if interface and hours:
        rows = TRACKER.history(d.name, interface, hours)
        return {"interface": interface, "samples": len(rows),
                "points": [{"ts": r[0].isoformat(timespec="minutes"), "in_bps": r[1], "out_bps": r[2]} for r in rows[-200:]]}
    sample = collect(ctx.inventory, d)
    if "error" in sample:
        raise ValueError(sample["error"])
    deltas = TRACKER.update(d.name, sample)
    ifs = {k: v for k, v in sample["interfaces"].items() if not interface or ifname_matches(interface, k)}
    for k, v in ifs.items():
        v["utilization_percent"] = utilization(v)
        if k in deltas:
            v["delta_since_last_sample"] = deltas[k]
    return {"device": d.name, "memory_percent": sample["memory_percent"], "interfaces": ifs}


COMMANDS = {"traffic": traffic_cmd, "errors": errors_cmd}
HELP = ["/traffic R1 — ინტერფეისების ტრაფიკი და დატვირთვა · /traffic R1 Gi0/1 24 — გრაფიკი · /errors — CRC/შეცდომები"]
BOT_COMMANDS = [("errors", "ინტერფეისების შეცდომები (CRC)"), ("traffic", "ტრაფიკი: /traffic R1")]
TOOLS = [({
    "name": "interface_stats",
    "description": "Interface counters of a device: status, in/out bit rate, bandwidth and utilization %, input/output "
                   "errors, CRC, drops, resets (with the change since the previous sample) and memory %. Use for "
                   "'why is the link slow', 'are there errors on Gi0/1', 'who is congested'. With interface + hours "
                   "returns the traffic history recorded every few minutes.",
    "input_schema": {"type": "object", "properties": {
        "device": {"type": "string"}, "interface": {"type": "string"},
        "hours": {"type": "integer", "description": "history window (needs interface)"}}, "required": ["device"]},
}, _tool)]


def jobs(monitoring):
    import asyncio

    from ..monitoring import Alert

    every = env_int("NETAGENT_TRAFFIC_INTERVAL", 5)
    if every <= 0:
        return []
    last_sent: dict[str, float] = {}

    async def run():
        s = monitoring.s
        inv = s.inventory()
        devices = [d for d in inv.devices.values() if d.watch and family(d.device_type) in COMMANDS_BY_FAMILY]
        if not devices:
            return
        results = await asyncio.to_thread(dev.run_on_devices, inv, devices, lambda d: collect(inv, d))
        for d in devices:
            sample = results.get(d.name)
            if not isinstance(sample, dict) or "interfaces" not in sample or s.mutes.is_muted(d.name):
                continue
            deltas = TRACKER.update(d.name, sample)
            await asyncio.to_thread(TRACKER.record, d.name, sample)
            fresh = []
            for text in analyze(d, sample, deltas):
                key = text.split(":")[0]
                if time.time() - last_sent.get(key, 0) > 3600:  # same problem at most once an hour
                    last_sent[key] = time.time()
                    fresh.append(text)
            if fresh:
                await monitoring.emit(Alert("watch", "\n".join(fresh), [d.name]))

    return [("traffic", every * 60, 100, run)]
