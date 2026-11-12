"""Network map from CDP/LLDP neighbors: who is connected to whom, on which ports.

Neighbor tables are read with TextFSM where a template exists (field names differ
between ntc-templates versions, so several are accepted) and with a small raw parser
for MikroTik. The result is a list of links, cached in data/topology.json, and can be
drawn as a PNG.
"""

from __future__ import annotations

import json
import math
import random
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .inventory import Device, Inventory
from .tools import device as dev


@dataclass(frozen=True)
class Link:
    a: str          # inventory device name
    a_port: str
    b: str          # neighbor name (inventory name when it could be matched)
    b_port: str
    b_known: bool   # True when b is a device in the inventory
    b_ip: str = ""
    b_platform: str = ""


_NAME_KEYS = ("neighbor_name", "destination_host", "neighbor", "system_name", "device_id", "neighbor_id", "identity")
_LOCAL_KEYS = ("local_interface", "local_port", "local_intf", "interface")
_REMOTE_KEYS = ("neighbor_interface", "remote_port", "port_id", "port_info", "neighbor_port_id", "port_description")
_IP_KEYS = ("management_ip", "mgmt_address", "mgmt_ip", "management_address", "address")
_PLATFORM_KEYS = ("platform", "neighbor_description", "system_description")


def _first(row: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = row.get(k)
        if isinstance(v, list):
            v = v[0] if v else ""
        if v:
            return str(v).strip()
    return ""


def short_name(name: str) -> str:
    """'SW1.corp.local' -> 'SW1', 'SW1(FOC1234)' -> 'SW1'."""
    name = re.sub(r"\(.*\)$", "", name.strip())
    return name.split(".")[0] if not re.match(r"^\d+\.\d+\.\d+\.\d+$", name) else name


def parse_mikrotik_neighbors(text: str) -> list[dict]:
    rows, cur = [], {}
    for line in text.splitlines():
        if re.match(r"^\s*\d+\s", line) and cur:
            rows.append(cur)
            cur = {}
        for k, v in re.findall(r'([\w-]+)=("[^"]*"|\S+)', line):
            cur[k] = v.strip('"')
    if cur:
        rows.append(cur)
    return [{"neighbor_name": r.get("identity", ""), "local_interface": r.get("interface", ""),
             "neighbor_interface": r.get("interface-name", ""), "mgmt_address": r.get("address", ""),
             "platform": r.get("platform", "")} for r in rows if r.get("identity") or r.get("address")]


def neighbor_commands(device: Device) -> list[tuple[str, bool]]:
    """(command, parse_with_textfsm) pairs for the platform."""
    dt = device.device_type.lower()
    if dt.startswith("mikrotik"):
        return [("/ip neighbor print detail", False)]
    if dt.startswith(("cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr")):
        return [("show cdp neighbors detail", True), ("show lldp neighbors detail", True)]
    if dt.startswith(("huawei", "hp_comware")):
        return [("display lldp neighbor brief", True)]
    return [("show lldp neighbors detail", True), ("show lldp neighbors", True)]


def collect_neighbors(inventory: Inventory, device: Device) -> list[dict]:
    rows: list[dict] = []
    cmds = neighbor_commands(device)
    results = dev.run_commands(inventory, device, [c for c, _ in cmds], parse=True, max_chars=None)
    for (cmd, parse), res in zip(cmds, results):
        if "parsed" in res and isinstance(res["parsed"], list):
            rows += [r for r in res["parsed"] if isinstance(r, dict)]
        elif "output" in res and device.device_type.lower().startswith("mikrotik"):
            rows += parse_mikrotik_neighbors(res["output"])
    return rows


def build_links(inventory: Inventory, neighbors: dict[str, list[dict]]) -> list[Link]:
    by_name = {d.name.lower(): d.name for d in inventory.devices.values()}
    by_ip = {d.host: d.name for d in inventory.devices.values()}
    seen: set[tuple] = set()
    links: list[Link] = []
    for name, rows in neighbors.items():
        for r in rows:
            raw = _first(r, _NAME_KEYS)
            ip = _first(r, _IP_KEYS)
            if not raw and not ip:
                continue
            match = by_name.get(short_name(raw).lower()) or by_ip.get(ip)
            b = match or short_name(raw) or ip
            if b == name:
                continue
            a_port, b_port = _first(r, _LOCAL_KEYS), _first(r, _REMOTE_KEYS)
            key = tuple(sorted([(name, a_port), (b, b_port)]))
            if key in seen:  # the same cable seen from both ends
                continue
            seen.add(key)
            links.append(Link(name, a_port, b, b_port, bool(match), ip, _first(r, _PLATFORM_KEYS)[:40]))
    return links


def discover_topology(inventory: Inventory, cache: Path | None = None) -> dict[str, Any]:
    devices = list(inventory.devices.values())
    results = dev.run_on_devices(inventory, devices, lambda d: collect_neighbors(inventory, d))
    neighbors = {k: v for k, v in results.items() if isinstance(v, list)}
    errors = {k: v.get("error", "") for k, v in results.items() if isinstance(v, dict)}
    links = build_links(inventory, neighbors)
    data = {
        "generated": datetime.now().isoformat(timespec="minutes"),
        "devices": [d.name for d in devices],
        "links": [asdict(l) for l in links],
        "errors": {k: str(v).splitlines()[0][:120] if v else "" for k, v in errors.items()},
    }
    if cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return data


def format_links(data: dict) -> str:
    links = data.get("links", [])
    if not links:
        msg = "🗺 CDP/LLDP neighbor-ები ვერ ვიპოვე."
        if data.get("errors"):
            msg += "\n" + "\n".join(f"⚠️ {k}: {v}" for k, v in data["errors"].items())
        return msg + "\n(მოწყობილობებზე CDP ან LLDP ჩართული უნდა იყოს)"
    lines = [f"🗺 **ქსელის რუკა** — {len(links)} კავშირი", "```"]
    for l in links:
        mark = "" if l["b_known"] else " (?)"
        lines.append(f"{l['a']} {l['a_port']} ↔ {l['b']}{mark} {l['b_port']}".rstrip())
    lines.append("```")
    if any(not l["b_known"] for l in links):
        lines.append("(?) = inventory-ში არ არის. დასამატებლად: /discover")
    for k, v in (data.get("errors") or {}).items():
        lines.append(f"⚠️ {k}: {v}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- drawing

_PORT_ABBR = [("TwentyFiveGigE", "Twe"), ("HundredGigE", "Hu"), ("FortyGigabitEthernet", "Fo"),
              ("TenGigabitEthernet", "Te"), ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"),
              ("Port-channel", "Po"), ("Ethernet", "Eth")]


def abbreviate_port(port: str) -> str:
    for long, short in _PORT_ABBR:
        if port.startswith(long):
            return short + port[len(long):]
    return port


def _layout(nodes: list[str], edges: list[tuple[str, str]], iters: int = 300) -> dict[str, tuple[float, float]]:
    """Small Fruchterman-Reingold layout (deterministic)."""
    rnd = random.Random(42)
    n = max(len(nodes), 1)
    pos = {v: [math.cos(2 * math.pi * i / n) + rnd.uniform(-0.05, 0.05),
               math.sin(2 * math.pi * i / n) + rnd.uniform(-0.05, 0.05)] for i, v in enumerate(nodes)}
    k = 1.6 / math.sqrt(n)
    temp = 0.2
    for _ in range(iters):
        disp = {v: [0.0, 0.0] for v in nodes}
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = max(math.hypot(dx, dy), 0.01)
                f = k * k / d
                disp[a][0] += dx / d * f; disp[a][1] += dy / d * f
                disp[b][0] -= dx / d * f; disp[b][1] -= dy / d * f
        for a, b in edges:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = max(math.hypot(dx, dy), 0.01)
            f = d * d / k
            disp[a][0] -= dx / d * f; disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f; disp[b][1] += dy / d * f
        for v in nodes:
            dx, dy = disp[v]
            d = max(math.hypot(dx, dy), 0.01)
            pos[v][0] += dx / d * min(d, temp)
            pos[v][1] += dy / d * min(d, temp)
        temp *= 0.985
    return {v: (p[0], p[1]) for v, p in pos.items()}


def draw_map(data: dict, path: Path, down: set[str] | None = None) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    down = down or set()
    links = data.get("links", [])
    nodes = list(dict.fromkeys([*data.get("devices", []), *[l["b"] for l in links]]))
    if not nodes:
        raise ValueError("რუკისთვის მოწყობილობები არ არის")
    edges = [(l["a"], l["b"]) for l in links]
    pos = _layout(nodes, edges)
    known = set(data.get("devices", []))

    plt.rcParams.update({"font.family": "DejaVu Sans"})
    size = max(6.0, min(14.0, 3 + len(nodes) * 0.6))
    fig, ax = plt.subplots(figsize=(size, size * 0.75), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")
    for l in links:
        (x1, y1), (x2, y2) = pos[l["a"]], pos[l["b"]]
        ax.plot([x1, x2], [y1, y2], color="#c3c2b7", linewidth=2, zorder=1, solid_capstyle="round")
        for (x, y), (ox, oy), port in (((x1, y1), (x2, y2), l["a_port"]), ((x2, y2), (x1, y1), l["b_port"])):
            if port:
                ax.text(x + (ox - x) * 0.33, y + (oy - y) * 0.33, abbreviate_port(port), fontsize=7.5, color="#52514e",
                        ha="center", va="center", zorder=3,
                        bbox={"boxstyle": "round,pad=0.15", "fc": "#fcfcfb", "ec": "none"})
    for v in nodes:
        x, y = pos[v]
        color = "#d03b3b" if v in down else ("#2a78d6" if v in known else "#898781")
        ax.scatter([x], [y], s=900 if v in known else 500, color=color, zorder=2, edgecolors="#fcfcfb", linewidths=2.5)
        label = v + ("  ✕ მიუწვდომელი" if v in down else "")
        ax.text(x, y - 0.13, label, ha="center", va="top", fontsize=9.5, color="#0b0b0b",
                weight="bold" if v in known else "normal", zorder=4)
    ax.set_title(f"ქსელის რუკა — {len(nodes)} მოწყობილობა, {len(links)} კავშირი", loc="left",
                 fontsize=12, color="#0b0b0b", weight="bold")
    ax.text(0, -0.04, "ლურჯი: inventory   ·   ნაცრისფერი: უცნობი neighbor   ·   წითელი: მიუწვდომელი",
            transform=ax.transAxes, fontsize=8, color="#52514e")
    ax.axis("off")
    ax.margins(0.18)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, facecolor="#fcfcfb")
    plt.close(fig)
    return path
