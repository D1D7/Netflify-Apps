"""Deep monitoring of selected devices: interface status, BGP / OSPF neighbors, CPU.

Opt-in per device in the inventory:

    R1:
      host: 10.0.0.1
      device_type: cisco_ios
      watch:
        interfaces: [Gi0/0, Gi0/1]   # alert when these go down / come back
        bgp: true                    # alert when a BGP session leaves Established
        ospf: true                   # alert when an OSPF neighbor leaves FULL/2WAY
        cpu: 80                      # alert when CPU >= 80%

Parsing works on raw CLI text (no TextFSM dependency) so the same code covers
several vendors; unknown formats simply yield no data instead of false alerts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .inventory import Device, Inventory
from .tools import device as dev

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"


def family(device_type: str) -> str:
    dt = device_type.lower()
    if dt.startswith("cisco_nxos"):
        return "nxos"
    if dt.startswith(("cisco_ios", "cisco_xe", "dell_os10", "aruba_aoscx")):
        return "ios"
    if dt.startswith("arista"):
        return "arista"
    if dt.startswith("juniper"):
        return "junos"
    if dt.startswith("mikrotik"):
        return "mikrotik"
    if dt.startswith(("huawei", "hp_comware", "h3c")):
        return "huawei"
    if dt.startswith("linux"):
        return "linux"
    return "other"


COMMANDS: dict[str, dict[str, str]] = {
    "ios": {"interfaces": "show ip interface brief", "bgp": "show ip bgp summary",
            "ospf": "show ip ospf neighbor", "cpu": "show processes cpu | include CPU utilization"},
    "nxos": {"interfaces": "show ip interface brief vrf all", "bgp": "show ip bgp summary",
             "ospf": "show ip ospf neighbors", "cpu": "show system resources"},
    "arista": {"interfaces": "show ip interface brief", "bgp": "show ip bgp summary",
               "ospf": "show ip ospf neighbor", "cpu": "show processes top once"},
    "junos": {"interfaces": "show interfaces terse", "bgp": "show bgp summary",
              "ospf": "show ospf neighbor", "cpu": "show chassis routing-engine"},
    "mikrotik": {"interfaces": "/interface print terse", "cpu": "/system resource print"},
    "huawei": {"interfaces": "display interface brief", "bgp": "display bgp peer",
               "ospf": "display ospf peer brief", "cpu": "display cpu-usage"},
    "linux": {"interfaces": "ip -br link"},
}


# --------------------------------------------------------------------------- interface names


def _split_ifname(name: str) -> tuple[str, str]:
    m = re.match(r"^([A-Za-z-]+)\s*(.*)$", name.strip())
    return (m.group(1).lower(), m.group(2).lower()) if m else (name.lower(), "")


def ifname_matches(wanted: str, actual: str) -> bool:
    """'Gi0/1' matches 'GigabitEthernet0/1', 'Po1' matches 'Port-channel1', exact names always match."""
    if wanted.strip().lower() == actual.strip().lower():
        return True
    wp, wn = _split_ifname(wanted)
    ap, an = _split_ifname(actual)
    return bool(wn) and wn == an and (ap.startswith(wp) or wp.startswith(ap))


def find_interface(wanted: str, states: dict[str, str]) -> str | None:
    for name in states:
        if ifname_matches(wanted, name):
            return name
    return None


# --------------------------------------------------------------------------- parsers


def parse_interfaces(fam: str, text: str) -> dict[str, str]:
    """Return {interface: 'up' | 'down' | 'admin-down'}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("Interface", "Flags", "Columns", "#", "Name", "PHY:")):
            continue
        if fam == "junos":
            m = re.match(r"^(\S+)\s+(up|down)\s+(up|down)\b", line)
            if m:
                out[m.group(1)] = "admin-down" if m.group(2) == "down" else ("up" if m.group(3) == "up" else "down")
        elif fam == "mikrotik":
            m = re.match(r"^\s*\d+\s+([A-Z]*)\s*name=(\S+)", line)
            if m:
                flags = m.group(1)
                out[m.group(2).strip('"')] = "admin-down" if "X" in flags else ("up" if "R" in flags else "down")
        elif fam == "huawei":
            m = re.match(r"^(\S+)\s+(\*down|\^?down|up)\s+(up(?:\(s\))?|\*?down)\b", line)
            if m:
                phy, proto = m.group(2), m.group(3)
                out[m.group(1)] = "admin-down" if phy.startswith("*") else (
                    "up" if phy == "up" and proto.startswith("up") else "down")
        elif fam == "linux":
            m = re.match(r"^(\S+?)(?:@\S+)?\s+(UP|DOWN|UNKNOWN|LOWERLAYERDOWN)\b", line)
            if m:
                out[m.group(1)] = "up" if m.group(2) in {"UP", "UNKNOWN"} else "down"
        else:  # IOS / NX-OS / Arista style tables
            tokens = line.split()
            if len(tokens) < 3 or not re.match(r"^[A-Za-z]", tokens[0]):
                continue
            rest = " ".join(tokens[1:]).lower()
            if "administratively down" in rest or "admin-down" in rest or "admin down" in rest or "admindown" in rest:
                out[tokens[0]] = "admin-down"
                continue
            if "protocol-up/link-up" in rest:
                out[tokens[0]] = "up"
                continue
            if "protocol-down" in rest or "link-down" in rest:
                out[tokens[0]] = "down"
                continue
            states = [t for t in tokens[1:] if t.lower() in {"up", "down", "lowerlayerdown", "notpresent"}]
            if states:
                out[tokens[0]] = "up" if all(s.lower() == "up" for s in states[:2]) else "down"
    return out


_BGP_STATES = {"idle", "connect", "active", "opensent", "openconfirm", "established", "estab", "establ"}


def parse_bgp(fam: str, text: str) -> dict[str, str]:
    """Return {neighbor_ip: 'established' | other state}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(rf"^\s*({_IP})\s+\S+", line)
        if not m:
            continue
        tokens = line.split()
        low = [t.lower() for t in tokens]
        if any(t in {"established", "estab", "establ"} for t in low):
            out[m.group(1)] = "established"
            continue
        state_tokens = [t for t in low if t.strip("()") in _BGP_STATES or t in {"(admin)", "idle(admin)"}]
        if state_tokens:
            out[m.group(1)] = "admin-down" if "admin" in " ".join(low) else state_tokens[-1].strip("()")
        elif fam in {"ios", "nxos", "arista"} and tokens[-1].isdigit():
            out[m.group(1)] = "established"  # IOS shows the received-prefix count when Established
    return out


_OSPF_GOOD = {"full", "2way", "2-way"}


def parse_ospf(fam: str, text: str) -> dict[str, str]:
    """Return {neighbor_id: state (lowercase, e.g. 'full', 'init')}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if fam == "junos":
            m = re.match(rf"^\s*({_IP})\s+\S+\s+(\w+)\s+({_IP})", line)
            if m:
                out[m.group(3)] = m.group(2).lower()
            continue
        if fam == "huawei":
            m = re.match(rf"^\s*\S+\s+\S+\s+({_IP})\s+(\w+)", line)
            if m:
                out[m.group(1)] = m.group(2).lower()
            continue
        m = re.match(rf"^\s*({_IP})\s+.*?\b(FULL|2WAY|INIT|EXSTART|EXCHANGE|LOADING|DOWN|ATTEMPT)\b", line, re.I)
        if m:
            out[m.group(1)] = m.group(2).lower()
    return out


def parse_cpu(fam: str, text: str) -> float | None:
    patterns = [
        (r"one minute:\s*(\d+)%", False),                 # Cisco IOS
        (r"cpu-load:\s*(\d+)%", False),                    # MikroTik
        (r"CPU Usage\s*:\s*(\d+)%", False),                # Huawei
        (r"Idle\s+(\d+)\s+percent", True),                 # Junos (first RE)
        (r"([\d.]+)%\s*idle", True),                       # NX-OS
        (r"([\d.]+)\s*id\b", True),                        # Arista/Linux top
    ]
    for pattern, is_idle in patterns:
        m = re.search(pattern, text, re.I)
        if m:
            value = float(m.group(1))
            return round(100 - value, 1) if is_idle else value
    return None


# --------------------------------------------------------------------------- collection & comparison


@dataclass
class Snapshot:
    interfaces: dict[str, str] = field(default_factory=dict)
    bgp: dict[str, str] | None = None
    ospf: dict[str, str] | None = None
    cpu: float | None = None
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], {})}


def watch_config(device: Device) -> dict:
    return device.watch if isinstance(device.watch, dict) else {}


def collect(inventory: Inventory, device: Device, everything: bool = False) -> Snapshot:
    """Run the monitoring commands for one device. everything=True ignores the watch config."""
    fam = family(device.device_type)
    cmds = COMMANDS.get(fam, {})
    cfg = watch_config(device)
    wanted = {
        "interfaces": everything or bool(cfg.get("interfaces")),
        "bgp": everything or bool(cfg.get("bgp")),
        "ospf": everything or bool(cfg.get("ospf")),
        "cpu": everything or bool(cfg.get("cpu")),
    }
    kinds = [k for k, on in wanted.items() if on and k in cmds]
    snap = Snapshot()
    if not kinds:
        if any(wanted.values()):
            snap.errors.append(f"device_type '{device.device_type}'-ისთვის მონიტორინგის ბრძანებები არ არის")
        return snap
    results = dev.run_commands(inventory, device, [cmds[k] for k in kinds], parse=False, max_chars=None)
    for kind, res in zip(kinds, results):
        if "error" in res:
            snap.errors.append(f"{kind}: {res['error'].splitlines()[0][:100]}")
            continue
        text = res.get("output", "")
        if kind == "interfaces":
            snap.interfaces = parse_interfaces(fam, text)
        elif kind == "bgp":
            snap.bgp = parse_bgp(fam, text)
        elif kind == "ospf":
            snap.ospf = parse_ospf(fam, text)
        elif kind == "cpu":
            snap.cpu = parse_cpu(fam, text)
    return snap


def _neighbor_alerts(name: str, proto: str, prev: dict[str, str] | None, new: dict[str, str] | None, good) -> list[str]:
    alerts: list[str] = []
    if prev is None or new is None:
        return alerts
    for peer in sorted(set(prev) | set(new)):
        old_state, new_state = prev.get(peer), new.get(peer)
        was_good = old_state is not None and good(old_state)
        is_good = new_state is not None and good(new_state)
        if was_good and not is_good:
            alerts.append(f"🔴 **{name}**: {proto} neighbor {peer} დაეცა ({new_state or 'გაქრა'})")
        elif is_good and not was_good:
            # Covers both "was down" and "had vanished from the table" (e.g. OSPF neighbor lost).
            alerts.append(f"🟢 **{name}**: {proto} neighbor {peer} აღდგა ({new_state})")
    return alerts


def compare(device: Device, prev: Snapshot | None, new: Snapshot) -> list[str]:
    """Alerts for state changes between two snapshots (prev=None -> baseline)."""
    name = device.name
    cfg = watch_config(device)
    alerts: list[str] = []

    for wanted in cfg.get("interfaces") or []:
        actual = find_interface(str(wanted), new.interfaces)
        if new.interfaces and actual is None:
            if prev is None:
                alerts.append(f"⚠️ **{name}**: ინტერფეისი '{wanted}' ვერ ვიპოვე (watch-ში სახელი შეამოწმე)")
            continue
        if actual is None:
            continue
        state = new.interfaces[actual]
        old = prev.interfaces.get(actual) if prev else None
        if prev is None:
            if state != "up":
                alerts.append(f"🔴 **{name}** {actual}: {state}")
        elif old == "up" and state != "up":
            alerts.append(f"🔴 **{name}** {actual} ჩავარდა ({state})")
        elif old is not None and old != "up" and state == "up":
            alerts.append(f"🟢 **{name}** {actual} აღდგა")

    if cfg.get("bgp") and prev is not None:
        alerts += _neighbor_alerts(name, "BGP", prev.bgp, new.bgp, lambda s: s == "established")
    if cfg.get("ospf") and prev is not None:
        alerts += _neighbor_alerts(name, "OSPF", prev.ospf, new.ospf, lambda s: s in _OSPF_GOOD)

    threshold = cfg.get("cpu")
    if threshold and new.cpu is not None:
        try:
            threshold = float(threshold)
        except (TypeError, ValueError):
            threshold = 0
        old_cpu = prev.cpu if prev else None
        if threshold and new.cpu >= threshold and (old_cpu is None or old_cpu < threshold):
            alerts.append(f"🔥 **{name}**: CPU {new.cpu:.0f}% (ზღვარი {threshold:.0f}%)")
        elif threshold and old_cpu is not None and old_cpu >= threshold and new.cpu < threshold - 10:
            alerts.append(f"🟢 **{name}**: CPU ნორმას დაუბრუნდა ({new.cpu:.0f}%)")
    return alerts


class DeepMonitor:
    def __init__(self) -> None:
        self._last: dict[str, Snapshot] = {}

    def run(self, inventory: Inventory, devices: list[Device]) -> list[tuple[str, str]]:
        """Collect snapshots for watched devices; return (device, alert) pairs."""
        watched = [d for d in devices if watch_config(d)]
        if not watched:
            return []
        snaps = dev.run_on_devices(inventory, watched, lambda d: collect(inventory, d))
        alerts: list[tuple[str, str]] = []
        for d in watched:
            snap = snaps.get(d.name)
            if not isinstance(snap, Snapshot):
                continue  # unreachable: the reachability monitor reports that
            for a in compare(d, self._last.get(d.name), snap):
                alerts.append((d.name, a))
            self._last[d.name] = snap
        for name in list(self._last):
            if name not in {d.name for d in watched}:
                del self._last[name]
        return alerts


def format_health(device: Device, snap: Snapshot) -> dict[str, Any]:
    """Compact summary for the agent / chat."""
    out: dict[str, Any] = {"device": device.name}
    if snap.interfaces:
        counts = {"up": 0, "down": 0, "admin-down": 0}
        for s in snap.interfaces.values():
            counts[s] = counts.get(s, 0) + 1
        out["interfaces"] = counts
        out["interfaces_down"] = sorted(n for n, s in snap.interfaces.items() if s == "down")
    if snap.bgp is not None:
        out["bgp"] = snap.bgp
    if snap.ospf is not None:
        out["ospf"] = snap.ospf
    if snap.cpu is not None:
        out["cpu_percent"] = snap.cpu
    if snap.errors:
        out["errors"] = snap.errors
    return out


def format_health_text(name: str, snap: Snapshot) -> str:
    """Human-readable health summary (Telegram / CLI)."""
    lines = [f"🩺 **{name}** — მდგომარეობა"]
    if snap.interfaces:
        up = sum(1 for s in snap.interfaces.values() if s == "up")
        down = sorted(n for n, s in snap.interfaces.items() if s == "down")
        admin = sum(1 for s in snap.interfaces.values() if s == "admin-down")
        lines.append(f"ინტერფეისები: 🟢 {up} up · 🔴 {len(down)} down · ⚪ {admin} გამორთული")
        if down:
            lines.append("down: " + ", ".join(down[:15]) + (" …" if len(down) > 15 else ""))
    for proto, data, good in (("BGP", snap.bgp, lambda s: s == "established"),
                              ("OSPF", snap.ospf, lambda s: s in _OSPF_GOOD)):
        if data is None:
            continue
        if not data:
            lines.append(f"{proto}: neighbor-ები არ არის")
            continue
        items = [f"{'🟢' if good(st) else '🔴'} {peer}" + ("" if good(st) else f" ({st})") for peer, st in sorted(data.items())]
        lines.append(f"{proto}: " + " · ".join(items[:12]))
    if snap.cpu is not None:
        lines.append(f"CPU: {'🔥 ' if snap.cpu >= 80 else ''}{snap.cpu:.0f}%")
    for err in snap.errors:
        lines.append(f"⚠️ {err}")
    if len(lines) == 1:
        lines.append("მონაცემები ვერ მივიღე ამ პლატფორმისთვის.")
    return "\n".join(lines)
