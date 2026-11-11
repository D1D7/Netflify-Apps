"""Read-only access to network devices over SSH (Netmiko).

Supports any platform Netmiko supports. For common platforms there is a map of
"intent → command" so the agent can ask for e.g. `ip_addresses` without knowing
the vendor syntax; for everything else it can use `run_show_command`.
"""

from __future__ import annotations

import ipaddress
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..config import settings
from ..inventory import Device, Inventory
from ..security import mask_secrets, validate_command

INTENTS = (
    "interfaces",
    "ip_addresses",
    "arp",
    "mac_table",
    "routes",
    "version",
    "neighbors",
    "vlans",
    "running_config",
)

_IOS_LIKE = {
    "interfaces": ["show interfaces description"],
    "ip_addresses": ["show ip interface brief"],
    "arp": ["show ip arp"],
    "mac_table": ["show mac address-table"],
    "routes": ["show ip route"],
    "version": ["show version"],
    "neighbors": ["show cdp neighbors", "show lldp neighbors"],
    "vlans": ["show vlan brief"],
    "running_config": ["show running-config"],
}
_HUAWEI_LIKE = {
    "interfaces": ["display interface brief"],
    "ip_addresses": ["display ip interface brief"],
    "arp": ["display arp"],
    "mac_table": ["display mac-address"],
    "routes": ["display ip routing-table"],
    "version": ["display version"],
    "neighbors": ["display lldp neighbor brief"],
    "vlans": ["display vlan"],
    "running_config": ["display current-configuration"],
}
_VYOS_LIKE = {
    "interfaces": ["show interfaces"],
    "ip_addresses": ["show interfaces"],
    "arp": ["show arp"],
    "routes": ["show ip route"],
    "version": ["show version"],
    "neighbors": ["show lldp neighbors"],
    "running_config": ["show configuration commands"],
}

COMMAND_MAP: dict[str, dict[str, list[str]]] = {
    "cisco_ios": _IOS_LIKE,
    "cisco_xe": _IOS_LIKE,
    "cisco_nxos": {
        **_IOS_LIKE,
        "interfaces": ["show interface description"],
    },
    "cisco_xr": {
        "interfaces": ["show interfaces description"],
        "ip_addresses": ["show ipv4 interface brief"],
        "arp": ["show arp"],
        "routes": ["show route"],
        "version": ["show version"],
        "neighbors": ["show cdp neighbors", "show lldp neighbors"],
        "running_config": ["show running-config"],
    },
    "cisco_asa": {
        "interfaces": ["show interface ip brief"],
        "ip_addresses": ["show interface ip brief"],
        "arp": ["show arp"],
        "routes": ["show route"],
        "version": ["show version"],
        "running_config": ["show running-config"],
    },
    "arista_eos": {
        **_IOS_LIKE,
        "neighbors": ["show lldp neighbors"],
        "vlans": ["show vlan"],
    },
    "dell_os10": {
        **_IOS_LIKE,
        "neighbors": ["show lldp neighbors"],
        "vlans": ["show vlan"],
        "running_config": ["show running-configuration"],
    },
    "juniper_junos": {
        "interfaces": ["show interfaces descriptions"],
        "ip_addresses": ["show interfaces terse"],
        "arp": ["show arp no-resolve"],
        "mac_table": ["show ethernet-switching table"],
        "routes": ["show route"],
        "version": ["show version"],
        "neighbors": ["show lldp neighbors"],
        "vlans": ["show vlans"],
        "running_config": ["show configuration | display set"],
    },
    "mikrotik_routeros": {
        "interfaces": ["/interface print"],
        "ip_addresses": ["/ip address print"],
        "arp": ["/ip arp print"],
        "mac_table": ["/interface bridge host print"],
        "routes": ["/ip route print"],
        "version": ["/system resource print"],
        "neighbors": ["/ip neighbor print"],
        "vlans": ["/interface vlan print"],
        "running_config": ["/export"],
    },
    "huawei": _HUAWEI_LIKE,
    "huawei_vrpv8": _HUAWEI_LIKE,
    "hp_comware": _HUAWEI_LIKE,
    "hp_procurve": {
        "interfaces": ["show interfaces brief"],
        "ip_addresses": ["show ip"],
        "arp": ["show arp"],
        "mac_table": ["show mac-address"],
        "routes": ["show ip route"],
        "version": ["show version"],
        "neighbors": ["show lldp info remote-device"],
        "vlans": ["show vlans"],
        "running_config": ["show running-config"],
    },
    "aruba_aoscx": {
        **_IOS_LIKE,
        "neighbors": ["show lldp neighbor-info"],
        "vlans": ["show vlan"],
    },
    "extreme_exos": {
        "interfaces": ["show ports information"],
        "ip_addresses": ["show ipconfig"],
        "arp": ["show iparp"],
        "mac_table": ["show fdb"],
        "routes": ["show iproute"],
        "version": ["show version"],
        "neighbors": ["show lldp neighbors"],
        "vlans": ["show vlan"],
        "running_config": ["show configuration"],
    },
    "fortinet": {
        "interfaces": ["get system interface physical"],
        "ip_addresses": ["get system interface physical"],
        "arp": ["get system arp"],
        "routes": ["get router info routing-table all"],
        "version": ["get system status"],
        "running_config": ["show"],
    },
    "paloalto_panos": {
        "interfaces": ["show interface all"],
        "ip_addresses": ["show interface logical"],
        "arp": ["show arp all"],
        "mac_table": ["show mac all"],
        "routes": ["show routing route"],
        "version": ["show system info"],
        "running_config": ["show config running"],
    },
    "vyos": _VYOS_LIKE,
    "ubiquiti_edgerouter": _VYOS_LIKE,
    "linux": {
        "interfaces": ["ip -br link"],
        "ip_addresses": ["ip -br addr"],
        "arp": ["ip neigh"],
        "routes": ["ip route"],
        "version": ["uname -a"],
    },
}

MAX_OUTPUT_CHARS = 12000


def commands_for(device: Device, intent: str) -> list[str] | None:
    dt = device.device_type.lower()
    table = COMMAND_MAP.get(dt)
    if table is None:
        vendor = dt.split("_", 1)[0]
        table = next((v for k, v in COMMAND_MAP.items() if k.split("_", 1)[0] == vendor), None)
    if table is None:
        return None
    return table.get(intent)


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [output შემოკლდა, სულ {len(text)} სიმბოლო. გამოიყენე ფილტრი, მაგ. '| include']"


_PORT_LOCKS: dict[str, threading.Lock] = {}
_PORT_LOCKS_GUARD = threading.Lock()


def port_lock(port: str) -> threading.Lock:
    with _PORT_LOCKS_GUARD:
        return _PORT_LOCKS.setdefault(port.upper(), threading.Lock())


def _connect_serial(inventory: Inventory, device: Device):
    """Console cable: a COM port has one user at a time, so connections to it wait for each other."""
    from netmiko import ConnectHandler

    lock = port_lock(device.host)
    if not lock.acquire(timeout=60):
        raise ConnectionError(f"{device.host} დაკავებულია NetAgent-ის სხვა სესიით")
    try:
        try:
            cred = inventory.credential_for(device)
            user, password, secret = cred.username, cred.password, cred.secret
        except Exception:  # noqa: BLE001 - a console often has no login at all
            user, password, secret = "", "", ""
        params: dict[str, Any] = {"device_type": device.device_type, "username": user, "password": password,
                                  "serial_settings": {"port": device.host, "baudrate": device.baudrate, "bytesize": 8,
                                                      "parity": "N", "stopbits": 1, "timeout": 1},
                                  "conn_timeout": settings.device_timeout}
        if secret:
            params["secret"] = secret
        try:
            conn = ConnectHandler(**params)
        except Exception as exc:
            if "PermissionError" in repr(exc) or "Access is denied" in str(exc):
                raise ConnectionError(f"{device.host} სხვა პროგრამას უჭირავს (PuTTY / Tera Term?) — დახურე და სცადე თავიდან") from None
            raise
    except BaseException:
        lock.release()
        raise
    original = conn.disconnect

    def disconnect():
        try:
            original()
        finally:
            if lock.locked():
                lock.release()

    conn.disconnect = disconnect
    if secret:
        try:
            conn.enable()
        except Exception:  # noqa: BLE001
            pass
    return conn


def _connect(inventory: Inventory, device: Device):
    from netmiko import ConnectHandler  # imported lazily: slow import

    if device.is_serial:
        return _connect_serial(inventory, device)
    cred = inventory.credential_for(device)
    params: dict[str, Any] = {
        "device_type": device.device_type,
        "host": device.host,
        "port": device.port,
        "username": cred.username,
        "password": cred.password,
        "conn_timeout": settings.device_timeout,
        "auth_timeout": settings.device_timeout,
        "banner_timeout": settings.device_timeout,
    }
    if cred.secret:
        params["secret"] = cred.secret
    conn = ConnectHandler(**params)
    if cred.secret and device.device_type.startswith("cisco"):
        try:
            conn.enable()
        except Exception:
            pass
    return conn


def run_commands(
    inventory: Inventory,
    device: Device,
    commands: list[str],
    parse: bool = True,
    max_chars: int | None = MAX_OUTPUT_CHARS,
) -> list[dict[str, Any]]:
    """Run validated read-only commands on one device. Returns one entry per command.

    Raw output is truncated to `max_chars` (None = no limit, used for backups).
    """
    validated = [validate_command(c, device.device_type) for c in commands]
    results: list[dict[str, Any]] = []
    conn = _connect(inventory, device)
    try:
        for cmd in validated:
            try:
                out = conn.send_command(cmd, use_textfsm=parse, read_timeout=60)
            except Exception as exc:  # noqa: BLE001 - surface any device error to the agent
                results.append({"command": cmd, "error": f"{type(exc).__name__}: {exc}"})
                continue
            if isinstance(out, str):
                masked = mask_secrets(out)
                results.append({"command": cmd, "output": _truncate(masked, max_chars) if max_chars else masked})
            else:
                parsed = _mask_structured(out)
                results.append({"command": cmd, "parsed": parsed})
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return results


def _mask_structured(value: Any) -> Any:
    if isinstance(value, str):
        return mask_secrets(value)
    if isinstance(value, list):
        return [_mask_structured(v) for v in value]
    if isinstance(value, dict):
        return {k: _mask_structured(v) for k, v in value.items()}
    return value


def run_on_devices(
    inventory: Inventory, devices: list[Device], fn, precheck: bool = True
) -> dict[str, Any]:
    """Run fn(device) on many devices in parallel; collect results/errors by name.

    With several devices, a quick TCP check runs first so unreachable devices fail in
    seconds instead of each waiting for the full SSH timeout.
    """
    out: dict[str, Any] = {}
    if precheck and len(devices) > 1:
        from ..health import check_many

        reach = {r.device: r for r in check_many(devices, timeout=2.0)}
        for d in devices:
            if not reach[d.name].up:
                out[d.name] = {"error": f"მიუწვდომელია ({reach[d.name].reason})"}
        devices = [d for d in devices if reach[d.name].up]
    with ThreadPoolExecutor(max_workers=max(1, settings.max_parallel_devices)) as pool:
        futures = {pool.submit(fn, d): d for d in devices}
        for fut, dev in futures.items():
            try:
                out[dev.name] = fut.result()
            except Exception as exc:  # noqa: BLE001
                out[dev.name] = {"error": f"{type(exc).__name__}: {exc}"}
    return out


# ---------------------------------------------------------------------------
# Searching for an IP / subnet / MAC across devices
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_MAC_RE = re.compile(
    r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b|\b[0-9a-f]{12}\b",
    re.I,
)


def normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9a-f]", "", mac.lower())


def _line_matches(line: str, target: Any, kind: str) -> bool:
    if kind == "mac":
        return any(normalize_mac(m) == target for m in _MAC_RE.findall(line))
    for raw in _IPV4_RE.findall(line):
        try:
            iface = ipaddress.ip_interface(raw)
        except ValueError:
            continue
        if kind == "ip":
            # Exact host, or the line shows a subnet that contains the host.
            if iface.ip == target or (("/" in raw) and target in iface.network):
                return True
        elif kind == "network":
            if iface.ip in target:
                return True
    return False


def parse_search_target(query: str) -> tuple[str, Any]:
    q = query.strip()
    if _MAC_RE.fullmatch(q):
        return "mac", normalize_mac(q)
    if "/" in q:
        return "network", ipaddress.ip_network(q, strict=False)
    return "ip", ipaddress.ip_address(q)


def search_devices(inventory: Inventory, devices: list[Device], query: str) -> dict[str, Any]:
    kind, target = parse_search_target(query)
    intents = ["ip_addresses", "arp"] + (["mac_table"] if kind == "mac" else [])

    def one(device: Device) -> dict[str, Any]:
        cmds: list[str] = []
        for intent in intents:
            cmds += commands_for(device, intent) or []
        if not cmds:
            return {"skipped": f"device_type '{device.device_type}'-ისთვის ბრძანებები არ არის განსაზღვრული"}
        matches = []
        for res in run_commands(inventory, device, cmds, parse=False):
            if "error" in res:
                continue
            for line in res["output"].splitlines():
                if _line_matches(line, target, kind):
                    matches.append({"command": res["command"], "line": line.strip()})
        return {"matches": matches}

    results = run_on_devices(inventory, devices, one)
    found = {k: v for k, v in results.items() if v.get("matches")}
    errors = {k: v["error"] for k, v in results.items() if "error" in v}
    return {
        "query": query,
        "type": kind,
        "found_on": found,
        "not_found_on": [k for k, v in results.items() if "matches" in v and not v["matches"]],
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Subnet usage / free IP finder
# ---------------------------------------------------------------------------

MAX_USAGE_ADDRESSES = 4096  # /20 for IPv4
MAX_FREE_LISTED = 40


def addresses_in_lines(lines: list[str], network: ipaddress.IPv4Network) -> set[ipaddress.IPv4Address]:
    found = set()
    for line in lines:
        for raw in _IPV4_RE.findall(line):
            try:
                ip = ipaddress.ip_interface(raw).ip
            except ValueError:
                continue
            if ip in network:
                found.add(ip)
    return found


def summarize_usage(network: ipaddress.IPv4Network, used: dict[ipaddress.IPv4Address, set[str]]) -> dict[str, Any]:
    hosts = list(network.hosts()) if network.prefixlen < 31 else list(network)
    free = [ip for ip in hosts if ip not in used]
    return {
        "network": str(network),
        "usable_hosts": len(hosts),
        "used_count": len([ip for ip in used if ip in network]),
        "free_count": len(free),
        "used": [{"ip": str(ip), "seen_on": sorted(src)} for ip, src in sorted(used.items())],
        "free_sample": [str(ip) for ip in free[:MAX_FREE_LISTED]],
        "free_ranges": _ranges(free)[:20],
        "note": "თავისუფალი = არც ერთი მოწყობილობის ARP/ინტერფეისის ცხრილში არ ჩანს. გამორთული "
        "ან სტატიკური მოწყობილობა შეიძლება ARP-ში არ ჩანდეს — გამოყენებამდე შეამოწმე ping-ით.",
    }


def _ranges(ips: list[ipaddress.IPv4Address]) -> list[str]:
    out: list[str] = []
    if not ips:
        return out
    start = prev = ips[0]
    for ip in ips[1:]:
        if int(ip) == int(prev) + 1:
            prev = ip
            continue
        out.append(str(start) if start == prev else f"{start} - {prev}")
        start = prev = ip
    out.append(str(start) if start == prev else f"{start} - {prev}")
    return out


def subnet_usage(inventory: Inventory, devices: list[Device], network: str) -> dict[str, Any]:
    net = ipaddress.ip_network(network.strip(), strict=False)
    if net.version != 4:
        raise ValueError("ამჟამად მხოლოდ IPv4 ქსელებია მხარდაჭერილი")
    if net.num_addresses > MAX_USAGE_ADDRESSES:
        raise ValueError(f"ქსელი ძალიან დიდია (მაქს. /{32 - (MAX_USAGE_ADDRESSES.bit_length() - 1)})")

    def one(device: Device) -> dict[str, Any]:
        cmds: list[str] = []
        for intent in ("ip_addresses", "arp"):
            cmds += commands_for(device, intent) or []
        if not cmds:
            return {"skipped": True}
        lines: list[str] = []
        for res in run_commands(inventory, device, cmds, parse=False, max_chars=None):
            lines += res.get("output", "").splitlines()
        return {"ips": [str(ip) for ip in addresses_in_lines(lines, net)]}

    results = run_on_devices(inventory, devices, one)
    used: dict[ipaddress.IPv4Address, set[str]] = {}
    for name, r in results.items():
        for ip in r.get("ips", []):
            used.setdefault(ipaddress.IPv4Address(ip), set()).add(name)
    out = summarize_usage(net, used)
    out["errors"] = {k: v["error"] for k, v in results.items() if "error" in v}
    return out
