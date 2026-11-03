"""Deterministic extraction of network data (IPs, subnets, MACs, VLANs) from text.

Used for uploaded configs/logs so the agent gets an exact list instead of
having to scan thousands of lines itself.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any

_IPV4 = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
_IPV4_CIDR_RE = re.compile(rf"(?<![\d.])({_IPV4})(?:/(\d{{1,2}}))?(?![\d.])")
_IP_MASK_RE = re.compile(rf"\bip address\s+({_IPV4})\s+({_IPV4})(\s+secondary)?", re.I)
# Loose candidate match; every candidate is validated with the ipaddress module.
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?)(?![0-9A-Fa-f:])")
_MAC_RE = re.compile(
    r"\b((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})\b"
)
_VLAN_RE = re.compile(r"\bvlan(?:\s+|-?id\s*=?\s*|=)?(\d{1,4})\b", re.I)
_VLAN_NAME_RE = re.compile(r"^\s*vlan\s+(\d{1,4})\s*\n\s+name\s+(\S+)", re.I | re.M)
_INTERFACE_BLOCK_RE = re.compile(r"^interface\s+(\S+)\s*\n((?:[ \t]+.*\n?)*)", re.I | re.M)

MAX_ITEMS = 500


def _is_mask(addr: str) -> bool:
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{addr}")
        return addr.startswith("255.") or addr == "0.0.0.0"
    except ValueError:
        return False


def extract_network_data(text: str) -> dict[str, Any]:
    ipv4 = Counter()
    cidrs: set[str] = set()
    for m in _IPV4_CIDR_RE.finditer(text):
        addr, prefix = m.group(1), m.group(2)
        if _is_mask(addr):
            continue
        if prefix is not None and int(prefix) <= 32:
            cidrs.add(str(ipaddress.ip_interface(f"{addr}/{prefix}")))
        ipv4[addr] += 1

    for m in _IP_MASK_RE.finditer(text):
        try:
            cidrs.add(str(ipaddress.ip_interface(f"{m.group(1)}/{m.group(2)}")))
        except ValueError:
            pass

    ipv6: set[str] = set()
    for m in _IPV6_RE.finditer(text):
        cand = m.group(1)
        if not re.search(r"[0-9A-Fa-f]", cand):
            continue
        try:
            ipaddress.ip_interface(cand)
            ipv6.add(cand.lower())
        except ValueError:
            continue

    macs = sorted({m.group(1).lower() for m in _MAC_RE.finditer(text)})
    vlans = sorted({int(v) for v in _VLAN_RE.findall(text) if 1 <= int(v) <= 4094})
    vlan_names = {int(v): n for v, n in _VLAN_NAME_RE.findall(text)}

    interfaces = []
    for name, body in _INTERFACE_BLOCK_RE.findall(text):
        entry: dict[str, Any] = {"interface": name}
        desc = re.search(r"^\s+description\s+(.+)$", body, re.M | re.I)
        if desc:
            entry["description"] = desc.group(1).strip()
        addrs = []
        for m in _IP_MASK_RE.finditer(body):
            try:
                ip = str(ipaddress.ip_interface(f"{m.group(1)}/{m.group(2)}"))
                addrs.append(ip + (" (secondary)" if m.group(3) else ""))
            except ValueError:
                pass
        if addrs:
            entry["ip_addresses"] = addrs
        acc = re.search(r"switchport access vlan\s+(\d+)", body, re.I)
        if acc:
            entry["access_vlan"] = int(acc.group(1))
        if re.search(r"^\s+shutdown\s*$", body, re.M | re.I):
            entry["shutdown"] = True
        if len(entry) > 1:
            interfaces.append(entry)

    networks = sorted(
        {str(ipaddress.ip_interface(c).network) for c in cidrs},
        key=lambda n: ipaddress.ip_network(n),
    )

    def cap(items: list) -> list:
        return items[:MAX_ITEMS]

    return {
        "ipv4_addresses": cap(sorted(ipv4, key=lambda a: ipaddress.ip_address(a))),
        "ipv4_with_prefix": cap(sorted(cidrs, key=lambda c: ipaddress.ip_interface(c))),
        "networks": cap(networks),
        "ipv6": cap(sorted(ipv6)),
        "mac_addresses": cap(macs),
        "vlans": cap(vlans),
        "vlan_names": vlan_names,
        "interfaces": cap(interfaces),
        "counts": {
            "ipv4": len(ipv4),
            "networks": len(networks),
            "ipv6": len(ipv6),
            "mac": len(macs),
            "vlans": len(vlans),
            "interfaces_with_data": len(interfaces),
        },
    }
