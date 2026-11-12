"""Subnet / CIDR calculator (IPv4 and IPv6)."""

from __future__ import annotations

import ipaddress
from typing import Any

MAX_SUBNETS_LISTED = 64


def subnet_info(network: str, split_prefix: int | None = None) -> dict[str, Any]:
    """Describe a network. Accepts '192.168.1.10/24', '10.0.0.0 255.255.0.0', '2001:db8::/48'."""
    text = network.strip()
    if " " in text and "/" not in text:
        addr, mask = text.split(None, 1)
        text = f"{addr}/{mask.strip()}"
    iface = ipaddress.ip_interface(text)
    net = iface.network
    info: dict[str, Any] = {
        "input": network,
        "version": net.version,
        "network": str(net.network_address),
        "prefix": f"/{net.prefixlen}",
        "cidr": str(net),
        "total_addresses": net.num_addresses,
        "is_private": net.is_private,
    }
    if net.version == 4:
        hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
        info.update(
            {
                "netmask": str(net.netmask),
                "wildcard": str(net.hostmask),
                "broadcast": str(net.broadcast_address) if net.prefixlen < 31 else None,
                "first_host": str(net.network_address + 1) if net.prefixlen < 31 else str(net.network_address),
                "last_host": str(net.broadcast_address - 1) if net.prefixlen < 31 else str(net.broadcast_address),
                "usable_hosts": hosts,
            }
        )
    if iface.ip != net.network_address:
        info["given_address"] = str(iface.ip)
    if split_prefix is not None:
        split_prefix = int(split_prefix)
        if split_prefix <= net.prefixlen or split_prefix > net.max_prefixlen:
            raise ValueError(f"split_prefix უნდა იყოს {net.prefixlen + 1}-{net.max_prefixlen} შუალედში")
        count = 2 ** (split_prefix - net.prefixlen)
        subs = []
        for i, sub in enumerate(net.subnets(new_prefix=split_prefix)):
            if i >= MAX_SUBNETS_LISTED:
                break
            subs.append(str(sub))
        info["split"] = {"new_prefix": f"/{split_prefix}", "count": count, "subnets": subs,
                         "truncated": count > MAX_SUBNETS_LISTED}
    return info


def ip_in_network(address: str, network: str) -> dict[str, Any]:
    ip = ipaddress.ip_address(address.strip())
    net = ipaddress.ip_network(network.strip(), strict=False)
    return {"address": str(ip), "network": str(net), "contained": ip in net}
