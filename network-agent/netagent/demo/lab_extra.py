"""Demo lab, part 2 (v0.9 features): live interface counters, routing tables for path trace,
ACL / firewall rules, VPN, DHCP pools and hardware inventory - plus their failure scenarios.
"""

from __future__ import annotations

import ipaddress
import random
import time

SCENARIOS = {
    "errors": "SW-Access-2-ის Gi1/0/5-ზე (AP-Lobby) CRC შეცდომები იზრდება — ცუდი კაბელი",
    "congestion": "R1-ის WAN ხაზი 96%-ითაა დატვირთული",
    "vpn": "VPN გვირაბი R1 ↔ MT-Branch დაეცა",
    "dhcp": "SW-Core-1-ზე USERS DHCP pool გაივსო",
}
LATER = {"errors": "ალერტი ~1-2 წთ-ში (/errors)", "congestion": "ალერტი ~1-2 წთ-ში (/traffic R1)",
         "vpn": "სცადე: /runbook vpn", "dhcp": "სცადე: /runbook dhcp"}


# -- interfaces ------------------------------------------------------------------------------
def _iface(name, desc, ip, bw_mbit, in_mbps, out_mbps, status="up", proto="up"):
    return {"name": name, "desc": desc, "ip": ip, "bw": bw_mbit * 1_000_000, "in": in_mbps * 1e6, "out": out_mbps * 1e6,
            "status": status, "proto": proto, "crc": 0, "in_err": 0, "out_err": 0, "resets": 1,
            "in_bytes": random.randint(10**9, 10**11), "out_bytes": random.randint(10**9, 10**11), "t": time.time()}


IFACES = {
    "R1": [_iface("GigabitEthernet0/0/0", "WAN - ISP Magti", "203.0.113.2/30", 1000, 180, 62),
           _iface("GigabitEthernet0/0/1", "LAN - SW-Core-1", "10.0.0.1/24", 1000, 60, 175),
           _iface("GigabitEthernet0/0/2", "unused", "", 1000, 0, 0, "administratively down", "down"),
           _iface("Tunnel0", "VPN to MT-Branch", "172.16.0.1/30", 100, 3, 4)],
    "SW-Core-1": [_iface("GigabitEthernet1/0/1", "Uplink R1", "10.0.0.2/24", 1000, 175, 60),
                  _iface("GigabitEthernet1/0/2", "Trunk SW-Access-2", "", 1000, 40, 120),
                  _iface("GigabitEthernet1/0/3", "", "", 1000, 0, 0, "down", "down")],
    "SW-Access-2": [_iface("GigabitEthernet1/0/1", "", "", 1000, 12, 30),
                    _iface("GigabitEthernet1/0/2", "", "", 1000, 4, 9),
                    _iface("GigabitEthernet1/0/5", "AP-Lobby", "", 1000, 25, 70),
                    _iface("GigabitEthernet1/0/48", "Uplink SW-Core-1", "", 1000, 120, 40)],
}
MT_IFACES = [("ether1", 70, 22), ("ether2", 8, 30), ("bridge-lan", 9, 31), ("wg-hq", 2, 3)]


def _tick(i: dict, faults: dict, dev: str) -> None:
    now = time.time()
    dt = now - i["t"]
    i["t"] = now
    if i["status"] != "up":
        return
    jitter = random.uniform(0.85, 1.15)
    rin, rout = i["in"] * jitter, i["out"] * jitter
    if faults.get("congestion") and dev == "R1" and i["name"].endswith("0/0/0"):
        rin, rout = 0.41e9, 0.962e9
    i["cur_in"], i["cur_out"] = int(rin), int(rout)
    i["in_bytes"] += int(rin * dt / 8)
    i["out_bytes"] += int(rout * dt / 8)
    if faults.get("errors") and dev == "SW-Access-2" and i["name"].endswith("1/0/5"):
        i["crc"] += random.randint(25, 80)
        i["in_err"] = i["crc"] + random.randint(0, 5)


def show_interfaces(dev: str, faults: dict) -> str:
    out = []
    for i in IFACES[dev]:
        down = faults.get("uplink") and dev == "R1" and i["name"].endswith("0/0/0")
        i["status"], i["proto"] = ("down", "down") if down else (i.get("_st", i["status"]), i.get("_pr", i["proto"]))
        i.setdefault("_st", i["status"])
        i.setdefault("_pr", i["proto"])
        _tick(i, faults, dev)
        load = lambda r: max(1, min(255, int(255 * r / i["bw"])))  # noqa: E731
        out.append(
            f"{i['name']} is {i['status']}, line protocol is {i['proto']}\n"
            f"  Hardware is Gigabit Ethernet, address is 00a3.d1aa.{random.randint(4096, 65535):04x}\n"
            + (f"  Description: {i['desc']}\n" if i["desc"] else "")
            + (f"  Internet address is {i['ip']}\n" if i["ip"] else "")
            + f"  MTU 1500 bytes, BW {i['bw'] // 1000} Kbit/sec, DLY 10 usec,\n"
            f"     reliability 255/255, txload {load(i.get('cur_out', 0))}/255, rxload {load(i.get('cur_in', 0))}/255\n"
            f"  Input queue: 0/375/0/0 (size/max/drops/flushes); Total output drops: 0\n"
            f"  5 minute input rate {i.get('cur_in', 0)} bits/sec, {i.get('cur_in', 0) // 9000} packets/sec\n"
            f"  5 minute output rate {i.get('cur_out', 0)} bits/sec, {i.get('cur_out', 0) // 9000} packets/sec\n"
            f"     {i['in_bytes'] // 900} packets input, {i['in_bytes']} bytes, 0 no buffer\n"
            f"     {i['in_err']} input errors, {i['crc']} CRC, 0 frame, 0 overrun, 0 ignored\n"
            f"     {i['out_bytes'] // 900} packets output, {i['out_bytes']} bytes, 0 underruns\n"
            f"     {i['out_err']} output errors, 0 collisions, {i['resets']} interface resets")
    return "\n".join(out)


_MT_STATE = {n: {"rx": random.randint(10**9, 10**10), "tx": random.randint(10**9, 10**10), "t": time.time(), "in": a, "out": b}
             for n, a, b in MT_IFACES}


def mt_stats(faults: dict) -> str:
    now = time.time()
    lines = []
    for idx, (name, st) in enumerate(_MT_STATE.items()):
        dt = now - st["t"]
        st["t"] = now
        st["rx"] += int(st["in"] * 1e6 * dt / 8 * random.uniform(0.8, 1.2))
        st["tx"] += int(st["out"] * 1e6 * dt / 8 * random.uniform(0.8, 1.2))
        running = not (faults.get("vpn") and name == "wg-hq")
        lines.append(f" {idx}  {'R' if running else ' '} name={name} rx-byte={st['rx']} tx-byte={st['tx']} "
                     f"rx-packet={st['rx'] // 800} tx-packet={st['tx'] // 800} rx-drop=0 tx-drop=0 rx-error=0 tx-error=0")
    return "\n".join(lines)


# -- routing -------------------------------------------------------------------------------------
ROUTES = {
    "R1": [("0.0.0.0/0", "203.0.113.1", "GigabitEthernet0/0/0"), ("203.0.113.0/30", None, "GigabitEthernet0/0/0"),
           ("10.0.0.0/24", None, "GigabitEthernet0/0/1"), ("192.168.10.0/24", "10.0.0.2", "GigabitEthernet0/0/1"),
           ("192.168.20.0/24", "10.0.0.2", "GigabitEthernet0/0/1"), ("10.20.0.0/24", "172.16.0.2", "Tunnel0"),
           ("172.16.0.0/30", None, "Tunnel0")],
    "SW-Core-1": [("0.0.0.0/0", "10.0.0.1", "GigabitEthernet1/0/1"), ("10.0.0.0/24", None, "GigabitEthernet1/0/1"),
                  ("192.168.10.0/24", None, "Vlan10"), ("192.168.20.0/24", None, "Vlan20")],
    "SW-Access-2": [("0.0.0.0/0", "10.0.0.1", "Vlan99"), ("10.0.0.0/24", None, "Vlan99")],
    "MT-Branch": [("0.0.0.0/0", "198.51.100.1", "ether1"), ("10.20.0.0/24", None, "bridge-lan"),
                  ("198.51.100.0/30", None, "ether1"), ("172.16.0.0/30", None, "wg-hq"),
                  ("10.0.0.0/24", "172.16.0.1", "wg-hq"), ("192.168.10.0/24", "172.16.0.1", "wg-hq")],
}
OWN = {"R1": ["203.0.113.2", "10.0.0.1", "1.1.1.1", "172.16.0.1"], "SW-Core-1": ["10.0.0.2", "192.168.10.1", "192.168.20.1"],
       "SW-Access-2": ["10.0.0.3"], "MT-Branch": ["10.20.0.1", "198.51.100.2", "172.16.0.2"]}


def _table(dev: str, faults: dict) -> list:
    t = ROUTES[dev]
    if faults.get("uplink") and dev == "R1":
        t = [r for r in t if r[0] != "0.0.0.0/0"]
    if faults.get("vpn") and dev in {"R1", "MT-Branch"}:
        t = [r for r in t if r[2] not in {"Tunnel0", "wg-hq"}]
    return t


def _best(dev: str, dst: str, faults: dict):
    ip = ipaddress.ip_address(dst)
    cands = [(ipaddress.ip_network(c), nh, i) for c, nh, i in _table(dev, faults) if ip in ipaddress.ip_network(c)]
    return max(cands, key=lambda c: c[0].prefixlen) if cands else None


def show_ip_cef(dev: str, rest: str, faults: dict) -> str:
    dst = rest.strip()
    try:
        ipaddress.ip_address(dst)
    except ValueError:
        return "% Invalid input detected at '^' marker."
    if dst in OWN[dev]:
        return f"{dst}/32\n  receive for interface"
    b = _best(dev, dst, faults)
    if not b:
        return "0.0.0.0/0\n  no route"
    net, nh, iface = b
    return f"{net}\n  nexthop {nh} {iface}" if nh else f"{net}\n  attached to {iface}"


def mt_route_where(rest: str, faults: dict) -> str:
    dst = rest.split()[0] if rest.split() else ""
    try:
        ip = ipaddress.ip_address(dst)
    except ValueError:
        return "syntax error"
    lines = ["Flags: D - DYNAMIC; A - ACTIVE; c - CONNECT, s - STATIC", "Columns: DST-ADDRESS, GATEWAY, DISTANCE",
             "#     DST-ADDRESS        GATEWAY        DISTANCE"]
    for i, (c, nh, iface) in enumerate(_table("MT-Branch", faults)):
        if ip in ipaddress.ip_network(c):
            lines.append(f"{i}  {'As ' if nh else 'DAc'} {c:<18} {nh or iface:<14} {1 if nh else 0}")
    return "\n".join(lines)


# -- static extras -----------------------------------------------------------------------------
R1_ACL = """Standard IP access list MGMT
    10 permit 10.0.0.0, wildcard bits 0.0.0.255 (1204 matches)
    20 permit 192.168.10.50 (31 matches)
Extended IP access list OUTSIDE-IN
    10 permit tcp any host 203.0.113.2 eq 22 (45 matches)
    20 permit udp any host 203.0.113.2 eq isakmp (310 matches)
    30 permit esp any host 203.0.113.2 (9120 matches)
    40 deny ip 45.155.205.0 0.0.0.255 any log (17 matches)
    45 permit tcp 45.155.205.0 0.0.0.255 host 203.0.113.2 eq 443
    50 permit tcp any host 203.0.113.2 eq www
    60 deny tcp any host 203.0.113.2 eq 22
    70 deny ip any any log (5210 matches)"""

MT_FILTER = """/ip firewall filter add action=accept chain=input comment="established" connection-state=established,related
/ip firewall filter add action=accept chain=input protocol=icmp
/ip firewall filter add action=accept chain=input dst-port=22,8291 protocol=tcp src-address=10.0.0.0/8
/ip firewall filter add action=accept chain=input dst-port=22 protocol=tcp src-address=10.20.0.0/24
/ip firewall filter add action=drop chain=input in-interface=ether1
/ip firewall filter add action=fasttrack-connection chain=forward connection-state=established,related
/ip firewall filter add action=accept chain=forward connection-state=established,related
/ip firewall filter add action=accept chain=forward src-address=10.20.0.0/24"""

INVENTORY = {
    "R1": 'NAME: "Chassis", DESCR: "Cisco ISR4331 Chassis"\nPID: ISR4331/K9       , VID: V04  , SN: FDO21520XYZ\n\n'
          'NAME: "Power Supply Module 0", DESCR: "250W AC Power Supply for Cisco ISR 4330"\nPID: PWR-4330-AC      , VID: V02  , SN: PST2150A1B2',
    "SW-Core-1": 'NAME: "c38xx Stack", DESCR: "c38xx Stack"\nPID: WS-C3850-24T     , VID: V07  , SN: FCW2133D0AB',
    "SW-Access-2": 'NAME: "1", DESCR: "WS-C2960X-48FPD-L"\nPID: WS-C2960X-48FPD-L , VID: V05  , SN: FOC1945X1YZ',
}


def isakmp(faults: dict) -> str:
    state = ("MM_NO_STATE", "ACTIVE") if faults.get("vpn") else ("QM_IDLE", "ACTIVE")
    return ("IPv4 Crypto ISAKMP SA\ndst             src             state          conn-id status\n"
            f"198.51.100.2    203.0.113.2     {state[0]:<14} {1001:>7} {state[1]}")


_VPN = {"enc": 15233, "dec": 14980}


def ipsec_sa(faults: dict) -> str:
    _VPN["enc"] += random.randint(20, 90)
    if not faults.get("vpn"):
        _VPN["dec"] += random.randint(20, 90)
    return ("interface: Tunnel0\n    Crypto map tag: Tunnel0-head-0, local addr 203.0.113.2\n"
            "   current_peer 198.51.100.2 port 500\n"
            f"    #pkts encaps: {_VPN['enc']}, #pkts encrypt: {_VPN['enc']}, #pkts digest: {_VPN['enc']}\n"
            f"    #pkts decaps: {_VPN['dec']}, #pkts decrypt: {_VPN['dec']}, #pkts verify: {_VPN['dec']}")


def dhcp_pool(faults: dict) -> str:
    leased = 254 if faults.get("dhcp") else 231
    return (f"Pool USERS :\n Utilization mark (high/low)    : 100 / 0\n Total addresses                : 254\n"
            f" Leased addresses               : {leased}\n Pending event                  : none\n"
            "Pool VOICE :\n Total addresses                : 254\n Leased addresses               : 12\n")


def extend(devices: dict, faults: dict) -> None:
    """Add the v0.9 outputs/handlers to the FakeDevices built by lab.build_devices."""
    for name in ("R1", "SW-Core-1", "SW-Access-2"):
        d = devices[name]
        d.outputs["show interfaces"] = lambda n=name: show_interfaces(n, faults)
        d.outputs["show processes memory sorted | include Processor"] = (
            "Processor Pool Total:  1795999744 Used:  " + str(612_000_000 + random.randint(0, 9_000_000)) + " Free: 1183999744")
        d.outputs["show inventory"] = INVENTORY[name]
        d.handlers.append(("show ip cef ", lambda rest, n=name: show_ip_cef(n, rest, faults)))
        d.outputs["show ip dhcp pool"] = (lambda: dhcp_pool(faults)) if name == "SW-Core-1" else ""
        d.outputs["show ip dhcp conflict"] = ("IP address        Detection method   Detection time          VRF\n"
                                              "192.168.10.77     Ping               Nov 04 2026 09:12 AM") if name == "SW-Core-1" else ""
    r1 = devices["R1"]
    r1.outputs["show access-lists"] = R1_ACL
    r1.outputs["show crypto isakmp sa"] = lambda: isakmp(faults)
    r1.outputs["show crypto ipsec sa"] = lambda: ipsec_sa(faults)
    base_desc = r1.outputs["show interfaces description"]
    r1.outputs["show interfaces description"] = lambda: base_desc.replace(
        "Tu0                            up             up", "Tu0                            up             down") if faults.get("vpn") else base_desc
    mt = devices["MT-Branch"]
    mt.outputs["/interface print stats terse"] = lambda: mt_stats(faults)
    mt.outputs["/system resource print"] = mt.outputs["/system resource print"].replace("board-name: CHR", "board-name: hEX S")
    mt.outputs["/system routerboard print"] = ("routerboard: yes\nboard-name: hEX S\nmodel: RB760iGS\n"
                                               "serial-number: HE10AB1C2D3\nfirmware-type: mt7621L\ncurrent-firmware: 7.16.1")
    mt.outputs["/ip address print"] += "\n 2   172.16.0.2/30      172.16.0.0    wg-hq"
    mt.outputs["/ip firewall filter export terse"] = MT_FILTER
    mt.outputs["/ip ipsec active-peers print"] = lambda: "" if faults.get("vpn") else \
        " 0 R  198.51.100.2 established 3d4h5m"
    mt.outputs["/interface wireguard peers print"] = lambda: "Flags: X - disabled\n 0  interface=wg-hq endpoint-address=203.0.113.2 " \
        + ("last-handshake=never" if faults.get("vpn") else "last-handshake=37s")
    mt.outputs["/ip pool used print count-only"] = "18"
    mt.outputs["/ip dhcp-server lease print count-only"] = "18"
    mt.handlers.append(("/ip route print where ", lambda rest: mt_route_where(rest, faults)))
