"""Simulated network for the demo: SSH servers that answer like Cisco IOS / MikroTik devices.

Each device listens on its own loopback address (127.0.0.11-14) when the OS allows it,
otherwise on 127.0.0.1 with different ports. Scenarios change what the devices report
(and send matching syslog messages) so alerts can be tried without real hardware.
"""

from __future__ import annotations

import logging
import random
import socket
import threading
from dataclasses import dataclass, field

log = logging.getLogger("netagent.demo")
logging.getLogger("netagent.demo.ssh").setLevel(logging.CRITICAL)

LAB = None  # the running DemoLab (set by start_lab), used by the /demo command

USER, PASSWORD = "admin", "demo"

R1_CONFIG = """Building configuration...

Current configuration : 2154 bytes
!
version 17.9
service timestamps log datetime msec
hostname R1
!
enable secret 9 $9$demo$demo
username admin privilege 15 secret 9 $9$demo$demo
!
ip domain name corp.local
ip ssh version 2
ip http server
!
interface GigabitEthernet0/0/0
 description WAN - ISP Magti
 ip address 203.0.113.2 255.255.255.252
 ip nat outside
!
interface GigabitEthernet0/0/1
 description LAN - SW-Core-1
 ip address 10.0.0.1 255.255.255.0
 ip nat inside
!
interface GigabitEthernet0/0/2
 description unused
 no ip address
 shutdown
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
interface Tunnel0
 description VPN to MT-Branch
 ip address 172.16.0.1 255.255.255.252
!
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
!
router bgp 65010
 neighbor 203.0.113.1 remote-as 65100
 neighbor 172.16.0.2 remote-as 65020
!
ip route 0.0.0.0 0.0.0.0 203.0.113.1
snmp-server community public RO
logging host 10.0.0.250
!
line vty 0 4
 transport input telnet ssh
!
end"""

SW_CORE_CONFIG = """Building configuration...

Current configuration : 1850 bytes
!
hostname SW-Core-1
service password-encryption
aaa new-model
ip ssh version 2
ntp server 10.0.0.1
logging host 10.0.0.250
banner login ^Authorized access only^
!
vlan 10
 name USERS
vlan 20
 name VOICE
vlan 99
 name MGMT
!
interface GigabitEthernet1/0/1
 description Uplink R1
 no switchport
 ip address 10.0.0.2 255.255.255.0
!
interface GigabitEthernet1/0/2
 description Trunk SW-Access-2
 switchport mode trunk
!
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
!
interface Vlan20
 ip address 192.168.20.1 255.255.255.0
!
line vty 0 15
 access-class MGMT in
 transport input ssh
!
end"""

SW_ACCESS_CONFIG = """Building configuration...

hostname SW-Access-2
ip ssh version 2
!
interface GigabitEthernet1/0/1
 switchport access vlan 10
!
interface GigabitEthernet1/0/2
 switchport access vlan 10
!
interface GigabitEthernet1/0/5
 description AP-Lobby
 switchport access vlan 10
!
interface GigabitEthernet1/0/48
 description Uplink SW-Core-1
 switchport mode trunk
!
interface Vlan99
 ip address 10.0.0.3 255.255.255.0
!
snmp-server community private RW
line vty 0 4
 transport input ssh
end"""

MT_EXPORT = """# 2026-11-04 09:00:00 by RouterOS 7.16.1
# model = CHR
/interface bridge
add name=bridge-lan
/ip address
add address=10.20.0.1/24 interface=bridge-lan network=10.20.0.0
add address=198.51.100.2/30 interface=ether1 network=198.51.100.0
/ip dns
set allow-remote-requests=yes
/ip route
add dst-address=0.0.0.0/0 gateway=198.51.100.1
/system identity
set name=MT-Branch
"""


def _cdp_entry(name: str, ip: str, platform: str, local: str, remote: str) -> str:
    return (f"-------------------------\nDevice ID: {name}.corp.local\nEntry address(es): \n  IP address: {ip}\n"
            f"Platform: cisco {platform},  Capabilities: Router Switch IGMP \n"
            f"Interface: {local},  Port ID (outgoing port): {remote}\nHoldtime : 155 sec\n\n"
            f"Version :\nCisco IOS Software\n\nadvertisement version: 2\n\n")


def _arp(ip_mac_if: list[tuple[str, str, str]]) -> str:
    lines = ["Protocol  Address          Age (min)  Hardware Addr   Type   Interface"]
    for ip, mac, intf in ip_mac_if:
        lines.append(f"Internet  {ip:<16} {random.choice(['-', '3', '12', '0']):>9}   {mac}  ARPA   {intf}")
    return "\n".join(lines)


# Real vendor OUIs so the MAC lookup has something to find.
LAN_HOSTS = [
    ("192.168.10.21", "a45e.6012.ab01", "Vlan10"),   # Apple
    ("192.168.10.22", "f8bc.1201.ab02", "Vlan10"),   # Dell
    ("192.168.10.23", "3cd9.2b01.ab03", "Vlan10"),   # HP
    ("192.168.10.30", "dca6.32aa.0004", "Vlan10"),   # Raspberry Pi
    ("192.168.20.11", "0004.f2aa.0011", "Vlan20"),   # Polycom phone
]


@dataclass
class FakeDevice:
    name: str
    kind: str  # "cisco" | "mikrotik"
    ip: str
    port: int
    outputs: dict = field(default_factory=dict)  # command -> text, or a function returning text (live data)
    online: bool = True
    handlers: list = field(default_factory=list)  # (command prefix, fn(rest) -> text)

    @property
    def prompt(self) -> str:
        return f"[admin@{self.name}] > " if self.kind == "mikrotik" else f"{self.name}#"


def build_devices(ips: list[str], ports: list[int]) -> dict[str, FakeDevice]:
    r1, core, acc, mt = (FakeDevice("R1", "cisco", ips[0], ports[0]), FakeDevice("SW-Core-1", "cisco", ips[1], ports[1]),
                         FakeDevice("SW-Access-2", "cisco", ips[2], ports[2]), FakeDevice("MT-Branch", "mikrotik", ips[3], ports[3]))
    r1.outputs = {
        "show version": "Cisco IOS XE Software, Version 17.09.04a\nCisco IOS Software [Cupertino], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.4a, RELEASE SOFTWARE (fc5)\nR1 uptime is 5 weeks, 2 days, 3 hours, 12 minutes\ncisco ISR4331/K9 (1RU) processor with 1795999K/6147K bytes of memory.\nProcessor board ID FDO21520XYZ",
        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0/0   203.0.113.2     YES NVRAM  up                    up\nGigabitEthernet0/0/1   10.0.0.1        YES NVRAM  up                    up\nGigabitEthernet0/0/2   unassigned      YES NVRAM  administratively down down\nLoopback0              1.1.1.1         YES NVRAM  up                    up\nTunnel0                172.16.0.1      YES NVRAM  up                    up",
        "show interfaces description": "Interface                      Status         Protocol Description\nGi0/0/0                        up             up       WAN - ISP Magti\nGi0/0/1                        up             up       LAN - SW-Core-1\nGi0/0/2                        admin down     down     unused\nLo0                            up             up\nTu0                            up             up       VPN to MT-Branch",
        "show ip arp": _arp([("203.0.113.1", "0026.cb11.2201", "GigabitEthernet0/0/0"), ("10.0.0.2", "00a3.d1aa.0002", "GigabitEthernet0/0/1"),
                            ("10.0.0.3", "00a3.d1aa.0003", "GigabitEthernet0/0/1")]),
        "show ip route": "Codes: L - local, C - connected, S - static, O - OSPF, B - BGP, * - candidate default\n\nGateway of last resort is 203.0.113.1 to network 0.0.0.0\n\nS*    0.0.0.0/0 [1/0] via 203.0.113.1\n      1.0.0.0/32 is subnetted, 1 subnets\nC        1.1.1.1 is directly connected, Loopback0\nC     10.0.0.0/24 is directly connected, GigabitEthernet0/0/1\nB     10.20.0.0/24 [20/0] via 172.16.0.2, 3d04h\nO     192.168.10.0/24 [110/2] via 10.0.0.2, 5w2d, GigabitEthernet0/0/1\nO     192.168.20.0/24 [110/2] via 10.0.0.2, 5w2d, GigabitEthernet0/0/1\nC     203.0.113.0/30 is directly connected, GigabitEthernet0/0/0",
        "show ip route 0.0.0.0": "Routing entry for 0.0.0.0/0, supernet\n  Known via \"static\", distance 1, metric 0, candidate default path\n  Routing Descriptor Blocks:\n  * 203.0.113.1\n      Route metric is 0, traffic share count is 1",
        "ping 8.8.8.8 repeat 3 timeout 1": "Type escape sequence to abort.\nSending 3, 100-byte ICMP Echos to 8.8.8.8, timeout is 1 seconds:\n!!!\nSuccess rate is 100 percent (3/3), round-trip min/avg/max = 11/12/14 ms",
        "show ip bgp summary": "BGP router identifier 1.1.1.1, local AS number 65010\nNeighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n172.16.0.2      4        65020    4410    4402      120    0    0 3d04h            5\n203.0.113.1     4        65100   88120   44210      120    0    0 5w2d           812",
        "show ip ospf neighbor": "Neighbor ID     Pri   State           Dead Time   Address         Interface\n2.2.2.2           1   FULL/DR         00:00:35    10.0.0.2        GigabitEthernet0/0/1",
        "show processes cpu | include CPU utilization": "CPU utilization for five seconds: 9%/1%; one minute: 8%; five minutes: 7%",
        "show cdp neighbors detail": _cdp_entry("SW-Core-1", ips[1], "WS-C3850-24T", "GigabitEthernet0/0/1", "GigabitEthernet1/0/1"),
        "show running-config": R1_CONFIG,
    }
    core.outputs = {
        "show version": "Cisco IOS XE Software, Version 16.12.04\nCisco IOS Software [Gibraltar], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4\nSW-Core-1 uptime is 12 weeks, 1 day, 4 hours, 2 minutes\ncisco WS-C3850-24T (MIPS) processor",
        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet1/0/1   10.0.0.2        YES NVRAM  up                    up\nGigabitEthernet1/0/2   unassigned      YES unset  up                    up\nGigabitEthernet1/0/3   unassigned      YES unset  down                  down\nVlan10                 192.168.10.1    YES NVRAM  up                    up\nVlan20                 192.168.20.1    YES NVRAM  up                    up",
        "show interfaces description": "Interface                      Status         Protocol Description\nGi1/0/1                        up             up       Uplink R1\nGi1/0/2                        up             up       Trunk SW-Access-2\nGi1/0/3                        down           down\nVl10                           up             up       USERS\nVl20                           up             up       VOICE",
        "show ip arp": _arp([("10.0.0.1", "0026.cb11.0001", "GigabitEthernet1/0/1"), *LAN_HOSTS]),
        "show mac address-table": "          Mac Address Table\n-------------------------------------------\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  10    a45e.6012.ab01    DYNAMIC     Gi1/0/2\n  10    f8bc.1201.ab02    DYNAMIC     Gi1/0/2\n  10    3cd9.2b01.ab03    DYNAMIC     Gi1/0/2\n  10    dca6.32aa.0004    DYNAMIC     Gi1/0/2\n  20    0004.f2aa.0011    DYNAMIC     Gi1/0/2",
        "show vlan brief": "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n1    default                          active    Gi1/0/3\n10   USERS                            active\n20   VOICE                            active\n99   MGMT                             active",
        "show ip route": "Gateway of last resort is 10.0.0.1 to network 0.0.0.0\n\nO*E2  0.0.0.0/0 [110/1] via 10.0.0.1, 5w2d, GigabitEthernet1/0/1\nC     10.0.0.0/24 is directly connected, GigabitEthernet1/0/1\nC     192.168.10.0/24 is directly connected, Vlan10\nC     192.168.20.0/24 is directly connected, Vlan20",
        "show ip ospf neighbor": "Neighbor ID     Pri   State           Dead Time   Address         Interface\n1.1.1.1           1   FULL/BDR        00:00:33    10.0.0.1        GigabitEthernet1/0/1",
        "show processes cpu | include CPU utilization": "CPU utilization for five seconds: 14%/2%; one minute: 12%; five minutes: 11%",
        "show cdp neighbors detail": _cdp_entry("R1", ips[0], "ISR4331/K9", "GigabitEthernet1/0/1", "GigabitEthernet0/0/1")
        + _cdp_entry("SW-Access-2", ips[2], "WS-C2960X-48", "GigabitEthernet1/0/2", "GigabitEthernet1/0/48"),
        "show running-config": SW_CORE_CONFIG,
    }
    acc.outputs = {
        "show version": "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8\nSW-Access-2 uptime is 30 weeks, 4 days\ncisco WS-C2960X-48FPD-L (APM86XXX) processor",
        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet1/0/1   unassigned      YES unset  up                    up\nGigabitEthernet1/0/2   unassigned      YES unset  up                    up\nGigabitEthernet1/0/3   unassigned      YES unset  down                  down\nGigabitEthernet1/0/5   unassigned      YES unset  up                    up\nGigabitEthernet1/0/48  unassigned      YES unset  up                    up\nVlan99                 10.0.0.3        YES NVRAM  up                    up",
        "show interfaces description": "Interface                      Status         Protocol Description\nGi1/0/1                        up             up\nGi1/0/2                        up             up\nGi1/0/3                        down           down\nGi1/0/5                        up             up       AP-Lobby\nGi1/0/48                       up             up       Uplink SW-Core-1",
        "show ip arp": _arp([("10.0.0.1", "0026.cb11.0001", "Vlan99"), ("10.0.0.2", "00a3.d1aa.0002", "Vlan99")]),
        "show mac address-table": "          Mac Address Table\n-------------------------------------------\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  10    a45e.6012.ab01    DYNAMIC     Gi1/0/1\n  10    f8bc.1201.ab02    DYNAMIC     Gi1/0/2\n  10    00f2.8b1c.aa05    DYNAMIC     Gi1/0/5",
        "show vlan brief": "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n10   USERS                            active    Gi1/0/1, Gi1/0/2, Gi1/0/5\n99   MGMT                             active",
        "show processes cpu | include CPU utilization": "CPU utilization for five seconds: 5%/0%; one minute: 4%; five minutes: 4%",
        "show cdp neighbors detail": _cdp_entry("SW-Core-1", ips[1], "WS-C3850-24T", "GigabitEthernet1/0/48", "GigabitEthernet1/0/2")
        + _cdp_entry("AP-Lobby", "10.0.0.50", "AIR-AP2802I", "GigabitEthernet1/0/5", "GigabitEthernet0"),
        "show running-config": SW_ACCESS_CONFIG,
    }
    mt.outputs = {
        "/system identity print": "name: MT-Branch",
        "/system resource print": "uptime: 3w2d4h\nversion: 7.16.1 (stable)\ncpu-load: 6%\nfree-memory: 820.4MiB\ntotal-memory: 1024.0MiB\nboard-name: CHR",
        "/interface print terse": " 0  R name=ether1 default-name=ether1 type=ether mtu=1500 comment=WAN\n 1  R name=ether2 default-name=ether2 type=ether mtu=1500\n 2    name=ether3 default-name=ether3 type=ether mtu=1500\n 3  R name=bridge-lan type=bridge mtu=1500",
        "/interface print": "Flags: R - RUNNING\n #   NAME        TYPE    MTU\n 0 R ether1      ether   1500\n 1 R ether2      ether   1500\n 2   ether3      ether   1500\n 3 R bridge-lan  bridge  1500",
        "/ip address print": "Flags: D - DYNAMIC\n #   ADDRESS            NETWORK       INTERFACE\n 0   10.20.0.1/24       10.20.0.0     bridge-lan\n 1   198.51.100.2/30    198.51.100.0  ether1",
        "/ip arp print": "Flags: D - DYNAMIC; C - COMPLETE\n #    ADDRESS       MAC-ADDRESS        INTERFACE\n 0 DC 10.20.0.15    A4:5E:60:22:01:15  bridge-lan\n 1 DC 10.20.0.16    E4:5F:01:11:22:16  bridge-lan\n 2 DC 198.51.100.1  00:26:CB:99:00:01  ether1",
        "/ip route print": "Flags: D - DYNAMIC; A - ACTIVE; c - CONNECT, s - STATIC\n     DST-ADDRESS       GATEWAY       DISTANCE\n0  As 0.0.0.0/0         198.51.100.1         1\n1 DAc 10.20.0.0/24      bridge-lan           0\n2 DAc 198.51.100.0/30   ether1               0",
        "/ip route print where dst-address=0.0.0.0/0": "Flags: A - ACTIVE; s - STATIC\n     DST-ADDRESS  GATEWAY       DISTANCE\n0  As 0.0.0.0/0    198.51.100.1         1",
        "/ip neighbor print detail": "",
        "/export": MT_EXPORT,
    }
    devices = {d.name: d for d in (r1, core, acc, mt)}
    from . import lab_extra

    lab_extra.extend(devices, FAULTS)
    return devices


FAULTS: dict = {}  # active scenario flags read by the live outputs in lab_extra

ALIASES = {"show run": "show running-config", "sh run": "show running-config", "show ver": "show version",
           "sh ip int br": "show ip interface brief", "show ip int brief": "show ip interface brief"}


def _out(value) -> str:
    return value() if callable(value) else value


def respond(device: FakeDevice, line: str) -> str:
    import re

    line = ALIASES.get(line, line)
    if line in device.outputs:
        return _out(device.outputs[line])
    for prefix, fn in device.handlers:
        if line.startswith(prefix):
            return fn(line[len(prefix):])
    if not line or line.startswith(("terminal", "screen-length")):
        return ""
    if line.startswith("show clock"):
        import datetime

        return datetime.datetime.utcnow().strftime("*%H:%M:%S.000 UTC %a %b %d %Y")
    if device.kind == "cisco" and "|" in line:
        base, _, flt = line.partition("|")
        base = ALIASES.get(base.strip(), base.strip())
        if base in device.outputs:
            mode, _, needle = flt.strip().partition(" ")
            rows = _out(device.outputs[base]).splitlines()
            try:
                rx = re.compile(needle, re.I)  # IOS include/exclude take a regex
            except re.error:
                rx = re.compile(re.escape(needle), re.I)
            if mode.startswith("inc"):
                return "\n".join(r for r in rows if rx.search(r))
            if mode.startswith("exc"):
                return "\n".join(r for r in rows if not rx.search(r))
            if mode.startswith("beg"):
                for i, r in enumerate(rows):
                    if needle.lower() in r.lower():
                        return "\n".join(rows[i:])
    if device.kind == "mikrotik":
        return "bad command name (line 1 column 2)"
    return "% Invalid input detected at '^' marker."


class _Server:
    """One SSH listener for one fake device."""

    def __init__(self, device: FakeDevice, host_key) -> None:
        self.device = device
        self.host_key = host_key
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.device.ip, self.device.port))
        self.sock.listen(20)
        self.thread = threading.Thread(target=self._accept_loop, daemon=True, name=f"demo-{self.device.name}")
        self.thread.start()

    def stop(self) -> None:
        sock, self.sock = self.sock, None
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)  # Linux: wakes the thread blocked in accept()
            except OSError:
                pass
            sock.close()
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None

    def _accept_loop(self) -> None:
        sock = self.sock
        while sock is not None and self.sock is sock:
            try:
                conn, _ = sock.accept()
            except OSError:
                break
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn) -> None:
        import paramiko

        dev = self.device

        class Iface(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                ok = username.split("+")[0] == USER and password == PASSWORD  # MikroTik adds +flags to the user
                return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

            def get_allowed_auths(self, username):
                return "password"

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED

            def check_channel_pty_request(self, *args):
                return True

            def check_channel_shell_request(self, channel):
                return True

        try:
            transport = paramiko.Transport(conn)
            transport.set_log_channel("netagent.demo.ssh")  # port probes hang up early: keep that quiet
            transport.add_server_key(self.host_key)
            transport.start_server(server=Iface())
            chan = transport.accept(20)
            if chan is None:
                return
            chan.send(("\r\n" + dev.prompt).encode())
            buf = b""
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                buf += data
                while b"\n" in buf or b"\r" in buf:
                    i = min(x for x in (buf.find(b"\n"), buf.find(b"\r")) if x >= 0)
                    line, buf = buf[:i].decode(errors="replace").strip(), buf[i + 1:]
                    out = respond(dev, line)
                    chan.send((line + "\r\n" + (out.replace("\n", "\r\n") + "\r\n" if out else "") + dev.prompt).encode())
        except Exception:  # noqa: BLE001 - a client hanging up mid-session is normal
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


SCENARIOS = {
    "uplink": "R1-ის WAN (Gi0/0/0) ჩავარდა: BGP ISP-თან დაეცა, default route გაქრა",
    "cpu": "SW-Core-1-ის CPU 96%-მდე ავიდა",
    "config": "ვიღაცამ SW-Core-1-ის კონფიგურაცია შეცვალა",
    "down": "SW-Access-2 მთლიანად გაითიშა",
    "newdevice": "ქსელში უცნობი მოწყობილობა ჩაერთო",
    "bruteforce": "MT-Branch-ზე პაროლის გამოცნობის მცდელობა (წარუმატებელი შესვლები)",
}
from .lab_extra import SCENARIOS as _EXTRA  # noqa: E402

SCENARIOS.update(_EXTRA)
from .lab_extra import LATER as _LATER_EXTRA  # noqa: E402
SCENARIOS["restore"] = "ყველაფერი ნორმას დაუბრუნდა"


class DemoLab:
    def __init__(self, devices: dict[str, FakeDevice], syslog_port: int) -> None:
        import paramiko

        self.devices = devices
        self.syslog_port = syslog_port
        self.host_key = paramiko.RSAKey.generate(2048)
        self.servers = {n: _Server(d, self.host_key) for n, d in devices.items()}
        self._baseline = {n: dict(d.outputs) for n, d in devices.items()}

    def start(self) -> None:
        for srv in self.servers.values():
            srv.start()

    def stop(self) -> None:
        for srv in self.servers.values():
            srv.stop()

    # -- syslog from a device's own address -------------------------------------
    def syslog(self, device: str, severity: int, message: str) -> None:
        if self.syslog_port <= 0:
            return
        d = self.devices[device]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.bind((d.ip, 0))
            except OSError:
                pass
            s.sendto(f"<{8 * 23 + severity}>{message}".encode(), ("127.0.0.1", self.syslog_port))

    # -- scenarios ------------------------------------------------------------------
    def scenario(self, name: str) -> str:
        r1, core, acc, mt = (self.devices[n] for n in ("R1", "SW-Core-1", "SW-Access-2", "MT-Branch"))
        if name in {"errors", "congestion", "vpn", "dhcp"}:
            FAULTS[name] = True
            if name == "vpn":
                self.syslog("R1", 3, "%LINEPROTO-5-UPDOWN: Line protocol on Interface Tunnel0, changed state to down")
                self.syslog("R1", 4, "%CRYPTO-4-IKMP_NO_SA: IKE message from 198.51.100.2 has no SA")
            return SCENARIOS[name]
        if name == "uplink":
            FAULTS["uplink"] = True
            o = r1.outputs
            o["show ip interface brief"] = o["show ip interface brief"].replace(
                "GigabitEthernet0/0/0   203.0.113.2     YES NVRAM  up                    up",
                "GigabitEthernet0/0/0   203.0.113.2     YES NVRAM  down                  down")
            o["show ip bgp summary"] = o["show ip bgp summary"].replace("0 5w2d           812", "0 00:00:12  Active")
            o["show ip route 0.0.0.0"] = "% Network not in table"
            o["ping 8.8.8.8 repeat 3 timeout 1"] = ("Type escape sequence to abort.\nSending 3, 100-byte ICMP Echos to 8.8.8.8, "
                                                     "timeout is 1 seconds:\n...\nSuccess rate is 0 percent (0/3)")
            self.syslog("R1", 3, "%LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to down")
            self.syslog("R1", 5, "%BGP-5-ADJCHANGE: neighbor 203.0.113.1 Down Interface flap")
        elif name == "cpu":
            core.outputs["show processes cpu | include CPU utilization"] = "CPU utilization for five seconds: 97%/12%; one minute: 96%; five minutes: 71%"
        elif name == "config":
            core.outputs["show running-config"] = core.outputs["show running-config"].replace(
                "interface Vlan10", "interface GigabitEthernet1/0/10\n switchport access vlan 20\n no shutdown\n!\ninterface Vlan10")
            self.syslog("SW-Core-1", 5, "%SYS-5-CONFIG_I: Configured from console by gio on vty0 (192.168.10.77)")
        elif name == "down":
            self.servers["SW-Access-2"].stop()
            acc.online = False
        elif name == "newdevice":
            mac = "b8:27:eb:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(3))  # Raspberry Pi OUI
            cisco_mac = mac.replace(":", "")
            cisco_mac = f"{cisco_mac[:4]}.{cisco_mac[4:8]}.{cisco_mac[8:]}"
            ip = f"192.168.10.{random.randint(100, 199)}"
            core.outputs["show ip arp"] += f"\nInternet  {ip:<16} {'0':>9}   {cisco_mac}  ARPA   Vlan10"
        elif name == "bruteforce":
            for i in range(6):
                self.syslog("MT-Branch", 4, f"login failure for user admin from 45.155.205.{10 + i} via ssh")
        elif name == "restore":
            FAULTS.clear()
            for n, d in self.devices.items():
                d.outputs = dict(self._baseline[n])
            if not acc.online:
                self.servers["SW-Access-2"].start()
                acc.online = True
        else:
            raise ValueError(name)
        return SCENARIOS[name]

    def command(self, args):
        from ..commands import Button, CommandError, Result

        if not args:
            lines = ["🎮 **დემო ქსელი** — 4 ვირტუალური მოწყობილობა (R1, SW-Core-1, SW-Access-2, MT-Branch)",
                     "", "ავარიის სიმულაცია:"]
            lines += [f"• /demo {k} — {v}" for k, v in SCENARIOS.items()]
            return Result("\n".join(lines), buttons=[
                Button("🔴 WAN ჩავარდა", "/demo uplink"), Button("🔥 CPU", "/demo cpu"),
                Button("📝 config", "/demo config"), Button("⚫ switch გაითიშა", "/demo down"),
                Button("🆕 უცნობი მოწყობილობა", "/demo newdevice"), Button("🔐 brute force", "/demo bruteforce"),
                Button("⚡ CRC შეცდომები", "/demo errors"), Button("📈 გადატვირთული ხაზი", "/demo congestion"),
                Button("🔒 VPN დაეცა", "/demo vpn"), Button("📦 DHCP გაივსო", "/demo dhcp"),
                Button("✅ აღდგენა", "/demo restore")])
        name = args[0].lower()
        if name not in SCENARIOS:
            raise CommandError("უცნობი სცენარი. ხელმისაწვდომია: " + ", ".join(SCENARIOS))
        text = self.scenario(name)
        later = {"uplink": "ალერტები (Syslog მაშინვე, მონიტორინგი ~1 წთ-ში)", "cpu": "ალერტი ~1 წთ-ში",
                 "config": "Syslog-ის ალერტი მაშინვე, diff-ი ~2 წთ-ში", "down": "ალერტი ~1 წთ-ში",
                 "newdevice": "ალერტი ~1 წთ-ში", "bruteforce": "ალერტი მაშინვე", "restore": "აღდგენის ალერტები ~1 წთ-ში",
                 **_LATER_EXTRA}[name]
        hint = {"uplink": "სცადე: /runbook internet ან ჰკითხე „რატომ არ მუშაობს ინტერნეტი?“",
                "config": "სცადე: „ვინ შეცვალა SW-Core-1-ის config და რა შეცვალა?“",
                "down": "სცადე: /runbook device SW-Access-2", "newdevice": "სცადე: /newdevices",
                "cpu": "სცადე: /runbook slow", "bruteforce": "სცადე: /logs MT-Branch", "restore": "",
                "errors": "სცადე: /errors ან „რატომ წყდება Wi-Fi ლობიში?“", "congestion": "სცადე: /traffic R1",
                "vpn": "სცადე: /runbook vpn ან /path 10.20.0.15 192.168.10.21", "dhcp": "სცადე: /runbook dhcp"}[name]
        return Result(f"🎮 **სცენარი:** {text}\n⏱ {later}" + (f"\n💡 {hint}" if hint else ""),
                      buttons=[Button("✅ აღდგენა", "/demo restore")] if name != "restore" else [])


def _can_bind(ip: str) -> bool:
    try:
        with socket.socket() as s:
            s.bind((ip, 0))
        return True
    except OSError:
        return False


def start_lab(syslog_port: int, base_port: int = 2222) -> DemoLab:
    global LAB
    ips = ["127.0.0.11", "127.0.0.12", "127.0.0.13", "127.0.0.14"]
    if all(_can_bind(ip) for ip in ips):
        ports = [base_port] * 4
    else:  # e.g. macOS: only 127.0.0.1 exists by default
        ips = ["127.0.0.1"] * 4
        ports = [base_port + i for i in range(4)]
    lab = DemoLab(build_devices(ips, ports), syslog_port)
    lab.start()
    LAB = lab
    log.info("demo lab: %s", ", ".join(f"{d.name}@{d.ip}:{d.port}" for d in lab.devices.values()))
    return lab


def inventory_yaml(lab: DemoLab) -> str:
    d = lab.devices
    return f"""# NetAgent demo network (generated, overwritten on every demo start)
credentials:
  default: {{username_env: NETAGENT_DEMO_USER, password_env: NETAGENT_DEMO_PASS}}
devices:
  R1:
    host: {d['R1'].ip}
    port: {d['R1'].port}
    device_type: cisco_ios
    site: HQ
    role: router
    description: Internet edge (ISP Magti)
    watch: {{interfaces: [Gi0/0/0, Gi0/0/1], bgp: true, ospf: true, cpu: 80}}
  SW-Core-1:
    host: {d['SW-Core-1'].ip}
    port: {d['SW-Core-1'].port}
    device_type: cisco_ios
    site: HQ
    role: core-switch
    watch: {{ospf: true, cpu: 80}}
  SW-Access-2:
    host: {d['SW-Access-2'].ip}
    port: {d['SW-Access-2'].port}
    device_type: cisco_ios
    site: HQ
    role: access-switch
    watch: {{interfaces: [Gi1/0/48], cpu: 90}}
  MT-Branch:
    host: {d['MT-Branch'].ip}
    port: {d['MT-Branch'].port}
    device_type: mikrotik_routeros
    site: Branch-1
    role: router
    watch: {{cpu: 90}}
"""
