from __future__ import annotations

from datetime import datetime, timedelta

import pytest
import yaml

from netagent.charts import latency_chart
from netagent.discovery import Candidate, add_to_inventory, hostname_from_prompt
from netagent.health import Reachability
from netagent.history import LatencyHistory
from netagent.inventory import Device, Inventory
from netagent.notes import NoteStore
from netagent.state import StateStore
from netagent.watch import (
    Snapshot,
    compare,
    find_interface,
    ifname_matches,
    parse_bgp,
    parse_cpu,
    parse_interfaces,
    parse_ospf,
)

# --------------------------------------------------------------------------- interface parsing

IOS_BRIEF = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     203.0.113.2     YES NVRAM  up                    up
GigabitEthernet0/1     192.168.1.1     YES NVRAM  up                    down
GigabitEthernet0/2     unassigned      YES NVRAM  administratively down down
"""
NXOS_BRIEF = """IP Interface Status for VRF "default"(1)
Interface            IP Address      Interface Status
Vlan10               10.0.10.1       protocol-up/link-up/admin-up
Eth1/1               10.0.0.1        protocol-down/link-down/admin-up
"""
JUNOS_TERSE = """Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   inet     10.0.0.1/30
ge-0/0/1                up    down
ge-0/0/2                down  down
"""
MT_TERSE = """ 0  R name=ether1 default-name=ether1 type=ether mtu=1500
 1    name=ether2 default-name=ether2 type=ether mtu=1500
 2 X  name=ether3 default-name=ether3 type=ether mtu=1500
"""
HUAWEI_BRIEF = """PHY: Physical
Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors
GigabitEthernet0/0/1        up    up        0.01%  0.01%          0          0
GigabitEthernet0/0/2        down  down         0%     0%          0          0
GigabitEthernet0/0/3        *down down         0%     0%          0          0
"""


def test_parse_interfaces_multi_vendor():
    assert parse_interfaces("ios", IOS_BRIEF) == {
        "GigabitEthernet0/0": "up", "GigabitEthernet0/1": "down", "GigabitEthernet0/2": "admin-down"}
    assert parse_interfaces("nxos", NXOS_BRIEF) == {"Vlan10": "up", "Eth1/1": "down"}
    j = parse_interfaces("junos", JUNOS_TERSE)
    assert j["ge-0/0/0"] == "up" and j["ge-0/0/1"] == "down" and j["ge-0/0/2"] == "admin-down"
    assert parse_interfaces("mikrotik", MT_TERSE) == {"ether1": "up", "ether2": "down", "ether3": "admin-down"}
    h = parse_interfaces("huawei", HUAWEI_BRIEF)
    assert h == {"GigabitEthernet0/0/1": "up", "GigabitEthernet0/0/2": "down", "GigabitEthernet0/0/3": "admin-down"}
    assert parse_interfaces("linux", "lo  UNKNOWN  00:00\neth0@if5  UP  aa:bb\neth1  DOWN  cc:dd\n") == {
        "lo": "up", "eth0": "up", "eth1": "down"}


@pytest.mark.parametrize("wanted,actual,ok", [
    ("Gi0/1", "GigabitEthernet0/1", True),
    ("gi0/1", "GigabitEthernet0/10", False),
    ("Po1", "Port-channel1", True),
    ("Te1/1/1", "TenGigabitEthernet1/1/1", True),
    ("Eth1/1", "Ethernet1/1", True),
    ("ether1", "ether1", True),
    ("Gi0/1", "FastEthernet0/1", False),
])
def test_ifname_matches(wanted, actual, ok):
    assert ifname_matches(wanted, actual) is ok


def test_find_interface():
    assert find_interface("Gi0/1", {"GigabitEthernet0/10": "up", "GigabitEthernet0/1": "down"}) == "GigabitEthernet0/1"


# --------------------------------------------------------------------------- bgp / ospf / cpu

IOS_BGP = """BGP router identifier 1.1.1.1, local AS number 65000
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
203.0.113.1     4        65100    1200    1100       55    0    0 2d01h          812
10.255.0.2      4        65001       0       0        1    0    0 never    Active
10.255.0.6      4        65002       0       0        1    0    0 never    Idle (Admin)
"""
JUNOS_BGP = """Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
10.0.0.2              65001        100        101       0       0     1:00:00 Establ
  inet.0: 5/6/6/0
10.0.0.6              65002          0          0       0       1       10:00 Active
"""


def test_parse_bgp():
    assert parse_bgp("ios", IOS_BGP) == {"203.0.113.1": "established", "10.255.0.2": "active", "10.255.0.6": "admin-down"}
    assert parse_bgp("junos", JUNOS_BGP) == {"10.0.0.2": "established", "10.0.0.6": "active"}


def test_parse_ospf():
    ios = "Neighbor ID  Pri  State  Dead Time  Address  Interface\n2.2.2.2  1  FULL/DR  00:00:35  10.0.0.2  Gi0/0\n3.3.3.3  1  INIT/DROTHER  00:00:31  10.0.0.3  Gi0/1\n"
    assert parse_ospf("ios", ios) == {"2.2.2.2": "full", "3.3.3.3": "init"}
    junos = "Address  Interface  State  ID  Pri  Dead\n10.0.0.2  ge-0/0/0.0  Full  2.2.2.2  128  36\n"
    assert parse_ospf("junos", junos) == {"2.2.2.2": "full"}


@pytest.mark.parametrize("fam,text,value", [
    ("ios", "CPU utilization for five seconds: 7%/0%; one minute: 6%; five minutes: 5%", 6),
    ("mikrotik", "uptime: 3d\ncpu-load: 4%\n", 4),
    ("junos", "Routing Engine status:\n    Idle                        95 percent", 5),
    ("nxos", "CPU states  :   3.50% user,   2.00% kernel,   94.50% idle", 5.5),
    ("huawei", "CPU Usage            : 12% Max: 40%", 12),
    ("arista", "%Cpu(s):  2.0 us,  1.0 sy,  0.0 ni, 96.0 id,  0.0 wa", 4),
])
def test_parse_cpu(fam, text, value):
    assert parse_cpu(fam, text) == pytest.approx(value)


# --------------------------------------------------------------------------- alerts


def _dev(**watch):
    return Device(name="R1", host="1.1.1.1", device_type="cisco_ios", watch=watch)


def test_compare_baseline_and_transitions():
    d = _dev(interfaces=["Gi0/0", "Gi0/9"], bgp=True, ospf=True, cpu=80)
    base = Snapshot(interfaces={"GigabitEthernet0/0": "up"}, bgp={"10.0.0.2": "established"},
                    ospf={"2.2.2.2": "full"}, cpu=10)
    first = compare(d, None, base)
    assert any("Gi0/9" in a for a in first)  # missing watched interface is reported once
    assert not any("ჩავარდა" in a for a in first)

    bad = Snapshot(interfaces={"GigabitEthernet0/0": "down"}, bgp={"10.0.0.2": "active"}, ospf={}, cpu=95)
    alerts = compare(d, base, bad)
    text = "\n".join(alerts)
    assert "GigabitEthernet0/0 ჩავარდა" in text and "BGP neighbor 10.0.0.2" in text
    assert "OSPF neighbor 2.2.2.2" in text and "CPU 95%" in text
    assert not any("Gi0/9" in a for a in alerts)  # not repeated after baseline

    assert compare(d, bad, bad) == []  # no change, no alert
    rec = compare(d, bad, base)
    assert sum("აღდგა" in a for a in rec) == 3 and any("CPU ნორმას" in a for a in rec)


def test_cpu_hysteresis():
    d = _dev(cpu=80)
    high, mid = Snapshot(cpu=85), Snapshot(cpu=75)
    assert compare(d, high, mid) == []  # 75 is not below 80-10: still "high", no flapping alert


def test_compare_ignores_unwatched_device():
    d = _dev()
    assert compare(d, Snapshot(bgp={"1.1.1.1": "established"}), Snapshot(bgp={})) == []


# --------------------------------------------------------------------------- discovery


@pytest.mark.parametrize("prompt,name", [
    ("R1#", "R1"), ("SW-Core-1>", "SW-Core-1"), ("[admin@MT-Office] >", "MT-Office"),
    ("<HUAWEI-SW1>", "HUAWEI-SW1"), ("admin@mx480-re0>", "mx480-re0"), ("FGT60F #", "FGT60F"),
    ("R1(config)#", "R1"), ("garbage prompt !!", None),
])
def test_hostname_from_prompt(prompt, name):
    assert hostname_from_prompt(prompt) == name


def test_add_to_inventory_appends_and_preserves_comments(tmp_path):
    p = tmp_path / "devices.yaml"
    p.write_text("# my comment\ncredentials:\n  default: {username_env: U, password_env: P}\ndevices:\n  R1:\n    host: 10.0.0.1\n    device_type: cisco_ios\n", encoding="utf-8")
    added = add_to_inventory(p, [
        Candidate("10.0.0.2", device_type="mikrotik_routeros", hostname="R1"),   # name clash -> R1-2
        Candidate("10.0.0.3", device_type="juniper_junos", hostname="J 1"),      # unsafe chars
        Candidate("10.0.0.1", device_type="cisco_ios", hostname="dup"),          # host already present
        Candidate("10.0.0.4", device_type=None, error="unknown"),                # not detected
        Candidate("10.0.0.5", device_type="cisco_ios", already_in_inventory="X"),
    ], site="HQ")
    assert added == ["R1-2", "J-1"]
    text = p.read_text(encoding="utf-8")
    assert "# my comment" in text
    devs = yaml.safe_load(text)["devices"]
    assert devs["R1-2"] == {"host": "10.0.0.2", "device_type": "mikrotik_routeros", "site": "HQ", "description": "auto-discovered"}
    Inventory.load(p)  # still a valid inventory


def test_add_to_inventory_empty_devices_and_rewrite(tmp_path):
    p = tmp_path / "devices.yaml"
    p.write_text("devices: {}\ncredentials:\n  default: {username_env: U, password_env: P}\n", encoding="utf-8")
    added = add_to_inventory(p, [Candidate("10.0.0.9", device_type="cisco_ios", hostname="SW9")])
    assert added == ["SW9"]
    assert yaml.safe_load(p.read_text())["devices"]["SW9"]["host"] == "10.0.0.9"
    assert (tmp_path / "devices.yaml.bak").exists()  # devices was not the last section -> rewrite + backup


# --------------------------------------------------------------------------- notes / history / chart


def test_notes(tmp_path):
    n = NoteStore(StateStore(tmp_path / "s.json"))
    assert n.add("R1", "ISP Magti") == 1
    n.add("", "general note")
    n.add("R1", "circuit 12345")
    assert [x["text"] for x in n.list("R1")] == ["ISP Magti", "circuit 12345"]
    assert n.delete("R1", 1)["text"] == "ISP Magti"
    with pytest.raises(ValueError):
        n.delete("R1", 5)
    with pytest.raises(ValueError):
        n.add("R1", "   ")
    assert "general note" in n.format("")
    assert set(n.all()) == {"R1", "_general"}


def test_history_and_chart(tmp_path):
    h = LatencyHistory(tmp_path / "lat")
    now = datetime.now()
    for i in range(30):
        up = i not in (10, 11, 12)
        h.record([Reachability("R1", "1.1.1.1", 22, up, 10.0 + i if up else None)], when=now - timedelta(minutes=5 * (29 - i)))
    pts = h.read("R1", 24)
    assert len(pts) == 30
    st = h.stats("R1", 24)
    assert st["samples"] == 30 and st["uptime_percent"] == 90.0 and st["max_ms"] == 39.0
    out = latency_chart("R1", pts, tmp_path / "c.png", 24, st)
    assert out.exists() and out.stat().st_size > 10_000
    assert h.stats("nope")["samples"] == 0


def test_history_prunes_old_files(tmp_path):
    h = LatencyHistory(tmp_path)
    old = tmp_path / "2020-01-01.csv"
    old.write_text("x\n")
    h.record([Reachability("R1", "1.1.1.1", 22, True, 1.0)])
    assert not old.exists()
