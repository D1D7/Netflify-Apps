from __future__ import annotations

import asyncio
import socket

from netagent.inventory import Device, Inventory
from netagent.syslogd import LogEntry, SyslogAnalyzer, SyslogStore, parse_message, start_syslog
from netagent.topology import build_links, draw_map, format_links, parse_mikrotik_neighbors, short_name

# --------------------------------------------------------------------------- syslog


def test_parse_message_formats():
    assert parse_message(b"<189>123: *Nov  4 10:00:01.123 UTC: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.5)") == (
        5, "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.5)")
    sev, msg = parse_message(b"<187>Nov  4 10:00:02 R1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down")
    assert sev == 3 and msg.startswith("%LINK-3-UPDOWN")
    sev, msg = parse_message(b"<134>1 2026-11-04T10:00:00Z mt1 router - - - login failure for user admin from 1.2.3.4 via ssh")
    assert sev == 6 and msg.startswith("login failure")
    assert parse_message(b"no pri here") == (6, "no pri here")


def _e(msg, sev=5, device="R1"):
    return LogEntry("2026-11-04T10:00:00", "10.0.0.1", device, sev, msg)


def test_analyzer_rules_and_cooldown():
    a = SyslogAnalyzer()
    t = 1000.0
    cfg = a.analyze(_e("%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.5)"), t)
    assert "admin" in cfg and "10.0.0.5" in cfg
    down = a.analyze(_e("%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", 3), t)
    assert "GigabitEthernet0/1" in down
    assert a.analyze(_e("%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", 3), t + 30) is None  # cooldown
    assert a.analyze(_e("%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", 3), t + 700)  # after cooldown
    assert "BGP" in a.analyze(_e("%BGP-5-ADJCHANGE: neighbor 203.0.113.1 Down BGP Notification sent"), t)
    assert a.analyze(_e("%LINK-3-UPDOWN: Interface Gi0/2, changed state to up", 3), t) is None
    assert a.analyze(_e("something boring", 6), t) is None
    assert "CRIT" in a.analyze(_e("fan failure", 2), t)


def test_login_bruteforce_threshold():
    a = SyslogAnalyzer()
    msgs = [a.analyze(_e("login failure for user admin from 1.2.3.4 via ssh", 4, "MT1"), 100 + i) for i in range(5)]
    assert msgs[:4] == [None] * 4 and "5 წარუმატებელი" in msgs[4] and "1.2.3.4" in msgs[4]


def test_store_search_and_prune(tmp_path):
    store = SyslogStore(tmp_path)
    (tmp_path / "2020-01-01.jsonl").write_text("{}\n")
    store.append(_e("%LINK-3-UPDOWN: Interface Gi0/1, changed state to down", 3))
    store.append(_e("normal info", 6, device="SW1"))
    assert not (tmp_path / "2020-01-01.jsonl").exists()
    # entries carry today's ts in real use; give the search a wide window
    assert len(store.search(hours=24 * 3650)) == 2
    assert [r["device"] for r in store.search(device="sw1", hours=24 * 3650)] == ["SW1"]
    assert len(store.search(text="updown", hours=24 * 3650)) == 1
    assert len(store.search(max_severity=4, hours=24 * 3650)) == 1


def test_udp_server_end_to_end(tmp_path):
    alerts = []

    async def go():
        store = SyslogStore(tmp_path)
        transport, proto = await start_syslog("127.0.0.1", 0, store, lambda ip: "R1" if ip == "127.0.0.1" else ip,
                                              lambda d, t: alerts.append((d, t)))
        port = transport.get_extra_info("sockname")[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"<189>1: %SYS-5-CONFIG_I: Configured from console by nodo on vty0 (10.9.9.9)", ("127.0.0.1", port))
        for _ in range(50):
            if proto.received:
                break
            await asyncio.sleep(0.02)
        transport.close()
        return store

    store = asyncio.run(go())
    assert alerts and alerts[0][0] == "R1" and "nodo" in alerts[0][1]
    assert store.search(hours=1)[0]["device"] == "R1"


# --------------------------------------------------------------------------- topology


def _inv():
    return Inventory({
        "R1": Device(name="R1", host="10.0.0.1", device_type="cisco_ios"),
        "SW1": Device(name="SW1", host="10.0.0.2", device_type="cisco_ios"),
        "MT1": Device(name="MT1", host="10.0.0.3", device_type="mikrotik_routeros"),
    }, {})


def test_short_name():
    assert short_name("SW1.corp.local") == "SW1"
    assert short_name("SW1(FOC123)") == "SW1"
    assert short_name("10.0.0.2") == "10.0.0.2"


def test_build_links_dedupes_and_matches_inventory():
    neighbors = {
        "R1": [{"neighbor_name": "SW1.corp.local", "local_interface": "Gi0/1", "neighbor_interface": "Gi1/0/1",
                "mgmt_address": "10.0.0.2", "platform": "cisco WS-C2960"},
               {"destination_host": "AP-Lobby", "local_port": "Gi0/2", "remote_port": "eth0"}],
        "SW1": [{"neighbor_name": "R1", "local_interface": "Gi1/0/1", "neighbor_interface": "Gi0/1"}],  # same cable
        "MT1": parse_mikrotik_neighbors(' 0 interface=ether1 address=10.0.0.2 identity="SW1" platform=Cisco interface-name=Gi1/0/2\n'),
    }
    links = build_links(_inv(), neighbors)
    pairs = {(l.a, l.a_port, l.b, l.b_port, l.b_known) for l in links}
    assert ("R1", "Gi0/1", "SW1", "Gi1/0/1", True) in pairs
    assert ("R1", "Gi0/2", "AP-Lobby", "eth0", False) in pairs
    assert ("MT1", "ether1", "SW1", "Gi1/0/2", True) in pairs
    assert len(links) == 3  # R1<->SW1 counted once


def test_format_and_draw_map(tmp_path):
    data = {"devices": ["R1", "SW1"], "links": [
        {"a": "R1", "a_port": "Gi0/1", "b": "SW1", "b_port": "Gi1/0/1", "b_known": True, "b_ip": "", "b_platform": ""},
        {"a": "R1", "a_port": "Gi0/2", "b": "AP-Lobby", "b_port": "eth0", "b_known": False, "b_ip": "", "b_platform": ""}],
        "errors": {}}
    text = format_links(data)
    assert "R1 Gi0/1 ↔ SW1 Gi1/0/1" in text and "AP-Lobby (?)" in text
    out = draw_map(data, tmp_path / "map.png", down={"SW1"})
    assert out.exists() and out.stat().st_size > 10_000
    assert "ვერ ვიპოვე" in format_links({"devices": ["R1"], "links": [], "errors": {}})
