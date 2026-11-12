"""Who uses the internet: NetFlow per device, SNMP switch ports + MAC table, daily totals, heavy-user alert."""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from types import SimpleNamespace as NS

import pytest

from netagent.features import flows, talkers
from netagent.state import StateStore


def v5_packet(records: list[tuple[str, str, int, int, int]]) -> bytes:
    """NetFlow v5: (src, dst, bytes, sport, dport) per record."""
    head = struct.pack("!HHIIIIBBH", 5, len(records), 0, int(time.time()), 0, 1, 0, 0, 0)
    body = b""
    for src, dst, n, sp, dp in records:
        body += struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", socket.inet_aton(src), socket.inet_aton(dst), socket.inet_aton("0.0.0.0"),
                            0, 0, 10, n, 0, 0, sp, dp, 0, 0, 6, 0, 0, 0, 0, 0, 0)
    return head + body


@pytest.fixture
def stats(monkeypatch):
    s = flows.FlowStats()
    monkeypatch.setattr(flows, "STATS", s)
    return s


NAMES = {"ip:192.168.100.5": {"name": "Nodo-S23", "ip": "192.168.100.5", "mac": "7e:25:85:4f:8c:ba", "icon": "smartphone", "self": False},
         "mac:7e:25:85:4f:8c:ba": {"name": "Nodo-S23", "ip": "192.168.100.5", "mac": "7e:25:85:4f:8c:ba", "icon": "smartphone", "self": False},
         "mac:e4:e3:3d:ed:b0:b2": {"name": "TV", "ip": "192.168.100.2", "mac": "e4:e3:3d:ed:b0:b2", "icon": "tv", "self": False}}


def test_netflow_per_device(stats, tmp_path):
    flows_ = flows.parse_v5(v5_packet([("142.250.1.1", "192.168.100.5", 300_000_000, 443, 50000),   # phone downloads
                                       ("192.168.100.5", "142.250.1.1", 20_000_000, 50000, 443),    # and uploads
                                       ("104.16.1.1", "192.168.100.9", 50_000_000, 443, 51000)]))   # a PC
    stats.add(flows_, "192.168.100.1")
    r = talkers.report(StateStore(tmp_path / "s.json"), "15", names=NAMES)
    assert [x["name"] for x in r["rows"]] == ["Nodo-S23", "192.168.100.9"]
    phone = r["rows"][0]
    assert phone["down"] == 300_000_000 and phone["up"] == 20_000_000 and phone["icon"] == "smartphone" and phone["source"] == ["NetFlow"]
    assert r["sources"]["netflow"] and not r["hint"] and r["apps"][0]["app"] == "HTTPS"
    text = talkers.format_usage(r)
    assert "Nodo-S23" in text and "ჩამოტვირთვა (download) 300.0 MB" in text and "⬇" not in text


def test_no_source_gives_a_hint(stats, tmp_path, monkeypatch):
    monkeypatch.setattr(talkers, "setup_hint", lambda: "როუტერი ამას არ აგზავნის")
    monkeypatch.setattr(talkers, "PORTS", talkers.SwitchPorts())
    r = talkers.report(StateStore(tmp_path / "s.json"), "15", names={})
    assert r["rows"] == [] and r["hint"] and "მონაცემი ჯერ არ არის" in talkers.format_usage(r)


class FakeSwitch:
    """IF-MIB + BRIDGE-MIB of a 3-port switch: Fa0/1 the phone, Fa0/2 the TV, Gi0/1 an uplink with many MACs."""

    def __init__(self):
        self.inb = {"1": 1000, "2": 5000, "24": 10**9}
        self.outb = {"1": 2000, "2": 9000, "24": 10**9}

    def bump(self, ifx, down, up):
        self.outb[ifx] += down
        self.inb[ifx] += up

    def walk(self, host, community, oid):
        mac = lambda m: ".".join(str(int(x, 16)) for x in m.split(":"))  # noqa: E731
        if oid == talkers.IF_NAME:
            return {f"{oid}.1": "Fa0/1", f"{oid}.2": "Fa0/2", f"{oid}.24": "Gi0/1"}
        if oid == talkers.IF_IN:
            return {f"{oid}.{k}": v for k, v in self.inb.items()}
        if oid == talkers.IF_OUT:
            return {f"{oid}.{k}": v for k, v in self.outb.items()}
        if oid == talkers.BRIDGE_IFINDEX:
            return {f"{oid}.1": 1, f"{oid}.2": 2, f"{oid}.24": 24}
        if oid == talkers.FDB_PORT:
            return {f"{oid}.{mac('7e:25:85:4f:8c:ba')}": 1, f"{oid}.{mac('e4:e3:3d:ed:b0:b2')}": 2,
                    f"{oid}.{mac('28:5b:0c:56:da:2e')}": 24, f"{oid}.{mac('aa:bb:cc:00:00:01')}": 24}
        return {}


def test_switch_ports_by_mac(stats, tmp_path, monkeypatch):
    sw = FakeSwitch()
    ports = talkers.SwitchPorts(walk=sw.walk)
    monkeypatch.setattr(talkers, "PORTS", ports)
    ports.sample("SW1", "10.0.0.2", "public", now=1000.0)
    assert ports.rates == {}  # the first sample only sets the baseline
    sw.bump("1", 75_000_000, 5_000_000)
    sw.bump("2", 7_500_000, 0)
    sw.bump("24", 10**9, 10**9)  # the uplink: many devices, not counted
    ports.sample("SW1", "10.0.0.2", "public", now=1060.0)
    phone = ports.rates["mac:7e:25:85:4f:8c:ba"]
    assert phone["down"] == 75_000_000 * 8 / 60 and phone["up"] == 5_000_000 * 8 / 60 and phone["port"] == "SW1 Fa0/1"
    assert "mac:28:5b:0c:56:da:2e" not in ports.rates
    for k in ports.rates:
        ports.rates[k]["ts"] = time.time()
    r = talkers.report(StateStore(tmp_path / "s.json"), "15", names=NAMES)
    by = {x["name"]: x for x in r["rows"]}
    assert by["Nodo-S23"]["port"] == "SW1 Fa0/1" and by["Nodo-S23"]["source"] == ["SNMP"] and by["TV"]["down_bps"] == 1_000_000
    assert ports.take_deltas()["mac:7e:25:85:4f:8c:ba"] == [75_000_000, 5_000_000] and ports.take_deltas() == {}
    sw.inb["1"] = 0  # a counter reset is skipped, not a huge negative
    ports.sample("SW1", "10.0.0.2", "public", now=1120.0)
    assert ports.take_deltas().get("mac:7e:25:85:4f:8c:ba") is None


def test_daily_totals(tmp_path):
    st = StateStore(tmp_path / "s.json")
    talkers.add_daily(st, {"ip:192.168.100.5": [100, 10]}, day="2026-11-10")
    talkers.add_daily(st, {"ip:192.168.100.5": [50, 5], "mac:e4:e3:3d:ed:b0:b2": [7, 0]}, day="2026-11-11")
    talkers.add_daily(st, {"ip:192.168.100.5": [1, 1]}, day="2026-11-11")
    d = st.get(talkers.DAILY_KEY)
    assert d["2026-11-11"]["ip:192.168.100.5"] == [51, 6]
    week = talkers.report(st, "week", names=NAMES)
    phone = next(x for x in week["rows"] if x["name"] == "Nodo-S23")
    assert phone["down"] == 151 and phone["up"] == 16  # IP row and MAC row of the same phone merged
    for i in range(talkers.KEEP_DAYS + 3):
        talkers.add_daily(st, {"ip:x": [1, 1]}, day=f"2027-01-{i + 1:02d}")
    assert len(st.get(talkers.DAILY_KEY)) == talkers.KEEP_DAYS


def test_job_adds_minutes_and_alerts_heavy_use(stats, tmp_path, monkeypatch):
    st = StateStore(tmp_path / "s.json")
    monkeypatch.setattr(talkers, "live_names", lambda: NAMES)
    monkeypatch.setattr(talkers, "snmp_switches", lambda inv: [])
    monkeypatch.setenv("NETAGENT_HOG_GB_HOUR", "1")
    alerts = []

    async def emit(a):
        alerts.append(a)

    (_, every, _, tick), = talkers.jobs(NS(s=NS(state=st, inventory=lambda: None), emit=emit))
    assert every == 60
    minute_ago = time.time() - 60
    stats.add(flows.parse_v5(v5_packet([("142.250.1.1", "192.168.100.5", 2_000_000_000, 443, 50000)])), "r", now=minute_ago)
    asyncio.run(tick())
    today = next(iter(st.get(talkers.DAILY_KEY).values()))
    assert today["ip:192.168.100.5"] == [2_000_000_000, 0]
    assert len(alerts) == 1 and "Nodo-S23 ბევრს იყენებს" in alerts[0].text
    asyncio.run(tick())
    assert len(alerts) == 1  # once a day
    assert next(iter(st.get(talkers.DAILY_KEY).values()))["ip:192.168.100.5"] == [2_000_000_000, 0]  # a minute is counted once


def test_command_periods(stats, tmp_path):
    s = NS(state=StateStore(tmp_path / "s.json"))
    assert "დღეს" in talkers.bandwidth_cmd(s, ["today"], "app:admin").text
    assert "ბოლო 15 წთ" in talkers.bandwidth_cmd(s, ["nonsense"], "app:admin").text


def test_one_silent_switch_does_not_stop_the_others(stats, tmp_path, monkeypatch):
    st = StateStore(tmp_path / "s.json")
    monkeypatch.setattr(talkers, "live_names", lambda: {})
    monkeypatch.setattr(talkers, "snmp_switches", lambda inv: [("SW-dead", "10.0.0.9", "public"), ("SW1", "10.0.0.2", "public")])
    calls = []

    def sample(name, host, comm, now=None):
        calls.append(name)
        if name == "SW-dead":
            raise TimeoutError("no SNMP answer")

    monkeypatch.setattr(talkers.PORTS, "sample", sample)
    (_, _, _, tick), = talkers.jobs(NS(s=NS(state=st, inventory=lambda: None), emit=None))
    asyncio.run(tick())
    assert calls == ["SW-dead", "SW1"]
    asyncio.run(tick())
    assert calls == ["SW-dead", "SW1", "SW1"]  # the silent one waits 10 minutes
