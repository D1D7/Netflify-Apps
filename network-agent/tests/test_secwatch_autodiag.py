"""Security watch (ARP spoofing, rogue DHCP, new open ports) and automatic diagnosis on alerts."""

from __future__ import annotations

import asyncio
import socket
import struct

import pytest

from netagent.features import diagnose as dg
from netagent.features import secwatch as sw

GW, GW_MAC, EVIL = "192.168.1.1", "28:5b:0c:56:da:2e", "02:11:22:33:44:55"


@pytest.fixture
def svc(tmp_path):
    from netagent.config import settings

    inv = tmp_path / "devices.yaml"
    inv.write_text("devices:\n  R1:\n    host: 127.0.0.1\n    port: 1\n    device_type: cisco_ios\n", encoding="utf-8")
    fake = {"inventory_path": inv, "data_dir": tmp_path / "data", "export_dir": tmp_path / "exports",
            "backup_dir": tmp_path / "backups", "audit_log_path": tmp_path / "audit.jsonl"}
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)
    from netagent.services import Services

    s = Services.create(client=object())
    yield s
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


# -- ARP ---------------------------------------------------------------------------------------------
def test_arp_learns_then_needs_two_sightings():
    w = {}
    assert sw.check_arp(w, GW, {GW: GW_MAC}) == [] and w["gw_mac"] == GW_MAC
    assert sw.check_arp(w, GW, {GW: EVIL}) == []  # one odd reading is not enough
    out = sw.check_arp(w, GW, {GW: EVIL}, vendor=lambda m: "Unknown Co")
    assert len(out) == 1 and "ARP spoofing" in out[0] and EVIL in out[0] and "Unknown Co" in out[0]
    assert sw.check_arp(w, GW, {GW: EVIL}) == []  # reported once, the new MAC is now the baseline


def test_arp_glitch_is_forgotten():
    w = {}
    sw.check_arp(w, GW, {GW: GW_MAC})
    sw.check_arp(w, GW, {GW: EVIL})
    sw.check_arp(w, GW, {GW: GW_MAC})
    assert sw.check_arp(w, GW, {GW: EVIL}) == []  # not two in a row


def test_arp_other_ip_with_router_mac_and_noise_ignored():
    w = {}
    sw.check_arp(w, GW, {GW: GW_MAC})
    table = {GW: GW_MAC, "192.168.1.66": GW_MAC, "192.168.1.255": "ff:ff:ff:ff:ff:ff", "224.0.0.22": "01:00:5e:00:00:16"}
    out = sw.check_arp(w, GW, table)
    assert len(out) == 1 and "192.168.1.66" in out[0]
    assert sw.check_arp(w, GW, table) == []  # same pair is not repeated


def test_new_network_resets_baseline():
    w = {}
    sw.check_arp(w, GW, {GW: GW_MAC})
    assert sw.check_arp(w, "10.0.0.1", {"10.0.0.1": EVIL}) == [] and w["gateway"] == "10.0.0.1"


# -- DHCP --------------------------------------------------------------------------------------------
def _offer(xid: bytes, server: str, offered: str, router: str) -> bytes:
    head = struct.pack("!BBBB4sHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, socket.inet_aton(offered),
                       b"\0" * 4, b"\0" * 4, b"\0" * 16, b"\0" * 64, b"\0" * 128)
    opts = bytes([53, 1, 2, 54, 4]) + socket.inet_aton(server) + bytes([3, 4]) + socket.inet_aton(router) \
        + bytes([6, 8]) + socket.inet_aton("8.8.8.8") + socket.inet_aton("1.1.1.1") + bytes([0, 255])
    return head + b"\x63\x82\x53\x63" + opts


def test_parse_offer():
    xid = b"\x01\x02\x03\x04"
    o = sw.parse_offer(_offer(xid, "192.168.1.1", "192.168.1.50", "192.168.1.1"), xid)
    assert o == {"offered": "192.168.1.50", "server": "192.168.1.1", "router": "192.168.1.1", "dns": "8.8.8.8"}
    assert sw.parse_offer(_offer(xid, "192.168.1.1", "192.168.1.50", "192.168.1.1"), b"\0\0\0\0") is None
    assert sw.parse_offer(b"short", xid) is None
    discover = sw._discover_packet(b"\x02" * 6, xid)  # noqa: SLF001
    assert discover[0] == 1 and discover[4:8] == xid and discover[236:240] == b"\x63\x82\x53\x63"


def test_rogue_dhcp():
    w = {}
    good = {"server": GW, "from": GW, "offered": "192.168.1.50"}
    assert sw.check_dhcp(w, [good], now=1000) == [] and w["dhcp_known"] == [GW]
    rogue = {"server": "192.168.1.77", "from": "192.168.1.77", "offered": "10.0.0.9", "router": "10.0.0.1", "dns": "10.0.0.1"}
    out = sw.check_dhcp(w, [good, rogue], now=2000)
    assert len(out) == 1 and "192.168.1.77" in out[0] and "gateway: 10.0.0.1" in out[0]
    assert sw.check_dhcp(w, [good, rogue], now=3000) == []  # not again within 6 h
    assert len(sw.check_dhcp(w, [good, rogue], now=2000 + sw.DHCP_REALERT + 1)) == 1
    assert sw.check_dhcp(w, None) == []  # this PC could not check: no news


def test_two_dhcp_servers_on_first_check():
    out = sw.check_dhcp({}, [{"server": GW, "from": GW}, {"server": "192.168.1.2", "from": "192.168.1.2"}], now=1)
    assert len(out) == 2


# -- ports -------------------------------------------------------------------------------------------
def _scan(at, devices):
    return {"scanned_at": at, "devices": devices}


def test_new_open_port_after_learning():
    w = {}
    pc = {"ip": "192.168.1.20", "mac": "aa:aa:aa:aa:aa:01", "ports": [445], "name": "", "vendor": "Dell"}
    me = {"ip": "192.168.1.10", "mac": "", "ports": [], "self": True}
    assert sw.check_ports(w, _scan("t1", [pc, me])) == []
    assert sw.check_ports(w, _scan("t1", [dict(pc, ports=[445, 3389])])) == []  # same scan again: ignored
    out = sw.check_ports(w, _scan("t2", [dict(pc, ports=[445, 3389, 7000]), dict(me, ports=[3389])]),
                         {"aa:aa:aa:aa:aa:01": "სამუშაო PC"})
    assert len(out) == 1 and "3389 RDP" in out[0] and "სამუშაო PC" in out[0] and "7000" not in out[0]
    assert sw.check_ports(w, _scan("t3", [dict(pc, ports=[445])])) == []  # asleep
    assert sw.check_ports(w, _scan("t4", [dict(pc, ports=[445, 3389])])) == []  # back: seen before, no repeat


def test_new_device_is_learned_not_reported():
    w = {}
    sw.check_ports(w, _scan("t1", []))
    assert sw.check_ports(w, _scan("t2", [{"ip": "192.168.1.30", "mac": "bb", "ports": [23]}])) == []


# -- /security -----------------------------------------------------------------------------------------
def test_security_command(svc, monkeypatch):
    from netagent import commands

    monkeypatch.setattr(sw.homenet, "default_gateway", lambda: GW)
    monkeypatch.setattr(sw.homenet, "read_arp", lambda: {GW: GW_MAC})
    monkeypatch.setattr(sw, "dhcp_probe", lambda: [{"server": GW, "from": GW}])
    assert "ჯერ არ შემოწმებულა" in commands.run(svc, "/security", "view:gio").text
    text = commands.run(svc, "/security check", "view:gio").text
    assert "ახალი საფრთხე ვერ ვიპოვე" in text and GW_MAC in text and f"მხოლოდ {GW}" in text
    monkeypatch.setattr(sw, "dhcp_probe", lambda: [{"server": GW, "from": GW}, {"server": "192.168.1.77", "from": "192.168.1.77"}])
    text = commands.run(svc, "/security check", "app:nodo").text
    assert "უცხო DHCP სერვერი" in text and "ბოლო მიგნებები" in text
    assert commands.run(svc, "/security reset", "view:gio").text.startswith("⛔")
    assert "წაიშალა" in commands.run(svc, "/security reset", "app:nodo").text
    assert svc.state.get(sw.KEY) is None


def test_security_job_emits_alert(svc, monkeypatch):
    monkeypatch.setattr(sw.homenet, "default_gateway", lambda: GW)
    monkeypatch.setattr(sw.homenet, "read_arp", lambda: {GW: GW_MAC, "192.168.1.66": GW_MAC})
    monkeypatch.setattr(sw, "dhcp_probe", lambda: None)
    sent = []

    class Mon:
        s = svc

        async def emit(self, alert):
            sent.append(alert)

    (name, every, delay, fn), = sw.jobs(Mon())
    asyncio.run(fn())
    assert name == "secwatch" and sent and sent[0].kind == "security" and "192.168.1.66" in sent[0].text


# -- automatic diagnosis ---------------------------------------------------------------------------------
class FakeMonitoring:
    def __init__(self, s):
        self.s, self.sent = s, []

    async def emit(self, alert):
        self.sent.append(alert)
        from netagent import features

        features.on_alert(self.s, alert)  # like the real emit


def _alert(kind, text, devices=()):
    from netagent.monitoring import Alert

    return Alert(kind, text, list(devices))


def test_auto_target():
    assert dg.auto_target(_alert("down", "🔴 R1", ["R1", "SW1"])) == "R1"
    assert dg.auto_target(_alert("isp", "🔴 **ინტერნეტი გაითიშა** (10:00-დან)")) == ""
    assert dg.auto_target(_alert("isp", "🟢 **ინტერნეტი აღდგა**")) is None
    assert dg.auto_target(_alert("up", "🟢 R1", ["R1"])) is None


def test_auto_diagnosis_follows_alert_and_outage_cause_repeats(svc, monkeypatch):
    calls = []

    def fake_diag(s, text="", probes=None):
        calls.append(text)
        d = dg.Diagnosis("x")
        d.found("პრობლემა WAN-ზეა", ["დაურეკე პროვაიდერს"])
        return d

    monkeypatch.setattr(dg, "diagnose", fake_diag)
    mon = FakeMonitoring(svc)
    dg.jobs(mon)

    async def scenario():
        await mon.emit(_alert("isp", "🔴 **ინტერნეტი გაითიშა** (10:00-დან)"))
        await mon.emit(_alert("isp", "🔴 **ინტერნეტი გაითიშა** (10:01-დან)"))  # cooldown: no second run
        for _ in range(50):
            await asyncio.sleep(0.02)
            if any(a.kind == "diagnosis" for a in mon.sent):
                break
        await mon.emit(_alert("isp", "🟢 **ინტერნეტი აღდგა** — არ იყო 5 წთ"))
        await asyncio.sleep(0.05)

    asyncio.run(scenario())
    diag = [a for a in mon.sent if a.kind == "diagnosis"]
    assert calls == [""] and len(diag) == 2
    assert "ავტოდიაგნოსტიკა — ინტერნეტი" in diag[0].text and "WAN" in diag[0].text and "დაურეკე" in diag[0].text
    assert diag[0].buttons[0].command == "/diagnose"
    assert "გათიშვის მიზეზი" in diag[1].text and svc.state.get(dg.ISP_KEY) is None


def test_auto_diagnosis_for_device_and_switch_off(svc, monkeypatch):
    seen = []
    monkeypatch.setattr(dg, "diagnose", lambda s, text="", probes=None: (seen.append(text), dg.Diagnosis("x"))[1])
    mon = FakeMonitoring(svc)
    dg.jobs(mon)

    async def go(alert):
        await mon.emit(alert)
        await asyncio.sleep(0.1)

    asyncio.run(go(_alert("down", "🔴 R1 · SW1", ["R1", "SW1"])))
    assert seen == ["R1"]
    d = [a for a in mon.sent if a.kind == "diagnosis"][0]
    assert "ასევე მიუწვდომელია: SW1" in d.text and d.devices == ["R1", "SW1"]
    monkeypatch.setenv("NETAGENT_AUTODIAGNOSE", "off")
    svc.state.set("autodiag_last", None)
    asyncio.run(go(_alert("down", "🔴 R1", ["R1"])))
    assert seen == ["R1"]
