"""Live Devices: scanner, liveness pings, ARP fallback, names, OUI lookup, settings, CSV, API — on a fake network.
Plus the bug fixes that came with it: owner-only secret files, safe state writes across processes."""

from __future__ import annotations

import socket
import struct
import tempfile
from pathlib import Path

import pytest

from netagent.features import livedevices as lv
from netagent.macvendor import VendorDB, normalize
from netagent.state import StateStore

IFACE = {"name": "Wi-Fi", "ip": "192.168.1.10", "netmask": "255.255.255.0", "network": "192.168.1.0/24", "prefix": 24,
         "mac": "0c:9a:3c:d1:1e:9c", "up": True, "virtual": False}
ROUTER, PHONE, PC, PRINTER = "192.168.1.1", "192.168.1.20", "192.168.1.30", "192.168.1.40"


class FakeNet(lv.Prober):
    """Who answers what: pings {ip: ms}, arps {ip: mac}. Change them between rounds to simulate the network."""

    name = "fake"

    def __init__(self, pings=None, arps=None):
        self.notices = []
        self.pings = dict(pings or {})
        self.arps = dict(arps or {})
        self.ping_calls = []

    def ping(self, ip, timeout=1.0):
        self.ping_calls.append(ip)
        return self.pings.get(ip)

    def arp(self, ip):
        return self.arps.get(ip, "")


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def vendors(tmp_path):
    cache = tmp_path / "oui.txt"
    cache.write_text("285b0c\tRouterCo\nc0956d\tApple, Inc.\nf4b520\tBiostar\n", encoding="utf-8")
    return VendorDB(cache)


def engine(tmp_path, net, vendors=None, clock=None, arp_table=None, names=None, state=None, interfaces=None):
    return lv.LiveEngine(state or StateStore(tmp_path / "s.json"), vendors, prober=net,
                         names=names or (lambda ip: ("", "")), interfaces=lambda: interfaces or [IFACE],
                         local_ip=lambda: IFACE["ip"], gateway=lambda: ROUTER, arp_table=lambda: dict(arp_table or {}),
                         labels=lambda: {}, log_path=tmp_path / "logs" / "live-devices.log", clock=clock or Clock())


def rows(e):
    return {r["ip"]: r for r in e.snapshot()["devices"]}


# -- discovery -----------------------------------------------------------------------------------------
def test_sweep_finds_devices_by_ping_or_arp(tmp_path, vendors):
    net = FakeNet(pings={ROUTER: 1.2, PHONE: 40.0},                       # PC blocks ICMP, answers ARP only
                  arps={ROUTER: "28:5b:0c:56:da:2e", PC: "f4:b5:20:5b:70:1c", PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net, vendors)
    e.sweep()
    r = rows(e)
    assert set(r) == {IFACE["ip"], ROUTER, PHONE, PC}
    assert r[ROUTER]["mac"] == "28:5b:0c:56:da:2e" and r[ROUTER]["vendor"] == "RouterCo" and r[ROUTER]["gateway"]
    assert r[ROUTER]["latency_ms"] == 1.2 and r[ROUTER]["online"]
    assert r[PC]["online"] and r[PC]["latency_ms"] is None and not r[PC]["icmp"]  # alive via ARP, no ping
    assert r[PHONE]["vendor"] == "Apple, Inc."
    assert r[IFACE["ip"]]["self"] and r[IFACE["ip"]]["hostname"] == socket.gethostname()
    assert not any(x["new"] for x in r.values())  # first sweep is a baseline
    assert e.snapshot()["events"] == []


def test_mac_na_without_arp_answer_and_arp_table_fallback(tmp_path):
    net = FakeNet(pings={PHONE: 5.0, PRINTER: 3.0})                       # nobody answers ARP
    e = engine(tmp_path, net, arp_table={PRINTER: "aa:bb:cc:00:11:22", "10.9.9.9": "aa:bb:cc:00:11:33",
                                         "192.168.1.255": "ff:ff:ff:ff:ff:ff"})
    e.sweep()
    r = rows(e)
    assert r[PHONE]["mac"] == "N/A"                                        # answered ping, MAC unknown
    assert r[PRINTER]["mac"] == "aa:bb:cc:00:11:22"                        # from the system ARP table
    assert "10.9.9.9" not in r and "192.168.1.255" not in r                # other subnet / broadcast ignored


def test_second_arp_try_for_devices_that_answered_ping(tmp_path):
    class Sleepy(FakeNet):  # phone in power save: misses the first ARP request, answers once awake
        def __init__(self):
            super().__init__(pings={PHONE: 80.0})
            self.asked = 0

        def arp(self, ip):
            if ip != PHONE:
                return ""
            self.asked += 1
            return "c0:95:6d:2f:85:33" if self.asked > 1 else ""

    e = engine(tmp_path, Sleepy())
    e.sweep()
    assert rows(e)[PHONE]["mac"] == "c0:95:6d:2f:85:33"


def test_off_subnet_mac_is_na(tmp_path):
    e = engine(tmp_path, FakeNet())
    e.iface = IFACE
    with e.lock:
        d = e._upsert("10.0.0.5", "aa:bb:cc:dd:ee:ff", 3.0, e.clock())  # noqa: SLF001
    assert d.mac == "" and d.key == "ip:10.0.0.5"


# -- liveness ------------------------------------------------------------------------------------------
def test_offline_after_missed_pings_then_back(tmp_path):
    clock = Clock()
    net = FakeNet(pings={PHONE: 10.0}, arps={PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    net.pings, net.arps = {}, {}                                           # phone leaves
    for i in range(2):
        clock.t += 10
        e.tick(block=True)
        assert rows(e)[PHONE]["online"], f"still online after {i + 1} miss(es)"
    clock.t += 10
    e.tick(block=True)
    r = rows(e)[PHONE]
    assert not r["online"] and r["latency_ms"] is None and r["mac"] == "c0:95:6d:2f:85:33"  # kept, not removed
    assert e.snapshot()["events"][0]["event"] == "offline"
    net.pings = {PHONE: 12.0}                                              # comes back (found by the next sweep)
    clock.t += 60
    e.sweep()
    assert rows(e)[PHONE]["online"] and e.snapshot()["events"][0]["event"] == "online"
    log = (tmp_path / "logs" / "live-devices.log").read_text(encoding="utf-8").splitlines()
    assert [line.split("\t")[1] for line in log] == ["offline", "online"] and PHONE in log[0]


def test_arp_keeps_ping_blocking_pc_online(tmp_path):
    clock = Clock()
    net = FakeNet(arps={PC: "f4:b5:20:5b:70:1c"})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    for _ in range(5):
        clock.t += 3
        e.tick(block=True)
    r = rows(e)[PC]
    assert r["online"] and r["latency_ms"] is None and r["misses"] == 0


def test_new_device_after_baseline(tmp_path, vendors):
    clock = Clock()
    net = FakeNet(pings={ROUTER: 1.0}, arps={ROUTER: "28:5b:0c:56:da:2e"})
    e = engine(tmp_path, net, vendors, clock=clock)
    e.sweep()
    net.pings[PHONE], net.arps[PHONE] = 30.0, "c0:95:6d:2f:85:33"
    clock.t += 60
    e.sweep()
    r = rows(e)
    assert r[PHONE]["new"] and not r[ROUTER]["new"]
    ev = e.snapshot()["events"][0]
    assert ev["event"] == "new" and ev["ip"] == PHONE and ev["vendor"] == "Apple, Inc."
    clock.t += lv.NEW_SECONDS + 1
    assert not rows(e)[PHONE]["new"]                                       # highlight wears off


def test_mac_learned_later_rekeys(tmp_path):
    clock = Clock()
    net = FakeNet(pings={PHONE: 9.0})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    assert rows(e)[PHONE]["key"] == f"ip:{PHONE}"
    net.arps[PHONE] = "c0:95:6d:2f:85:33"
    clock.t += 3
    e.tick(block=True)
    r = rows(e)[PHONE]
    assert r["key"] == "c0:95:6d:2f:85:33" and r["mac"] == "c0:95:6d:2f:85:33"


def test_dhcp_moves_device_to_new_ip(tmp_path):
    clock = Clock()
    mac = "c0:95:6d:2f:85:33"
    net = FakeNet(pings={PHONE: 9.0}, arps={PHONE: mac})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    net.pings, net.arps = {"192.168.1.21": 9.0}, {"192.168.1.21": mac}
    clock.t += 60
    e.sweep()
    r = rows(e)
    assert PHONE not in r and r["192.168.1.21"]["mac"] == mac and len([x for x in r.values() if x["mac"] == mac]) == 1


def test_restart_keeps_first_seen_and_does_not_flood_events(tmp_path):
    clock = Clock()
    state = StateStore(tmp_path / "s.json")
    net = FakeNet(pings={PHONE: 9.0}, arps={PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net, clock=clock, state=state)
    e.sweep()
    first = rows(e)[PHONE]["first_seen"]
    e.close()
    clock.t += 3600
    e2 = engine(tmp_path, net, clock=clock, state=StateStore(tmp_path / "s.json"))
    assert not rows(e2)[PHONE]["online"]                                   # loaded, not yet confirmed
    e2.sweep()
    r = rows(e2)[PHONE]
    assert r["online"] and r["first_seen"] == first and not r["new"]
    assert e2.snapshot()["events"] == []                                   # no "online" flood after a restart
    e2.close()


def test_ticks_skip_offline_devices(tmp_path):
    clock = Clock()
    net = FakeNet(pings={PHONE: 9.0}, arps={PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    net.pings, net.arps = {}, {}
    for _ in range(3):
        clock.t += 10
        e.tick(block=True)
    clock.t += 300
    net.ping_calls.clear()
    e.tick(block=True)
    assert PHONE not in net.ping_calls                                     # the sweep re-checks it, not every tick


# -- settings, interfaces, views ------------------------------------------------------------------------
def test_settings_are_clamped_and_interface_change_resets(tmp_path):
    net = FakeNet(pings={ROUTER: 1.0})
    e = engine(tmp_path, net)
    e.sweep()
    s = e.update_settings({"ping_interval": 0, "scan_interval": 99999, "offline_after": "x"})
    assert s["ping_interval"] == 1 and s["scan_interval"] == 3600 and s["offline_after"] == 3
    e.update_settings({"interface": "Ethernet"})
    assert e.settings()["interface"] == "Ethernet"
    e.sweep()                                                              # "Ethernet" does not exist: auto + notice
    assert e.iface["name"] == "Wi-Fi" and any("Ethernet" in n for n in e.notices)
    assert ROUTER in rows(e) and not rows(e)[ROUTER]["new"]                # memory kept: not "new" again


def test_pick_interface_and_big_subnets():
    vm = dict(IFACE, name="VMware Network Adapter VMnet8", ip="192.168.204.1", network="192.168.204.0/24", virtual=True)
    assert lv.pick_interface([vm, IFACE], "", IFACE["ip"])["name"] == "Wi-Fi"
    assert lv.pick_interface([vm, IFACE], "", "10.0.0.1")["name"] == "Wi-Fi"          # prefer a real adapter
    assert lv.pick_interface([vm, IFACE], vm["name"], IFACE["ip"]) is vm               # manual choice wins
    assert lv.pick_interface([], "", "") is None
    targets, note = lv.scan_targets(dict(IFACE, ip="10.20.30.40", network="10.20.0.0/16", prefix=16))
    assert len(targets) == 254 and targets[0] == "10.20.30.1" and "10.20.30.0/24" in note
    targets, note = lv.scan_targets(IFACE)
    assert len(targets) == 254 and note == ""


def test_list_interfaces_filters_noise():
    found = lv.list_interfaces()
    assert all(not i["ip"].startswith(("127.", "169.254.")) and i["prefix"] < 31 for i in found)


def test_snapshot_history_and_csv(tmp_path, vendors):
    clock = Clock()
    net = FakeNet(pings={ROUTER: 1.5, PHONE: 20.0}, arps={ROUTER: "28:5b:0c:56:da:2e"})
    e = engine(tmp_path, net, vendors, clock=clock, names=lambda ip: ("iPhone.local", "mDNS") if ip == PHONE else ("", ""))
    e.sweep()
    import time as _t
    _t.sleep(0.2)                                                          # names resolve in the background
    for _ in range(3):
        clock.t += 3
        e.tick(block=True)
    snap = e.snapshot()
    assert snap["online"] == 3 and snap["offline"] == 0 and snap["interface"]["name"] == "Wi-Fi"
    assert rows(e)[PHONE]["hostname"] == "iPhone.local" and rows(e)[PHONE]["hostname_source"] == "mDNS"
    h = e.history("28:5b:0c:56:da:2e")
    assert h["samples"] == 4 and h["min_ms"] == 1.5 and h["loss_pct"] == 0.0
    assert e.history("nope") is None
    csv_text = e.export_csv()
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("status,ip,mac,vendor,hostname") and len(lines) == 4
    assert "online,192.168.1.1,28:5b:0c:56:da:2e,RouterCo" in csv_text and "N/A" in csv_text


def test_background_thread_runs_and_closes(tmp_path):
    import time as _t

    net = FakeNet(pings={ROUTER: 1.0})
    e = engine(tmp_path, net)
    e.update_settings({"ping_interval": 1})
    e.start()
    for _ in range(50):
        if e.last_scan:
            break
        _t.sleep(0.05)
    assert e.last_scan and ROUTER in rows(e)
    e.close()
    assert not e._thread.is_alive()  # noqa: SLF001


# -- names --------------------------------------------------------------------------------------------
def test_ptr_query_and_compressed_answer():
    q = lv.ptr_query("192.168.1.20", tid=7)
    assert q[:2] == b"\x00\x07" and b"\x0220\x011\x03168\x03192\x07in-addr\x04arpa\x00" in q
    assert q.endswith(struct.pack("!HH", 12, 0x8001))
    # answer: same question, then a PTR record whose owner name points back at the question (0xC00C)
    answer = (struct.pack("!HHHHHH", 7, 0x8400, 1, 1, 0, 0) + q[12:]
              + b"\xc0\x0c" + struct.pack("!HHIH", 12, 0x8001, 120, 13) + b"\x06iPhone\x05local\x00")
    assert lv.parse_ptr(answer) == "iPhone.local"
    assert lv.parse_ptr(b"\x00" * 5) == "" and lv.parse_ptr(answer[:40]) == ""


def test_netbios_status_parse():
    def entry(name, suffix, flags):
        return name.ljust(15).encode() + bytes([suffix]) + struct.pack("!H", flags)

    q = lv.nbstat_query(5)
    assert q[12] == 0x20 and q[13:15] == b"CK"
    rdata = bytes([3]) + entry("WORKGROUP", 0x00, 0x8400) + entry("DESKTOP-K9OTDM7", 0x00, 0x0400) + entry("DESKTOP-K9OTDM7", 0x20, 0x0400)
    resp = struct.pack("!HHHHHH", 5, 0x8400, 0, 1, 0, 0) + q[12:46] + struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata
    assert lv.parse_nbstat(resp) == "DESKTOP-K9OTDM7"                    # group name skipped
    assert lv.parse_nbstat(b"\x00" * 12) == ""


def test_resolve_name_order(monkeypatch):
    monkeypatch.setattr(lv, "mdns_name", lambda ip: "")
    monkeypatch.setattr(lv, "netbios_name", lambda ip: "DESKTOP-1")
    monkeypatch.setattr(lv, "reverse_dns", lambda ip: "dhcp-20.isp.example")
    assert lv.resolve_name("192.168.1.20") == ("DESKTOP-1", "NetBIOS")
    monkeypatch.setattr(lv, "netbios_name", lambda ip: "")
    monkeypatch.setattr(lv, "reverse_dns", lambda ip: "20.1.168.192.in-addr.arpa")
    assert lv.resolve_name("192.168.1.20") == ("", "")                   # placeholders are not names


def test_udp_name_query_against_a_local_responder():
    """Real sockets: a tiny NetBIOS-style responder on localhost answers our query."""
    import threading

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def answer():
        data, addr = srv.recvfrom(512)
        srv.sendto(data[:2] + b"OK", addr)
        srv.close()

    threading.Thread(target=answer, daemon=True).start()
    got = lv._udp_ask("127.0.0.1", port, b"\x12\x34hello", lambda d: d.decode(errors="replace"), 2.0)  # noqa: SLF001
    assert got.endswith("OK")


# -- ping primitives -------------------------------------------------------------------------------------
def test_icmp_checksum():
    header = struct.pack("!BBHHH", 8, 0, 0, 0, 1) + b"abcd"
    c = lv._checksum(header)  # noqa: SLF001
    assert lv._checksum(header[:2] + struct.pack("!H", c) + header[4:]) == 0  # noqa: SLF001


def test_real_ping_to_localhost():
    """The real prober for this OS answers for 127.0.0.1 (Windows: IcmpSendEcho, no admin)."""
    p = lv.make_prober()
    ms = p.ping("127.0.0.1", 1.0)
    if ms is None and not isinstance(p, lv.WindowsProber) and not getattr(p, "dgram", False):
        pytest.skip("no ICMP permission for this user (see the notice the panel shows)")
    assert ms is not None and ms < 100
    assert p.ping("192.0.2.1", 0.3) is None  # TEST-NET-1: never answers


# -- OUI ------------------------------------------------------------------------------------------------
def test_oui_offline_bundled_and_longest_prefix():
    db = VendorDB(Path(tempfile.mkdtemp()) / "not-downloaded.txt")
    assert db.size > 30000                                                  # shipped copy, no internet needed
    assert db.lookup("00:00:0C:12:34:56") and "cisco" in db.lookup("00:00:0C:12:34:56").lower()
    assert db.lookup("02:11:22:33:44:55") is not None                      # randomized (private) MAC label
    assert db.lookup("nonsense") is None and normalize("AA-BB-CC-DD-EE-FF") == "aabbccddeeff"


def test_oui_longest_prefix_wins(tmp_path):
    cache = tmp_path / "oui.txt"
    cache.write_text("70b3d5\tIEEE Registration Authority\n70b3d5123\tSmall Vendor (MA-S)\n", encoding="utf-8")
    db = VendorDB(cache)
    assert db.lookup("70:b3:d5:12:34:56") == "Small Vendor (MA-S)"
    assert db.lookup("70:b3:d5:99:34:56") == "IEEE Registration Authority"


# -- API ------------------------------------------------------------------------------------------------
H = {"X-NetAgent": "1"}


@pytest.fixture
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from netagent.config import settings
    from netagent.monitoring import MonitoringService
    from netagent.services import Services
    from netagent.web.app import create_app
    from netagent.web.auth import WebAuth

    fake = {"data_dir": tmp_path / "data", "audit_log_path": tmp_path / "audit.jsonl", "export_dir": tmp_path / "exports"}
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)
    services = Services.create(client=object())
    auth = WebAuth(tmp_path / "data" / "web_auth.json")
    auth.set_password("a-long-password")
    auth.add_user("gio", "viewer-password-1", "viewer")
    net = FakeNet(pings={ROUTER: 1.5, PHONE: 9.0}, arps={ROUTER: "28:5b:0c:56:da:2e", PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net, services.vendors)
    e.sweep()
    monkeypatch.setattr(lv, "ENGINE", e)
    client = TestClient(create_app(services, MonitoringService(services), auth, None))
    yield client, e
    e.close()
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


def test_api_live(api):
    client, e = api
    assert client.get("/api/live").status_code == 401
    assert client.post("/api/login", json={"password": "a-long-password"}, headers=H).status_code == 200
    data = client.get("/api/live").json()
    assert data["online"] == 3 and {r["ip"] for r in data["devices"]} == {IFACE["ip"], ROUTER, PHONE}
    assert data["interface"]["network"] == "192.168.1.0/24" and data["settings"]["ping_interval"] == 3
    h = client.get("/api/live/device", params={"key": "28:5b:0c:56:da:2e"}).json()
    assert h["ip"] == ROUTER and h["points"]
    assert client.get("/api/live/device", params={"key": "x"}).status_code == 404
    assert client.post("/api/live/scan", json={}, headers=H).json() == {"ok": True}
    assert client.post("/api/live/settings", json={"ping_interval": 5}, headers=H).json()["ping_interval"] == 5
    r = client.get("/api/live/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"] and r.text.lstrip("﻿").startswith("status,ip,mac")


def test_api_live_viewer_cannot_change_settings(api):
    client, e = api
    client.post("/api/login", json={"username": "gio", "password": "viewer-password-1"}, headers=H)
    assert client.get("/api/live").status_code == 200
    assert client.post("/api/live/settings", json={"ping_interval": 5}, headers=H).status_code == 403
    assert client.post("/api/live/settings", json={"ping_interval": 5}).status_code == 403  # CSRF header too
    assert e.settings()["ping_interval"] == 3


def test_api_live_off(api, monkeypatch):
    client, _ = api
    client.post("/api/login", json={"password": "a-long-password"}, headers=H)
    monkeypatch.setattr(lv, "ENGINE", None)
    assert client.get("/api/live").status_code == 503
    assert client.get("/api/live/export.csv").status_code == 503


def test_live_command(tmp_path, monkeypatch):
    from netagent.result import Result

    e = engine(tmp_path, FakeNet(pings={ROUTER: 1.5}, arps={ROUTER: "28:5b:0c:56:da:2e"}))
    e.sweep()
    monkeypatch.setattr(lv, "ENGINE", e)
    out = lv.live_cmd(None, [], "app:nodo")
    assert isinstance(out, Result) and "192.168.1.1" in out.text and "1.5 ms" in out.text
    monkeypatch.setattr(lv, "ENGINE", None)
    assert "გამორთულია" in lv.live_cmd(None, [], "app:nodo").text


# -- bug fixes that came along ------------------------------------------------------------------------------
def test_atomic_write_private_and_no_leftovers(tmp_path):
    from netagent.osutil import atomic_write, is_private

    p = tmp_path / "secret.json"
    atomic_write(p, '{"k": 1}', private=True)
    assert p.read_text() == '{"k": 1}' and is_private(p)
    atomic_write(p, b"bytes too")
    assert p.read_bytes() == b"bytes too"
    assert [x.name for x in tmp_path.iterdir()] == ["secret.json"]


def test_state_store_sees_other_process_writes(tmp_path):
    a = StateStore(tmp_path / "state.json")
    b = StateStore(tmp_path / "state.json")      # e.g. the CLI while the server runs
    a.set("x", 1)
    b.set("y", 2)                                 # b reloads a's file first instead of overwriting it
    a.set("z", 3)
    fresh = StateStore(tmp_path / "state.json")
    assert (fresh.get("x"), fresh.get("y"), fresh.get("z")) == (1, 2, 3)


def test_secret_files_are_private(tmp_path):
    from netagent.osutil import is_private
    from netagent.web.push import VapidKeys

    VapidKeys(tmp_path / "vapid.pem")
    assert is_private(tmp_path / "vapid.pem")


def test_subprocess_calls_hide_console_windows():
    import re

    root = Path(__file__).resolve().parent.parent / "netagent"
    offenders = []
    for f in root.rglob("*.py"):
        if f.name in {"cli.py", "osutil.py"} or "demo" in f.parts:
            continue
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r"subprocess\.run\(", text):
            call = text[m.start(): text.find(")", text.find("timeout", m.start())) + 1]
            if "creationflags" not in text[m.start(): m.start() + 400]:
                offenders.append(f"{f.name}: {call[:60]}")
    assert not offenders, offenders


def test_interface_switch_during_sweep_discards_stale_results(tmp_path):
    class SwitchMidway(FakeNet):
        def arp_many(self, ips, pool):
            if not self.switched:
                self.switched = True
                self.engine.update_settings({"interface": ""})  # user picks another interface while we scan
            return super().arp_many(ips, pool)

    net = SwitchMidway(pings={ROUTER: 1.0}, arps={ROUTER: "28:5b:0c:56:da:2e"})
    net.switched = False
    e = engine(tmp_path, net)
    net.engine = e
    e.sweep()
    assert e.snapshot()["devices"] == []        # the old sweep wrote nothing into the new list
    e.sweep()
    assert ROUTER in rows(e)                     # the next sweep fills it


def test_list_shows_only_the_watched_subnet(tmp_path):
    state = StateStore(tmp_path / "s.json")
    state.set(lv.KNOWN_KEY, {"00:50:56:fa:81:e5": {"ip": "192.168.204.254", "mac": "00:50:56:fa:81:e5",
                                                   "first_seen": 1_799_999_000.0, "last_seen": 1_799_999_900.0}})
    e = engine(tmp_path, FakeNet(pings={ROUTER: 1.0}), state=state)
    e.sweep()
    assert set(rows(e)) == {IFACE["ip"], ROUTER}                      # the VMware record is not mixed in
    assert "00:50:56:fa:81:e5" in state.get(lv.KNOWN_KEY)             # but it is kept


def test_phone_power_save_does_not_flap(tmp_path):
    clock = Clock()
    net = FakeNet(pings={PHONE: 9.0}, arps={PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    net.pings, net.arps = {}, {}                  # silent for 3 checks, but only 9 seconds
    for _ in range(3):
        clock.t += 3
        e.tick(block=True)
    assert rows(e)[PHONE]["online"] and e.snapshot()["events"] == []
    net.pings = {PHONE: 30.0}                     # wakes up again: no offline/online pair was logged
    clock.t += 3
    e.tick(block=True)
    assert rows(e)[PHONE]["online"] and e.snapshot()["events"] == []


def test_no_online_flood_from_pings_right_after_restart(tmp_path):
    clock = Clock()
    net = FakeNet(pings={PHONE: 9.0, ROUTER: 1.0}, arps={PHONE: "c0:95:6d:2f:85:33", ROUTER: "28:5b:0c:56:da:2e"})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    e.close()
    clock.t += 30
    e2 = engine(tmp_path, net, clock=clock, state=StateStore(tmp_path / "s.json"))
    e2._choose_interface()  # noqa: SLF001 - the ping loop starts before the first sweep has finished
    e2.tick(block=True)
    assert rows(e2)[PHONE]["online"] and e2.snapshot()["events"] == []
    e2.sweep()
    assert e2.snapshot()["events"] == []
    e2.close()


def test_switching_back_remembers_devices(tmp_path):
    vm = dict(IFACE, name="VMnet8", ip="192.168.204.1", network="192.168.204.0/24", mac="00:50:56:c0:00:08", virtual=True)
    clock = Clock()
    net = FakeNet(pings={ROUTER: 1.0, "192.168.204.254": 1.0}, arps={ROUTER: "28:5b:0c:56:da:2e"})
    e = engine(tmp_path, net, clock=clock, interfaces=[IFACE, vm])
    e.sweep()
    e.update_settings({"interface": "VMnet8"})
    clock.t += 60
    e.sweep()
    assert set(rows(e)) == {"192.168.204.1", "192.168.204.254"}           # only the watched subnet is listed
    assert not any(r["new"] for r in rows(e).values())                    # first look at VMnet8: baseline
    e.update_settings({"interface": ""})
    clock.t += 60
    e.sweep()
    assert ROUTER in rows(e) and not rows(e)[ROUTER]["new"]               # back on Wi-Fi: known, not "new"
    assert all(ev["event"] != "new" for ev in e.snapshot()["events"])
