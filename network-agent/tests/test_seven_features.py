"""Device types, online history, trusted/unknown alerts, IoT check, speed history + ISP PDF, self-healing, live map."""

from __future__ import annotations

import os
import random
import socket
import struct
import threading
from datetime import datetime, timedelta
from types import SimpleNamespace as NS

import pytest

from netagent.features import iotcheck, isp, livedevices as lv, livemap, selfheal
from netagent.state import StateStore

IFACE = {"name": "Wi-Fi", "ip": "192.168.1.10", "netmask": "255.255.255.0", "network": "192.168.1.0/24", "prefix": 24,
         "mac": "0c:9a:3c:d1:1e:9c", "up": True, "virtual": False}
ROUTER, PHONE, CAM = "192.168.1.1", "192.168.1.20", "192.168.1.30"


class Net(lv.Prober):
    name = "fake"

    def __init__(self, pings=None, arps=None):
        self.notices, self.pings, self.arps = [], dict(pings or {}), dict(arps or {})

    def ping(self, ip, timeout=1.0):
        return self.pings.get(ip)

    def arp(self, ip):
        return self.arps.get(ip, "")


class Clock:
    def __init__(self, t=None):
        self.t = t or datetime(2026, 11, 8, 14, 0).timestamp()

    def __call__(self):
        return self.t


def engine(tmp_path, net, clock=None, state=None, ports=None, notify=None, names=None, vendors=None):
    return lv.LiveEngine(state or StateStore(tmp_path / "s.json"), vendors, prober=net, names=names or (lambda ip: ("", "")),
                         interfaces=lambda: [IFACE], local_ip=lambda: IFACE["ip"], gateway=lambda: ROUTER,
                         arp_table=lambda: {}, labels=lambda: {}, log_path=tmp_path / "live.log", clock=clock or Clock(),
                         ports=ports or (lambda ip: []), notify=notify)


def rows(e):
    return {r["ip"]: r for r in e.snapshot()["devices"]}


def settle(e):
    e._name_pool.shutdown(wait=True)  # noqa: SLF001 - wait for background name/port lookups


# =========================================================================== 1. device types
@pytest.mark.parametrize("vendor,host,ports,want", [
    ("", "DESKTOP-K9OTDM7", (), "pc"), ("", "iPad-Air-4th-generation.local", (), "phone"),
    ("", "living-room-tv", (), "tv"), ("", "ps5-console", (), "console"), ("", "HP-LaserJet-Pro", (), "printer"),
    ("Intel Corporate", "", (), "pc"), ("", "", (554,), "camera"), ("", "", (9100,), "printer"),
    ("Espressif Inc.", "", (), "iot"), ("TP-LINK TECHNOLOGIES", "", (), "network"), ("", "", (62078,), "phone"),
    ("Qingdao Intelligent&Precise Electronics", "", (7000,), "tv"), ("Qingdao Intelligent&Precise Electronics", "", (), "tv"),
    ("", "MacBook-Pro", (7000, 22), "pc"),
    ("", "", (8009,), "tv"), ("Synology", "", (5000,), "nas"), ("", "", (3389, 445), "pc"), ("", "mystery", (), ""),
])
def test_classify(vendor, host, ports, want):
    assert lv.classify(vendor, host, ports) == want


def test_classify_random_mac_gateway_self():
    from netagent.macvendor import RANDOM_LABEL

    assert lv.classify(RANDOM_LABEL) == "phone"
    assert lv.classify("Intel", gateway=True) == "router" and lv.classify("Intel", me=True) == "self"


def test_kind_and_ports_flow_into_rows(tmp_path):
    net = Net(pings={ROUTER: 1.0, CAM: 5.0}, arps={ROUTER: "28:5b:0c:56:da:2e", CAM: "c0:56:e3:00:00:01"})
    e = engine(tmp_path, net, ports=lambda ip: [80, 554] if ip == CAM else [80])
    e.sweep()
    settle(e)
    r = rows(e)
    assert r[CAM]["kind"] == "camera" and r[CAM]["icon"] == "camera" and r[CAM]["ports"] == [80, 554]
    assert r[ROUTER]["kind"] == "router" and r[IFACE["ip"]]["kind"] == "self"
    assert "type" in e.export_csv().splitlines()[0]


# =========================================================================== 2. online history
def test_runs_roundtrip():
    s = {5, 6, 7, 10, 20, 21}
    assert lv.unruns(lv.runs(s)) == s


def test_timeline_day_and_week(tmp_path):
    clock = Clock()
    net = Net(pings={PHONE: 9.0}, arps={PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    for _ in range(12):                    # online for one hour, one check every 5 minutes
        clock.t += 300
        e.tick(block=True)
    net.pings, net.arps = {}, {}
    for _ in range(6):                     # then away for half an hour
        clock.t += 300
        e.tick(block=True)
    day = e.timeline("c0:95:6d:2f:85:33", 1)
    assert day["slot_seconds"] == 300 and len(day["values"]) == 288
    known = [v for v in day["values"] if v is not None]
    assert sum(known) == 13 and known[-1] == 0 and 1.0 in known
    assert 1.0 <= day["online_hours"] <= 1.2
    week = e.timeline("c0:95:6d:2f:85:33", 7)
    assert week["slot_seconds"] == 3600 and len(week["values"]) == 168 and any(0 < v < 1 for v in week["values"] if v)
    assert e.timeline("nope", 1) is None


def test_timeline_survives_restart(tmp_path):
    clock = Clock()
    net = Net(pings={PHONE: 9.0}, arps={PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net, clock=clock)
    e.sweep()
    before = sum(v for v in e.timeline("c0:95:6d:2f:85:33", 1)["values"] if v)
    e.close()
    e2 = engine(tmp_path, net, clock=clock, state=StateStore(tmp_path / "s.json"))
    assert sum(v for v in e2.timeline("c0:95:6d:2f:85:33", 1)["values"] if v) == before > 0


# =========================================================================== 3. trusted / unknown + alerts
def test_first_run_trusts_what_is_already_there_then_alerts_newcomers(tmp_path):
    clock = Clock()
    sent = []
    net = Net(pings={ROUTER: 1.0}, arps={ROUTER: "28:5b:0c:56:da:2e"})
    e = engine(tmp_path, net, clock=clock, notify=lambda text, buttons: sent.append((text, buttons)))
    e.sweep()
    assert rows(e)[ROUTER]["trusted"] and any("ავტომატურად მოინიშნა" in n for n in e.notices) and sent == []
    net.pings[PHONE], net.arps[PHONE] = 30.0, "c0:95:6d:2f:85:33"
    clock.t += 60
    e.sweep()
    assert len(sent) == 1 and "უცნობი მოწყობილობა ქსელში" in sent[0][0] and PHONE in sent[0][0]
    assert sent[0][1][0].command == "/trust c0:95:6d:2f:85:33"
    assert not rows(e)[PHONE]["trusted"]
    assert e.set_trust("c0:95:6d:2f:85:33", True, "app:nodo") and rows(e)[PHONE]["trusted"]
    assert not e.set_trust("nope", True)


def test_unknown_returning_is_rate_limited_and_night_mode(tmp_path):
    clock = Clock(datetime(2026, 11, 8, 14, 0).timestamp())
    sent = []
    net = Net(pings={ROUTER: 1.0}, arps={ROUTER: "28:5b:0c:56:da:2e"})
    e = engine(tmp_path, net, clock=clock, notify=lambda t, b: sent.append(t))
    e.sweep()
    phone = "c0:95:6d:2f:85:33"
    net.pings[PHONE], net.arps[PHONE] = 30.0, phone

    def leave_and_return(minutes_away):
        net.pings.pop(PHONE), net.arps.pop(PHONE)
        for _ in range(3):
            clock.t += 10
            e.tick(block=True)
        clock.t += minutes_away * 60
        net.pings[PHONE], net.arps[PHONE] = 30.0, phone
        e.sweep()

    clock.t += 60
    e.sweep()                                   # joins: alert 1
    leave_and_return(30)                        # back after 30 min: within 6 h -> no alert
    assert len(sent) == 1
    leave_and_return(7 * 60)                    # back after 7 h: alert 2
    assert len(sent) == 2 and "დაბრუნდა" in sent[1]
    e.set_trust(phone, True)
    e.update_settings({"night_alerts": True, "night": "00:00-07:00"})
    clock.t = datetime(2026, 11, 9, 3, 0).timestamp()
    leave_and_return(90)                        # trusted, but it is night: alert 3
    assert len(sent) == 3 and "ღამით" in sent[2]
    e.update_settings({"alert_unknown": False})
    assert e.settings()["alert_unknown"] is False


def test_settings_validation(tmp_path):
    e = engine(tmp_path, Net())
    s = e.update_settings({"night": "junk", "night_alerts": "on", "alert_unknown": "0"})
    assert s["night"] == "00:00-07:00" and s["night_alerts"] is True and s["alert_unknown"] is False
    assert lv.in_window("22:30-06:00", datetime(2026, 1, 1, 23, 0)) and not lv.in_window("22:30-06:00", datetime(2026, 1, 1, 12, 0))


def test_trust_commands(tmp_path, monkeypatch):
    net = Net(pings={ROUTER: 1.0, PHONE: 9.0}, arps={ROUTER: "28:5b:0c:56:da:2e", PHONE: "c0:95:6d:2f:85:33"})
    e = engine(tmp_path, net)
    e.state.set(lv.TRUST_KEY, {})          # not the first run: nothing is trusted automatically
    e.sweep()
    monkeypatch.setattr(lv, "ENGINE", e)
    assert "ნაცნობია" in lv.trust_cmd(None, [PHONE], "app:nodo").text and rows(e)[PHONE]["trusted"]
    assert "მოიხსნა" in lv.untrust_cmd(None, ["C0-95-6D-2F-85-33"], "app:nodo").text and not rows(e)[PHONE]["trusted"]
    assert "3 მოწყობილობა" in lv.trust_cmd(None, ["all"], "app:nodo").text
    from netagent.result import CommandError

    with pytest.raises(CommandError):
        lv.trust_cmd(None, ["10.9.9.9"], "app:nodo")
    from netagent.permissions import VIEWER_BLOCKED_COMMANDS

    assert {"trust", "untrust", "heal"} <= VIEWER_BLOCKED_COMMANDS


# =========================================================================== 4. IoT check
def fake_probe(open_ports, rtsp=None, mqtt=None, adb="", server=""):
    return {"open": lambda ip, p: p in open_ports, "rtsp": lambda ip, p: rtsp, "mqtt": lambda ip, p: mqtt,
            "adb": lambda ip, p: adb, "http": lambda ip, p: server}


def titles(fs):
    return [(f["severity"], f["title"]) for f in fs]


def test_iot_findings():
    fs = iotcheck.check_device(CAM, "", "camera", fake_probe({23, 80, 554, 34567}, rtsp=200, server="uc-httpd 1.0.0"))
    sev = [f["severity"] for f in fs]
    assert sev[:3] == ["high", "high", "high"] and fs == sorted(fs, key=lambda f: iotcheck.RANK[f["severity"]])
    text = " ".join(t for _, t in titles(fs))
    assert "Telnet" in text and "პაროლის გარეშე" in text and "34567" in text and "uc-httpd" in text and "HTTP-ით" in text
    ok = iotcheck.check_device(CAM, "", "camera", fake_probe({554, 443}, rtsp=401))
    assert titles(ok)[0] == ("ok", "RTSP 554 პაროლითაა დაცული")
    assert iotcheck.check_device(PHONE, "", "phone", fake_probe(set()))[0]["severity"] == "ok"


def test_iot_adb_only_when_it_speaks_adb():
    assert not any("ADB" in t for _, t in titles(iotcheck.check_device(ROUTER, "", "router", fake_probe({5555}, adb=""))))
    assert titles(iotcheck.check_device(PHONE, "", "tv", fake_probe({5555}, adb="open")))[0][0] == "high"
    assert titles(iotcheck.check_device(PHONE, "", "tv", fake_probe({5555}, adb="auth")))[0][0] == "medium"


def test_iot_mqtt_and_vendor_ports():
    fs = titles(iotcheck.check_device(PHONE, "TP-LINK", "iot", fake_probe({1883, 9999}, mqtt=True)))
    assert ("high", "MQTT პაროლის გარეშე იღებს კავშირს — 1883") in fs and any("9999" in t for _, t in fs)
    assert any(s == "low" for s, _ in titles(iotcheck.check_device(PHONE, "", "iot", fake_probe({1883}, mqtt=False))))


def test_protocol_packets():
    pkt = iotcheck.mqtt_connect_packet("x")
    assert pkt[0] == 0x10 and pkt[1] == len(pkt) - 2 and pkt[2:8] == b"\x00\x04MQTT" and pkt[8] == 4
    adb = iotcheck.adb_packet()
    cmd, arg0, _, n, csum, magic = struct.unpack("<6I", adb[:24])
    assert adb[:4] == b"CNXN" and n == 7 and adb[24:] == b"host::\x00" and magic == cmd ^ 0xFFFFFFFF and csum == sum(b"host::\x00")
    assert iotcheck.old_server("GoAhead-Webs") and iotcheck.old_server("Boa/0.94.14rc21") and not iotcheck.old_server("nginx/1.25.3")


def _responder(reply: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        conn, _ = srv.accept()
        with conn:
            conn.recv(1024)
            conn.sendall(reply)
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_real_sockets_rtsp_mqtt_adb():
    assert iotcheck.rtsp_status("127.0.0.1", _responder(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n")) == 401
    assert iotcheck.rtsp_status("127.0.0.1", _responder(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n")) == 200
    assert iotcheck.mqtt_anonymous("127.0.0.1", _responder(b"\x20\x02\x00\x00")) is True
    assert iotcheck.mqtt_anonymous("127.0.0.1", _responder(b"\x20\x02\x00\x05")) is False
    assert iotcheck.adb_status("127.0.0.1", _responder(b"AUTH" + b"\x00" * 20)) == "auth"
    assert iotcheck.adb_status("127.0.0.1", _responder(b"HTTP/1.1 400 Bad\r\n\r\n")) == ""
    assert iotcheck.http_server("127.0.0.1", _responder(b"HTTP/1.0 200 OK\r\nServer: GoAhead-Webs\r\n\r\n")) == "GoAhead-Webs"


def test_run_check_stores_results(tmp_path):
    st = StateStore(tmp_path / "s.json")
    s = NS(state=st)
    devs = [{"ip": CAM, "vendor": "", "kind": "camera", "label": "ეზოს კამერა"}]
    r = iotcheck.run_check(s, devices=devs, probe=fake_probe({23}))
    assert r["results"][CAM][0]["severity"] == "high" and st.get(iotcheck.KEY)["devices"][CAM]
    assert "ეზოს კამერა" in iotcheck.format_report(r) and "1 სერიოზული" in iotcheck.format_report(r)


# =========================================================================== 5. speed history + ISP PDF + outages
def _tests(n=6, plan_low=False):
    now = datetime(2026, 11, 8, 12, 0)
    return [{"ts": (now - timedelta(hours=12 * i)).isoformat(timespec="seconds"), "down_mbps": 10.0 + i * (1 if plan_low else 20),
             "up_mbps": 50.0, "ping_ms": 5, "isp": "Silknet"} for i in range(n)][::-1]


def test_speed_stats():
    st = isp.speed_stats(_tests(4), plan=100)
    assert st["count"] == 4 and st["down_min"] == 10.0 and st["down_max"] == 70.0 and st["plan_pct"] == 40 and st["below_half"] == 2
    assert isp.speed_stats([]) == {"count": 0}
    assert "NETAGENT_ISP_PLAN_MBPS" in isp.format_speed_history(isp.speed_stats(_tests(2)), 30)


@pytest.fixture
def svc(tmp_path):
    from netagent.config import settings

    inv = tmp_path / "devices.yaml"
    inv.write_text("devices: {}\n", encoding="utf-8")
    fake = {"inventory_path": inv, "data_dir": tmp_path / "data", "export_dir": tmp_path / "exports",
            "backup_dir": tmp_path / "backups", "audit_log_path": tmp_path / "audit.jsonl"}
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)
    from netagent.services import Services

    s = Services.create(client=object())
    isp._MONITORS.clear()  # noqa: SLF001
    yield s
    isp._MONITORS.clear()  # noqa: SLF001
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


def test_speedhistory_command_and_pdf(svc, tmp_path):
    from netagent import commands, features

    features.install()
    now = datetime.now()
    svc.state.set("isp_speedtests", [{**t, "ts": (now - timedelta(hours=6 * i)).isoformat(timespec="seconds")}
                                     for i, t in enumerate(_tests(5))])
    r = commands.run(svc, "/speedhistory 7", "app:nodo")
    assert "სიჩქარის ისტორია" in r.text and r.image and r.image.exists() and r.image.stat().st_size > 5000
    r = commands.run(svc, "/isp pdf 30", "app:nodo")
    pdf = r.files[0]
    assert pdf.suffix == ".pdf" and pdf.read_bytes()[:5] == b"%PDF-" and pdf.stat().st_size > 10000
    assert any(b.command == "/isp pdf 30" for b in commands.run(svc, "/isp", "app:nodo").buttons)


def test_pc_sleep_is_not_an_outage(tmp_path):
    st = StateStore(tmp_path / "s.json")
    m = isp.InternetMonitor(st, tmp_path / "isp")
    t = datetime(2026, 11, 8, 1, 0)
    for i in range(5):
        m.record({"online": True, "latency_ms": 10.0, "loss": 0}, t + timedelta(minutes=i))
    t += timedelta(minutes=5)
    m.record({"online": False, "latency_ms": None, "loss": 100}, t)               # last probe before sleep fails
    t += timedelta(hours=9)
    assert m.record({"online": False, "latency_ms": None, "loss": 100}, t) is None  # first probe after wake fails too
    t += timedelta(minutes=1)
    m.record({"online": True, "latency_ms": 10.0, "loss": 0}, t)
    assert not st.get("isp_outages") and not st.get("isp_outage_start")          # no 9-hour "outage"
    for i in range(1, 4):                                                          # a real 3-minute outage still counts
        m.record({"online": False, "latency_ms": None, "loss": 100}, t + timedelta(minutes=i))
    ev = m.record({"online": True, "latency_ms": 10.0, "loss": 0}, t + timedelta(minutes=4))
    assert ev and ev["type"] == "up" and len(st.get("isp_outages")) == 1


def test_stored_false_outage_is_trimmed_in_reports(tmp_path):
    st = StateStore(tmp_path / "s.json")
    m = isp.InternetMonitor(st, tmp_path / "isp")
    now = datetime.now().replace(microsecond=0)
    start = now - timedelta(hours=10)
    m.record({"online": False, "latency_ms": None, "loss": 100}, start)
    m.record({"online": False, "latency_ms": None, "loss": 100}, now - timedelta(minutes=2))
    m.record({"online": True, "latency_ms": 9.0, "loss": 0}, now - timedelta(minutes=1))
    st.set("isp_outages", [{"start": (start - timedelta(minutes=1)).isoformat(), "end": (now - timedelta(minutes=1)).isoformat(),
                            "seconds": 36000}])                                      # written by the old code
    assert m.summary(1)["outages"] == []


# =========================================================================== 6. self-healing
ERRDIS = ("Port      Name               Status       Reason               Err-disabled Vlans\n"
          "Gi1/0/12  Printer-3F         err-disabled bpduguard\nGi1/0/7                      err-disabled psecure-violation")


def test_parse_errdisabled():
    rows_ = selfheal.parse_errdisabled(ERRDIS)
    assert [(r["port"], r["name"], r["reason"]) for r in rows_] == [("Gi1/0/12", "Printer-3F", "bpduguard"), ("Gi1/0/7", "", "psecure-violation")]


def test_detect_and_verify_with_fake_device(tmp_path):
    d = NS(name="SW1", device_type="cisco_ios", host="10.0.0.2", role="", site="")
    inv = NS(get=lambda n: d, devices={"SW1": d})
    s = NS(inventory=lambda: inv, state=StateStore(tmp_path / "s.json"))
    out = {"show interfaces status err-disabled": ERRDIS, "show running-config": "hostname SW1\nip http server\nline vty 0 4\n transport input telnet\n"}
    run = lambda cmds: [out[c] for c in cmds]  # noqa: E731
    issues = selfheal.detect_device(s, inv, d, run)
    kinds = [(i["kind"], i["target"]) for i in issues]
    assert ("errdisable", "Gi1/0/12") in kinds and ("golden", "ip http server") in kinds
    assert not any("transport input" in i["target"] for i in issues)        # sub-mode lines are not auto-fixed
    issue = issues[0]
    assert issue["fix"] == ["interface Gi1/0/12", "shutdown", "no shutdown"] and "BPDU" in issue["advice"]
    rolled = []
    c = {"id": 3, "heal": issue}
    res = selfheal.after_apply(s, c, {"status": "applied", "log": []}, run=run, rollback=lambda: rolled.append(1), wait=0)
    assert res["status"] == "rolledback" and rolled == [1] and "ავტომატურად დაბრუნდა" in res["log"][-1]
    out["show interfaces status err-disabled"] = ERRDIS.splitlines()[0]
    res = selfheal.after_apply(s, c, {"status": "applied", "log": []}, run=run, rollback=lambda: rolled.append(2), wait=0)
    assert res["status"] == "applied" and rolled == [1] and "მოგვარდა" in res["log"][-1]
    assert selfheal.after_apply(s, c, {"status": "failed", "log": ["x"]}, run=run, wait=0)["status"] == "failed"


@pytest.fixture(scope="module")
def heal_lab(tmp_path_factory):
    pytest.importorskip("paramiko")
    from netagent.config import settings
    from netagent.demo import lab as lab_mod

    tmp = tmp_path_factory.mktemp("heal")
    base = random.randint(21000, 29000)
    lab = lab_mod.DemoLab(lab_mod.build_devices(["127.0.0.1"] * 4, [base + i for i in range(4)]), syslog_port=0)
    lab.start()
    lab_mod.LAB = lab
    (tmp / "devices.yaml").write_text(lab_mod.inventory_yaml(lab), encoding="utf-8")
    env = {"NETAGENT_DEMO_USER": "admin", "NETAGENT_DEMO_PASS": "demo", "NETAGENT_CHANGES": "on", "NETAGENT_HEAL_VERIFY_WAIT": "0"}
    old_env = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    fake = {"inventory_path": tmp / "devices.yaml", "data_dir": tmp / "data", "export_dir": tmp / "exports",
            "backup_dir": tmp / "backups", "audit_log_path": tmp / "audit.jsonl"}
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)
    from netagent import features
    from netagent.features import changes
    from netagent.services import Services

    features.install()
    changes.set_pin("246810")
    yield Services.create(client=object()), lab
    lab.stop()
    lab_mod.LAB = None
    lab_mod.FAULTS.clear()
    for k, v in saved.items():
        object.__setattr__(settings, k, v)
    for k, v in old_env.items():
        os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _heal(s, lab, scenario, golden=False):
    from netagent import commands
    from netagent.features import changes

    lab.scenario("restore")
    if scenario:
        lab.scenario(scenario)
    commands.run(s, "/heal", "app:nodo")
    issues = s.state.get(selfheal.KEY)["issues"]
    n = next(i for i, x in enumerate(issues, 1) if (x["kind"] == "golden") == golden)
    assert commands.run(s, f"/heal fix {n}", "view:gio").text.startswith("⛔")     # viewers cannot
    r = commands.run(s, f"/heal fix {n}", "app:nodo")
    cid = int(r.buttons[0].command.split()[1])
    commands.run(s, f"/approve {cid} 246810", "app:nodo")
    return changes.get(s.state, cid)


def test_selfheal_on_demo_lab(heal_lab):
    s, lab = heal_lab
    c = _heal(s, lab, "errdisable")
    assert c["status"] == "applied" and "მოგვარდა" in c["log"][-1]
    assert "Gi1/0/12" not in lab.devices["SW-Access-2"].outputs["show interfaces status err-disabled"]
    c = _heal(s, lab, "errdisable-sticky")
    assert c["status"] == "rolledback" and "ავტომატურად დაბრუნდა" in c["log"][-1]
    c = _heal(s, lab, None, golden=True)
    assert c["status"] == "applied" and "ip http server" not in lab.devices["R1"].outputs["show running-config"].split("\n")


# =========================================================================== 7. live map
def test_build_map_with_load(tmp_path, monkeypatch):
    from netagent.config import settings

    object.__setattr__(settings, "data_dir", tmp_path)
    try:
        devs = {n: NS(name=n, host=h, device_type="cisco_ios", role="") for n, h in (("R1", "10.0.0.1"), ("SW1", "10.0.0.2"))}
        inv = NS(devices=devs, get=lambda n: devs[n])
        topo = {"generated": "2026-11-08T10:00", "links": [
            {"a": "R1", "a_port": "Gi0/0/1", "b": "SW1", "b_port": "Gi1/0/1", "b_known": True, "b_ip": "10.0.0.2", "b_platform": ""},
            {"a": "SW1", "a_port": "Gi1/0/2", "b": "AP-Lobby", "b_port": "eth0", "b_known": False, "b_ip": "10.0.0.50", "b_platform": "AIR-AP"}],
            "errors": {}}
        calls = []
        discover = lambda inv_, path: (calls.append(1), path.write_text(__import__("json").dumps(topo)), topo)[2]  # noqa: E731
        check = lambda devices, t, r: [NS(device="R1", up=True, latency_ms=2.0), NS(device="SW1", up=False, latency_ms=None)]  # noqa: E731
        tracker = NS(prev={"R1": {"interfaces": {"GigabitEthernet0/0/1": {"in_bps": 850e6, "out_bps": 10e6, "bw_bps": 1e9}}}})
        s = NS(inventory=lambda: inv)
        m = livemap.build_map(s, check=check, tracker=tracker, discover=discover)
        nodes = {n["id"]: n for n in m["nodes"]}
        assert set(nodes) == {"R1", "SW1", "AP-Lobby"} and nodes["R1"]["up"] and nodes["SW1"]["up"] is False
        assert nodes["AP-Lobby"]["known"] is False and nodes["AP-Lobby"]["ip"] == "10.0.0.50" and nodes["AP-Lobby"]["up"] is None
        assert all(0 <= n["x"] <= 1 and 0 <= n["y"] <= 1 for n in m["nodes"])
        link = next(l for l in m["links"] if l["a"] == "R1")
        assert link["util"] == 85.0 and m["up"] == 1 and m["down"] == 1
        livemap.build_map(s, check=check, tracker=tracker, discover=discover)
        assert calls == [1]                                                     # cached: no second discovery
        livemap.build_map(s, refresh=True, check=check, tracker=tracker, discover=discover)
        assert calls == [1, 1]                                                  # refresh asked: discovered again
    finally:
        pass


def test_map_without_devices(tmp_path):
    from netagent.config import settings

    saved = settings.data_dir
    object.__setattr__(settings, "data_dir", tmp_path)
    try:
        m = livemap.build_map(NS(inventory=lambda: NS(devices={}, get=None)), check=lambda *a: [], tracker=NS(prev={}))
        assert m["nodes"] == [] and m["links"] == []
    finally:
        object.__setattr__(settings, "data_dir", saved)


def test_layered_layout_router_on_top():
    names = ["SW-Core-1", "R1", "SW-Access-2", "Printer", "AP"]
    edges = [("R1", "SW-Core-1"), ("SW-Core-1", "SW-Access-2"), ("SW-Access-2", "AP")]
    pos, rows = livemap.layered(names, edges, {"R1": "router", "SW-Core-1": "core-switch"})
    assert rows == 5
    order = sorted(["R1", "SW-Core-1", "SW-Access-2", "AP"], key=lambda n: pos[n][1])
    assert order == ["R1", "SW-Core-1", "SW-Access-2", "AP"]                  # one row per hop from the router
    assert pos["Printer"][1] == max(p[1] for p in pos.values())              # uncabled devices in the last row
    assert livemap.layered([], [], {}) == ({}, 0)
