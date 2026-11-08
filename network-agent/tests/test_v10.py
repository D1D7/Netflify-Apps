"""Wave 2 features: interface counters, firewall, path trace, CVE, golden config, git backups,
incidents, passport, weekly PDF, IPAM, extra runbooks — unit tests plus a run against the demo lab."""

from __future__ import annotations

import socket
from datetime import datetime, timedelta
from types import SimpleNamespace as NS

import pytest

from netagent.demo import lab_extra
from netagent.features import cve, firewall, golden, ifstats, incidents, ipam, passport, pathtrace


# -- interface counters -----------------------------------------------------------------------
def test_parse_ios_interfaces_and_alerts():
    text = lab_extra.show_interfaces("SW-Access-2", {})
    ifs = ifstats.parse_ios_interfaces(text)
    gi5 = ifs["GigabitEthernet1/0/5"]
    assert gi5["status"] == "up" and gi5["bw_bps"] == 1_000_000_000 and gi5["description"] == "AP-Lobby"
    assert gi5["crc"] == 0 and "in_bps" in gi5
    tr = ifstats.TrafficTracker()
    tr.update("SW", {"ts": 0, "interfaces": ifs, "memory_percent": 40})
    ifs2 = ifstats.parse_ios_interfaces(lab_extra.show_interfaces("SW-Access-2", {"errors": True}))
    deltas = tr.update("SW", {"ts": 300, "interfaces": ifs2, "memory_percent": 95})
    assert deltas["GigabitEthernet1/0/5"]["crc"] >= 25
    dev = NS(name="SW", watch={"memory": 90})
    alerts = ifstats.analyze(dev, {"interfaces": ifs2, "memory_percent": 95}, deltas)
    assert any("შეცდომები იზრდება" in a for a in alerts) and any("მეხსიერება 95" in a for a in alerts)


def test_congestion_and_mikrotik_stats():
    ifs = ifstats.parse_ios_interfaces(lab_extra.show_interfaces("R1", {"congestion": True}))
    assert ifstats.utilization(ifs["GigabitEthernet0/0/0"]) >= 90
    mt = ifstats.parse_mikrotik_stats(lab_extra.mt_stats({}))
    assert mt["ether1"]["status"] == "up" and mt["ether1"]["rx_bytes"] > 0
    assert ifstats.parse_memory("mikrotik", "free-memory: 256.0MiB\ntotal-memory: 1024.0MiB") == 75.0
    assert ifstats.parse_memory("ios", "Processor Pool Total:  1000 Used:  250 Free: 750") == 25.0
    assert ifstats.human_bps(962_000_000) == "962.0 Mbps"


# -- firewall -----------------------------------------------------------------------------------
def test_cisco_acl_analysis():
    acls = firewall.parse_cisco_acls(lab_extra.R1_ACL)
    assert set(acls) == {"MGMT", "OUTSIDE-IN"}
    a = firewall.analyze(acls["OUTSIDE-IN"], "cisco")
    assert {b.seq for b, _ in a["shadowed"]} == {"45", "60"}
    assert {r.seq for r in a["unused"]} == {"45", "50", "60"}
    r = firewall.evaluate(acls["OUTSIDE-IN"], "tcp", "45.155.205.9", "203.0.113.2", 443, "cisco")
    assert r["allowed"] is False and r["rule"] == "40"
    r = firewall.evaluate(acls["OUTSIDE-IN"], "tcp", "1.2.3.4", "203.0.113.2", 22, "cisco")
    assert r["allowed"] is True and r["rule"] == "10"
    r = firewall.evaluate(acls["OUTSIDE-IN"], "udp", "1.2.3.4", "203.0.113.2", 53, "cisco")
    assert r["allowed"] is False and r["rule"] == "70"
    std = firewall.analyze(acls["MGMT"], "cisco")
    assert not std["shadowed"] and acls["MGMT"][1].src.prefixlen == 32


def test_wildcards_and_ports():
    assert str(firewall.wildcard_to_net("10.1.0.0", "0.0.255.255")) == "10.1.0.0/16"
    assert firewall.wildcard_to_net("10.0.0.0", "0.255.0.255") is None
    r = firewall.parse_cisco_entry("10 permit tcp 10.0.0.0 0.255.0.255 any range 1000 2000 established", 1, False)
    assert r.extra and r.dports == [(1000, 2000)]
    r = firewall.parse_cisco_entry("permit tcp any any neq 23", 1, False)
    assert r.dports == [(0, 22), (24, 65535)]


def test_mikrotik_filter_analysis():
    chains = firewall.parse_mikrotik_filter(lab_extra.MT_FILTER)
    a = firewall.analyze(chains["input"], "mikrotik")
    assert [b.index for b, _ in a["redundant"]] == [4]
    assert a["no_final_drop"] is True
    r = firewall.evaluate(chains["input"], "tcp", "10.20.0.5", "10.20.0.1", 8291, "mikrotik")
    assert r["allowed"] and r["rule"] == 3
    exported = "/ip firewall filter\nadd action=accept chain=input protocol=icmp\nadd action=drop chain=input\n"
    a = firewall.analyze(firewall.parse_mikrotik_filter(exported)["input"], "mikrotik")
    assert a["no_final_drop"] is False


# -- path trace ----------------------------------------------------------------------------------
def test_route_parsers():
    assert pathtrace.parse_cef("0.0.0.0/0\n  nexthop 203.0.113.1 GigabitEthernet0/0/0") == {
        "prefix": "0.0.0.0/0", "kind": "nexthop", "nexthop": "203.0.113.1", "interface": "GigabitEthernet0/0/0"}
    assert pathtrace.parse_cef("192.168.10.0/24\n  attached to Vlan10")["kind"] == "attached"
    assert pathtrace.parse_cef("0.0.0.0/0\n  no route")["kind"] == "none"
    mt = lab_extra.mt_route_where("192.168.10.21 in dst-address", {})
    assert pathtrace.parse_mikrotik_routes(mt, "192.168.10.21") == {"prefix": "192.168.10.0/24", "kind": "nexthop", "nexthop": "172.16.0.1"}
    assert pathtrace.parse_junos_route("10.1.0.0/16 *[OSPF/10] 2d\n  > to 10.0.0.9 via ge-0/0/1.0")["nexthop"] == "10.0.0.9"


# -- CVE --------------------------------------------------------------------------------------------
def test_cve_detect_parse_and_cache(tmp_path, monkeypatch):
    from netagent.config import settings

    assert cve.detect_os("cisco_ios", "Cisco IOS XE Software, Version 17.09.04a") == ("cpe:2.3:o:cisco:ios_xe", "17.9.4a")
    assert cve.detect_os("cisco_ios", "Version 15.2(7)E8,") == ("cpe:2.3:o:cisco:ios", "15.2\\(7\\)e8")
    assert cve.detect_os("mikrotik_routeros", "version: 7.16.1 (stable)")[1] == "7.16.1"
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-1", "published": "2024-01-01T00", "descriptions": [{"lang": "en", "value": "low"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 4.3, "baseSeverity": "MEDIUM"}}]}}},
        {"cve": {"id": "CVE-2", "cisaExploitAdd": "2024-02-02", "descriptions": [{"lang": "en", "value": "bad"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]}
    items = cve.parse_nvd(payload)
    assert [i["id"] for i in items] == ["CVE-2", "CVE-1"] and items[0]["kev"]
    saved = settings.data_dir
    object.__setattr__(settings, "data_dir", tmp_path)
    try:
        calls = []
        fetch = lambda c: calls.append(c) or payload  # noqa: E731
        assert len(cve.lookup("cpe:x", fetch)) == 2
        assert len(cve.lookup("cpe:x", fetch)) == 2 and len(calls) == 1  # cached
    finally:
        object.__setattr__(settings, "data_dir", saved)


# -- golden config ---------------------------------------------------------------------------------
def test_golden_rules():
    dev = NS(device_type="cisco_ios", role="access-switch", site="HQ")
    rules = golden.rules_for(dev, {"cisco_ios": golden.DEFAULT_RULES["cisco_ios"],
                                   "role:access-switch": {"required": [{"name": "BPDU guard", "pattern": "spanning-tree portfast bpduguard"}]}})
    res = golden.check_config("hostname X\nntp server 1.1.1.1\nip http server\nline vty 0 4\n transport input telnet ssh\n", rules)
    assert "BPDU guard" in res["missing"] and "NTP სერვერი" not in res["missing"]
    assert any(f.startswith("HTTP სერვერი") for f in res["forbidden"]) and any("Telnet" in f for f in res["forbidden"])
    assert 0 < res["score"] < 100


# -- git-versioned backups ---------------------------------------------------------------------------
def test_git_backup_history(tmp_path, monkeypatch):
    import shutil

    if not shutil.which("git"):
        pytest.skip("git not installed")
    from netagent.backup import BackupStore
    from netagent.config import settings
    from netagent.features import gitbackup

    saved = settings.backup_dir
    object.__setattr__(settings, "backup_dir", tmp_path / "backups")
    try:
        store = BackupStore(settings.backup_dir)
        store.save("R1", "hostname R1\nntp server 1.1.1.1\n", datetime(2026, 1, 1, 10))
        store.save("R1", "hostname R1\nntp server 2.2.2.2\n", datetime(2026, 1, 2, 10))
        h = gitbackup.history("R1")
        assert len(h) == 2 and h[0]["added"] == 1 and h[0]["removed"] == 1
        diff = gitbackup.show_change("R1", 1)
        assert "+ntp server 2.2.2.2" in diff and "-ntp server 1.1.1.1" in diff
    finally:
        object.__setattr__(settings, "backup_dir", saved)


# -- incidents -----------------------------------------------------------------------------------------
def test_incident_lifecycle(tmp_path):
    from netagent.monitoring import Alert
    from netagent.state import StateStore

    st = StateStore(tmp_path / "s.json")
    store = incidents.IncidentStore(st)
    t0 = datetime(2026, 11, 4, 10, 0)
    store.record(Alert("down", "🔴 **R1** (10.0.0.1) მიუწვდომელია — timeout", ["R1"]), t0)
    store.record(Alert("watch", "🔴 **R1**: BGP neighbor 203.0.113.1 დაეცა (active)", ["R1"]), t0)
    store.record(Alert("syslog", "**R1**: 🔴 ინტერფეისი Gi0/0/0 ჩავარდა", ["R1"]), t0 + timedelta(minutes=1))
    store.record(Alert("watch", "🟢 **R1**: BGP neighbor 203.0.113.1 აღდგა (established)", ["R1"]), t0 + timedelta(minutes=9))
    store.record(Alert("up", "🟢 **R1** (10.0.0.1) ისევ ხელმისაწვდომია", ["R1"]), t0 + timedelta(minutes=12))
    items = store.all()
    assert len(items) == 2 and all(i["closed"] for i in items)
    assert items[0]["seconds"] == 720 and items[1]["seconds"] == 540
    assert any("Gi0/0/0" in e[1] for e in items[0]["events"])
    store.add_note(1, "ISP-მ კაბელი შეცვალა", "me")
    assert store.search(text="კაბელი")[0]["id"] == 1
    store.record(Alert("isp", "🔴 **ინტერნეტი გაითიშა** (10:00-დან)"), t0)
    assert store.search(open_only=True)[0]["key"] == "ინტერნეტი"


# -- passport --------------------------------------------------------------------------------------------
def test_passport_parse():
    p = passport.parse("ios", "Cisco IOS XE Software, Version 17.09.04a\nR1 uptime is 5 weeks\n" + lab_extra.INVENTORY["R1"])
    assert p == {"model": "ISR4331/K9", "serial": "FDO21520XYZ", "version": "17.09.04a", "uptime": "5 weeks"}
    m = passport.parse("mikrotik", "version: 7.16.1 (stable)\nmodel: RB760iGS\nserial-number: HE10\ncurrent-firmware: 7.16.1")
    assert m["model"] == "RB760iGS" and m["serial"] == "HE10"
    soon = (datetime.now() + timedelta(days=30)).date().isoformat()
    assert passport.warnings({}, {"warranty_until": soon, "eol": "2020-01-01"})[0].startswith("🟠")


# -- integration against the demo lab ---------------------------------------------------------------
@pytest.fixture(scope="module")
def labsvc(tmp_path_factory):
    pytest.importorskip("paramiko")
    import os

    from netagent.config import settings
    from netagent.demo import lab as lab_mod

    tmp = tmp_path_factory.mktemp("lab10")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        base = s.getsockname()[1]
    lab = lab_mod.DemoLab(lab_mod.build_devices(["127.0.0.1"] * 4, [base + i for i in range(4)]), syslog_port=0)
    lab.start()
    lab_mod.LAB = lab
    (tmp / "devices.yaml").write_text(lab_mod.inventory_yaml(lab), encoding="utf-8")
    os.environ.update(NETAGENT_DEMO_USER="admin", NETAGENT_DEMO_PASS="demo")
    fake = {"inventory_path": tmp / "devices.yaml", "data_dir": tmp / "data", "export_dir": tmp / "exports",
            "backup_dir": tmp / "backups", "audit_log_path": tmp / "audit.jsonl"}
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)
    from netagent.services import Services

    yield Services.create(client=object()), lab
    lab.stop()
    lab_mod.LAB = None
    lab_mod.FAULTS.clear()
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


def run(s, line):
    from netagent import commands

    return commands.run(s, line, "test")


def test_lab_path_firewall_runbooks(labsvc):
    s, lab = labsvc
    t = pathtrace.trace(s.inventory(), "192.168.10.21", "8.8.8.8")
    assert [h["device"] for h in t["hops"]] == ["SW-Core-1", "R1"] and "ISP" in t["result"]
    t = pathtrace.trace(s.inventory(), "10.20.0.15", "192.168.10.21")
    assert [h["device"] for h in t["hops"]] == ["MT-Branch", "R1", "SW-Core-1"] and t["result"].startswith("✅")
    assert "#60 არასდროს იმუშავებს" in run(s, "/firewall R1").text
    assert "VPN-ები რიგზეა" in run(s, "/runbook vpn").text
    lab.scenario("vpn")
    lab.scenario("dhcp")
    assert "MM_NO_STATE" in run(s, "/runbook vpn").text
    assert "pool გავსებულია" in run(s, "/runbook dhcp").text
    lab.scenario("restore")
    from netagent import tools

    enum = next(t for t in tools.TOOL_SCHEMAS if t["name"] == "run_runbook")["input_schema"]["properties"]["name"]["enum"]
    assert {"vpn", "wifi", "dhcp"} <= set(enum)


def test_lab_traffic_passport_weekly_ipam(labsvc):
    s, lab = labsvc
    assert "GigabitEthernet0/0/0" in run(s, "/traffic R1").text
    lab.scenario("errors")
    run(s, "/errors SW-Access-2")
    assert "crc" in run(s, "/errors SW-Access-2").text
    lab.scenario("restore")
    res = run(s, "/passport excel")
    assert res.files and res.files[0].suffix == ".xlsx"
    assert "RB760iGS" in run(s, "/passport MT-Branch").text
    res = run(s, "/weekly")
    assert res.files[0].read_bytes()[:4] == b"%PDF"
    run(s, "/ip 192.168.10.21 laptop მე-2 სართული")
    run(s, "/ipam add 192.168.10.0/24 USERS vlan 10")
    assert "laptop" in run(s, "/ip 192.168.10.21").text
    u = ipam.usage(s, "192.168.10.0/24")
    assert u["used"] >= 1 and "192.168.10.21" in u["addresses"]
    assert "USERS" in run(s, "/ipam").text and run(s, "/ipam excel").files
