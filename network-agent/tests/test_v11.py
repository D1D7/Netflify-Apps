"""Wave 3: approved config changes, NetFlow/IPFIX, SNMP, NetBox/Zabbix import, Prometheus metrics."""

from __future__ import annotations

import socket
import struct
from types import SimpleNamespace as NS

import pytest

from netagent.features import changes, flows, importers, snmp
from netagent.result import CommandError


# -- changes: validation ------------------------------------------------------------------------------
IOS = NS(name="R1", host="10.0.0.1", device_type="cisco_ios")
MT = NS(name="MT", host="10.0.0.2", device_type="mikrotik_routeros")
JUN = NS(name="J1", host="10.0.0.3", device_type="juniper_junos")


@pytest.mark.parametrize("cmd", ["reload", "write erase", "do write", "username x privilege 15 secret y",
                                 "enable secret abc", "aaa new-model", "boot system flash:x", "crypto key zeroize rsa"])
def test_dangerous_commands_refused(cmd):
    with pytest.raises(CommandError):
        changes.validate(IOS, [cmd])


def test_validate_and_risks():
    assert changes.validate(IOS, ["configure terminal", "interface Gi0/5", " description X", "end"]) == ["interface Gi0/5", " description X"]
    with pytest.raises(CommandError):
        changes.validate(MT, ["ip address add address=1.1.1.1/24"])  # must start with /
    with pytest.raises(CommandError):
        changes.validate(MT, ["/system reboot"])
    with pytest.raises(CommandError):
        changes.validate(JUN, ["request system reboot"])
    assert changes.validate(JUN, ["set interfaces ge-0/0/1 description X"])
    with pytest.raises(CommandError):
        changes.validate(NS(name="F", host="1", device_type="fortinet"), ["config system interface"])
    r = changes.risks(IOS, ["interface Gi0/1", " ip address 10.0.0.1 255.255.255.0", " shutdown", "ip route 0.0.0.0 0.0.0.0 1.1.1.1"])
    assert any("მართვის IP" in x for x in r) and any("ითიშება" in x for x in r) and any("routing" in x for x in r)
    assert not any("წაშლას" in x for x in changes.risks(IOS, ["interface Gi0/2", " no shutdown"]))


def test_pin_and_lockout(tmp_path):
    from netagent.config import settings
    from netagent.state import StateStore

    saved = settings.data_dir
    object.__setattr__(settings, "data_dir", tmp_path)
    try:
        st = StateStore(tmp_path / "s.json")
        with pytest.raises(CommandError):
            changes.check_pin(st, "123456")  # no PIN yet
        with pytest.raises(ValueError):
            changes.set_pin("12")
        changes.set_pin("246810")
        changes.check_pin(st, "246810")
        for _ in range(5):
            with pytest.raises(CommandError):
                changes.check_pin(st, "000000")
        with pytest.raises(CommandError, match="ბევრი"):
            changes.check_pin(st, "246810")  # locked even with the right PIN
    finally:
        object.__setattr__(settings, "data_dir", saved)


# -- changes: end-to-end against the demo lab -------------------------------------------------------
@pytest.fixture(scope="module")
def labsvc(tmp_path_factory):
    pytest.importorskip("paramiko")
    import os

    from netagent.config import settings
    from netagent.demo import lab as lab_mod

    tmp = tmp_path_factory.mktemp("lab11")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        base = s.getsockname()[1]
    lab = lab_mod.DemoLab(lab_mod.build_devices(["127.0.0.1"] * 4, [base + i for i in range(4)]), syslog_port=0)
    lab.start()
    (tmp / "devices.yaml").write_text(lab_mod.inventory_yaml(lab), encoding="utf-8")
    os.environ.update(NETAGENT_DEMO_USER="admin", NETAGENT_DEMO_PASS="demo", NETAGENT_CHANGES="on")
    fake = {"inventory_path": tmp / "devices.yaml", "data_dir": tmp / "data", "export_dir": tmp / "exports",
            "backup_dir": tmp / "backups", "audit_log_path": tmp / "audit.jsonl", "device_timeout": 10}
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)
    from netagent.services import Services

    changes.set_pin("246810")
    yield Services.create(client=object()), lab, tmp
    lab.stop()
    os.environ.pop("NETAGENT_CHANGES", None)
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


def run(s, line):
    from netagent import commands

    return commands.run(s, line, "test")


def test_change_lifecycle_cisco(labsvc):
    s, lab, tmp = labsvc
    r1 = lab.devices["R1"]
    res = run(s, "/change R1 interface GigabitEthernet0/0/2 ; description Printer-2F ; no shutdown")
    assert "ელოდება" in res.text and res.buttons[0].command == "/approve 1"
    assert "PIN" in run(s, "/approve 1").text  # asks for the PIN
    assert "არასწორია" in run(s, "/approve 1 111111").text
    res = run(s, "/approve 1 246810")
    assert "გატარებულია" in res.text, res.text
    assert " description Printer-2F" in r1.applied and r1.reload_pending is False and "rollback" in r1.saved
    assert {b.command for b in res.buttons} == {"/save-change 1", "/undo 1"}
    assert "შენახულია" in run(s, "/save-change 1").text and "startup" in r1.saved
    # a command the device rejects is rolled back automatically
    run(s, "/change R1 bad-command now")
    res = run(s, "/approve 2 246810")
    assert "დაბრუნებულია" in res.text and r1.reload_pending is False
    # undo restores the rollback copy
    run(s, "/change R1 interface GigabitEthernet0/0/2 ; description TEMP")
    run(s, "/approve 3 246810")
    assert "TEMP" in r1.outputs["show running-config"]
    assert "დაბრუნდა" in run(s, "/undo 3 246810").text
    assert "TEMP" not in r1.outputs["show running-config"]
    audit = (tmp / "audit.jsonl").read_text(encoding="utf-8")
    assert "config_change_applied" in audit and "config_change_undo" in audit
    assert "246810" not in audit


def test_change_mikrotik_and_tool(labsvc):
    s, lab, _ = labsvc
    from netagent.tools import ToolContext, execute_tool

    ctx = ToolContext(inventory=s.inventory(), user="ai-test", services=s)
    text, err = execute_tool("propose_config_change", {"device": "MT-Branch", "commands": [
        "/ip address add address=10.30.0.1/24 interface=ether3"], "reason": "new VLAN"}, ctx)
    assert not err and "NOT applied" in text and ctx.buttons[0].command.startswith("/approve ")
    cid = ctx.buttons[0].command.split()[1]
    assert lab.devices["MT-Branch"].applied == []  # nothing happened before approval
    assert "შენახულია" in run(s, f"/approve {cid} 246810").text
    assert lab.devices["MT-Branch"].applied == ["/ip address add address=10.30.0.1/24 interface=ether3"]
    text, err = execute_tool("propose_config_change", {"device": "R1", "commands": ["reload"]}, ctx)
    assert err and "დაშვებული არ არის" in text


# -- NetFlow / IPFIX ----------------------------------------------------------------------------------
def test_netflow_v5_and_stats():
    from netagent.demo.lab_extra import v5_packet

    pkt = v5_packet([("142.250.1.1", "192.168.1.21", 443, 50000, 100, 150_000, 6),
                     ("192.168.1.21", "142.250.1.1", 50000, 443, 50, 5_000, 6),
                     ("192.168.1.21", "192.168.1.30", 445, 50001, 10, 20_000, 6)], 1)
    recs = flows.TemplateCache().parse(pkt, "r1")
    assert recs[0] == {"src": "142.250.1.1", "dst": "192.168.1.21", "packets": 100, "bytes": 150000, "sport": 443, "dport": 50000, "proto": 6}
    st = flows.FlowStats()
    st.add(recs, "r1", now=1_000_000)
    w = st.window(5, now=1_000_000)
    assert w["down"]["192.168.1.21"] == 150000 and w["up"]["192.168.1.21"] == 5000 and w["lan"]["192.168.1.30"] == 20000
    assert w["app"]["tcp/443"] == 155000
    assert flows.is_local("100.64.1.1") and not flows.is_local("203.0.113.5") and flows.is_local("10.1.1.1")


def _v9(template: bool = True) -> bytes:
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4)]
    tmpl = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", t, n) for t, n in fields)
    tset = struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl
    rec = socket.inet_aton("10.0.0.5") + socket.inet_aton("8.8.8.8") + struct.pack("!HHBI", 40000, 53, 17, 1234)
    dset = struct.pack("!HH", 256, 4 + len(rec) + 3) + rec + b"\x00\x00\x00"  # padded
    body = (tset if template else b"") + dset
    return struct.pack("!HHIIII", 9, 2, 0, 0, 1, 7) + body


def test_netflow_v9_templates():
    cache = flows.TemplateCache()
    assert cache.parse(_v9(template=False), "r") == []  # data before template is ignored
    recs = cache.parse(_v9(), "r")
    assert recs == [{"src": "10.0.0.5", "dst": "8.8.8.8", "sport": 40000, "dport": 53, "proto": 17, "bytes": 1234}]
    assert cache.parse(_v9(template=False), "r") == recs  # template remembered


def test_ipfix():
    fields = [(8, 4), (12, 4), (1, 8), (11, 2), (0x8000 | 100, 4)]  # last one is an enterprise field
    tmpl = struct.pack("!HH", 300, len(fields)) + b"".join(
        struct.pack("!HH", t, n) + (b"\x00\x00\x00\x09" if t & 0x8000 else b"") for t, n in fields)
    tset = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl
    rec = socket.inet_aton("1.2.3.4") + socket.inet_aton("192.168.0.9") + (99999).to_bytes(8, "big") + struct.pack("!H", 443) + b"abcd"
    dset = struct.pack("!HH", 300, 4 + len(rec)) + rec
    body = tset + dset
    pkt = struct.pack("!HHIII", 10, 16 + len(body), 0, 1, 1) + body
    assert flows.TemplateCache().parse(pkt, "x") == [{"src": "1.2.3.4", "dst": "192.168.0.9", "bytes": 99999, "dport": 443}]


# -- SNMP ---------------------------------------------------------------------------------------------
def test_ber_roundtrip():
    pkt = snmp.encode_request("public", ["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.318.1.1.1.2.2.1.0"], 12345)
    _, msg, _ = snmp._read(pkt, 0)  # noqa: SLF001
    assert pkt[0] == 0x30 and b"public" in msg
    assert snmp._decode_oid(snmp._oid("1.3.6.1.4.1.318.1.1.1.2.2.1.0")[2:]) == "1.3.6.1.4.1.318.1.1.1.2.2.1.0"  # noqa: SLF001


def test_snmp_against_fake_printer_and_ups():
    from netagent.demo import lab_extra

    faults: dict = {}
    agents = lab_extra.start_snmp(["127.0.0.1", "127.0.0.1"], 0, faults)
    try:
        p = snmp.query("127.0.0.1", "public", agents[0].port)
        assert p["name"] == "Printer-2F" and p["supplies"][0]["percent"] == 65 and p["interfaces"] == {"HP ETHERNET": "up"}
        u = snmp.query("127.0.0.1", "public", agents[1].port)
        assert u["ups"]["on_battery"] is False and u["ups"]["charge"] == 100
        faults.update(toner=True, power=True)
        assert snmp.query("127.0.0.1", "public", agents[0].port)["supplies"][0]["percent"] == 6
        assert "ბატარეაზეა" in snmp.format_query("UPS", snmp.query("127.0.0.1", "public", agents[1].port))
        with pytest.raises(TimeoutError):
            snmp.request("127.0.0.1", "wrong-community", ["1.3.6.1.2.1.1.1.0"], timeout=0.3, retries=0, port=agents[0].port)
        dev = NS(name="P", host="127.0.0.1", port=agents[0].port, credentials="none", device_type="snmp")
        up, ms, _ = snmp.probe_device(dev)
        assert up and ms is not None
    finally:
        for a in agents:
            a.stop()


# -- importers ----------------------------------------------------------------------------------------
def test_platform_mapping():
    assert importers.map_platform("cisco-ios-xe") == "cisco_xe"
    assert importers.map_platform("Cisco IOS") == "cisco_ios"
    assert importers.map_platform("MikroTik RouterOS 7") == "mikrotik_routeros"
    assert importers.map_platform("Juniper Junos") == "juniper_junos"
    assert importers.map_platform("Windows") is None


def test_netbox_and_zabbix_import(tmp_path, monkeypatch):
    import yaml

    from netagent.config import settings

    monkeypatch.setenv("NETBOX_URL", "https://nb")
    monkeypatch.setenv("NETBOX_TOKEN", "t")
    nb = [{"name": "core sw 1", "primary_ip4": {"address": "10.0.0.2/24"}, "platform": {"slug": "cisco-ios", "name": "IOS"},
           "site": {"name": "HQ"}, "role": {"name": "core"}},
          {"name": "fw", "primary_ip4": {"address": "10.0.0.9/24"}, "platform": {"slug": "weird", "name": "Weird OS"}}]
    found, skipped = importers.from_netbox(fetch=lambda path: nb)
    assert found == [{"name": "core-sw-1", "host": "10.0.0.2", "device_type": "cisco_ios", "site": "HQ", "role": "core"}]
    assert skipped and "Weird" in skipped[0]
    monkeypatch.setenv("ZABBIX_URL", "https://zbx/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "t")
    hosts = [{"host": "mt1", "name": "MT Branch", "interfaces": [{"ip": "10.20.0.1", "main": "1"}],
              "inventory": {"os": "RouterOS 7.16"}, "tags": [], "hostgroups": [{"name": "Branch"}]},
             {"host": "srv", "name": "srv", "interfaces": [{"ip": "10.0.0.50", "main": "1"}], "inventory": {"os": ""},
              "tags": [{"tag": "netagent_type", "value": "linux"}]}]
    found2, _ = importers.from_zabbix(rpc=lambda m, p: hosts)
    assert [d["device_type"] for d in found2] == ["mikrotik_routeros", "linux"] and found2[0]["site"] == "Branch"
    inv = tmp_path / "devices.yaml"
    inv.write_text("credentials:\n  default: {username_env: U, password_env: P}\ndevices:\n  R1: {host: 10.0.0.2, device_type: cisco_ios}\n")
    saved = settings.inventory_path
    object.__setattr__(settings, "inventory_path", inv)
    try:
        added = importers.add_devices(found + found2, "default")
        assert added == ["MT-Branch", "srv"]  # 10.0.0.2 already there
        data = yaml.safe_load(inv.read_text())
        assert data["devices"]["MT-Branch"]["site"] == "Branch" and data["credentials"]["default"]["username_env"] == "U"
    finally:
        object.__setattr__(settings, "inventory_path", saved)


# -- metrics endpoint ----------------------------------------------------------------------------------
def test_metrics_endpoint(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from netagent.config import settings
    from netagent.health import Reachability

    inv = tmp_path / "devices.yaml"
    inv.write_text("devices:\n  R1: {host: 127.0.0.1, port: 1, device_type: cisco_ios, site: HQ}\n")
    fake = {"inventory_path": inv, "data_dir": tmp_path / "data", "export_dir": tmp_path / "exports"}
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)
    try:
        from netagent.monitoring import MonitoringService
        from netagent.services import Services
        from netagent.web.app import create_app
        from netagent.web.auth import WebAuth

        s = Services.create(client=object())
        s.history.record([Reachability("R1", "127.0.0.1", 1, True, 3.5)])
        app = create_app(s, MonitoringService(s), WebAuth(tmp_path / "auth.json"), None)
        c = TestClient(app)
        monkeypatch.delenv("NETAGENT_METRICS_TOKEN", raising=False)
        assert c.get("/metrics").status_code == 404  # off by default
        monkeypatch.setenv("NETAGENT_METRICS_TOKEN", "secret-token")
        assert c.get("/metrics").status_code == 401
        r = c.get("/metrics", headers={"Authorization": "Bearer secret-token"})
        assert r.status_code == 200
        assert 'netagent_device_up{device="R1",site="HQ",type="cisco_ios"} 1' in r.text
        assert 'netagent_device_latency_ms{device="R1",site="HQ",type="cisco_ios"} 3.5' in r.text
    finally:
        for k, v in saved.items():
            object.__setattr__(settings, k, v)
