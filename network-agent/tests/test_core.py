from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from netagent import agent as agent_mod
from netagent.formatting import markdown_to_telegram_html, split_markdown
from netagent.inventory import Device, Inventory
from netagent.security import CommandRejected, mask_secrets, validate_command
from netagent.tools import ToolContext, execute_tool
from netagent.tools import device as dev
from netagent.tools.extract import extract_network_data
from netagent.tools.subnet import subnet_info


# --------------------------------------------------------------------------- security

@pytest.mark.parametrize(
    "cmd,dtype",
    [
        ("show ip interface brief", "cisco_ios"),
        ("show run | include hostname", "cisco_ios"),
        ("show running-config | section interface", "cisco_ios"),
        ("show configuration | display set", "juniper_junos"),
        ("display ip interface brief", "huawei"),
        ("/ip address print", "mikrotik_routeros"),
        ("/interface bridge host print where interface=bridge1", "mikrotik_routeros"),
        ("get system status", "fortinet"),
        ("ip -br addr", "linux"),
    ],
)
def test_allowed_commands(cmd, dtype):
    assert validate_command(cmd, dtype)


@pytest.mark.parametrize(
    "cmd,dtype",
    [
        ("reload", "cisco_ios"),
        ("configure terminal", "cisco_ios"),
        ("write memory", "cisco_ios"),
        ("copy run start", "cisco_ios"),
        ("clear ip bgp *", "cisco_ios"),
        ("show ip int brief\nreload", "cisco_ios"),
        ("debug ip packet", "cisco_ios"),
        ("request system reboot", "juniper_junos"),
        ("system-view", "huawei"),
        ("/ip address add address=1.1.1.1/32 interface=ether1", "mikrotik_routeros"),
        ("/system reboot", "mikrotik_routeros"),
        ("/export show-sensitive", "mikrotik_routeros"),
        ("ip addr; rm -rf /", "linux"),
        ("ip link set eth0 down", "linux"),
        ("rm -rf /", "linux"),
        ("execute reboot", "fortinet"),
    ],
)
def test_rejected_commands(cmd, dtype):
    with pytest.raises(CommandRejected):
        validate_command(cmd, dtype)


def test_mask_secrets():
    cfg = """
enable secret 9 $9$abcdefg
username admin privilege 15 secret 5 $1$xyz
snmp-server community S3cr3t RO
tacacs-server host 1.1.1.1 key MyTacKey
 ip ospf authentication-key 7 0822455D0A16
service password-encryption
set password ENC SH2abcdef
/user add name=x password=hunter2
"""
    out = mask_secrets(cfg)
    for secret in ["$9$abcdefg", "$1$xyz", "S3cr3t", "MyTacKey", "0822455D0A16", "SH2abcdef", "hunter2"]:
        assert secret not in out, secret
    assert "service password-encryption" in out
    assert "enable secret 9 <masked>\n" in out
    junos = mask_secrets('set system root-authentication encrypted-password "$6$abc"\nset snmp community public1 authorization read-only')
    assert "$6$abc" not in junos and "public1" not in junos


# --------------------------------------------------------------------------- extract / subnet

CISCO_CFG = """hostname R1
!
vlan 10
 name USERS
vlan 20
 name VOICE
!
interface GigabitEthernet0/0
 description Uplink to ISP
 ip address 203.0.113.2 255.255.255.252
!
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
 ip address 192.168.11.1 255.255.255.0 secondary
!
interface GigabitEthernet0/2
 switchport access vlan 20
 shutdown
!
ip route 0.0.0.0 0.0.0.0 203.0.113.1
"""


def test_extract_cisco_config():
    r = extract_network_data(CISCO_CFG)
    assert "203.0.113.2/30" in r["ipv4_with_prefix"]
    assert "192.168.10.0/24" in r["networks"]
    assert "255.255.255.0" not in r["ipv4_addresses"]  # masks are not hosts
    assert r["vlans"] == [10, 20]
    assert r["vlan_names"] == {10: "USERS", 20: "VOICE"}
    vl10 = next(i for i in r["interfaces"] if i["interface"] == "Vlan10")
    assert vl10["ip_addresses"] == ["192.168.10.1/24", "192.168.11.1/24 (secondary)"]
    gi2 = next(i for i in r["interfaces"] if i["interface"] == "GigabitEthernet0/2")
    assert gi2["access_vlan"] == 20 and gi2["shutdown"]


def test_extract_macs_and_ipv6():
    r = extract_network_data("a4:5e:60:12:ab:cd  aabb.ccdd.eeff  2001:db8::1/64  fe80::1")
    assert set(r["mac_addresses"]) == {"a4:5e:60:12:ab:cd", "aabb.ccdd.eeff"}
    assert "2001:db8::1/64" in r["ipv6"]


def test_subnet_info():
    r = subnet_info("192.168.1.130/26")
    assert r["cidr"] == "192.168.1.128/26"
    assert r["broadcast"] == "192.168.1.191"
    assert r["usable_hosts"] == 62
    assert r["wildcard"] == "0.0.0.63"
    r = subnet_info("10.0.0.0 255.255.252.0", split_prefix=24)
    assert r["split"]["subnets"] == ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]


# --------------------------------------------------------------------------- device helpers

def test_commands_for_vendor_fallback():
    d = Device(name="x", host="1.1.1.1", device_type="cisco_ios_telnet")
    assert dev.commands_for(d, "arp") == ["show ip arp"]
    d = Device(name="y", host="1.1.1.1", device_type="mikrotik_routeros")
    assert dev.commands_for(d, "ip_addresses") == ["/ip address print"]
    for table in dev.COMMAND_MAP.values():
        for dtype_cmds in table.values():
            for c in dtype_cmds:
                validate_command(c, "mikrotik_routeros" if c.startswith("/") else ("linux" if c.split()[0] in {"ip", "uname"} else "cisco_ios"))


def test_line_matching():
    kind, target = dev.parse_search_target("192.168.1.57")
    assert dev._line_matches("Internet  192.168.1.57  3  a45e.6012.abcd  ARPA  Vlan10", target, kind)
    assert dev._line_matches("ge-0/0/1.0  up up inet 192.168.1.1/24", target, kind)
    assert not dev._line_matches("Internet  192.168.1.5  3  a45e.6012.abcd  ARPA  Vlan10", target, kind)
    kind, target = dev.parse_search_target("a4:5e:60:12:ab:cd")
    assert dev._line_matches("10  a45e.6012.abcd  DYNAMIC  Gi1/0/14", target, kind)
    kind, target = dev.parse_search_target("10.10.0.0/16")
    assert dev._line_matches("Vlan5  10.10.4.1  YES NVRAM  up  up", target, kind)


# --------------------------------------------------------------------------- tool dispatch

@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setattr("netagent.tools.settings", SimpleNamespace(audit_log_path=tmp_path / "audit.jsonl"))
    inv = Inventory({"R1": Device(name="R1", host="10.0.0.1", device_type="cisco_ios", site="HQ")}, {})
    return ToolContext(inventory=inv, user="test")


def test_execute_tool_validation(ctx):
    text, err = execute_tool("subnet_calculator", {"network": "10.0.0.0/30"}, ctx)
    assert not err and json.loads(text)["usable_hosts"] == 2
    text, err = execute_tool("subnet_calculator", {"network": 5}, ctx)
    assert err
    text, err = execute_tool("get_device_data", {"device": "R1", "data": "bogus"}, ctx)
    assert err
    text, err = execute_tool("run_show_command", {"device": "R1", "command": "reload"}, ctx)
    assert err and "აკრძალული" in text
    text, err = execute_tool("list_devices", {}, ctx)
    assert not err and json.loads(text)[0]["name"] == "R1"
    assert "password" not in text


def test_execute_tool_never_leaks_credentials(ctx):
    text, _ = execute_tool("list_devices", {"filter": "HQ"}, ctx)
    assert "credentials" not in text


# --------------------------------------------------------------------------- formatting

def test_telegram_formatting():
    md = "**R1** ინტერფეისები:\n```\nGi0/0  10.0.0.1  up\n```\n<script> `x`"
    out = markdown_to_telegram_html(md)
    assert "<b>R1</b>" in out and "<pre>Gi0/0  10.0.0.1  up</pre>" in out
    assert "&lt;script&gt;" in out and "<code>x</code>" in out


def test_split_keeps_fences_balanced():
    md = "intro\n```\n" + "\n".join(f"line {i} " + "x" * 50 for i in range(200)) + "\n```\nend"
    chunks = split_markdown(md, limit=1000)
    assert len(chunks) > 1
    for c in chunks:
        assert c.count("```") % 2 == 0


# --------------------------------------------------------------------------- agent loop (fake Claude)

def _block(**kw):
    return SimpleNamespace(**kw)


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


def _usage():
    return SimpleNamespace(input_tokens=100, cache_read_input_tokens=0, cache_creation_input_tokens=0)


def test_agent_tool_loop(tmp_path, monkeypatch):
    inv_file = tmp_path / "devices.yaml"
    inv_file.write_text("devices:\n  R1:\n    host: 10.0.0.1\n    device_type: cisco_ios\n", encoding="utf-8")
    fake_settings = SimpleNamespace(
        model="claude-opus-5-5", effort="medium", inventory_path=inv_file, audit_log_path=tmp_path / "a.jsonl"
    )
    monkeypatch.setattr(agent_mod, "settings", fake_settings)
    monkeypatch.setattr("netagent.tools.settings", fake_settings)

    responses = [
        SimpleNamespace(
            stop_reason="tool_use",
            usage=_usage(),
            content=[
                _block(type="tool_use", id="t1", name="subnet_calculator", input={"network": "10.0.0.0/24"}),
                _block(type="tool_use", id="t2", name="list_devices", input={}),
            ],
        ),
        SimpleNamespace(stop_reason="end_turn", usage=_usage(), content=[_block(type="text", text="254 ჰოსტი")]),
    ]
    fake = FakeMessages(responses)
    client = SimpleNamespace(beta=SimpleNamespace(messages=fake))
    seen = []
    a = agent_mod.NetAgent(client=client)
    answer = a.chat("s1", "რამდენი ჰოსტია?", user="test", on_tool=lambda n, i: seen.append(n))

    assert answer.text == "254 ჰოსტი" and answer.files == []
    assert seen == ["subnet_calculator", "list_devices"]
    second = fake.calls[1]["messages"]
    results = second[2]["content"]  # [user, assistant(tool_use), user(tool_results), ...]
    assert [r["tool_use_id"] for r in results] == ["t1", "t2"]  # all results in ONE user message
    assert fake.calls[0]["model"] == "claude-opus-5-5"
    assert fake.calls[0]["fallbacks"] == "default"


def test_agent_refusal_rolls_back(tmp_path, monkeypatch):
    inv_file = tmp_path / "devices.yaml"
    inv_file.write_text("devices: {}\n", encoding="utf-8")
    fake_settings = SimpleNamespace(
        model="claude-opus-5-5", effort="medium", inventory_path=inv_file, audit_log_path=tmp_path / "a.jsonl"
    )
    monkeypatch.setattr(agent_mod, "settings", fake_settings)
    fake = FakeMessages([SimpleNamespace(stop_reason="refusal", usage=_usage(), content=[])])
    a = agent_mod.NetAgent(client=SimpleNamespace(beta=SimpleNamespace(messages=fake)))
    out = a.chat("s1", "x", user="t")
    assert "ვერ გავეცი" in out.text
    assert a._session("s1").messages == []
