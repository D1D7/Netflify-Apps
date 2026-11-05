from __future__ import annotations

import ipaddress
import time
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from netagent import agent as agent_mod
from netagent.alerts import ALL, AlertMutes, format_duration, parse_duration
from netagent.compliance import audit_config, find_duplicate_ips, format_findings, interface_addresses
from netagent.security import mask_secrets
from netagent.state import StateStore
from netagent.tools.device import addresses_in_lines, summarize_usage
from netagent.usage import UsageTracker, cost_of, price_for

# --------------------------------------------------------------------------- compliance

BAD_IOS = mask_secrets("""hostname R1
enable password cisco
username admin password 0 admin123
snmp-server community public RO
snmp-server community MyRwComm RW
ip http server
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
line vty 0 4
 exec-timeout 0 0
 transport input telnet ssh
""")

GOOD_IOS = """hostname R2
service password-encryption
aaa new-model
enable secret 9 $9$xyz
username admin privilege 15 secret 9 $9$abc
ip ssh version 2
no ip http server
ntp server 10.0.0.10
logging host 10.0.0.20
banner login ^Authorized only^
interface Gi0/0
 ip address 10.0.0.2 255.255.255.252
line vty 0 15
 access-class MGMT in
 exec-timeout 10 0
 transport input ssh
"""


def _ids(findings):
    return {f.rule_id for f in findings}


def test_audit_bad_cisco():
    ids = _ids(audit_config("R1", "cisco_ios", BAD_IOS))
    assert {"telnet", "enable-password", "user-password", "snmp-default", "snmp-rw", "http-server",
            "ssh-v2", "vty-acl", "ntp", "aaa", "password-encryption", "syslog", "exec-timeout", "banner"} <= ids


def test_audit_good_cisco_is_clean():
    assert audit_config("R2", "cisco_ios", GOOD_IOS) == []


def test_findings_sorted_by_severity():
    sev = [f.severity for f in audit_config("R1", "cisco_ios", BAD_IOS)]
    assert sev == sorted(sev, key={"high": 0, "medium": 1, "low": 2}.get)


def test_audit_unknown_platform_returns_none():
    assert audit_config("X", "paloalto_panos", "anything") is None
    assert audit_config("X", "cisco_ios_telnet", GOOD_IOS) == []  # prefix match


MIKROTIK = """# 2026-01-01 10:00:00 by RouterOS 7.14
/ip address
add address=192.168.88.1/24 comment=defconf interface=\\
    bridge network=192.168.88.0
add address=10.0.0.2/30 interface=ether1
/ip dns
set allow-remote-requests=yes
/ip service
set telnet disabled=yes
set ftp disabled=yes
/system ntp client
set enabled=yes
/tool mac-server
set allowed-interface-list=LAN
"""


def test_audit_mikrotik():
    ids = _ids(audit_config("MT", "mikrotik_routeros", MIKROTIK))
    assert "telnet" not in ids and "ftp" not in ids and "ntp" not in ids and "mac-server" not in ids
    assert {"www", "api", "dns-open", "syslog"} <= ids


JUNOS = """set system services telnet
set system services ssh root-login deny
set system ntp server 10.0.0.10
set snmp community public authorization read-only
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30
set interfaces lo0 unit 0 family inet address 1.1.1.1/32
"""


def test_audit_junos():
    ids = _ids(audit_config("J1", "juniper_junos", mask_secrets(JUNOS)))
    assert {"telnet", "snmp-default", "syslog"} <= ids
    assert "root-ssh" not in ids and "ntp" not in ids


def test_interface_addresses_multi_vendor():
    cisco = {(i, str(a)) for i, a in interface_addresses(BAD_IOS)}
    assert cisco == {("Vlan10", "192.168.10.1/24")}
    mt = {(i, str(a)) for i, a in interface_addresses(MIKROTIK)}
    assert mt == {("bridge", "192.168.88.1/24"), ("ether1", "10.0.0.2/30")}
    jn = {(i, str(a)) for i, a in interface_addresses(JUNOS)}
    assert ("ge-0/0/0.0", "10.0.0.1/30") in jn
    nxos = interface_addresses("interface Vlan5\n  ip address 10.5.0.1/24\n")
    assert str(nxos[0][1]) == "10.5.0.1/24"


def test_duplicate_ips():
    dups = find_duplicate_ips({
        "R1": "interface Gi0/0\n ip address 10.0.0.1 255.255.255.252\n",
        "R2": "interface Gi0/0\n ip address 10.0.0.2 255.255.255.252\ninterface Lo0\n ip address 10.0.0.1 255.255.255.255\n",
        "R3": "interface Gi0/1\n ip address 10.0.0.2 255.255.255.252\n",
    })
    assert [d["ip"] for d in dups] == ["10.0.0.1", "10.0.0.2"]
    assert dups[0]["where"] == ["R1 Gi0/0", "R2 Lo0"]


def test_format_findings_mentions_everything():
    text = format_findings(
        {"R1": audit_config("R1", "cisco_ios", BAD_IOS), "R2": [], "PA": None},
        [{"ip": "10.0.0.1", "where": ["R1 Gi0/0", "R2 Lo0"]}],
        {"SW9": "მიუწვდომელია"},
    )
    assert "R1" in text and "✅ **R2**" in text and "⚪ **PA**" in text and "10.0.0.1" in text and "SW9" in text


def test_default_snmp_community_not_masked_but_custom_is():
    out = mask_secrets("snmp-server community public RO\nsnmp-server community Sup3r RW\n")
    assert "public" in out and "Sup3r" not in out


# --------------------------------------------------------------------------- state / mutes / usage


def test_state_store_persists(tmp_path):
    p = tmp_path / "state.json"
    s = StateStore(p)
    s.set("a", {"x": 1})
    s.update("a", lambda v: {**v, "y": 2})
    assert StateStore(p).get("a") == {"x": 1, "y": 2}
    p.write_text("{broken", encoding="utf-8")
    assert StateStore(p).get("a") is None  # corrupt file -> fresh start, no crash


@pytest.mark.parametrize("text,secs", [("30m", 1800), ("2h", 7200), ("1d", 86400), ("90", 5400), ("2ს", 7200), ("45s", 45)])
def test_parse_duration(text, secs):
    assert parse_duration(text) == secs


def test_parse_duration_invalid():
    with pytest.raises(ValueError):
        parse_duration("forever")


def test_mutes(tmp_path):
    m = AlertMutes(StateStore(tmp_path / "s.json"))
    m.mute("R1", 3600)
    assert m.is_muted("R1") and not m.is_muted("R2")
    m.mute(ALL, 60)
    assert m.is_muted("R2")
    assert m.unmute("R1") and not m.unmute("R1")
    m.unmute_all()
    assert not m.is_muted("R2")
    # expired entries disappear
    m.state.set(m.KEY, {"R5": time.time() - 1})
    assert not m.is_muted("R5") and m.active() == {}
    assert "1 სთ" in format_duration(3600)


def _usage(i=0, o=0, cr=0, cw=0):
    return SimpleNamespace(input_tokens=i, output_tokens=o, cache_read_input_tokens=cr, cache_creation_input_tokens=cw)


def test_cost_calculation():
    assert cost_of("claude-opus-5-5", _usage(i=1_000_000)) == pytest.approx(4.0)
    assert cost_of("claude-opus-5-5", _usage(o=1_000_000, cr=1_000_000)) == pytest.approx(20.2)
    assert price_for("claude-opus-5-5-something") == price_for("claude-opus-5-5")


def test_usage_tracker_and_budget(tmp_path):
    t = UsageTracker(StateStore(tmp_path / "s.json"), daily_budget_usd=1.0)
    t.record("claude-opus-5-5", _usage(i=100_000, o=10_000))  # 0.4 + 0.2
    assert t.day()["requests"] == 1 and t.day()["cost"] == pytest.approx(0.6)
    assert not t.over_budget()
    t.record("claude-opus-5-5", _usage(i=100_000, o=10_000))
    assert t.over_budget()
    t.record("claude-opus-5-5", _usage(i=1_000_000), today=date.today() - timedelta(days=100))
    assert all(k >= (date.today() - timedelta(days=62)).isoformat() for k in t.state.get(t.KEY))
    assert "$" in t.summary()


def test_agent_refuses_when_over_budget(tmp_path):
    t = UsageTracker(StateStore(tmp_path / "s.json"), daily_budget_usd=0.01)
    t.record("claude-opus-5-5", _usage(o=10_000))

    class NoCalls:
        def create(self, **kw):
            raise AssertionError("API must not be called over budget")

    a = agent_mod.NetAgent(client=SimpleNamespace(beta=SimpleNamespace(messages=NoCalls())), usage=t)
    assert "ბიუჯეტი" in a.chat("s", "hi", user="t").text


# --------------------------------------------------------------------------- subnet usage


def test_subnet_usage_summary():
    net = ipaddress.ip_network("10.1.1.0/28")
    lines = ["Internet  10.1.1.1   -  aaaa.bbbb.cccc ARPA Vlan5", "Internet  10.1.1.9  3  aaaa.bbbb.dddd ARPA Vlan5",
             "Vlan5  10.1.1.1/28 up", "Internet 10.9.9.9 5 x"]
    used = {ip: {"SW1"} for ip in addresses_in_lines(lines, net)}
    r = summarize_usage(net, used)
    assert r["used_count"] == 2 and r["free_count"] == 12
    assert r["free_ranges"] == ["10.1.1.2 - 10.1.1.8", "10.1.1.10 - 10.1.1.14"]
