"""/diagnose: intent detection and root cause per failing layer (network replaced by a fake)."""

from __future__ import annotations

import pytest

from netagent.features import diagnose as dg


@pytest.fixture
def svc(tmp_path):
    from netagent.config import settings

    inv = tmp_path / "devices.yaml"
    inv.write_text("devices:\n  R1:\n    host: 127.0.0.1\n    port: 1\n    device_type: cisco_ios\n    site: office2\n"
                   "  SW-Core-1:\n    host: 127.0.0.2\n    port: 1\n    device_type: cisco_ios\n", encoding="utf-8")
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


class FakeNet(dg.Probes):
    """Healthy network by default; each test breaks one layer."""

    def __init__(self, **kw):
        self.ip = kw.get("ip", "192.168.1.10")
        self.gw = kw.get("gw", "192.168.1.1")
        self.gw_ping = kw.get("gw_ping", {"reachable": True, "packet_loss_percent": 0, "avg_rtt_ms": 2.0})
        self.gw_ports = kw.get("gw_ports", set())
        self.online = kw.get("online", True)
        self.dns_ok = kw.get("dns_ok", True)
        self.dns_1111 = kw.get("dns_1111", True)
        self.web = kw.get("web", {"ok": True, "status": 204, "ms": 40})
        self.wifi_info = kw.get("wifi", {})
        self.hosts = kw.get("hosts", {})  # ip -> {"ping": bool, "ports": set}
        self.arp_table = kw.get("arp", {})
        self.dns_ms = kw.get("dns_ms", 9.0)

    def local_ip(self):
        return self.ip

    def gateway(self):
        return self.gw

    def wifi(self):
        return self.wifi_info

    def ping(self, host, count=4):
        if host == self.gw:
            return self.gw_ping
        h = self.hosts.get(host, {})
        return {"reachable": h.get("ping", False), "packet_loss_percent": 0 if h.get("ping") else 100,
                "avg_rtt_ms": 5.0 if h.get("ping") else None}

    def tcp(self, host, port, timeout=1.5):
        if host == self.gw:
            return port in self.gw_ports
        return port in self.hosts.get(host, {}).get("ports", set())

    def arp(self):
        return self.arp_table

    def internet(self):
        return {"online": self.online, "latency_ms": 12.0 if self.online else None, "loss": 0 if self.online else 100}

    def dns(self, name, server=None):
        if name.endswith(".invalid"):
            return {"error": "NXDOMAIN (დომენი არ არსებობს)"}
        if (server == "1.1.1.1" and self.dns_1111) or (server is None and self.dns_ok):
            return {"records": ["142.250.1.1"], "time_ms": 9.0 if server else self.dns_ms}
        return {"error": "Timeout"}

    def http(self, url, timeout=8.0, follow=False):
        return self.web


def marks(d):
    return {c.layer: c.mark for c in d.checks}


# -- intent ----------------------------------------------------------------------------------------
def test_classify_words(svc):
    inv = svc.inventory()
    assert dg.classify("", inv).kind == "internet"
    assert dg.classify("ინტერნეტი არ მუშაობს", inv).kind == "internet"
    assert dg.classify("ინტერნეტი ძალიან ნელია", inv).kind == "slow"
    assert dg.classify("R1-ზე რაღაც ხდება", inv) == dg.Intent("device", "R1")
    assert dg.classify("sw-core-1 არ ჩანს", inv).target == "SW-Core-1"
    assert dg.classify("127.0.0.2 არ პასუხობს", inv).target == "SW-Core-1"  # host of an inventory device
    assert dg.classify("192.168.1.50 არ პასუხობს", inv) == dg.Intent("target", "192.168.1.50")
    assert dg.classify("google.com-ზე ვერ შევდივარ", inv) == dg.Intent("target", "google.com")
    assert dg.classify("https://example.com/login არ იხსნება", inv).target == "https://example.com/login"
    assert dg.classify("VPN გაითიშა", inv).kind == "vpn"
    assert dg.classify("IP არ ეძლევა ლეპტოპს", inv).kind == "dhcp"
    assert dg.classify("wifi სიგნალი ცუდია", inv).kind == "wifi"
    assert dg.classify("office2-ში ინტერნეტი ნელია", inv) == dg.Intent("slow", "", "office2")


# -- internet chain: the lowest failing layer is the cause ------------------------------------------
def test_no_dhcp_address(svc):
    d = dg.diagnose(svc, "", FakeNet(ip="169.254.10.3"))
    assert marks(d)["ეს კომპიუტერი"] == dg.FAIL and "DHCP" in d.cause
    assert marks(d)["ინტერნეტი"] == dg.SKIP


def test_router_down(svc):
    d = dg.diagnose(svc, "", FakeNet(gw_ping={"reachable": False, "packet_loss_percent": 100}, online=False))
    assert marks(d)["როუტერი"] == dg.FAIL and "ლოკალურ ქსელშია" in d.cause
    assert marks(d)["DNS"] == dg.SKIP


def test_router_without_ping_is_not_blamed(svc):
    d = dg.diagnose(svc, "", FakeNet(gw_ping={"reachable": False, "packet_loss_percent": 100}, gw_ports={80}))
    assert marks(d)["როუტერი"] == dg.OK and marks(d)["ვებ"] == dg.OK


def test_weak_wifi_blamed_when_router_unreachable(svc):
    d = dg.diagnose(svc, "", FakeNet(wifi={"ssid": "Home", "signal": "18%"}, gw_ping={"reachable": False}))
    assert marks(d)["Wi-Fi"] == dg.FAIL and "Wi-Fi სიგნალი" in d.cause


def test_isp_down(svc):
    d = dg.diagnose(svc, "ინტერნეტი არ მუშაობს", FakeNet(online=False))
    assert marks(d)["როუტერი"] == dg.OK and marks(d)["ინტერნეტი"] == dg.FAIL
    assert "WAN" in d.cause and marks(d)["DNS"] == dg.SKIP and marks(d)["ვებ"] == dg.SKIP
    assert "ჩემი მოწყობილობები" in marks(d)  # own devices checked for the default route


def test_router_dns_broken(svc):
    d = dg.diagnose(svc, "", FakeNet(dns_ok=False))
    assert marks(d)["DNS"] == dg.FAIL and "DNS სერვერი" in d.cause and marks(d)["ვებ"] == dg.SKIP


def test_all_dns_blocked(svc):
    d = dg.diagnose(svc, "", FakeNet(dns_ok=False, dns_1111=False))
    assert "53" in d.cause


def test_captive_portal(svc):
    d = dg.diagnose(svc, "", FakeNet(web={"ok": True, "status": 302, "ms": 30, "location": "http://login"}))
    assert marks(d)["ვებ"] == dg.WARN and "captive portal" in d.cause


def test_everything_ok_points_to_the_device(svc):
    d = dg.diagnose(svc, "", FakeNet())
    assert marks(d)["ვებ"] == dg.OK
    assert "R1" in d.cause  # the inventory hosts (port 1) are down, so they are named


def test_slow_lan(svc):
    d = dg.diagnose(svc, "ნელია", FakeNet(gw_ping={"reachable": True, "packet_loss_percent": 15, "avg_rtt_ms": 80.0}))
    assert marks(d)["როუტერი"] == dg.WARN and "როუტერამდე" in d.cause
    assert any(b.command == "/speedtest" for b in d.buttons)


def test_site_filter(svc):
    d = dg.diagnose(svc, "office2-ში ინტერნეტი არ მუშაობს", FakeNet())
    assert "office2" in d.understood and "1 მოწყობილობა" in d.understood


# -- one host / service ----------------------------------------------------------------------------
def test_target_port_closed(svc):
    net = FakeNet(hosts={"10.0.0.5": {"ping": True, "ports": set()}})
    d = dg.diagnose(svc, "https://10.0.0.5:8443/ არ იხსნება", net)
    assert marks(d)["პორტი"] == dg.FAIL and "8443" in d.cause


def test_target_firewalled_but_present(svc):
    d = dg.diagnose(svc, "192.168.1.50", FakeNet(arp={"192.168.1.50": "aa:bb:cc:dd:ee:ff"}))
    assert "firewall" in d.cause


def test_target_gone(svc):
    d = dg.diagnose(svc, "192.168.1.50", FakeNet())
    assert "/scan" in " ".join(d.fix)


def test_target_ok_without_ping(svc):
    d = dg.diagnose(svc, "192.168.1.60", FakeNet(hosts={"192.168.1.60": {"ping": False, "ports": {443}}}))
    assert "მისაწვდომია" in d.cause


def test_unknown_domain(svc):
    d = dg.diagnose(svc, "nothing.invalid", FakeNet())
    assert marks(d)["DNS"] == dg.FAIL and "არ არსებობს" in d.cause


def test_domain_when_dns_is_down(svc):
    d = dg.diagnose(svc, "example.com", FakeNet(dns_ok=False))
    assert "DNS საერთოდ არ მუშაობს" in d.cause


def test_target_cause_names_the_host(svc):
    d = dg.diagnose(svc, "example.com", FakeNet(hosts={"142.250.1.1": {"ping": True, "ports": {443}}}))
    assert d.cause.startswith("example.com (142.250.1.1)")


def test_slow_dns(svc):
    d = dg.diagnose(svc, "ნელია", FakeNet(dns_ms=1800.0))
    assert marks(d)["DNS"] == dg.WARN and "DNS ნელია" in d.cause


def test_clues_skip_alerts_of_other_devices(svc):
    svc.alerts.add("down", "🔴 GHOST მიუწვდომელია", ["GHOST"])
    svc.alerts.add("down", "🔴 R1 მიუწვდომელია", ["R1"])
    svc.alerts.add("isp", "🔴 ინტერნეტი გაითიშა")
    d = dg.diagnose(svc, "", FakeNet())
    text = " | ".join(d.clues)
    assert "R1 მიუწვდომელია" in text and "ინტერნეტი გაითიშა" in text and "GHOST" not in text


# -- wiring ----------------------------------------------------------------------------------------
def test_registered_and_formatted(svc, monkeypatch):
    from netagent import commands, features, tools
    from netagent.permissions import VIEWER_BLOCKED_COMMANDS

    features.install()
    assert "diagnose" in commands.COMMANDS and "diagnose" not in VIEWER_BLOCKED_COMMANDS
    assert any(t["name"] == "diagnose_problem" for t in tools.TOOL_SCHEMAS)
    monkeypatch.setattr(dg, "Probes", lambda: FakeNet(online=False))
    res = commands.run(svc, "/diagnose ინტერნეტი არ მუშაობს", "view:gio")
    assert "🎯 **მიზეზი:**" in res.text and "🔧" in res.text
    assert res.buttons and res.buttons[-1].command.startswith("/diagnose")


def test_sample_inventory_not_used(svc, monkeypatch):
    monkeypatch.setattr("netagent.doctor._same_devices", lambda example, inv: True)
    d = dg.diagnose(svc, "R1", FakeNet())
    assert d.title != "მოწყობილობა R1"  # sample devices are not treated as real ones
    assert any("სანიმუშო" in c for c in d.clues)


def test_tool_returns_plain_dict(svc, monkeypatch):
    from types import SimpleNamespace as NS

    monkeypatch.setattr(dg, "Probes", lambda: FakeNet(dns_ok=False))
    out = dg.TOOLS[0][1](NS(services=svc), problem="საიტები არ იხსნება")
    assert out["root_cause"] and out["next_steps"] and isinstance(out["checks"], list)
