"""v0.9 features: LAN scan, ISP monitor, sites, maintenance/escalation/schedules, notify, self-management, teach."""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import pytest

from netagent import features
from netagent.features import homenet, isp, ops, selfmgmt, sites, teach


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


def run(s, line):
    from netagent import commands

    return commands.run(s, line, "test")


# -- registry --------------------------------------------------------------------------------
def test_install_registers_everything(svc):
    from netagent import commands, tools

    features.install()  # idempotent
    for name in ("scan", "isp", "speedtest", "site", "sites", "maintenance", "ack", "schedule", "schedules",
                 "notify", "update", "selfbackup", "version", "teach", "quiz"):
        assert name in commands.COMMANDS, name
    names = [t["name"] for t in tools.TOOL_SCHEMAS]
    assert len(names) == len(set(names))
    assert {"scan_local_network", "internet_status", "run_speedtest", "check_website"} <= set(names)
    assert "/scan" in commands.HELP and commands.HELP.rstrip().endswith("„R1-ის IP-ები მაჩვენე“.")


# -- home network ------------------------------------------------------------------------------
WIN_ARP = """
Interface: 192.168.1.10 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           a4-5e-60-12-ab-01     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
LINUX_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.20     0x1         0x2         b8:27:eb:01:02:03     *        eth0
192.168.1.21     0x1         0x0         00:00:00:00:00:00     *        eth0
"""


def test_parse_arp_tables():
    assert homenet.parse_arp_table(WIN_ARP) == {"192.168.1.1": "a4:5e:60:12:ab:01"}
    assert homenet.parse_arp_table(LINUX_ARP) == {"192.168.1.20": "b8:27:eb:01:02:03"}
    assert homenet.parse_arp_table("? (10.0.0.1) at 4c:5e:c:1:2:3 on en0") == {}  # short macOS form ignored safely


def test_private_only():
    from netagent.result import CommandError

    for bad in ("8.8.8.0/24", "10.0.0.0/8", "nonsense"):
        with pytest.raises(CommandError):
            homenet.check_private(bad)
    assert str(homenet.check_private("192.168.1.7/24")) == "192.168.1.0/24"


def test_scan_with_fake_network(monkeypatch):
    from netagent.macvendor import VendorDB

    up = {("192.168.1.1", 80), ("192.168.1.1", 443), ("192.168.1.30", 554), ("192.168.1.40", 9100)}
    monkeypatch.setattr(homenet, "_probe", lambda ip, port, timeout: (ip, port) in up)
    monkeypatch.setattr(homenet, "read_arp", lambda: {"192.168.1.1": "4c:5e:0c:00:00:01", "192.168.1.30": "00:11:22:33:44:55",
                                                      "192.168.1.40": "3c:d9:2b:00:00:40", "192.168.1.50": "da:00:00:00:00:50"})
    monkeypatch.setattr(homenet, "local_ip", lambda: "192.168.1.10")
    monkeypatch.setattr(homenet, "default_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(homenet, "_name", lambda ip: "")
    res = homenet.scan("", VendorDB(__import__("pathlib").Path("/nonexistent")))
    kinds = {e["ip"]: e["kind"] for e in res["devices"]}
    assert kinds == {"192.168.1.1": "როუტერი (gateway)", "192.168.1.10": "ეს კომპიუტერი", "192.168.1.30": "კამერა / NVR",
                     "192.168.1.40": "პრინტერი", "192.168.1.50": "ტელეფონი/ლეპტოპი (privacy MAC)"}
    text = homenet.format_scan(res)
    assert "192.168.1.30" in text and "RTSP" in text


# -- ISP monitor --------------------------------------------------------------------------------
def test_outage_lifecycle(svc, tmp_path):
    m = isp.InternetMonitor(svc.state, tmp_path / "isp")
    (tmp_path / "isp").mkdir()
    t0 = datetime.now() - timedelta(minutes=30)
    ok = {"online": True, "latency_ms": 12.0, "loss": 0}
    bad = {"online": False, "latency_ms": None, "loss": 100}
    assert m.record(ok, t0) is None
    assert m.record(bad, t0 + timedelta(minutes=1)) is None  # one failure is not an outage
    ev = m.record(bad, t0 + timedelta(minutes=2))
    assert ev["type"] == "down"
    assert m.record(bad, t0 + timedelta(minutes=3)) is None
    ev = m.record(ok, t0 + timedelta(minutes=5))
    assert ev["type"] == "up" and ev["seconds"] == 240
    r = m.summary(1)
    assert r["samples"] == 5 and len(r["outages"]) == 1 and r["uptime_percent"] == 40.0
    assert "გათიშვები: 1" in isp.format_summary(r)
    svc.state.set("isp_speedtests", [{"ts": datetime.now().isoformat(), "down_mbps": 40.0, "up_mbps": 10.0, "ping_ms": 9,
                                      "isp": "Magti", "ip": "1.2.3.4"}])
    report = isp.format_report(m.summary(30), plan_mbps=100)
    assert "Magti" in report and "40%" in report and "გათიშვების სია" in report


# -- websites ------------------------------------------------------------------------------------
def test_url_and_domain_helpers():
    assert sites.normalize_url("example.com") == "https://example.com"
    assert sites.registrable_domain("www.example.co.uk") == "example.co.uk"
    assert sites.registrable_domain("mail.google.com") == "google.com"
    assert sites.registrable_domain("10.0.0.1") is None


def test_tcp_check_and_untrusted_cert(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10))
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(3):
            try:
                conn, _ = srv.accept()
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    assert sites.check(f"tcp://127.0.0.1:{port}")["up"] is True
    info = sites.cert_expiry("localhost", port)
    srv.close()
    assert info["cert_trusted"] is False and 8 <= info["cert_days_left"] <= 10
    text = sites.format_check({"url": "https://x", "up": True, "status": 200, "ms": 5, **info})
    assert "🔴 სერტიფიკატი" in text


def test_site_commands(svc, monkeypatch):
    monkeypatch.setattr(sites, "check", lambda url, deep=False: {"url": url, "up": True, "status": 200, "ms": 12})
    assert "დაემატა" in run(svc, "/site add https://example.com Example").text
    assert "უკვე" in run(svc, "/site add https://example.com").text
    assert "Example" in run(svc, "/sites").text
    assert "წაიშალა" in run(svc, "/site del 1").text
    assert sites.sites(svc.state) == []


# -- maintenance, escalation, schedules -----------------------------------------------------------
def test_maintenance_suppresses_notifications(svc):
    from netagent.monitoring import Alert, MonitoringService

    mon = MonitoringService(svc)
    got = []

    async def notifier(a):
        got.append(a)

    mon.add_notifier(notifier)
    assert "დაიგეგმა" in run(svc, "/maintenance R1 now 1h რემონტი").text
    asyncio.run(mon.emit(Alert("down", "R1 down", ["R1"])))
    asyncio.run(mon.emit(Alert("report", "daily")))  # reports still go out
    assert [a.kind for a in got] == ["report"]
    assert svc.alerts.recent(5)[1]["text"].startswith("🛠")
    assert "R1" in run(svc, "/maintenance").text
    run(svc, "/maintenance cancel 1")
    asyncio.run(mon.emit(Alert("down", "R1 down", ["R1"])))
    assert got[-1].kind == "down"


def test_parse_start_and_days():
    now = datetime(2026, 11, 4, 21, 30)
    assert ops.parse_start("22:00", now) == datetime(2026, 11, 4, 22, 0)
    assert ops.parse_start("08:00", now) == datetime(2026, 11, 5, 8, 0)
    assert ops.parse_days("weekdays") == [0, 1, 2, 3, 4]
    assert ops.parse_days("mon,fri") == [0, 4]
    assert ops.escalation_due(15, 15, 0) and not ops.escalation_due(20, 15, 1) and ops.escalation_due(31, 15, 1)


def test_schedules_run(svc):
    assert "დაემატა" in run(svc, "/schedule daily 00:00 /version").text
    items = svc.state.get("schedules")
    items[0]["last_run"] = ""
    svc.state.set("schedules", items)
    assert ops.due_schedules(items, datetime(2026, 11, 4, 0, 1)) == [0]
    items[0]["last_run"] = "2026-11-04"
    assert ops.due_schedules(items, datetime(2026, 11, 4, 9, 0)) == []

    from netagent.monitoring import MonitoringService

    mon = MonitoringService(svc)
    sent = []

    async def notifier(a):
        sent.append(a)

    mon.add_notifier(notifier)
    items[0]["last_run"] = ""
    items[0]["time"] = "00:00"
    svc.state.set("schedules", items)
    job = dict((n, fn) for n, _, _, fn in ops.jobs(mon))["schedules"]
    asyncio.run(job())
    assert sent and sent[0].kind == "scheduled" and "NetAgent" in sent[0].text
    assert "/version" in run(svc, "/schedules").text
    run(svc, "/unschedule 1")
    assert svc.state.get("schedules") == []


def test_escalation_job(svc, monkeypatch):
    from netagent.health import Reachability
    from netagent.monitoring import MonitoringService

    monkeypatch.setenv("NETAGENT_ESCALATE_MINUTES", "1")
    mon = MonitoringService(svc)
    sent = []

    async def notifier(a):
        sent.append(a)

    mon.add_notifier(notifier)
    svc.monitor.update([Reachability("R1", "127.0.0.1", 1, False, reason="timeout")])
    svc.monitor._down_since["R1"] -= 120  # noqa: SLF001 - pretend it has been down for 2 minutes
    job = dict((n, fn) for n, _, _, fn in ops.jobs(mon))["escalation"]
    asyncio.run(job())
    assert sent[-1].kind == "escalation" and sent[-1].buttons[0].command == "/ack R1"
    run(svc, "/ack R1")
    svc.monitor._down_since["R1"] -= 600  # noqa: SLF001
    asyncio.run(job())
    assert len(sent) == 1


# -- notify ---------------------------------------------------------------------------------------
def test_notify_channels(monkeypatch):
    from netagent.features import notify

    calls = []
    monkeypatch.setenv("NETAGENT_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("NETAGENT_EMAIL_TO", "a@example.com")
    monkeypatch.setenv("NETAGENT_DISCORD_WEBHOOK", "https://discord.example/x")
    monkeypatch.setattr(notify, "send_email", lambda cfg, subj, body: calls.append(("email", subj, body)))

    async def fake_post(url, payload):
        calls.append(("hook", url, payload))

    monkeypatch.setattr(notify, "post_webhook", fake_post)
    ok = asyncio.run(notify.deliver("🔴 R1", "**R1** ```\nx\n``` down", "down"))
    assert ok == ["email", "discord"]
    assert "**" not in calls[0][2] and "```" not in calls[0][2] and calls[0][1] == "NetAgent: 🔴 R1"
    [send] = notify.notifiers(None)
    calls.clear()
    asyncio.run(send(NS(kind="up", title="up", text="x")))
    assert calls == []  # "up" is not mailed unless NETAGENT_NOTIFY_UP


# -- self management ---------------------------------------------------------------------------------
def test_selfbackup_excludes_secrets(svc):
    import zipfile

    from netagent.config import settings

    (settings.data_dir / "demo").mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "demo" / "x.json").write_text("{}")
    (settings.data_dir / "notes.json").write_text("{}")
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    (settings.backup_dir / "R1.cfg").write_text("hostname R1")
    res = run(svc, "/selfbackup")
    names = zipfile.ZipFile(res.files[0]).namelist()
    assert "data/notes.json" in names and "backups/R1.cfg" in names and "inventory/devices.yaml" in names
    assert not any(n.endswith(".env") or "/demo/" in n for n in names)


def test_update_without_git(svc, monkeypatch):
    monkeypatch.setattr(selfmgmt, "in_git", lambda: False)
    assert "git-ით არ არის" in run(svc, "/update").text


# -- teach & quiz ------------------------------------------------------------------------------------
def test_teach_and_quiz(svc):
    assert features.prompt_extra(svc) == ""
    run(svc, "/teach on")
    assert "სასწავლო რეჟიმი" in features.prompt_extra(svc)
    run(svc, "/teach off")
    assert features.prompt_extra(svc) == ""
    for q, options, correct, why in teach.QUESTIONS:
        assert len(options) == 4 and 0 <= correct < 4 and why
    q = run(svc, "/quiz")
    assert len(q.buttons) == 4
    qi = int(q.buttons[0].command.split()[2])
    right = run(svc, f"/quiz answer {qi} {teach.QUESTIONS[qi][2]}").text
    wrong = run(svc, f"/quiz answer {qi} {(teach.QUESTIONS[qi][2] + 1) % 4}").text
    assert right.startswith("✅") and wrong.startswith("❌") and "1/2" in wrong
