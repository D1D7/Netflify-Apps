from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from openpyxl import load_workbook

from netagent.backup import BackupStore, changes_since, diff_stats, normalize_config, unified_diff
from netagent.export import write_xlsx
from netagent.health import Reachability, ReachabilityMonitor, check_one
from netagent.inventory import Device, Inventory
from netagent.tools import ToolContext, execute_tool
from netagent.tools.network import parse_ping_output

# --------------------------------------------------------------------------- backup


def test_normalize_drops_volatile_lines():
    a = "Building configuration...\n\nCurrent configuration : 1234 bytes\n! Last configuration change at 10:00\nhostname R1\n"
    b = "Building configuration...\n\nCurrent configuration : 1299 bytes\n! Last configuration change at 11:00\nhostname R1\n"
    assert normalize_config(a) == normalize_config(b) == "hostname R1\n"


def test_backup_store_saves_only_on_change(tmp_path):
    store = BackupStore(tmp_path)
    t0 = datetime(2026, 1, 1, 9, 0, 0)
    snap, changed = store.save("R1", "hostname R1\nenable secret 5 $1$abc\n", when=t0)
    assert changed and "$1$abc" not in snap.read()  # secrets masked on disk
    _, changed = store.save("R1", "hostname R1\nenable secret 5 $1$abc\n", when=t0 + timedelta(hours=1))
    assert not changed
    _, changed = store.save("R1", "hostname R1-new\nenable secret 5 $1$abc\n", when=t0 + timedelta(hours=2))
    assert changed
    assert len(store.snapshots("R1")) == 2


def test_changes_since(tmp_path):
    store = BackupStore(tmp_path)
    now = datetime.now()
    store.save("SW1", "vlan 10\n name USERS\n", when=now - timedelta(hours=48))
    store.save("SW1", "vlan 10\n name USERS\nvlan 20\n name VOICE\n", when=now - timedelta(hours=1))
    c = changes_since(store, "SW1", 24)
    assert c["changed"] and c["added"] == 2 and c["removed"] == 0
    assert "+vlan 20" in c["diff"]
    assert changes_since(store, "nope", 24) is None


def test_diff_stats():
    d = unified_diff("a\nb\n", "a\nc\nd\n", "old", "new")
    assert diff_stats(d) == (2, 1)


# --------------------------------------------------------------------------- health


def test_reachability_monitor_transitions():
    m = ReachabilityMonitor()
    up = lambda n: Reachability(n, "1.1.1.1", 22, True, 1.0)  # noqa: E731
    down = lambda n: Reachability(n, "1.1.1.1", 22, False, reason="timeout")  # noqa: E731
    first = m.update([up("A"), down("B")])
    assert [(r.device, s) for r, s in first] == [("B", "down")]  # baseline: only already-down reported
    assert m.update([up("A"), down("B")]) == []
    changes = m.update([down("A"), up("B")])
    assert sorted((r.device, s) for r, s in changes) == [("A", "down"), ("B", "up")]


def test_check_one_open_and_closed_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert check_one(Device(name="x", host="127.0.0.1", device_type="linux", port=port)).up
    finally:
        srv.close()
    r = check_one(Device(name="x", host="127.0.0.1", device_type="linux", port=port), timeout=1)
    assert not r.up and r.reason


# --------------------------------------------------------------------------- export


def test_write_xlsx(tmp_path):
    path = write_xlsx(
        tmp_path,
        "ip addresses/../evil",
        [{"name": "IPs:all", "columns": ["device", "ip"], "rows": [["R1", "10.0.0.1"], ["R2", "=HYPERLINK(1)"]]}],
    )
    assert path.parent == tmp_path and path.suffix == ".xlsx"
    ws = load_workbook(path)["IPs_all"]
    assert [c.value for c in ws[1]] == ["device", "ip"]
    assert ws["B3"].value == "'=HYPERLINK(1)"  # formula injection neutralized


# --------------------------------------------------------------------------- tools


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    fake = SimpleNamespace(
        audit_log_path=tmp_path / "audit.jsonl", backup_dir=tmp_path / "backups", export_dir=tmp_path / "exports"
    )
    monkeypatch.setattr("netagent.tools.settings", fake)
    inv = Inventory({"R1": Device(name="R1", host="127.0.0.1", device_type="cisco_ios", port=1)}, {})
    return ToolContext(inventory=inv, user="test")


def test_export_tool_attaches_file(ctx):
    text, err = execute_tool(
        "export_excel",
        {"filename": "ips", "sheets": [{"name": "s", "columns": ["a"], "rows": [["1"]]}]},
        ctx,
    )
    assert not err, text
    assert len(ctx.files) == 1 and ctx.files[0].exists()


def test_export_tool_rejects_bad_input(ctx):
    _, err = execute_tool("export_excel", {"filename": "x", "sheets": "nope"}, ctx)
    assert err and not ctx.files


def test_config_changes_without_backup(ctx):
    text, err = execute_tool("config_changes", {"device": "R1"}, ctx)
    assert not err and "backup ჯერ არ არსებობს" in text


def test_reachability_tool(ctx):
    text, err = execute_tool("check_reachability", {}, ctx)
    data = json.loads(text)
    assert not err and data["down"] == 1


def test_parse_ping_output_windows_and_linux():
    assert parse_ping_output("Lost = 4 (100% loss),")["packet_loss_percent"] == 100
    assert parse_ping_output("rtt min/avg/max/mdev = 1.0/2.5/3.0/0.1 ms")["avg_rtt_ms"] == 2.5
