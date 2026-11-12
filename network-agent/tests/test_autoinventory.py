"""Managed devices are added to the inventory by themselves when they join the network."""

from __future__ import annotations

from types import SimpleNamespace as NS

import yaml

from netagent.discovery import Candidate, add_to_inventory
from netagent.features import autoinventory as ai
from netagent.inventory import Inventory
from netagent.state import StateStore

INV = """credentials:
  default:
    username_env: NET_USER
    password_env: NET_PASS
  mikrotik:
    username_env: MIKROTIK_USER
    password_env: MIKROTIK_PASS
devices: {}
"""


def row(ip, kind="", vendor="", online=True, gateway=False, me=False, ports=()):
    return {"ip": ip, "kind": kind, "vendor": vendor, "online": online, "gateway": gateway, "self": me,
            "ports": list(ports), "first_seen": 0}


ROWS = [row("192.168.1.1", "router", "Sichuan Jiuzhou", gateway=True), row("192.168.1.2", "network", "MikroTik", ports=[8291]),
        row("192.168.1.3", "phone", "Apple"), row("192.168.1.4", "pc", "Intel", me=True),
        row("192.168.1.5", "network", "Cisco", online=False)]


def setup(tmp_path, monkeypatch):
    path = tmp_path / "devices.yaml"
    path.write_text(INV, encoding="utf-8")
    monkeypatch.setenv("NET_USER", "u")
    monkeypatch.setenv("MIKROTIK_USER", "m")
    st = StateStore(tmp_path / "state.json")
    s = NS(state=st, inventory=lambda: Inventory.load(path))
    live = NS(snapshot=lambda: {"devices": ROWS, "online": 3})
    add = lambda _p, cands, prof, site="": add_to_inventory(path, cands, prof, site)  # noqa: E731
    return path, st, s, NS(snapshot=live.snapshot, add=add)


def test_only_network_gear_gets_credentials(tmp_path, monkeypatch):
    path, st, s, live = setup(tmp_path, monkeypatch)
    calls = []

    def detect(inv, host, port, prof):
        calls.append((host, prof))
        if host == "192.168.1.2" and prof == "mikrotik":
            return Candidate(host=host, port=port, device_type="mikrotik_routeros", hostname="hAP-Office")
        return Candidate(host=host, port=port, error="Authentication failed")

    added = ai.check(s, live=live, add=live.add, detect=detect, probe=lambda ip: True, now=1000.0)
    assert added == [{"ip": "192.168.1.2", "name": "hAP-Office", "device_type": "mikrotik_routeros", "profile": "mikrotik"}]
    hosts = {h for h, _ in calls}
    assert hosts == {"192.168.1.1", "192.168.1.2"}  # never the phone, this PC or an offline device
    assert calls[calls.index(("192.168.1.2", "mikrotik"))] and calls[[h for h, _ in calls].index("192.168.1.2")][1] == "mikrotik"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["devices"]["hAP-Office"] == {"host": "192.168.1.2", "device_type": "mikrotik_routeros",
                                             "credentials": "mikrotik", "description": "auto-discovered"}
    assert "credentials" in data and data["credentials"]["default"]["username_env"] == "NET_USER"
    tried = st.get(ai.TRIED_KEY)
    assert tried["192.168.1.2"]["result"] == "დაემატა: hAP-Office" and "Authentication" in tried["192.168.1.1"]["result"]

    # next minute: the added one is in the inventory, the failed login waits 6 hours
    calls.clear()
    assert ai.check(s, live=live, add=live.add, detect=detect, probe=lambda ip: True, now=1060.0) == [] and calls == []
    ai.check(s, live=live, add=live.add, detect=detect, probe=lambda ip: True, now=1000.0 + ai.RETRY_SECONDS + 1)
    assert {h for h, _ in calls} == {"192.168.1.1"}


def test_ssh_closed_and_no_credentials(tmp_path, monkeypatch):
    path, st, s, live = setup(tmp_path, monkeypatch)
    called = []
    ai.check(s, live=live, add=live.add, detect=lambda *a: called.append(a), probe=lambda ip: False, now=0.0)
    assert not called and st.get(ai.TRIED_KEY)["192.168.1.1"]["result"] == ai.CLOSED
    ai.check(s, live=live, add=live.add, detect=lambda *a: called.append(a), probe=lambda ip: False, now=ai.SSH_RETRY_SECONDS + 1)
    assert st.get(ai.TRIED_KEY)["192.168.1.1"]["ts"] == ai.SSH_RETRY_SECONDS + 1  # looked again after 30 min

    monkeypatch.delenv("NET_USER")
    monkeypatch.delenv("MIKROTIK_USER")
    st.set(ai.TRIED_KEY, {})
    ai.check(s, live=live, add=live.add, detect=lambda *a: called.append(a), probe=lambda ip: True, now=0.0)
    assert not called and "credentials" in st.get(ai.TRIED_KEY)["192.168.1.1"]["result"]


def test_profiles_order(monkeypatch):
    monkeypatch.setenv("NET_USER", "u")
    monkeypatch.setenv("MIKROTIK_USER", "m")
    inv = Inventory({}, yaml.safe_load(INV)["credentials"])
    assert ai.profiles(inv, row("x", vendor="Routerboard.com")) == ["mikrotik", "default"]
    assert ai.profiles(inv, row("x", vendor="Cisco")) == ["default", "mikrotik"]


def test_add_to_empty_inventory_keeps_comments(tmp_path):
    p = tmp_path / "devices.yaml"
    p.write_text("# my comment\n" + INV, encoding="utf-8")
    assert add_to_inventory(p, [Candidate(host="10.0.0.1", port=22, device_type="cisco_ios", hostname="R1")]) == ["R1"]
    text = p.read_text(encoding="utf-8")
    assert "# my comment" in text and Inventory.load(p).devices["R1"].host == "10.0.0.1"


def test_command(tmp_path, monkeypatch):
    path, st, s, live = setup(tmp_path, monkeypatch)
    st.set(ai.TRIED_KEY, {"192.168.1.1": {"ts": 1.0, "result": ai.CLOSED}})
    assert "SSH დახურულია" in ai.autoinv_cmd(s, [], None).text
    ai.autoinv_cmd(s, ["retry"], None)
    assert st.get(ai.TRIED_KEY) == {}
