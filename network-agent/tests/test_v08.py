"""v0.8: MAC vendors, new-device detection, runbooks, demo lab."""

from __future__ import annotations

import socket

import pytest

from netagent import macvendor, newdevices
from netagent.state import StateStore


# -- MAC vendor ------------------------------------------------------------------------
def test_normalize_formats():
    for mac in ("A4:5E:60:12:AB:01", "a4-5e-60-12-ab-01", "a45e.6012.ab01", "a45e6012ab01"):
        assert macvendor.normalize(mac) == "a45e6012ab01"


def test_parsers_and_longest_prefix(tmp_path):
    csv = 'Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,"Acme, Inc.",Somewhere\n'
    assert macvendor.parse_ieee_csv(csv) == {"aabbcc": "Acme, Inc."}
    manuf = "AA:BB:CC\tAcme\tAcme Networks Ltd\nAA:BB:CC:D0:00:00/28\tSmall\tSmall Vendor\n# comment\n"
    db = macvendor.parse_wireshark_manuf(manuf)
    assert db["aabbcc"] == "Acme Networks Ltd" and db["aabbccd"] == "Small Vendor"
    cache = tmp_path / "oui.txt"
    cache.write_text("\n".join(f"{k}\t{v}" for k, v in db.items()), encoding="utf-8")
    v = macvendor.VendorDB(cache)
    assert v.lookup("aa:bb:cc:d1:22:33") == "Small Vendor"
    assert v.lookup("aa:bb:cc:e1:22:33") == "Acme Networks Ltd"


def test_builtin_and_random(tmp_path):
    v = macvendor.VendorDB(tmp_path / "missing.txt")
    assert v.lookup("b8:27:eb:01:02:03").startswith("Raspberry Pi")
    assert v.lookup("02:42:ac:11:00:02") == "Docker container"
    assert v.lookup("da:a1:19:00:00:01") == macvendor.RANDOM_LABEL  # randomized phone MAC
    assert v.lookup("not-a-mac") is None


# -- new devices -------------------------------------------------------------------------
CISCO_ARP = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.10.21          3   a45e.6012.ab01  ARPA   Vlan10
Internet  192.168.10.255         -   ffff.ffff.ffff  ARPA   Vlan10
Internet  192.168.10.22          0   Incomplete      ARPA
"""


def test_parse_arp_skips_broadcast():
    assert newdevices.parse_arp(CISCO_ARP) == [("192.168.10.21", "a4:5e:60:12:ab:01")]


def test_tracker_baseline_then_new(tmp_path):
    t = newdevices.NewDeviceTracker(StateStore(tmp_path / "s.json"))
    assert t.process({"SW1": [("10.0.0.5", "a4:5e:60:12:ab:01")]}) == []  # baseline
    assert t.recent("2000-01-01") == []  # baseline devices are not "new"
    new = t.process({"SW1": [("10.0.0.5", "a4:5e:60:12:ab:01"), ("10.0.0.9", "b8:27:eb:00:00:09")]})
    assert [e["mac"] for e in new] == ["b8:27:eb:00:00:09"]
    assert t.process({"SW1": [("10.0.0.9", "b8:27:eb:00:00:09")]}) == []  # only once
    assert [e["mac"] for e in t.recent("2000-01-01")] == ["b8:27:eb:00:00:09"]
    assert "10.0.0.9" in newdevices.format_new(new)


# -- demo lab ------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def lab():
    pytest.importorskip("paramiko")
    from netagent.demo import lab as lab_mod

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        base = s.getsockname()[1]
    ips = ["127.0.0.1"] * 4
    ports = [base + i for i in range(4)]
    for p in ports:  # make sure they are free
        with socket.socket() as s:
            s.bind(("127.0.0.1", p))
    lb = lab_mod.DemoLab(lab_mod.build_devices(ips, ports), syslog_port=0)
    lb.start()
    lab_mod.LAB = lb
    yield lb
    lb.stop()
    lab_mod.LAB = None


def test_lab_responses_and_scenarios(lab):
    from netagent.demo.lab import respond

    r1 = lab.devices["R1"]
    assert "Gateway of last resort" in respond(r1, "show ip route")
    assert respond(r1, "show run") == r1.outputs["show running-config"]
    assert "Invalid input" in respond(r1, "show nonsense")
    assert "CPU utilization" in respond(r1, "show processes cpu | include CPU utilization")
    assert respond(r1, "show ip interface brief | include Loopback").startswith("Loopback0")
    lab.scenario("uplink")
    assert "Active" in r1.outputs["show ip bgp summary"]
    assert "0 percent" in r1.outputs["ping 8.8.8.8 repeat 3 timeout 1"]
    lab.scenario("down")
    acc = lab.devices["SW-Access-2"]
    with pytest.raises(OSError):
        socket.create_connection((acc.ip, acc.port), timeout=1).close()
    lab.scenario("restore")
    assert "Active" not in r1.outputs["show ip bgp summary"]
    socket.create_connection((acc.ip, acc.port), timeout=2).close()


def test_lab_over_ssh(lab):
    import paramiko

    d = lab.devices["MT-Branch"]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with pytest.raises(paramiko.AuthenticationException):
        c.connect(d.ip, d.port, username="admin", password="wrong", look_for_keys=False, allow_agent=False, timeout=5)
    c.connect(d.ip, d.port, username="admin+cte", password="demo", look_for_keys=False, allow_agent=False, timeout=5)
    chan = c.invoke_shell()
    chan.settimeout(5)
    chan.send("/ip address print\n")
    out = b""
    while b"bridge-lan" not in out or not out.rstrip().endswith(b">"):
        out += chan.recv(4096)
    c.close()
    assert b"10.20.0.1/24" in out


def test_demo_command(lab):
    from netagent.commands import CommandError

    res = lab.command([])
    assert "/demo uplink" in res.text and any(b.command == "/demo restore" for b in res.buttons)
    with pytest.raises(CommandError):
        lab.command(["bogus"])
    assert "WAN" in lab.command(["uplink"]).text
    lab.scenario("restore")


def test_inventory_yaml_loads(lab, tmp_path):
    from netagent.demo.lab import inventory_yaml
    from netagent.inventory import Inventory

    p = tmp_path / "devices.yaml"
    p.write_text(inventory_yaml(lab), encoding="utf-8")
    inv = Inventory.load(p)
    assert set(inv.devices) == {"R1", "SW-Core-1", "SW-Access-2", "MT-Branch"}
    assert inv.devices["R1"].watch.get("bgp") is True
    assert inv.devices["MT-Branch"].device_type == "mikrotik_routeros"


# -- MikroTik CHR first login ----------------------------------------------------------------
def _fake_fresh_chr():
    """SSH server that behaves like a factory-new RouterOS: empty password, license + new-password prompts."""
    import threading

    import paramiko

    key = paramiko.RSAKey.generate(1024)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    got = {"commands": [], "password": None}

    class Iface(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL if username.startswith("admin") and password == "" else paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password"

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_pty_request(self, *a):
            return True

        def check_channel_shell_request(self, channel):
            return True

    def readline(chan):
        buf = b""
        while not buf.endswith(b"\r"):
            ch = chan.recv(1)
            if not ch:
                raise EOFError
            buf += ch
        return buf.decode().strip()

    def serve():
        conn, _ = sock.accept()
        t = paramiko.Transport(conn)
        t.add_server_key(key)
        t.start_server(server=Iface())
        chan = t.accept(10)
        chan.send(b"Do you want to see the software license? [Y/n]: ")
        assert readline(chan) == "n"
        chan.send(b"\r\nChange your password\r\nnew password> ")
        pw = readline(chan)
        chan.send(b"\r\nrepeat new password> ")
        assert readline(chan) == pw
        got["password"] = pw
        chan.send(b"\r\nPassword changed\r\n[admin@MikroTik] > ")
        try:
            while True:
                got["commands"].append(readline(chan))
                chan.send(b"\r\n[admin@MikroTik] > ")
        except Exception:  # noqa: BLE001 - client closed
            pass

    threading.Thread(target=serve, daemon=True).start()
    return sock, got


def test_chr_first_login_and_files(tmp_path):
    pytest.importorskip("paramiko")
    import time

    import yaml

    from netagent.demo import chr_init

    sock, got = _fake_fresh_chr()
    chr_init.first_login("127.0.0.1", sock.getsockname()[1], "Lab-secret123", wait=10)
    for _ in range(50):
        if len(got["commands"]) == len(chr_init.SETUP):
            break
        time.sleep(0.1)
    sock.close()
    assert got["password"] == "Lab-secret123"
    assert got["commands"] == chr_init.SETUP

    env = tmp_path / ".env"
    env.write_text("NET_USER=a\n", encoding="utf-8")
    chr_init.update_env(env, "admin", "p1")
    chr_init.update_env(env, "admin", "p2")
    text = env.read_text(encoding="utf-8")
    assert text.count("LAB_PASS=") == 1 and "LAB_PASS=p2" in text and text.count("# MikroTik CHR lab") == 1

    inv = tmp_path / "devices.yaml"
    assert chr_init.update_inventory(inv, "127.0.0.1", 2230) == "CHR-Lab"
    data = yaml.safe_load(inv.read_text(encoding="utf-8"))
    assert data["credentials"]["lab"]["password_env"] == "LAB_PASS"
    assert data["devices"]["CHR-Lab"]["port"] == 2230 and data["devices"]["CHR-Lab"]["credentials"] == "lab"
    chr_init.update_inventory(inv, "127.0.0.1", 2230)  # idempotent
    assert len(yaml.safe_load(inv.read_text(encoding="utf-8"))["devices"]) == 1
