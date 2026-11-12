"""Console cable (COM port): prompt detection, auto-baud, read-only identification, setup dialog, login,
inventory entry and the serial connection path."""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest
import yaml

from netagent.features import console as con
from netagent.inventory import Inventory

SHOW_VERSION = """Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
ROM: Bootstrap program is C2960 boot loader
SW1 uptime is 2 hours, 14 minutes
System image file is "flash:/c2960-lanbasek9-mz.150-2.SE11.bin"
cisco WS-C2960-24TT-L (PowerPC405) processor (revision P0) with 65536K bytes of memory.
Processor board ID FOC1234X5YZ
Model number                    : WS-C2960-24TT-L
System serial number            : FOC1234X5YZ
"""
IP_BRIEF = """Interface              IP-Address      OK? Method Status                Protocol
Vlan1                  unassigned      YES unset  administratively down down
FastEthernet0/1        unassigned      YES unset  up                    up
FastEthernet0/2        unassigned      YES unset  down                  down
"""


@pytest.fixture(autouse=True)
def fast_console(monkeypatch):
    monkeypatch.setattr(con, "PACE", 0.03)  # the simulated device answers at once: no need to wait seconds


class FakeCisco:
    """A serial port with a Cisco console behind it (only at its own baud rate)."""

    def __init__(self, mode="exec", baud=9600, hostname="SW1", password="secret1"):
        self.mode, self.baud, self.hostname, self.password = mode, baud, hostname, password
        self.sent: list[str] = []
        self.out = b""

    def opener(self, port, baud, **kw):
        if self.mode == "busy":
            import serial

            raise serial.SerialException(f"could not open port '{port}': PermissionError(13, 'Access is denied.', None, 5)")
        self.cur_baud = baud
        return self

    # pyserial-like API
    @property
    def in_waiting(self):
        return len(self.out)

    def read(self, n=1):
        data, self.out = self.out[:max(n, 1)], self.out[max(n, 1):]
        return data

    def reset_input_buffer(self):
        self.out = b""

    def flush(self):
        pass

    def close(self):
        pass

    def write(self, data: bytes):
        if self.cur_baud != self.baud:
            self.out += b"\xfe\x80\x9f\x00\xff"  # wrong speed: garbage
            return
        text = data.decode()
        self.sent.append(text)
        cmd = text.strip()
        p = self.prompt()
        if self.mode == "setup":
            if cmd == "no":
                self.mode = "autoinstall"
                self.out += b"\r\nWould you like to terminate autoinstall? [yes]: "
            else:
                self.out += b"\r\nWould you like to enter the initial configuration dialog? [yes/no]: "
        elif self.mode == "autoinstall":
            self.mode = "exec"
            self.out += b"\r\n\r\nPress RETURN to get started!\r\n"
        elif self.mode == "user":
            self.mode = "password" if cmd == "admin" else "user"
            self.out += b"\r\nPassword: " if self.mode == "password" else b"\r\nUsername: "
        elif self.mode == "password":
            self.mode = "exec" if cmd == self.password else "user"
            self.out += (b"\r\n" + self.prompt().encode()) if self.mode == "exec" else b"\r\n% Login invalid\r\n\r\nUsername: "
        elif cmd == "show version":
            self.out += (text + SHOW_VERSION.replace("\n", "\r\n") + p).encode()
        elif cmd == "show ip interface brief":
            self.out += (text + IP_BRIEF.replace("\n", "\r\n") + p).encode()
        elif cmd == "terminal length 0":
            self.out += (text + p).encode()
        else:
            self.out += ("\r\n" + p).encode()

    def prompt(self):
        return f"{self.hostname}{'#' if self.mode == 'enable' else '>'}"


@pytest.mark.parametrize("text,state", [
    ("\r\nSW1>", "exec"), ("\r\nCore-SW.1#", "enable"), ("\r\nR1(config-if)#", "config"),
    ("Would you like to enter the initial configuration dialog? [yes/no]: ", "setup_dialog"),
    ("\r\nUser Access Verification\r\n\r\nUsername: ", "login_user"), ("\r\nPassword: ", "login_password"),
    ("rommon 1 >", "rommon"), ("switch: ", "rommon"), ("", "silent"), ("\xfe\x80\x9f\x00\xff\xfe\x80", "garbage"),
    ("Press RETURN to get started!", "press_return"),
])
def test_detect_state(text, state):
    assert con.detect_state(text)[0] == state


def test_hostname_from_prompt():
    assert con.hostname_from("SW1>") == "SW1" and con.hostname_from("R1(config)#") == "R1" and con.hostname_from("blah") == ""


def test_probe_finds_the_speed():
    dev = FakeCisco(baud=115200)
    p = con.probe("COM3", opener=dev.opener)
    assert p["state"] == "exec" and p["baud"] == 115200 and p["hostname"] == "SW1"
    assert all(s == "\r" for s in dev.sent)  # the probe only presses Enter


def test_probe_busy_and_silent():
    assert con.probe("COM3", opener=FakeCisco(mode="busy").opener)["state"] == "busy"
    dead = FakeCisco(baud=1)  # answers on no speed we try
    assert con.probe("COM3", opener=dead.opener)["state"] == "garbage"


def test_identify_is_read_only():
    dev = FakeCisco()
    info = con.identify("COM3", 9600, opener=dev.opener)
    assert info["model"] == "WS-C2960-24TT-L" and info["version"] == "15.0(2)SE11" and info["hostname"] == "SW1"
    assert info["serial"] == "FOC1234X5YZ" and info["uptime"] == "2 hours, 14 minutes" and info["vendor"] == "cisco"
    assert [i["name"] for i in info["interfaces"]] == ["Vlan1", "FastEthernet0/1", "FastEthernet0/2"]
    assert info["interfaces"][1]["status"] == "up" and info["interfaces"][0]["status"] == "administratively down"
    typed = [s.strip() for s in dev.sent if s.strip()]
    assert typed == ["terminal length 0", "show version", "show ip interface brief"]  # nothing that changes the device


def test_setup_dialog_is_skipped_only_on_request():
    dev = FakeCisco(mode="setup")
    assert con.probe("COM3", opener=dev.opener)["state"] == "setup_dialog"
    assert not any(s.strip() for s in dev.sent)  # the probe did not answer it
    r = con.skip_setup("COM3", 9600, opener=dev.opener)
    assert r["state"] == "exec" and "no\r" in dev.sent


def test_login_uses_env_credentials(monkeypatch):
    monkeypatch.setenv("CONSOLE_USER", "admin")
    monkeypatch.setenv("CONSOLE_PASS", "secret1")
    dev = FakeCisco(mode="user")
    assert con.login("COM3", 9600, opener=dev.opener)["state"] == "exec"
    monkeypatch.setenv("CONSOLE_PASS", "wrong")
    with pytest.raises(Exception, match="ვერ მოხერხდა"):
        con.login("COM3", 9600, opener=FakeCisco(mode="user").opener)
    monkeypatch.delenv("CONSOLE_PASS")
    monkeypatch.delenv("NET_PASS", raising=False)
    with pytest.raises(Exception, match="CONSOLE_PASS"):
        con.login("COM3", 9600, opener=FakeCisco(mode="user").opener)


INV = "credentials:\n  default:\n    username_env: NET_USER\n    password_env: NET_PASS\ndevices: {}\n"


def test_add_device_writes_a_serial_entry(tmp_path, monkeypatch):
    path = tmp_path / "devices.yaml"
    path.write_text(INV, encoding="utf-8")
    import netagent.config as cfg

    monkeypatch.setattr(cfg, "settings", NS(inventory_path=path))
    s = NS(inventory=lambda: Inventory.load(path))
    info = con.identify("COM3", 9600, opener=FakeCisco().opener) | {"baud": 9600}
    assert con.add_device(s, "COM3", info) == "SW1"
    d = Inventory.load(path).devices["SW1"]
    assert d.host == "COM3" and d.device_type == "cisco_ios_serial" and d.baudrate == 9600 and d.is_serial
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["devices"]["SW1"]["role"] == "console"
    assert con.add_device(s, "com3", info) == "SW1"  # already there: nothing new
    with pytest.raises(Exception, match="Cisco"):
        con.add_device(s, "COM4", {"vendor": "", "baud": 9600})


def test_serial_reachability_and_connection(monkeypatch):
    from netagent import health
    from netagent.inventory import Device
    from netagent.tools import device as dev

    d = Device(name="SW1", host="COM3", device_type="cisco_ios_serial", baudrate=9600)
    monkeypatch.setattr(health, "serial_present", lambda port: port == "COM3")
    assert health.check_one(d).up
    assert not health.check_one(Device(name="X", host="COM9", device_type="cisco_ios_serial")).up

    seen = {}

    class Conn:
        def disconnect(self):
            seen["closed"] = True

    def fake_connect(**params):
        seen["params"] = params
        return Conn()

    import netmiko

    monkeypatch.setattr(netmiko, "ConnectHandler", fake_connect)
    inv = NS(credential_for=lambda device: NS(username="", password="", secret=""))
    conn = dev._connect(inv, d)  # noqa: SLF001
    assert seen["params"]["serial_settings"]["port"] == "COM3" and seen["params"]["serial_settings"]["baudrate"] == 9600
    assert "host" not in seen["params"] and dev.port_lock("COM3").locked()  # one user per COM port
    conn.disconnect()
    assert seen["closed"] and not dev.port_lock("com3").locked()

    def busy(**params):
        raise OSError("could not open port 'COM3': PermissionError(13, 'Access is denied.', None, 5)")

    monkeypatch.setattr(netmiko, "ConnectHandler", busy)
    with pytest.raises(ConnectionError, match="PuTTY"):
        dev._connect(inv, d)  # noqa: SLF001
    assert not dev.port_lock("COM3").locked()


def test_ip_brief_and_version_parsers_tolerate_noise():
    assert con.parse_ip_brief("garbage\n\n") == []
    assert con.parse_show_version("nothing here") == {"vendor": ""}


def test_plug_in_is_found_by_the_job(tmp_path, monkeypatch):
    import asyncio

    import serial

    from netagent.state import StateStore

    path = tmp_path / "devices.yaml"
    path.write_text(INV, encoding="utf-8")
    import netagent.config as cfg

    monkeypatch.setattr(cfg, "settings", NS(inventory_path=path))
    st = StateStore(tmp_path / "state.json")
    s = NS(inventory=lambda: Inventory.load(path), state=st)
    ports = []
    monkeypatch.setattr(con, "list_ports", lambda: [{"port": p, "description": "USB Serial Port", "hwid": "", "vid": "0403",
                                                     "pid": "6001", "usb": True} for p in ports])
    dev = FakeCisco(mode="busy")
    monkeypatch.setattr(serial, "Serial", dev.opener)
    alerts = []

    async def emit(a):
        alerts.append(a)

    mon = NS(s=s, emit=emit)
    (name, every, first, check), = con.jobs(mon)
    assert name == "console" and every == 5
    clock = [1000.0]
    monkeypatch.setattr(con.time, "time", lambda: clock[0])

    asyncio.run(check())  # nothing plugged in
    assert not alerts and st.get(con.TRIED_KEY) == {}

    ports.append("COM3")  # plugged in while PuTTY has it open
    asyncio.run(check())
    assert st.get(con.TRIED_KEY)["COM3"]["state"] == "busy" and not alerts

    dev.mode = "exec"  # PuTTY closed
    clock[0] += 5
    asyncio.run(check())
    assert st.get(con.TRIED_KEY)["COM3"]["state"] == "busy"  # too soon to look again
    clock[0] += con.RETRY["busy"]
    asyncio.run(check())
    assert "SW1" in Inventory.load(path).devices and "დაემატა: SW1" in alerts[-1].text

    ports.clear()  # unplugged: forgotten, so a re-plug is looked at at once
    asyncio.run(check())
    assert st.get(con.TRIED_KEY) == {}
