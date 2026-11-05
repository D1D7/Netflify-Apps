"""Local fixes: scan warning wording, privacy-MAC label shown once, doctor detects the sample inventory."""

from netagent import doctor
from netagent.config import PROJECT_ROOT
from netagent.features import homenet
from netagent.inventory import Inventory
from netagent.macvendor import RANDOM_LABEL


def _res(devices, gateway="192.168.1.1"):
    return {"network": "192.168.1.0/24", "gateway": gateway, "devices": devices}


def _dev(ip, ports=(), kind="", vendor="", **kw):
    return {"ip": ip, "mac": "", "vendor": vendor, "name": "", "ports": list(ports), "kind": kind, **kw}


def test_privacy_mac_label_not_duplicated():
    text = homenet.format_scan(_res([_dev("192.168.1.5", kind="ტელეფონი/ლეპტოპი (privacy MAC)", vendor=RANDOM_LABEL),
                                     _dev("192.168.1.4", kind="iPhone / iPad", vendor=RANDOM_LABEL)]))
    assert text.count("privacy MAC") == 2  # once per device
    assert RANDOM_LABEL not in text


def test_telnet_on_router_warns_without_internet_claim():
    text = homenet.format_scan(_res([_dev("192.168.1.1", ports=[23, 80], kind="როუტერი (gateway)")]))
    assert "192.168.1.1 (Telnet)" in text
    assert "ინტერნეტში არ უნდა იყოს გახსნილი" not in text


def test_smb_rdp_only_flagged_on_router():
    pc = _dev("192.168.1.20", ports=[139, 445, 3389], kind="Windows კომპიუტერი")
    assert "⚠️" not in homenet.format_scan(_res([pc]))
    router = _dev("192.168.1.1", ports=[445], kind="როუტერი (gateway)")
    assert "192.168.1.1 (SMB)" in homenet.format_scan(_res([router]))


def test_self_never_flagged():
    me = _dev("192.168.1.10", ports=[23], self=True)
    assert "⚠️" not in homenet.format_scan(_res([me]))


def test_doctor_detects_sample_inventory_with_different_bytes(tmp_path):
    example = PROJECT_ROOT / "inventory" / "devices.example.yaml"
    copy = tmp_path / "devices.yaml"
    copy.write_bytes(example.read_bytes().replace(b"\n", b"\r\n") + b"\n# my comment\n")
    assert doctor._same_devices(example, Inventory.load(copy))


# -- security fixes -----------------------------------------------------------------------------
import pytest  # noqa: E402

from netagent.security import CommandRejected, validate_command  # noqa: E402


@pytest.mark.parametrize("cmd,dtype", [
    ("show run | redirect tftp://1.2.3.4/x", "cisco_ios"),
    ("show run | tee flash:x", "cisco_ios"),
    ("show run | append flash:x", "cisco_ios"),
    ("show configuration | save /var/tmp/x", "juniper_junos"),
    ('/log print; :execute "/system reboot"', "mikrotik_routeros"),
    ("/log print; /system reboot", "mikrotik_routeros"),
    ("/ip address print [/system reboot]", "mikrotik_routeros"),
    ("/system script run 0 print", "mikrotik_routeros"),
    ("/tool fetch url=http://x print", "mikrotik_routeros"),
    (":do {/system reboot} print", "mikrotik_routeros"),
])
def test_guard_blocks_bypasses(cmd, dtype):
    with pytest.raises(CommandRejected):
        validate_command(cmd, dtype)


@pytest.mark.parametrize("cmd,dtype", [
    ("show logging | include %LINK-3-UPDOWN", "cisco_ios"),
    ("show log | include save", "cisco_ios"),
    ("show interfaces Gi0/1 status", "cisco_ios"),
    ("/ip arp print where mac-address=AA:BB:CC:DD:EE:FF", "mikrotik_routeros"),
    ('/ip firewall filter print where comment="web"', "mikrotik_routeros"),
    ("/ip route print where 10.0.0.5 in dst-address", "mikrotik_routeros"),
])
def test_guard_still_allows_reads(cmd, dtype):
    assert validate_command(cmd, dtype)


def test_changes_mikrotik_v7_paths_and_scripting():
    from types import SimpleNamespace as NS

    from netagent.features import changes
    from netagent.result import CommandError

    mt = NS(name="M", host="10.0.0.9", device_type="mikrotik_routeros")
    for bad in ("/system/reboot", "/user/add name=x group=full", "/ip address print; /user add name=x",
                ':execute "/system reboot"', "/interface set [/system reboot] disabled=yes"):
        with pytest.raises(CommandError):
            changes.validate(mt, [bad])
    assert changes.validate(mt, ["/interface set [find name=ether2] disabled=yes", "/system clock set time=12:00:00"])


def test_selfbackup_has_no_session_key(tmp_path):
    import json
    import zipfile

    from netagent.config import settings
    from netagent.features import selfmgmt

    keys = ("data_dir", "backup_dir", "inventory_path", "export_dir")
    saved = {k: getattr(settings, k) for k in keys}
    for k in keys:
        object.__setattr__(settings, k, tmp_path / k)
    try:
        settings.data_dir.mkdir(parents=True)
        (settings.data_dir / "web_auth.json").write_text(json.dumps({"password": {"x": 1}, "session_key": "SECRET"}))
        z = zipfile.ZipFile(selfmgmt.make_backup())
        data = json.loads(z.read("data/web_auth.json"))
    finally:
        for k, v in saved.items():
            object.__setattr__(settings, k, v)
    assert "session_key" not in data and data["password"] == {"x": 1}


def test_flow_memory_budget():
    from netagent.features.flows import FlowStats

    fs = FlowStats(max_keys=50)
    for i in range(200):
        fs.add([{"src": f"10.0.0.{i}", "dst": "8.8.8.8", "bytes": 10}], "e", now=60)
    assert fs.budget.total <= 50
    fs.add([{"src": "10.0.0.1", "dst": "1.1.1.1", "bytes": 5}], "e", now=60 + 25 * 3600)
    assert 0 < fs.budget.total <= 10  # old day freed first, new minute recorded


def test_syslog_flood_guard():
    from netagent import syslogd

    stored, alerts = [], []
    store = type("S", (), {"append": lambda self, e: stored.append(e)})()
    srv = syslogd.SyslogServer(store, lambda ip: ip, lambda d, t: alerts.append(t))
    for i in range(5000):
        srv.datagram_received(b"<10>%SYS-2-MALLOCFAIL: x" + str(i).encode(), (f"10.9.{i // 250}.{i % 250}", 514))
    assert len(stored) < 1500 and srv.dropped > 3000
    assert len(alerts) == syslogd.MAX_ALERTS


# -- new features: accounts, roles, names, router check, WoL, interface names ----------------------
def test_multi_user_login_and_roles(tmp_path):
    from netagent.web.auth import WebAuth, totp_code

    a = WebAuth(tmp_path / "auth.json")
    a.set_password("owner-password-1")
    owner, _ = a.login("owner-password-1", "", "c")
    assert a.session_user(owner) == {"name": "admin", "role": "admin"}
    a.add_user("gio", "gio-password-1", "viewer")
    secret = a.enable_user_totp("gio")
    assert a.login("gio-password-1", "", "c2", "gio")[0] is None
    token, _ = a.login("gio-password-1", totp_code(secret), "c3", "gio")
    assert a.session_user(token) == {"name": "gio", "role": "viewer"}
    assert a.login("owner-password-1", "", "c4", "gio")[0] is None
    a.delete_user("gio")
    assert a.session_user(token) is None and a.verify_session(owner)
    with pytest.raises(ValueError):
        a.add_user("admin", "x" * 12)


def test_viewer_cannot_change_things():
    from netagent import commands
    from netagent.features import install
    from netagent.permissions import DENIED

    install()
    for line in ("/approve 1 123456", "/name 192.168.1.5 x", "/wake pc", "/update now"):
        assert commands.run(None, line, "view:gio").text == DENIED


class _State(dict):
    def set(self, k, v):
        self[k] = v


def test_names_shown_with_ip_and_privacy_mac():
    from types import SimpleNamespace as NS

    from netagent.features import lan

    s = NS(state=_State(), vendors=None)
    s.state.set("home_last_scan", {"devices": [{"ip": "192.168.100.5", "mac": "22:36:e0:cb:d1:48"}]})
    lan.name_cmd(s, ["192.168.100.5", "დედას", "ტელეფონი"], "app:admin")
    res = {"network": "192.168.100.0/24", "gateway": "192.168.100.1", "devices": [
        {"ip": "192.168.100.5", "mac": "22:36:e0:cb:d1:48", "vendor": RANDOM_LABEL, "name": "", "ports": [],
         "kind": "ტელეფონი/ლეპტოპი (privacy MAC)"}]}
    text = homenet.format_scan(homenet.apply_names(s.state, res))
    assert "**192.168.100.5** — 🏷️ **დედას ტელეფონი** · ტელეფონი/ლეპტოპი (privacy MAC)" in text
    assert "`22:36:e0:cb:d1:48`" in text
    assert lan.resolve(s.state, "დედას ტელეფონი") == ("192.168.100.5", "22:36:e0:cb:d1:48")


def test_router_check_wording_and_wol_packet():
    from netagent.features import lan

    text = lan.format_router_check({"gateway": "192.168.1.1", "mac": "", "vendor": "", "open": [23, 80], "upnp": True})
    assert "Telnet ღიაა" in text and "UPnP ჩართულია" in text and "WPS" in text
    packet = lan.magic_packet("aa:bb:cc:dd:ee:ff")
    assert packet[:6] == b"\xff" * 6 and len(packet) == 102


def test_interface_name_parsing():
    from netagent.features.ifnames import parse_names

    ios = "Interface IP-Address OK? Method Status Protocol\nGigabitEthernet0/0 10.0.0.1 YES NVRAM up up\nVlan10 unassigned YES unset up up\n"
    assert parse_names(ios, "first") == ["GigabitEthernet0/0", "Vlan10"]
    assert parse_names(' 0 R name="ether1" type="ether"\n 1 name=bridge1\n', "ros") == ["ether1", "bridge1"]
