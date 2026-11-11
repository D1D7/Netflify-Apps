"""Wi-Fi drop log and evil twin detection."""

from __future__ import annotations

from datetime import datetime

import pytest

from netagent.features import eviltwin as et
from netagent.features import wifidrops as wd
from netagent.state import StateStore


def ev(ts, id_, ssid="Biker", reason="The network is disconnected by the driver."):
    msg = f"x\n\nSSID: {ssid}\nBSS Type: Infrastructure\n" + (f"Reason: {reason}\n" if id_ == 8003 else "")
    if id_ == 8002:
        msg += "Failure Reason:The driver disconnected while associating.\n"
    return {"ts": ts, "id": id_, "msg": msg}


def test_drops_ignore_sleep_and_user():
    data = {"wlan": [ev("2026-11-10T21:00:00", 8003), ev("2026-11-10T21:05:00", 8001),          # a real drop, 5 min
                     ev("2026-11-10T23:00:00", 8003), ev("2026-11-11T07:00:00", 8001),          # sleep
                     ev("2026-11-11T09:00:00", 8003, reason="The network is disconnected by the user."), ev("2026-11-11T09:01:00", 8001),
                     ev("2026-11-11T10:00:00", 8002, ssid="Phone"),
                     ev("2026-11-11T11:00:00", 8003)],                                         # still down
            "power": [{"ts": "2026-11-10T23:00:30", "id": 42}]}
    r = wd.analyse(data, now=datetime(2026, 11, 11, 11, 30))
    assert [d["kind"] for d in r["all"]] == ["drop", "sleep", "user", "drop"]
    assert r["count"] == 2 and r["sleep"] == 1 and r["down_seconds"] == 300
    assert r["drops"][-1]["back"] is None and r["failed"][0]["ssid"] == "Phone"
    text = wd.format_drops(r, 7)
    assert "გაწყვეტა: **2**" in text and "ჯერ არ აღდგენილა" in text and "დრაივერმა გათიშა" in text


def test_no_wifi_events():
    assert "არ გაწყვეტილა" in wd.format_drops(wd.analyse({"wlan": [], "power": []}), 7)


def test_read_events_parses_single_objects():
    import json

    one = json.dumps({"wlan": {"ts": "2026-11-10T21:00:00", "id": 8001, "msg": "SSID: Biker"}, "power": None})
    d = wd.read_events(1, run=lambda script: one)
    assert len(d["wlan"]) == 1 and d["power"] == []


ROUTER = "28:5b:0c:56:da:2e"


def net(bssid, auth="WPA2-Personal", ssid="Biker", signal=80):
    return {"ssid": ssid, "bssid": bssid, "auth": auth, "signal": signal, "channel": 8}


def test_related_macs():
    assert et.related("5c:62:8b:27:3a:26", "5c:62:8b:27:3a:27")        # dual band
    assert et.related("5c:e9:31:e5:95:82", "5e:e9:31:25:95:82")        # locally administered variant
    assert not et.related(ROUTER, "aa:bb:cc:11:22:33")


@pytest.fixture
def st(tmp_path):
    return StateStore(tmp_path / "s.json")


CUR = {"ssid": "Biker", "bssid": ROUTER, "auth": "WPA2-Personal"}


def test_twin_detection(st):
    assert et.check(st, [net(ROUTER), net("28:5b:0c:56:da:2f")], CUR) == []           # learn: first look
    known = st.get(et.KEY)["Biker"]["known"]
    assert set(known) == {ROUTER, "28:5b:0c:56:da:2f"}
    assert et.check(st, [net(ROUTER), net("28:5b:0c:56:da:30")], CUR) == []           # same family: learned silently
    sus = et.check(st, [net(ROUTER), net("aa:bb:cc:11:22:33", auth="Open")], CUR)
    assert len(sus) == 1 and sus[0]["level"] == "high" and len(sus[0]["why"]) == 2
    assert et.check(st, [net(ROUTER), net("aa:bb:cc:11:22:33", auth="Open")], CUR) == []  # alerted once
    assert "ყალბი ასლი" in et.alert_text(sus[0])
    assert "🔴 aa:bb:cc:11:22:33" in et.format_status(st)  # while it is on the air
    sus = et.check(st, [net("de:ad:be:ef:00:01")], CUR)
    assert sus and sus[0]["level"] == "medium"
    assert et.trust(st, "DE-AD-BE-EF-00-01") == "Biker"
    assert "de:ad:be:ef:00:01" in st.get(et.KEY)["Biker"]["known"]
    with pytest.raises(Exception):
        et.trust(st, "not-a-mac")
    assert "ყალბი ასლი არ ჩანს" in et.format_status(st)  # gone from the air in the latest scan


def test_twin_needs_a_connection(st):
    assert et.check(st, [net(ROUTER)], None) == [] and et.check(st, [net(ROUTER)], {}) == []
    assert st.get(et.KEY) is None
