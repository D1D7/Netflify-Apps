"""Wi-Fi room by room (phone -> PC test) and the network score."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from netagent.features import rooms, score
from netagent.state import StateStore

H = {"X-NetAgent": "1"}


@pytest.fixture
def st(tmp_path):
    return StateStore(tmp_path / "state.json")


# ---------------------------------------------------------------- rooms
def test_save_and_summary(st):
    rooms.save(st, "  სამზარეულო ", {"down": 220.4, "up": 180, "ping": 4, "jitter": 1})
    rooms.save(st, "საძინებელი", {"down": 30, "up": 20, "ping": 12, "jitter": 3})
    rooms.save(st, "საძინებელი", {"down": 50, "up": 25, "ping": 10, "jitter": 2})
    rooms.save(st, "აივანი", {"down": 6, "up": 3, "ping": 80, "jitter": 45})
    rows = rooms.summary(st)
    assert [r["room"] for r in rows] == ["სამზარეულო", "საძინებელი", "აივანი"]
    assert rows[1]["down"] == 40.0 and rows[1]["count"] == 2  # median of the room's tests
    text = rooms.format_rooms(rows)
    assert "სუსტი წერტილი" in text and "აივანი" in text and "არასტაბილური: აივანი" in text
    assert "⬇" not in text and "Mbps" in text
    with pytest.raises(Exception):
        rooms.save(st, "  ", {"down": 1})
    with pytest.raises(Exception):
        rooms.save(st, "x", {})


def test_limits(st):
    for i in range(15):
        rooms.save(st, "A", {"down": i, "ping": 1})
    assert len(st.get(rooms.KEY)["A"]) == rooms.MAX_PER_ROOM
    for i in range(rooms.MAX_ROOMS + 3):
        rooms.save(st, f"R{i}", {"down": 1e9, "ping": -5})
    v = st.get(rooms.KEY)
    assert len(v) == rooms.MAX_ROOMS and v["R40"] if "R40" in v else True
    assert v[f"R{rooms.MAX_ROOMS + 2}"][-1]["down"] == 100000.0 and v[f"R{rooms.MAX_ROOMS + 2}"][-1]["ping"] == 0


def test_all_good_advice(st):
    rooms.save(st, "A", {"down": 300, "up": 200, "ping": 3})
    rooms.save(st, "B", {"down": 200, "up": 150, "ping": 5})
    assert any("ყველა გაზომილ ოთახში კარგია" in a for a in rooms.advice(rooms.summary(st)))


@pytest.fixture
def api(tmp_path, monkeypatch):
    from netagent.config import settings
    from netagent.monitoring import MonitoringService
    from netagent.services import Services
    from netagent.web.app import create_app
    from netagent.web.auth import WebAuth

    fake = {"data_dir": tmp_path / "data", "audit_log_path": tmp_path / "audit.jsonl", "export_dir": tmp_path / "exports"}
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)
    services = Services.create(client=object())
    auth = WebAuth(tmp_path / "data" / "web_auth.json")
    auth.set_password("a-long-password")
    client = TestClient(create_app(services, MonitoringService(services), auth, None))
    yield client, services
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


def test_lantest_api(api):
    client, services = api
    assert client.get("/api/lantest/ping").status_code == 401
    assert client.post("/api/login", json={"password": "a-long-password"}, headers=H).status_code == 200
    assert client.get("/api/lantest/ping").json() == {"ok": True}
    r = client.get("/api/lantest/down", params={"mb": 2})
    assert len(r.content) == 2 * 1024 * 1024 and r.headers["cache-control"] == "no-store"
    assert len(client.get("/api/lantest/down", params={"mb": 9999}).content) == rooms.MAX_TEST_MB * 1024 * 1024
    assert client.post("/api/lantest/up", content=b"x" * 300000, headers=H).json() == {"bytes": 300000}
    assert client.post("/api/lantest/up", content=b"x" * 10).status_code == 403  # CSRF header required
    assert client.post("/api/rooms", json={"room": "ოთახი", "down": 88.123, "up": 40, "ping": 5, "jitter": 1}, headers=H).json()["ok"]
    assert client.post("/api/rooms", json={"room": "", "down": 1}, headers=H).status_code == 400
    data = client.get("/api/rooms").json()
    assert data["rooms"][0]["room"] == "ოთახი" and data["rooms"][0]["down"] == 88.1 and isinstance(data["advice"], list)


# ---------------------------------------------------------------- score
def test_score_perfect_and_tips(st):
    sc = score.compute(st)
    assert sc.value == 100 and not sc.items
    assert {c for _, c in sc.tips} == {"/iot", "/bufferbloat", "/speedtest", "/rooms"}


def test_score_deductions(st):
    st.set("iot_last", {"devices": {"192.168.1.1": [{"severity": "high", "title": "Telnet ღიაა"}, {"severity": "low", "title": "HTTP"}]}})
    st.set("bufferbloat_tests", [{"grade": "C", "worst_increase_ms": 120}])
    st.set("isp_speedtests", [{"down_mbps": 8.0, "up_mbps": 5}])
    rooms.save(st, "აივანი", {"down": 5, "ping": 50})
    live = [{"ip": "192.168.1.50", "online": True, "trusted": False, "self": False, "vendor": "Xiaomi"},
            {"ip": "192.168.1.8", "online": True, "trusted": False, "self": True}]
    sc = score.compute(st, live_rows=live, isp_summary={"uptime_percent": 98.0, "latency_avg_ms": 9},
                       wifi_now={"channel": "8"}, wifi_hist=[(None, 45), (None, 55)],
                       wifi_adv={"current": 8, "best": 1, "gain": 0.3})
    assert sc.lost["security"] == 8 + 1 + 3
    assert sc.lost["internet"] == 6 + 7 + 8
    assert sc.lost["wifi"] == 5 + 5 + 3 + 8  # signal 50 % average: the milder step
    assert sc.value == 100 - 12 - 21 - 21
    assert sc.items[0][0] >= sc.items[-1][0]  # biggest fixes first
    text = score.format_score(sc, before=70)
    assert f"{sc.value}/100" in text and "▼" in text and "→ /bufferbloat" in text
    assert any("Xiaomi" in i[2] for i in sc.items) and len(text.split("• +")) - 1 == 5  # top 5 fixes shown


def test_area_caps(st):
    st.set("iot_last", {"devices": {f"10.0.0.{i}": [{"severity": "high", "title": "x"}] for i in range(20)}})
    sc = score.compute(st)
    assert sc.lost["security"] == score.AREAS["security"][1] and sc.area("security") == 0 and sc.value == 60


def test_history(st):
    now = datetime(2026, 11, 20, 9, 0)
    assert score.remember(st, 60, now - timedelta(days=8)) is None
    assert score.remember(st, 70, now - timedelta(days=1)) == 60
    assert score.remember(st, 80, now) == 60  # about a week ago
    assert score.remember(st, 82, now) == 60  # same day: replaced, still compared with last week
    assert st.get(score.HISTORY_KEY)[now.date().isoformat()] == 82
