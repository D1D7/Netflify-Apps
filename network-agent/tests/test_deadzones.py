"""Wi-Fi dead zones: grid heat map, walk-mode spots, classification, API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from netagent.features import deadzones as dz
from netagent.features import rooms
from netagent.state import StateStore

H = {"X-NetAgent": "1"}


@pytest.fixture
def st(tmp_path):
    return StateStore(tmp_path / "state.json")


@pytest.mark.parametrize("m,cls", [
    ({"down": 150, "ping": 4, "loss": 0}, "good"),
    ({"down": 50, "ping": 12, "loss": 0}, "ok"),
    ({"down": 15, "ping": 12, "loss": 0}, "weak"),
    ({"down": 90, "ping": 140, "loss": 0}, "weak"),
    ({"down": 90, "ping": 45, "loss": 0}, "ok"),
    ({"down": 90, "ping": 10, "loss": 10}, "weak"),
    ({"down": 3, "ping": 10, "loss": 0}, "dead"),
    ({"down": None, "ping": None, "loss": 100}, "dead"),
    ({"down": 200, "ping": 30, "loss": 0, "net": "cellular"}, "dead"),  # fell back to mobile data
])
def test_classify(m, cls):
    assert dz.classify(m) == cls


def test_grid_cells_and_resize(st):
    assert dz.load(st)["cols"] == 6 and dz.load(st)["rows"] == 4
    assert dz.save_cell(st, 0, 0, {"down": 200, "ping": 3, "loss": 0, "net": "wifi"})["class"] == "good"
    assert dz.save_cell(st, 3, 5, {"down": 2, "ping": 90, "loss": 40})["class"] == "dead"
    dz.save_cell(st, 1, 2, {"down": 12, "ping": 20, "loss": 0})
    with pytest.raises(Exception):
        dz.save_cell(st, 4, 0, {"down": 1})
    with pytest.raises(Exception):
        dz.save_cell(st, "x", 0, {"down": 1})
    p = dz.problems(st)
    assert {dz.cell_name(k) for k, _ in p["cells"]} == {"F4", "C2"}
    text = dz.format_deadzones(p)
    assert "მკვდარი:** F4" in text and "სუსტი:** C2" in text and "mesh" in text
    dz.set_size(st, 4, 3)  # squares outside the smaller grid are dropped
    assert set(dz.load(st)["cells"]) == {"0,0", "1,2"}
    with pytest.raises(Exception):
        dz.set_size(st, 1, 20)


def test_spots_rooms_and_cellular(st):
    dz.save_spot(st, "  აივანი ", {"ping": None, "loss": 100, "net": "cellular"})
    dz.save_spot(st, "", {"ping": 5, "loss": 0})
    rooms.save(st, "სარდაფი", {"down": 3, "up": 1, "ping": 40})
    p = dz.problems(st)
    assert [s["name"] for s in p["spots"]] == ["აივანი"] and dz.load(st)["spots"][1]["name"].startswith("ადგილი")
    assert [r["room"] for r in p["rooms"]] == ["სარდაფი"]
    text = dz.format_deadzones(p)
    assert "აივანი" in text and "სარდაფი" in text and "მობილურ ინტერნეტზე" in text
    for i in range(dz.MAX_SPOTS + 5):
        dz.save_spot(st, f"s{i}", {"ping": 5, "loss": 0, "net": "wifi;rm -rf"})
    v = dz.load(st)
    assert len(v["spots"]) == dz.MAX_SPOTS and v["spots"][-1]["net"] == ""  # odd values are not stored


def test_empty_and_all_good(st):
    assert "ჯერ არაფერი გაზომილა" in dz.format_deadzones(dz.problems(st))
    dz.save_cell(st, 0, 0, {"down": 300, "ping": 2, "loss": 0})
    assert "მკვდარი ზონა ვერ ვიპოვე" in dz.format_deadzones(dz.problems(st))
    assert "გასუფთავდა" in dz.deadzones_cmd(type("S", (), {"state": st})(), ["clear"], None).text
    assert dz.load(st)["cells"] == {}


@pytest.fixture
def api(tmp_path):
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
    yield TestClient(create_app(services, MonitoringService(services), auth, None))
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


def test_api(api):
    c = api
    assert c.get("/api/wifimap").status_code == 401
    c.post("/api/login", json={"password": "a-long-password"}, headers=H)
    assert c.get("/api/wifimap").json()["cols"] == 6
    r = c.post("/api/wifimap/cell", json={"row": 1, "col": 1, "down": 4, "ping": 30, "loss": 0}, headers=H).json()
    assert r["result"]["class"] == "dead" and "1,1" in r["map"]["cells"]
    assert c.post("/api/wifimap/cell", json={"row": 9, "col": 1}, headers=H).status_code == 400
    assert c.post("/api/wifimap/spot", json={"name": "დერეფანი", "ping": 50, "loss": 0}, headers=H).json()["result"]["class"] == "ok"
    assert c.post("/api/wifimap/size", json={"cols": 3, "rows": 3}, headers=H).json()["map"]["cols"] == 3
    assert c.post("/api/wifimap/size", json={"cols": 30, "rows": 3}, headers=H).status_code == 400
    assert c.post("/api/wifimap/clear", json={}, headers=H).json()["map"]["cells"] == {}
    assert c.post("/api/wifimap/nope", json={}, headers=H).status_code == 404
    assert c.post("/api/wifimap/clear", json={}).status_code == 403  # CSRF header
