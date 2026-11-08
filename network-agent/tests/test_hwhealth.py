"""This PC's disks (NVMe / SATA SMART) and RAM health."""

from __future__ import annotations

import struct
from datetime import datetime, timedelta

import pytest

from netagent.features import hwhealth as hw
from netagent.state import StateStore


def nvme_page(used=37, temp_c=34, spare=100, threshold=10, crit=0, written_units=59726000, hours=1751, unsafe=99, media=0):
    d = bytearray(512)
    d[0] = crit
    d[1:3] = (temp_c + 273).to_bytes(2, "little")
    d[3], d[4], d[5] = spare, threshold, used
    d[48:64] = written_units.to_bytes(16, "little")
    d[112:128] = (1282).to_bytes(16, "little")
    d[128:144] = hours.to_bytes(16, "little")
    d[144:160] = unsafe.to_bytes(16, "little")
    d[160:176] = media.to_bytes(16, "little")
    return bytes(d)


def test_parse_nvme_health():
    x = hw.parse_nvme_health(nvme_page())
    assert x["used_pct"] == 37 and x["temperature_c"] == 34 and x["spare_pct"] == 100
    assert x["written_tb"] == 30.58 and x["power_on_hours"] == 1751 and x["power_cycles"] == 1282 and x["unsafe_shutdowns"] == 99


def stat(value, valid=True):
    return struct.pack("<Q", (1 << 63 | (1 << 62 if valid else 0)) | value)


def test_parse_ata_stats():
    p1 = bytes(8) + stat(500) + stat(12000) + stat(2 * 10**9)  # resets, hours, sectors written
    p3 = bytes(32) + stat(7)
    p5 = bytes(8) + stat(41)
    p7 = bytes(8) + stat(12)
    x = hw.parse_ata_stats({1: p1, 3: p3, 5: p5, 7: p7})
    assert x == {"power_on_hours": 12000, "written_tb": 1.02, "reallocated_sectors": 7, "temperature_c": 41, "used_pct": 12}
    assert hw.parse_ata_stats({7: bytes(8) + stat(12, valid=False)}) == {}  # not valid = not reported
    assert hw.parse_ata_stats({5: bytes(8) + stat(0xF6)})["temperature_c"] == -10  # signed byte


@pytest.mark.parametrize("disk,status,life", [
    ({"bus": "NVMe", "health": "Healthy", "details": hw.parse_nvme_health(nvme_page())}, "ok", 63),
    ({"bus": "NVMe", "health": "Healthy", "details": hw.parse_nvme_health(nvme_page(used=85))}, "warn", 15),
    ({"bus": "NVMe", "health": "Healthy", "details": hw.parse_nvme_health(nvme_page(used=101))}, "bad", 0),
    ({"bus": "NVMe", "health": "Healthy", "details": hw.parse_nvme_health(nvme_page(crit=4))}, "bad", 63),
    ({"bus": "NVMe", "health": "Healthy", "details": hw.parse_nvme_health(nvme_page(spare=5))}, "bad", 63),
    ({"bus": "NVMe", "health": "Healthy", "details": hw.parse_nvme_health(nvme_page(temp_c=78))}, "warn", 63),
    ({"bus": "SATA", "media": "HDD", "health": "Healthy", "details": {"reallocated_sectors": 120}}, "bad", None),
    ({"bus": "SATA", "media": "HDD", "health": "Healthy", "details": {"temperature_c": 57}}, "warn", None),
    ({"bus": "SATA", "media": "SSD", "health": "Warning", "details": {}}, "warn", None),
    ({"bus": "SATA", "media": "SSD", "health": "Unhealthy", "details": {}}, "bad", None),
])
def test_judge_disk(disk, status, life):
    j = hw.judge_disk(disk)
    assert j["status"] == status and j["life_pct"] == life
    assert bool(j["why"]) == (status != "ok")


def test_kinds_and_ram_makers():
    assert hw.disk_kind({"bus": "NVMe", "media": "SSD"}) == "M.2 NVMe SSD"
    assert hw.disk_kind({"bus": "SATA", "media": "HDD"}) == "HDD"
    assert hw.disk_kind({"bus": "SATA", "media": "SSD"}) == "SATA SSD"
    assert hw.ram_maker("802C0000802C") == "Micron" and hw.ram_maker("80CE") == "Samsung" and hw.ram_maker("Kingston") == "Kingston"
    assert hw.ram_maker("") == "" and hw.ram_maker("Unknown") == ""


INV = {"disks": [{"id": 0, "name": "PC SN530 NVMe WDC 256GB", "media": "SSD", "bus": "NVMe", "health": "Healthy",
                  "status": "OK", "size": 256060514304},
                 {"id": 1, "name": "WDC WD10EZEX", "media": "HDD", "bus": "SATA", "health": "Healthy", "status": "OK", "size": 10**12}],
       "volumes": [{"disk": 0, "letter": "C", "label": "", "size": 254900000000, "free": 63900000000},
                   {"disk": 1, "letter": "D", "label": "Data", "size": 10**12, "free": 5 * 10**10}],
       "memory": [{"slot": "DIMM A", "maker": "802C0000802C", "part": "8ATF2G64HZ-3G2E2", "size": 16 * 2**30, "speed": 3200, "type": 26}],
       "whea": [], "memdiag": [], "diskevents": []}


def test_collect_and_format():
    details = lambda i, bus: hw.parse_nvme_health(nvme_page()) if bus == "NVMe" else {}  # noqa: E731
    d = hw.collect(INV, details)
    nvme, hdd = d["disks"]
    assert nvme["kind"] == "M.2 NVMe SSD" and nvme["life_pct"] == 63 and nvme["volumes"][0]["used_pct"] == 75
    assert hdd["kind"] == "HDD" and hdd["life_pct"] is None and hdd["volumes"][0]["used_pct"] == 95
    assert d["ram"]["modules"][0] == {"slot": "DIMM A", "maker": "Micron", "part": "8ATF2G64HZ-3G2E2", "size_gb": 16, "speed": 3200, "type": "DDR4"}
    text = hw.format_pc(d)
    assert "სიცოცხლე **63%**" in text and "DDR4-3200 · Micron" in text and "ადმინის გარეშე არ მოგვცა" in text


def test_ram_errors():
    inv = dict(INV, whea=[{"id": 19, "text": "A corrected hardware error has occurred."}])
    assert hw.collect(inv, lambda i, b: {})["ram"]["status"] == "bad"
    inv = dict(INV, whea=[{"id": 1, "text": "PCI Express"}])
    assert hw.collect(inv, lambda i, b: {})["ram"]["status"] == "warn"
    inv = dict(INV, memdiag=[{"id": 1202}])
    assert "Memory Diagnostic" in " ".join(hw.collect(inv, lambda i, b: {})["ram"]["why"])


def test_history_and_forecast(tmp_path):
    st = StateStore(tmp_path / "s.json")
    start = datetime(2026, 11, 1)
    for i, (used, units) in enumerate([(37, 59726000), (37, 59900000), (38, 60100000)]):
        d = hw.collect(INV, lambda _i, bus, u=used, w=units: hw.parse_nvme_health(nvme_page(used=u, written_units=w)) if bus == "NVMe" else {})
        hist = hw.remember(st, d, start + timedelta(days=i * 5))
    key = "PC SN530 NVMe WDC 256GB#0"
    assert list(hist) == [key]  # the HDD without SMART details is not tracked
    fc = hw.forecast(hist, key)
    assert fc["days"] == 10 and fc["tb_per_day"] == 0.019 and fc["years_left"] == round(62 / 0.1 / 365, 1)
    assert hw.forecast({key: {"2026-11-01": {"used": 1}, "2026-11-03": {"used": 1}}}, key) == {"wait_days": 5}
    assert hw.forecast({}, key) == {}


@pytest.mark.skipif(not hw.IS_WINDOWS, reason="Windows only")
def test_real_machine_smoke():
    d = hw.collect()
    assert d["disks"] and d["ram"]["total_gb"] > 0
