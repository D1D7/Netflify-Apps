"""PC menu: system information and the live sampler."""

from __future__ import annotations

import json

from netagent.features import sysinfo as si

STATIC = {"os": {"caption": "Microsoft Windows 11 Pro", "version": "10.0.26200", "build": "26200", "ubr": 9711,
                 "display": "25H2", "arch": "64-bit", "installed": "2026-09-29T10:00:00", "boot": "2026-11-04T01:00:00"},
          "computer": {"name": "DESKTOP-QOE49MP", "user": "DESKTOP-QOE49MP/NoisyBoy", "domain": "", "workgroup": "WORKGROUP"},
          "cpu": {"name": "11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz", "cores": 4, "threads": 8},
          "gpu": {"name": "Intel(R) Iris(R) Xe Graphics", "driver": "32.0.101.7088", "vram": 2147479552},
          "adapters": {"name": "Wi-Fi", "status": "Up", "mac": "0C-9A-3C-D1-1E-9C", "ipv4": "192.168.100.8/24",
                       "gateway": "192.168.100.1", "dns": "192.168.100.1", "dhcp": "Enabled", "virtual": False, "link": "144.4 Mbps"}}


def test_static_info_normalises_single_items(monkeypatch):
    monkeypatch.setattr(si, "IS_WINDOWS", True)
    d = si.static_info(run=lambda script: json.dumps(STATIC))
    assert d["cpu"][0]["threads"] == 8 and d["gpu"][0]["vram"] == 2147479552
    assert d["adapters"][0]["ipv4"] == ["192.168.100.8/24"] and d["adapters"][0]["dns"] == ["192.168.100.1"]
    assert d["os"]["pretty"] == "Windows 11 Pro 25H2 (build 26200.9711), 64-bit"


def test_info_and_format(monkeypatch):
    monkeypatch.setattr(si, "IS_WINDOWS", True)
    si._STATIC.clear()
    s = si.Sampler()
    monkeypatch.setattr(si, "SAMPLER", s)
    d = si.info(refresh=True, run=lambda script: json.dumps(STATIC))
    assert d["live"]["ram_total"] > 0 and 0 <= d["live"]["cpu"] <= 100 and len(d["live"]["cores"]) >= 1
    assert d["uptime_s"] > 0 and d["partitions"]
    text = si.format_info(d)
    assert "Windows 11 Pro 25H2" in text and "4 ბირთვი / 8 ნაკადი" in text and "192.168.100.8/24" in text and "gateway 192.168.100.1" in text


def test_static_failure_keeps_live(monkeypatch):
    monkeypatch.setattr(si, "IS_WINDOWS", True)
    si._STATIC.clear()
    monkeypatch.setattr(si, "SAMPLER", si.Sampler())

    def boom(script):
        raise OSError("powershell missing")

    d = si.info(refresh=True, run=boom)
    assert d["static_error"] and d["live"]["ram_total"] > 0


def test_history_is_bounded():
    s = si.Sampler()
    for _ in range(si.HISTORY + 20):
        s.sample()
    assert len(s.snapshot()["history"]) == si.HISTORY


def test_helpers():
    assert si.fmt_bytes(1536) == "1.5 KB" and si.fmt_bytes(None) == "—" and si.fmt_bytes(5) == "5 B"
    assert si.fmt_uptime(90061) == "1 დღე 1 სთ 1 წთ"
    assert si.pretty_os({"caption": "Microsoft Windows 10 Home", "build": "19045", "arch": "64-bit"}) == "Windows 10 Home (build 19045), 64-bit"


def test_pdh_gpu_counters_on_windows():
    import pytest

    if not si.IS_WINDOWS:
        pytest.skip("Windows only")
    p = si.Pdh()
    assert "gpu_pct" in p.handles
    import time

    time.sleep(1.1)
    assert isinstance(p.read(), dict)
