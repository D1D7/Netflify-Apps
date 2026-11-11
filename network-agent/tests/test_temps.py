"""Temperatures: LibreHardwareMonitor JSON, SMART fallback, thresholds, levels, alerts."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace as NS

import pytest

from netagent.features import temps as tp
from netagent.state import StateStore


def sensor(text, value, sid):
    return {"Text": text, "Min": "", "Value": f"{value} °C", "Max": f"{value + 10} °C", "SensorId": sid, "Type": "Temperature",
            "ImageURL": "images/transparent.png", "Children": []}


LHM = {"Text": "Sensor", "Children": [{"Text": "DESKTOP-QOE49MP", "ImageURL": "images_icon/computer.png", "Children": [
    {"Text": "11th Gen Intel Core i5-1135G7", "ImageURL": "images_icon/cpu.png", "Children": [
        {"Text": "Temperatures", "ImageURL": "images_icon/temperature.png", "Children": [
            sensor("CPU Core #1", 52.0, "/intelcpu/0/temperature/0"), sensor("CPU Core #2", 55.5, "/intelcpu/0/temperature/1"),
            sensor("CPU Package", 58.0, "/intelcpu/0/temperature/4"), sensor("Core Max", 55.5, "/intelcpu/0/temperature/5"),
            sensor("CPU Core #1 Distance to TjMax", 48.0, "/intelcpu/0/temperature/6")]},
        {"Text": "Load", "ImageURL": "images_icon/load.png", "Children": [
            {"Text": "CPU Total", "Value": "12.5 %", "SensorId": "/intelcpu/0/load/0", "Type": "Load", "Children": []}]}]},
    {"Text": "NVIDIA GeForce RTX 3060", "ImageURL": "images_icon/nvidia.png", "Children": [
        {"Text": "Temperatures", "Children": [sensor("GPU Core", 61.0, "/gpu-nvidia/0/temperature/0"),
                                              sensor("GPU Hot Spot", 70.0, "/gpu-nvidia/0/temperature/2")]}]},
    {"Text": "WD PC SN530", "ImageURL": "images_icon/hdd.png", "Children": [
        {"Text": "Temperatures", "Children": [sensor("Composite Temperature", 36.0, "/nvme/0/temperature/0"),
                                              sensor("Warning Temperature", 82.0, "/nvme/0/temperature/1"),
                                              sensor("Critical Temperature", 84.0, "/nvme/0/temperature/2")]}]}]}]}


def test_parse_lhm():
    s = tp.parse_lhm(LHM)
    kinds = {(x["kind"], x["name"]) for x in s}
    assert ("cpu", "CPU Package") in kinds and ("gpu", "GPU Core") in kinds and ("disk", "Composite Temperature") in kinds
    assert all(x["name"] != "CPU Total" for x in s)  # load is not a temperature
    names = {x["name"] for x in s}
    assert not names & {"Warning Temperature", "Critical Temperature", "Core Max", "CPU Core #1 Distance to TjMax"}
    assert tp.summarize(s) == {"cpu": 58.0, "gpu": 61.0, "disk": 36.0}
    assert next(x for x in s if x["name"] == "CPU Package")["max"] == 68.0


def test_sampler_sources():
    smp = tp.TempSampler(lhm=lambda: tp.parse_lhm(LHM), disks=lambda: [], zone=lambda: [])
    r = smp.sample()
    assert r["sources"] == ["LibreHardwareMonitor"] and r["summary"]["cpu"] == 58.0
    smp = tp.TempSampler(lhm=lambda: None, disks=lambda: [{"kind": "disk", "hw": "SN530", "name": "SMART", "value": 36.0, "max": None}],
                         zone=lambda: [])
    r = smp.sample()
    assert r["sources"] == ["SMART"] and r["summary"] == {"cpu": None, "gpu": None, "disk": 36.0}
    assert smp.snapshot()["history"][-1][1:] == (None, None, 36.0)


def test_levels_and_thresholds(tmp_path):
    st = StateStore(tmp_path / "s.json")
    th = tp.thresholds(st)
    assert th["cpu"] == [75, 90]
    assert tp.level("cpu", 60, th) == "green" and tp.level("cpu", 80, th) == "yellow" and tp.level("cpu", 95, th) == "red"
    assert tp.level("cpu", None, th) == ""
    assert tp.set_thresholds(st, {"cpu": [70, 85], "bogus": [1, 2]})["cpu"] == [70, 85]
    with pytest.raises(Exception):
        tp.set_thresholds(st, {"cpu": [90, 80]})
    with pytest.raises(Exception):
        tp.set_thresholds(st, {"disk": ["x"]})


def test_report_without_cpu_explains(tmp_path, monkeypatch):
    st = StateStore(tmp_path / "s.json")
    smp = tp.TempSampler(lhm=lambda: None, disks=lambda: [], zone=lambda: [])
    smp.sample()
    monkeypatch.setattr(tp, "SAMPLER", smp)
    r = tp.report(st)
    assert "LibreHardwareMonitor" in r["message"] and r["levels"]["cpu"] == ""
    text = tp.format_temps(r)
    assert "CPU: — (სენსორი მიუწვდომელია)" in text and "0°C" not in text


def test_overheat_alert_once(tmp_path, monkeypatch):
    st = StateStore(tmp_path / "s.json")
    hot = [{"kind": "cpu", "hw": "x", "name": "CPU Package", "value": 97.0, "max": None}]
    smp = tp.TempSampler(lhm=lambda: hot, disks=lambda: [], zone=lambda: [])
    smp.sample()
    monkeypatch.setattr(tp, "SAMPLER", smp)
    alerts = []

    async def emit(a):
        alerts.append(a)

    (_, _, _, check), = tp.jobs(NS(s=NS(state=st), emit=emit))
    for _ in range(4):
        asyncio.run(check())
    assert len(alerts) == 1 and "97°C" in alerts[0].text  # once, after two red checks in a row
