"""In-depth RAM test: patterns find flipped bits, progress/stop, start limits, the command."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace as NS

import numpy as np
import pytest

from netagent.features import memtest as mt


def test_plan_mb():
    gb = 2**30
    assert mt.plan_mb(16 * gb, 2 * gb) == 2048 - 1024  # at least 1 GB stays for Windows
    assert mt.plan_mb(64 * gb, 20 * gb) == 20480 - 3932  # 6 % of a big RAM
    assert mt.plan_mb(16 * gb, 15 * gb) == int(16384 * 0.8)  # never more than 80 % of RAM
    assert mt.plan_mb(4 * gb, 900 * 2**20) == 64  # a floor


def test_clean_run(tmp_path):
    out = tmp_path / "memtest.json"
    st = mt.Tester(4, 2, out, tmp_path / "memtest.stop").run()
    assert st["status"] == "passed" and st["errors"] == 0 and st["progress"] == 100.0
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["status"] == "passed" and saved["passes"] == 2 and "finished" in saved


class Flaky(mt.Tester):
    """A RAM chip whose bit 13 is stuck at 0 at one address."""

    def check(self, chunk, start, expected, test):
        if start == 0 and chunk.size > 1000:
            chunk[1000] &= ~np.uint64(1 << 13)
        super().check(chunk, start, expected, test)


def test_stuck_bit_is_found(tmp_path):
    st = Flaky(2, 1, tmp_path / "m.json").run()
    assert st["status"] == "failed" and st["errors"] > 0
    assert st["bad_bits"] == 1 << 13
    e = st["first_errors"][0]
    assert e["offset_mb"] == round(1000 * 8 / 2**20, 2) and int(e["expected"], 16) ^ int(e["got"], 16) == 1 << 13
    text = mt.describe(st)
    assert "RAM-ში შეცდომებია" in text and "არეული ბიტები: 13" in text and "MemTest86" in text


def test_stop_file(tmp_path):
    stop = tmp_path / "memtest.stop"
    stop.write_text("stop")
    st = mt.Tester(4, 3, tmp_path / "m.json", stop).run()
    assert st["status"] == "stopped" and st["progress"] < 5


def test_start_and_stop(tmp_path, monkeypatch):
    import psutil

    gb = 2**30
    monkeypatch.setattr(psutil, "virtual_memory", lambda: NS(total=16 * gb, available=3 * gb))
    calls = []
    st = mt.start_test("quick", tmp_path, popen=lambda args, **kw: calls.append((args, kw)) or NS(pid=4242))
    assert st["passes"] == 1 and st["mb"] == mt.plan_mb(16 * gb, 3 * gb) and st["coverage_pct"] == round(100 * st["mb"] / 16384)
    args, kw = calls[0]
    assert args[:3] == [sys.executable, "-m", "netagent.features.memtest"] and "--passes" in args
    assert mt.read_status(tmp_path)["pid"] == 4242
    monkeypatch.setattr(mt, "_alive", lambda pid: pid == 4242)
    with pytest.raises(Exception, match="უკვე მიმდინარეობს"):
        mt.start_test("full", tmp_path, popen=lambda *a, **k: NS(pid=1))
    assert mt.stop(tmp_path) and (tmp_path / "memtest.stop").exists()
    monkeypatch.setattr(mt, "_alive", lambda pid: False)
    assert not mt.stop(tmp_path)
    with pytest.raises(Exception):
        mt.start_test("forever", tmp_path)
    monkeypatch.setattr(psutil, "virtual_memory", lambda: NS(total=16 * gb, available=300 * 2**20))
    with pytest.raises(Exception, match="ძალიან ცოტაა"):
        mt.start_test("quick", tmp_path, popen=lambda *a, **k: NS(pid=1))


def test_command_permissions_and_status(tmp_path, monkeypatch):
    monkeypatch.setattr(mt, "read_status", lambda root=None: {})
    assert "ჯერ არ გაშვებულა" in mt.memtest_cmd(None, [], "app:admin").text
    with pytest.raises(Exception):
        mt.memtest_cmd(None, ["quick"], "view:gio")
    monkeypatch.setattr(mt, "read_status", lambda root=None: {"status": "passed", "mb": 2048, "passes": 10,
                                                              "coverage_pct": 13, "elapsed_s": 250, "locked": True})
    text = mt.memtest_cmd(None, [], "app:admin").text
    assert "გაიარა" in text and "4 წთ 10 წმ" in text and "თავისუფალი ნაწილი" in text


def test_windows_diagnostic_opens_elevated():
    seen = []
    if sys.platform != "win32":
        pytest.skip("Windows only")
    assert mt.schedule_windows_diagnostic(shell=lambda *a: seen.append(a) or 42)
    assert seen[0][1:3] == ("runas", "mdsched.exe")
    assert not mt.schedule_windows_diagnostic(shell=lambda *a: 5)  # UAC declined


def test_feature_start_hooks_are_plugin_hooks():
    """features.start() calls every module's start(services, monitoring): a helper must not use that name."""
    import inspect

    from netagent import features

    for m in features.modules():
        fn = getattr(m, "start", None)
        if fn is not None:
            assert inspect.iscoroutinefunction(fn) and list(inspect.signature(fn).parameters)[:2] == ["services", "monitoring"], m.__name__
