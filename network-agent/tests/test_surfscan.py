"""Disk surface scan: read-only reading, bad and slow sectors, the map, stop, UAC launch, history."""

from __future__ import annotations

import json
import os

import pytest

from netagent.features import surfscan as ss
from netagent.state import StateStore


class FakeDisk:
    """size bytes; sectors in `bad` cannot be read; reads touching `slow_at` take long."""

    def __init__(self, size=64 * 1024 * 1024, sector=512, bad=(), slow_at=(), clock=None):
        self.size, self.sector, self.bad, self.slow_at, self.clock = size, sector, set(bad), set(slow_at), clock
        self.reads = []

    def read(self, offset, length):
        self.reads.append((offset, length))
        if self.clock is not None:
            self.clock.t += 0.01 + (5.0 if any(offset <= x < offset + length for x in self.slow_at) else 0)
        first, last = offset // self.sector, (offset + length - 1) // self.sector
        if any(first <= b <= last for b in self.bad):
            raise OSError("read error 23")
        return b""

    def close(self):
        pass


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def test_clean_disk(tmp_path):
    out = tmp_path / "s.json"
    st = ss.Scanner(FakeDisk(), out, tmp_path / "s.stop", clock=Clock()).run()
    assert st["status"] == "ok" and st["progress"] == 100.0 and st["bad_count"] == 0
    saved = json.loads(out.read_text())
    assert saved["segments"] == "1" * ss.SEGMENTS and saved["finished"]


def test_bad_sectors_are_named(tmp_path):
    disk = FakeDisk(bad={100, 101, 50000})
    st = ss.Scanner(disk, tmp_path / "s.json", clock=Clock()).run()
    assert st["status"] == "bad" and st["bad_count"] == 3 and st["bad_sectors"] == [100, 101, 50000]
    assert "4" in st["segments"] and st["segments"][0] == "4"
    assert "ცუდი (წაუკითხავი) სექტორი" in ss.describe(st) and "backup" in ss.describe(st)


def test_slow_places(tmp_path):
    clock = Clock()
    disk = FakeDisk(size=256 * 1024 * 1024, slow_at={200 * 1024 * 1024}, clock=clock)
    st = ss.Scanner(disk, tmp_path / "s.json", clock=clock).run()
    assert st["status"] == "warn" and st["very_slow"] == 1 and "3" in st["segments"]


def test_stop(tmp_path):
    stop = tmp_path / "s.stop"
    stop.write_text("x")
    st = ss.Scanner(FakeDisk(), tmp_path / "s.json", stop, clock=Clock()).run()
    assert st["status"] == "stopped" and st["progress"] == 0


def test_file_reader_is_read_only(tmp_path):
    f = tmp_path / "disk.img"
    f.write_bytes(os.urandom(9 * 1024 * 1024))
    before = f.read_bytes()
    r = ss.FileReader(str(f))
    st = ss.Scanner(r, tmp_path / "s.json", clock=Clock()).run()
    r.close()
    assert st["status"] == "ok" and st["done"] == 9 * 1024 * 1024 and f.read_bytes() == before


def test_start_asks_uac_and_handles_decline(tmp_path):
    import time

    seen = []
    st = ss.start_scan(0, "დისკი 0", tmp_path, launch=lambda args: seen.append(args) or False)
    assert st["status"] == "waiting_uac"
    for _ in range(50):
        if ss.read_status(tmp_path).get("status") == "declined":
            break
        time.sleep(0.02)
    assert ss.read_status(tmp_path)["status"] == "declined"
    assert "-m netagent.features.surfscan --disk 0" in seen[0] and "--path" not in seen[0]
    assert "UAC არ დადასტურდა" in ss.describe(ss.read_status(tmp_path))


def test_history_once(tmp_path):
    st = StateStore(tmp_path / "state.json")
    done = {"status": "ok", "disk": 0, "finished": "2026-11-11T22:00:00", "bad_count": 0, "label": "დისკი 0"}
    ss.remember(st, done)
    ss.remember(st, done)
    ss.remember(st, {"status": "running", "disk": 0})
    assert len(st.get(ss.HISTORY_KEY)["0"]) == 1


def test_real_disk_without_admin_fails_cleanly():
    if os.name != "nt":
        pytest.skip("Windows only")
    from netagent.features.temps import is_admin

    if is_admin():
        pytest.skip("running as admin")
    with pytest.raises(PermissionError, match="ადმინის"):
        ss.DiskReader(0)


def test_chkdsk_drive_validation(tmp_path):
    with pytest.raises(Exception):
        ss.start_chkdsk("C; del", tmp_path, launch=lambda a: True)
    r = ss.start_chkdsk("c:", tmp_path, launch=lambda a: True)
    assert r["drive"] == "C"
