"""Disk surface scan: read every sector of a disk, find bad (unreadable) and slow sectors. READ-ONLY.

The disk is opened with GENERIC_READ only (no write access is ever requested) and read block by block
(4 MB, unbuffered). A block that cannot be read is re-read sector by sector to name the bad sectors (LBA).
Slow places are measured against the disk's own typical speed. The result is a 200-square map of the disk.

Reading a whole disk needs administrator rights on Windows, so the server (which runs without them) starts a
small helper with "Run as administrator": Windows shows one UAC prompt on the PC. The helper runs at low I/O
priority, writes its progress to data/surfscan.json and stops when data/surfscan.stop appears.

Also: `chkdsk C: /scan` (online file system check, no repair) the same way.

  /surfscan            status / last result      /surfscan start 0     scan disk 0
  /surfscan stop       stop                      /surfscan chkdsk C    chkdsk /scan of drive C
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

from ..result import Button, CommandError, Result

BLOCK = 4 * 1024 * 1024
SEGMENTS = 200
MAX_BAD = 200
HISTORY_KEY = "surfscan_history"
SEG_STATE = {0: "todo", 1: "ok", 2: "slow", 3: "very_slow", 4: "error"}


def status_path(root: Path | None = None) -> Path:
    from ..config import settings

    return (root or settings.data_dir) / "surfscan.json"


# =========================================================================================================
# readers
# =========================================================================================================
class FileReader:
    """Any file or device path through normal reads (tests, Linux block devices)."""

    def __init__(self, path: str, sector: int = 512):
        self.f = open(path, "rb", buffering=0)  # noqa: SIM115 - closed in close()
        self.f.seek(0, os.SEEK_END)
        self.size = self.f.tell()
        self.sector = sector

    def read(self, offset: int, length: int) -> bytes:
        self.f.seek(offset)
        data = self.f.read(length)
        if len(data) != length:
            raise OSError(f"short read at {offset}")
        return data

    def close(self) -> None:
        self.f.close()


class DiskReader:
    """\\\\.\\PhysicalDriveN, read-only, unbuffered (each read really goes to the disk)."""

    def __init__(self, disk: int):
        import ctypes
        from ctypes import wintypes

        self.ct, self.wt = ctypes, wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = wintypes.HANDLE
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                  wintypes.DWORD, wintypes.HANDLE]
        k.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                      wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k.VirtualAlloc.restype = ctypes.c_void_p
        k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
        self.k = k
        GENERIC_READ, SHARE_RW, OPEN_EXISTING, NO_BUFFERING = 0x80000000, 3, 3, 0x20000000
        self.h = k.CreateFileW(rf"\\.\PhysicalDrive{int(disk)}", GENERIC_READ, SHARE_RW, None, OPEN_EXISTING, NO_BUFFERING, None)
        if self.h in (None, wintypes.HANDLE(-1).value):
            raise PermissionError(f"PhysicalDrive{disk} ვერ გაიხსნა (ადმინის უფლება? შეცდომა {ctypes.get_last_error()})")
        buf = ctypes.create_string_buffer(256)
        got = wintypes.DWORD()
        if not k.DeviceIoControl(self.h, 0x000700A0, None, 0, buf, 256, ctypes.byref(got), None):  # DRIVE_GEOMETRY_EX
            raise OSError(f"დისკის ზომა ვერ წავიკითხე ({ctypes.get_last_error()})")
        self.sector = struct.unpack_from("<I", buf.raw, 20)[0] or 512   # DISK_GEOMETRY.BytesPerSector
        self.size = struct.unpack_from("<q", buf.raw, 24)[0]            # DiskSize
        self.buf = k.VirtualAlloc(None, BLOCK, 0x3000, 0x04)  # page aligned, as unbuffered reads require

    def read(self, offset: int, length: int) -> bytes:
        ct, wt = self.ct, self.wt

        class OVERLAPPED(ct.Structure):
            _fields_ = [("Internal", ct.c_void_p), ("InternalHigh", ct.c_void_p), ("Offset", wt.DWORD),
                        ("OffsetHigh", wt.DWORD), ("hEvent", wt.HANDLE)]

        ov = OVERLAPPED(None, None, offset & 0xFFFFFFFF, offset >> 32, None)
        got = wt.DWORD()
        if not self.k.ReadFile(self.h, self.buf, length, ct.byref(got), ct.byref(ov)) or got.value != length:
            raise OSError(f"read error {ct.get_last_error()} at {offset}")
        return b""  # the data itself is not needed

    def close(self) -> None:
        if self.buf:
            self.k.VirtualFree(self.buf, 0, 0x8000)
        self.k.CloseHandle(self.h)


# =========================================================================================================
class Scanner:
    def __init__(self, reader, out: Path | None = None, stop_file: Path | None = None, clock=time.monotonic, label: str = ""):
        self.r, self.out, self.stop_file, self.clock = reader, out, stop_file, clock
        self.segments = [0] * SEGMENTS
        self.bad: list[int] = []
        self.bad_count = 0
        self.slow = self.very_slow = 0
        self.times: list[float] = []
        self.state = {"status": "running", "label": label, "size": reader.size, "sector": reader.sector,
                      "started": datetime.now().isoformat(timespec="seconds"), "pid": os.getpid()}
        self.t0 = clock()
        self.last_write = 0.0

    def save(self, force: bool = False, done: int = 0, **kw) -> None:
        self.state.update(kw)
        now = self.clock()
        if not self.out or (not force and now - self.last_write < 0.5):
            return
        self.last_write = now
        el = max(now - self.t0, 0.001)
        speed = done / el
        self.state.update(done=done, progress=round(100 * done / max(self.r.size, 1), 2), speed_mbps=round(speed / 1e6, 1),
                          eta_s=round((self.r.size - done) / speed) if speed and done < self.r.size else 0,
                          elapsed_s=round(el), bad_sectors=self.bad[:MAX_BAD], bad_count=self.bad_count,
                          slow=self.slow, very_slow=self.very_slow, segments="".join(str(x) for x in self.segments))
        from ..osutil import atomic_write

        atomic_write(self.out, json.dumps(self.state))

    def mark(self, offset: int, level: int, length: int = 1) -> None:
        """Every map square this range touches gets at least this level."""
        size = max(self.r.size, 1)
        first = min(SEGMENTS - 1, offset * SEGMENTS // size)
        last = min(SEGMENTS - 1, (offset + max(length, 1) - 1) * SEGMENTS // size)
        for i in range(first, last + 1):
            self.segments[i] = max(self.segments[i], level)

    def limits(self) -> tuple[float, float]:
        """slow / very slow thresholds in seconds per block, from this disk's own typical speed."""
        if len(self.times) < 20:
            return 0.5, 2.0
        med = statistics.median(self.times[-500:])
        return max(10 * med, 0.15), max(40 * med, 0.8)

    def run(self) -> dict:
        size, sec = self.r.size, self.r.sector
        offset = 0
        try:
            while offset < size:
                if self.stop_file and self.stop_file.exists():
                    raise KeyboardInterrupt
                length = min(BLOCK, size - offset)
                length -= length % sec
                if length <= 0:
                    break
                t = self.clock()
                try:
                    self.r.read(offset, length)
                    dt = self.clock() - t
                    slow, very = self.limits()
                    self.times.append(dt)
                    level = 3 if dt > very else 2 if dt > slow else 1
                    self.slow += level == 2
                    self.very_slow += level == 3
                    self.mark(offset, level, length)
                except OSError:
                    self.find_bad(offset, length)
                offset += length
                self.save(done=offset)
                if self.bad_count > 10000:
                    self.save(True, done=offset, status="aborted", error="ძალიან ბევრი წაკითხვის შეცდომა — დისკი მძიმედ დაზიანებულია")
                    return self.state
            status = "bad" if self.bad_count else "warn" if self.very_slow else "ok"
        except KeyboardInterrupt:
            status = "stopped"
        self.save(True, done=offset, status=status, finished=datetime.now().isoformat(timespec="seconds"))
        return self.state

    def find_bad(self, offset: int, length: int) -> None:
        """Re-read the block sector by sector and remember the sectors that fail."""
        sec = self.r.sector
        for o in range(offset, offset + length, sec):
            try:
                self.r.read(o, sec)
            except OSError:
                self.bad_count += 1
                if len(self.bad) < MAX_BAD:
                    self.bad.append(o // sec)
                self.mark(o, 4)


# =========================================================================================================
# control from the server (no admin there)
# =========================================================================================================
def read_status(root: Path | None = None) -> dict:
    try:
        return json.loads(status_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _alive(pid) -> bool:
    try:
        import psutil

        return bool(pid) and psutil.pid_exists(int(pid))
    except Exception:  # noqa: BLE001
        return False


def running(root: Path | None = None) -> bool:
    st = read_status(root)
    if st.get("status") == "waiting_uac":
        return time.time() - st.get("asked", 0) < 120
    return st.get("status") == "running" and _alive(st.get("pid"))


def _python_w() -> str:
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    return str(w if w.exists() else exe)


def run_elevated(args: str, shell=None) -> bool:
    """ShellExecute "runas": Windows asks for admin (UAC) on the PC. Returns False when it was declined."""
    if os.name != "nt":
        raise CommandError("ზედაპირის სკანი ამ ვერსიაში მხოლოდ Windows-ზეა")
    import ctypes

    shell = shell or ctypes.windll.shell32.ShellExecuteW
    root = str(Path(__file__).resolve().parents[2])
    return int(shell(None, "runas", _python_w(), args, root, 0)) > 32


def start_scan(disk: int, label: str = "", root: Path | None = None, launch=run_elevated) -> dict:
    import threading

    from ..osutil import atomic_write

    if running(root):
        raise CommandError("სკანი უკვე მიმდინარეობს")
    path = status_path(root)
    path.with_suffix(".stop").unlink(missing_ok=True)
    st = {"status": "waiting_uac", "disk": int(disk), "label": label, "asked": time.time(),
          "started": datetime.now().isoformat(timespec="seconds")}
    atomic_write(path, json.dumps(st))
    args = f'-m netagent.features.surfscan --disk {int(disk)} --out "{path}" --label "{label.replace(chr(34), "")}"'

    def go():
        if not launch(args):
            atomic_write(path, json.dumps({**st, "status": "declined", "error": "UAC არ დადასტურდა"}))

    threading.Thread(target=go, daemon=True).start()  # ShellExecute waits for the UAC answer
    return st


def stop_scan(root: Path | None = None) -> bool:
    if not running(root):
        return False
    status_path(root).with_suffix(".stop").write_text("stop", encoding="utf-8")
    return True


def start_chkdsk(drive: str, root: Path | None = None, launch=run_elevated) -> dict:
    import re

    from ..config import settings

    d = drive.strip().rstrip(":\\").upper()
    if not re.fullmatch(r"[A-Z]", d):
        raise CommandError("მიუთითე დისკის ასო, მაგ. C")
    out = (root or settings.data_dir) / f"chkdsk-{d}.txt"
    out.unlink(missing_ok=True)
    ok = launch(f'-m netagent.features.surfscan --chkdsk {d} --out "{out}"')
    if not ok:
        raise CommandError("UAC არ დადასტურდა")
    return {"drive": d, "out": str(out)}


def chkdsk_result(drive: str, root: Path | None = None) -> str:
    from ..config import settings

    p = (root or settings.data_dir) / f"chkdsk-{drive.upper()}.txt"
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def remember(state, st: dict) -> None:
    """Keep finished scans per disk (once each)."""
    if st.get("status") not in {"ok", "warn", "bad", "stopped", "aborted"} or not st.get("finished"):
        return

    def fn(v):
        v = dict(v or {})
        key = str(st.get("disk", st.get("label", "?")))
        items = list(v.get(key) or [])
        if not any(x.get("finished") == st["finished"] for x in items):
            items.append({k: st.get(k) for k in ("finished", "status", "label", "bad_count", "slow", "very_slow",
                                                  "elapsed_s", "progress", "speed_mbps")})
        v[key] = items[-20:]
        return v

    state.update(HISTORY_KEY, fn)


# =========================================================================================================
def describe(st: dict) -> str:
    if not st:
        return "🔬 ზედაპირის სკანი ჯერ არ გაშვებულა. `/surfscan start 0` — დისკი 0 (PC ჩანართზე ჩანს ნომრები)."
    s = st.get("status")
    name = st.get("label") or f"დისკი {st.get('disk', '?')}"
    if s == "waiting_uac":
        return f"🔬 {name}: კომპიუტერზე Windows ითხოვს ადმინის დადასტურებას (UAC) — დააჭირე „Yes“."
    if s == "declined":
        return f"🔬 {name}: UAC არ დადასტურდა — სკანი არ დაწყებულა."
    if s == "running":
        return (f"🔬 {name}: **{st.get('progress', 0)}%** · {st.get('speed_mbps', 0)} MB/s · დარჩა ~{(st.get('eta_s') or 0) // 60} წთ · "
                f"ცუდი სექტორი: {st.get('bad_count', 0)} · ნელი ადგილი: {st.get('slow', 0) + st.get('very_slow', 0)}")
    head = {"ok": "✅ ცუდი და ნელი სექტორი არ არის", "warn": "🟠 ცუდი სექტორი არ არის, მაგრამ ძალიან ნელი ადგილები ჩანს",
            "bad": f"🔴 **{st.get('bad_count')} ცუდი (წაუკითხავი) სექტორი**", "stopped": "⏹ შეჩერდა",
            "aborted": f"🔴 შეწყდა: {st.get('error', '')}"}.get(s, s)
    lines = [f"🔬 **{name}** — {head}",
             f"წაკითხულია {st.get('progress', 0)}% · {st.get('speed_mbps', 0)} MB/s · {st.get('elapsed_s', 0) // 60} წთ"]
    if st.get("bad_sectors"):
        lines.append("ცუდი სექტორები (LBA): " + ", ".join(str(x) for x in st["bad_sectors"][:12]) + ("…" if st.get("bad_count", 0) > 12 else ""))
    if s == "bad":
        lines.append("🔧 დისკი იწყებს გაფუჭებას: **ახლავე გააკეთე მნიშვნელოვანი ფაილების backup** და დაგეგმე დისკის გამოცვლა.")
    elif st.get("very_slow"):
        lines.append(f"ძალიან ნელი ბლოკები: {st['very_slow']} — ხშირად სუსტი სექტორის პირველი ნიშანია; რამდენიმე კვირაში გაიმეორე.")
    return "\n".join(lines)


def surfscan_cmd(s, args, user) -> Result:
    from ..permissions import DENIED, is_viewer

    sub = args[0].lower() if args else ""
    if sub in {"start", "stop", "chkdsk"} and is_viewer(user):
        raise CommandError(DENIED)
    if sub == "start":
        disk = int(args[1]) if len(args) > 1 and args[1].isdigit() else 0
        start_scan(disk, f"დისკი {disk}")
        return Result(f"🔬 კომპიუტერზე Windows ადმინის დადასტურებას ითხოვს (UAC) — დააჭირე „Yes“, სკანი მაშინვე დაიწყება. "
                      "დისკი მხოლოდ იკითხება, არაფერი იწერება.", buttons=[Button("📊 სტატუსი", "/surfscan")])
    if sub == "stop":
        return Result("⏹ ვაჩერებ..." if stop_scan() else "სკანი არ მიმდინარეობს.")
    if sub == "chkdsk":
        r = start_chkdsk(args[1] if len(args) > 1 else "C")
        return Result(f"🧰 chkdsk {r['drive']}: /scan გაეშვა (UAC დადასტურების შემდეგ). შედეგი: /surfscan chkdskresult {r['drive']}")
    if sub == "chkdskresult":
        out = chkdsk_result(args[1] if len(args) > 1 else "C")
        return Result(f"```\n{out[-3000:]}\n```" if out else "შედეგი ჯერ არ არის (ან chkdsk ჯერ მუშაობს).")
    return Result(describe(read_status()), buttons=[Button("⏹ შეჩერება", "/surfscan stop")] if running() else [])


COMMANDS = {"surfscan": surfscan_cmd}
HELP = ["/surfscan start 0 — დისკის ზედაპირის სკანი (ყველა სექტორის წაკითხვა, მხოლოდ კითხვით; UAC) · /surfscan stop · "
        "/surfscan chkdsk C — chkdsk /scan"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="NetAgent read-only surface scan")
    ap.add_argument("--disk", type=int)
    ap.add_argument("--path")
    ap.add_argument("--chkdsk")
    ap.add_argument("--label", default="")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.chkdsk:
        import subprocess

        r = subprocess.run(["chkdsk", f"{a.chkdsk}:", "/scan"], capture_output=True, text=True, errors="replace",
                           creationflags=0x08000000)
        a.out.write_text((r.stdout or "") + (r.stderr or ""), encoding="utf-8")
        return r.returncode
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00100000)  # background I/O
        except Exception:  # noqa: BLE001
            pass
    try:
        reader = FileReader(a.path) if a.path else DiskReader(a.disk or 0)
    except OSError as exc:
        from ..osutil import atomic_write

        atomic_write(a.out, json.dumps({"status": "aborted", "disk": a.disk, "label": a.label, "error": str(exc),
                                        "finished": datetime.now().isoformat(timespec="seconds")}))
        return 1
    try:
        sc = Scanner(reader, a.out, a.out.with_suffix(".stop"), label=a.label)
        sc.state["disk"] = a.disk
        st = sc.run()
    finally:
        reader.close()
    return 0 if st["status"] in {"ok", "warn", "stopped"} else 2


if __name__ == "__main__":
    sys.exit(main())
