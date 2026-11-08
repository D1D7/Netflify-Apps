"""In-depth RAM test inside Windows (no reboot): write known patterns into as much free memory as possible,
read every word back, report any bit that did not keep its value.

Runs as its own low-priority process (python -m netagent.features.memtest ...) and writes its progress to
data/memtest.json, which the app shows live. The tested memory is locked in RAM where Windows allows it
(VirtualLock), so the test reads real memory chips, not the page file.

Patterns per pass (the usual memtest set):
  solid 0/1, checkerboard 0x55/0xAA, walking ones (bits 0..63), own address (catches address-line faults),
  inverted address, random (seeded, regenerated for checking), moving inversions up and down.
Limit: Windows and the running programs keep their memory, so only the free part is tested ("coverage").
Testing 100 % needs a reboot: Windows Memory Diagnostic (mdsched) or MemTest86 from a USB stick.

  /memtest            status / last result
  /memtest quick      1 pass   · /memtest full   10 passes · /memtest stop
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from ..result import Button, CommandError, Result

CHUNK = 32 * 1024 * 1024 // 8           # 32 MB of uint64 per step: progress, cancel, small temporaries
MASK = 0xFFFFFFFFFFFFFFFF
MODES = {"quick": 1, "full": 10}


def status_path(root: Path | None = None) -> Path:
    from ..config import settings

    return (root or settings.data_dir) / "memtest.json"


def plan_mb(total: int, available: int, reserve_mb: int = 1024) -> int:
    """How much to test: what is free minus a reserve for Windows (6 %, at least 1 GB), at most 80 % of RAM, at least 64 MB."""
    mb = (available >> 20) - max(reserve_mb, (total >> 20) * 6 // 100)
    return max(64, min(mb, int((total >> 20) * 0.8)))


def lock_memory(arr) -> bool:
    """Keep the buffer in RAM (no paging) where Windows allows it."""
    if os.name != "nt":
        return False
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    size = arr.nbytes
    proc = k32.GetCurrentProcess()
    k32.SetProcessWorkingSetSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]
    k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    if not k32.SetProcessWorkingSetSize(proc, size + (96 << 20), size + (256 << 20)):
        return False
    return bool(k32.VirtualLock(arr.ctypes.data, size))


# =========================================================================================================
class Tester:
    def __init__(self, mb: int, passes: int, out: Path | None = None, stop_file: Path | None = None, clock=time.monotonic):
        import numpy as np

        self.np = np
        self.mb, self.passes, self.out, self.stop_file, self.clock = mb, passes, out, stop_file, clock
        self.errors: list[dict] = []
        self.error_count = 0
        self.bad_bits = 0
        self.done_steps = 0
        self.total_steps = 0
        self.state = {"status": "starting", "mb": mb, "passes": passes, "started": datetime.now().isoformat(timespec="seconds")}
        self.t0 = clock()
        self.last_write = 0.0

    # -- bookkeeping ----------------------------------------------------------------------------------
    def save(self, force: bool = False, **kw) -> None:
        self.state.update(kw)
        now = self.clock()
        if not self.out or (not force and now - self.last_write < 0.5):
            return
        self.last_write = now
        self.state.update(errors=self.error_count, bad_bits=self.bad_bits, first_errors=self.errors[:20],
                          progress=round(100 * self.done_steps / max(self.total_steps, 1), 1),
                          elapsed_s=round(now - self.t0))
        from ..osutil import atomic_write

        atomic_write(self.out, json.dumps(self.state, ensure_ascii=False))

    def cancelled(self) -> bool:
        return bool(self.stop_file and self.stop_file.exists())

    def check(self, chunk, start: int, expected, test: str) -> None:
        np = self.np
        bad = np.flatnonzero(chunk != expected)
        if not bad.size:
            return
        self.error_count += int(bad.size)
        exp = np.broadcast_to(np.asarray(expected, dtype=np.uint64), chunk.shape)
        diff = chunk[bad] ^ exp[bad]
        self.bad_bits |= int(np.bitwise_or.reduce(diff))
        for i in bad[:20 - len(self.errors)] if len(self.errors) < 20 else []:
            self.errors.append({"test": test, "offset_mb": round((start + int(i)) * 8 / 2**20, 2),
                                "expected": f"{int(exp[i]):016x}", "got": f"{int(chunk[i]):016x}"})

    # -- the patterns ----------------------------------------------------------------------------------
    def chunks(self, n: int, reverse: bool = False):
        starts = range(0, n, CHUNK)
        return reversed(starts) if reverse else starts

    def fill_verify(self, buf, name: str, value_fn) -> None:
        """Write the whole buffer first, then read it all back (so every word sits in RAM for a while)."""
        n = buf.size
        for s in self.chunks(n):
            buf[s:s + CHUNK] = value_fn(s, min(CHUNK, n - s))
            self.step(name)
        for s in self.chunks(n):
            self.check(buf[s:s + CHUNK], s, value_fn(s, min(CHUNK, n - s)), name)
            self.step(name)

    def moving_inversions(self, buf, p: int) -> None:
        np = self.np
        n, q = buf.size, ~np.uint64(p)
        buf.fill(np.uint64(p))
        for s in self.chunks(n):
            c = buf[s:s + CHUNK]
            self.check(c, s, np.uint64(p), "moving inversions ↑")
            c[:] = q
            self.step("moving inversions ↑")
        for s in self.chunks(n, reverse=True):
            c = buf[s:s + CHUNK]
            self.check(c, s, q, "moving inversions ↓")
            c[:] = np.uint64(p)
            self.step("moving inversions ↓")

    def tests(self):
        np = self.np
        const = lambda v: (lambda s, k: np.uint64(v))  # noqa: E731
        walking = [1 << b for b in (0, 7, 15, 23, 31, 39, 47, 55, 63)]
        seed = int(time.time())
        out = [("0x00…", const(0)), ("0xFF…", const(MASK)), ("0x55…", const(0x5555555555555555)),
               ("0xAA…", const(0xAAAAAAAAAAAAAAAA))]
        out += [(f"walking 1 · bit {b.bit_length() - 1}", const(b)) for b in walking]
        out += [("own address", lambda s, k: np.arange(s, s + k, dtype=np.uint64)),
                ("inverted address", lambda s, k: ~np.arange(s, s + k, dtype=np.uint64)),
                ("random", lambda s, k: np.random.default_rng((seed, s)).integers(0, MASK, size=k, dtype=np.uint64, endpoint=True))]
        return out

    def step(self, name: str) -> None:
        self.done_steps += 1
        if self.cancelled():
            raise KeyboardInterrupt
        self.save(test=name)

    # -- run -------------------------------------------------------------------------------------------
    def run(self) -> dict:
        np = self.np
        n = self.mb * 2**20 // 8
        try:
            buf = np.empty(n, dtype=np.uint64)
        except MemoryError:
            self.save(True, status="error", error=f"{self.mb} MB ვერ გამოიყო — მეხსიერება დაკავებულია")
            return self.state
        locked = False
        try:
            locked = lock_memory(buf)
        except Exception:  # noqa: BLE001
            pass
        per_chunk = -(-n // CHUNK)
        tests = self.tests()
        self.total_steps = self.passes * (len(tests) * 2 * per_chunk + 2 * 2 * per_chunk)
        self.save(True, status="running", locked=locked, test="")
        try:
            for p in range(1, self.passes + 1):
                self.save(True, current_pass=p)
                for name, fn in tests:
                    self.fill_verify(buf, name, fn)
                for pat in (0x0F0F0F0F0F0F0F0F, 0x3C3C3C3C3C3C3C3C):
                    self.moving_inversions(buf, pat)
            status = "failed" if self.error_count else "passed"
        except KeyboardInterrupt:
            status = "stopped"
        gbps = round(self.done_steps * CHUNK * 8 / 1e9 / max(self.clock() - self.t0, 0.001), 2)
        self.save(True, status=status, finished=datetime.now().isoformat(timespec="seconds"), speed_gbps=gbps)
        return self.state


# =========================================================================================================
# control from the server
# =========================================================================================================
def read_status(root: Path | None = None) -> dict:
    try:
        return json.loads(status_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _alive(pid: int) -> bool:
    try:
        import psutil

        return psutil.pid_exists(pid) and "python" in psutil.Process(pid).name().lower()
    except Exception:  # noqa: BLE001
        return False


def running(root: Path | None = None) -> bool:
    st = read_status(root)
    return st.get("status") in {"starting", "running"} and _alive(st.get("pid", 0))


def start(mode: str = "quick", root: Path | None = None, popen=subprocess.Popen) -> dict:
    import psutil

    if mode not in MODES:
        raise CommandError("რეჟიმი: quick (1 გავლა) ან full (10 გავლა)")
    if running(root):
        raise CommandError("RAM-ის ტესტი უკვე მიმდინარეობს")
    vm = psutil.virtual_memory()
    mb = plan_mb(vm.total, vm.available)
    if (vm.available >> 20) < 600:
        raise CommandError(f"თავისუფალი მეხსიერება ძალიან ცოტაა ({vm.available >> 20} MB) — დახურე რამდენიმე პროგრამა და სცადე თავიდან.")
    path = status_path(root)
    stop = path.with_suffix(".stop")
    stop.unlink(missing_ok=True)
    from ..osutil import NO_WINDOW, atomic_write

    flags = NO_WINDOW | (0x00004000 if os.name == "nt" else 0)  # BELOW_NORMAL_PRIORITY_CLASS
    proc = popen([sys.executable, "-m", "netagent.features.memtest", "--mb", str(mb), "--passes", str(MODES[mode]),
                  "--out", str(path)], creationflags=flags, cwd=str(Path(__file__).resolve().parents[2]))
    st = {"status": "starting", "pid": proc.pid, "mb": mb, "passes": MODES[mode], "mode": mode,
          "total_mb": vm.total >> 20, "coverage_pct": round(100 * mb / (vm.total >> 20)),
          "started": datetime.now().isoformat(timespec="seconds")}
    atomic_write(path, json.dumps(st))
    return st


def stop(root: Path | None = None) -> bool:
    path = status_path(root)
    if not running(root):
        return False
    path.with_suffix(".stop").write_text("stop", encoding="utf-8")
    return True


def schedule_windows_diagnostic(shell=None) -> bool:
    """Open Windows Memory Diagnostic on the PC (it asks for admin with a UAC prompt and offers to reboot now)."""
    if os.name != "nt":
        raise CommandError("Windows Memory Diagnostic მხოლოდ Windows-ზეა")
    import ctypes

    shell = shell or ctypes.windll.shell32.ShellExecuteW
    rc = shell(None, "runas", "mdsched.exe", None, None, 1)
    return int(rc) > 32


# =========================================================================================================
def describe(st: dict) -> str:
    if not st:
        return ("🧠 **RAM-ის სიღრმისეული ტესტი** ჯერ არ გაშვებულა.\n`/memtest quick` — 1 გავლა (რამდენიმე წუთი) · "
                "`/memtest full` — 10 გავლა. ტესტი ამოწმებს თავისუფალ მეხსიერებას; 100%-ისთვის — გადატვირთვით (PC ჩანართი).")
    cov = f"{st.get('mb', 0) / 1024:.1f} GB (RAM-ის ~{st.get('coverage_pct', '?')}%)"
    s = st.get("status")
    if s in {"starting", "running"}:
        return (f"🧠 RAM-ის ტესტი მიმდინარეობს: **{st.get('progress', 0)}%** · გავლა {st.get('current_pass', 1)}/{st.get('passes')} · "
                f"{st.get('test', '')} · ტესტდება {cov} · შეცდომა: {st.get('errors', 0)}")
    head = {"passed": "✅ **RAM-ის ტესტი გაიარა** — შეცდომა არ არის", "failed": f"🔴 **RAM-ში შეცდომებია: {st.get('errors')}**",
            "stopped": "⏹ RAM-ის ტესტი შეჩერდა", "error": f"⚠️ ტესტი ვერ დაიწყო: {st.get('error', '')}"}.get(s, f"სტატუსი: {s}")
    lines = [head, f"შემოწმდა {cov}, {st.get('passes')} გავლა, {st.get('elapsed_s', 0) // 60} წთ {st.get('elapsed_s', 0) % 60} წმ"
             + (" · მეხსიერება ჩაკეტილი იყო RAM-ში" if st.get("locked") else "")]
    if s == "failed":
        bits = [str(b) for b in range(64) if st.get("bad_bits", 0) >> b & 1]
        lines.append(f"არეული ბიტები: {', '.join(bits[:16])}" + ("…" if len(bits) > 16 else ""))
        for e in st.get("first_errors", [])[:5]:
            lines.append(f"• {e['test']}: {e['offset_mb']} MB-ზე ველოდი {e['expected']}, წავიკითხე {e['got']}")
        lines.append("🔧 RAM-ის მოდული სავარაუდოდ დაზიანებულია: გადაამოწმე Windows Memory Diagnostic-ით ან MemTest86-ით, "
                     "სცადე მოდულის ამოღება-ჩადება / სხვა სლოტი; თუ მეორდება — მოდული გამოსაცვლელია.")
    if st.get("coverage_pct", 100) < 60 and s in {"passed", "stopped"}:
        lines.append("ℹ️ შემოწმდა მხოლოდ თავისუფალი ნაწილი. მეტის შესამოწმებლად დახურე პროგრამები (ბრაუზერი) ან გაუშვი ტესტი გადატვირთვით.")
    return "\n".join(lines)


def memtest_cmd(s, args, user) -> Result:
    from ..permissions import DENIED, is_viewer

    sub = args[0].lower() if args else ""
    if sub in {"quick", "full", "stop", "reboot"} and is_viewer(user):
        raise CommandError(DENIED)
    if sub in MODES:
        st = start(sub)
        return Result(f"🧠 RAM-ის ტესტი დაიწყო: {st['mb'] / 1024:.1f} GB (~{st['coverage_pct']}%), {st['passes']} გავლა. "
                      "პროგრესი — PC ჩანართზე ან /memtest.", buttons=[Button("⏹ შეჩერება", "/memtest stop")])
    if sub == "stop":
        return Result("⏹ ვაჩერებ..." if stop() else "ტესტი არ მიმდინარეობს.")
    if sub == "reboot":
        ok = schedule_windows_diagnostic()
        return Result("🖥 კომპიუტერზე გაიხსნა Windows Memory Diagnostic — დაადასტურე (UAC) და აირჩიე „Restart now“. "
                      "შედეგს გადატვირთვის შემდეგ PC ჩანართზე ნახავ." if ok else "Windows Memory Diagnostic ვერ გაიხსნა (UAC უარყოფილია?).")
    return Result(describe(read_status()), buttons=[Button("⚡ სწრაფი ტესტი", "/memtest quick"), Button("🔬 სრული", "/memtest full")])


COMMANDS = {"memtest": memtest_cmd}
HELP = ["/memtest quick|full|stop — RAM-ის სიღრმისეული ტესტი Windows-ში (პატერნების ჩაწერა-წაკითხვა) · /memtest reboot — 100% ტესტი გადატვირთვით"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="NetAgent RAM test")
    ap.add_argument("--mb", type=int, required=True)
    ap.add_argument("--passes", type=int, default=1)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    prev = read_status(a.out.parent) if a.out.name == "memtest.json" else {}
    t = Tester(a.mb, a.passes, a.out, a.out.with_suffix(".stop"))
    t.state.update({k: prev[k] for k in ("mode", "total_mb", "coverage_pct", "pid") if k in prev})
    t.state["pid"] = os.getpid()
    st = t.run()
    return 0 if st["status"] in {"passed", "stopped"} else 1


if __name__ == "__main__":
    sys.exit(main())
