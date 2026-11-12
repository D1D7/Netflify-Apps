"""OS helpers shared by the whole app.

atomic_write   write a file via a unique temp file + os.replace, retrying while Windows has the
               target briefly locked (antivirus, indexer, a reader in another process)
make_private   owner-only file: chmod 0600 on Linux/macOS; on Windows the same effect needs an ACL
               (chmod there only toggles "read-only"), so inheritance is cut and only the current
               user and SYSTEM keep access
is_private     check the above (POSIX mode bits / Windows ACL read as SDDL, so it is language-independent)
NO_WINDOW      creationflags for subprocess: without it every `ping`/`arp`/`route` started by the
               windowless background server (pythonw.exe) pops up a console window
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from functools import lru_cache
from pathlib import Path

log = logging.getLogger("netagent.osutil")

IS_WINDOWS = os.name == "nt"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SYSTEM_SID = "S-1-5-18"


def atomic_write(path: Path, data: str | bytes, private: bool = False, retries: int = 10) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")  # unique per process/thread
    try:
        if isinstance(data, bytes):
            tmp.write_bytes(data)
        else:
            tmp.write_text(data, encoding="utf-8")
        if private:
            make_private(tmp)
        for attempt in range(retries):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == retries - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


@lru_cache(maxsize=1)
def current_user_sid() -> str:
    """SID of the user running NetAgent ("S-1-5-21-..."), via `whoami /user` (no extra libraries)."""
    try:
        out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=15,
                             creationflags=NO_WINDOW, errors="replace").stdout
        m = re.search(r'"(S-1-[\d-]+)"', out)
        if m:
            return m.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def make_private(path: Path) -> bool:
    """Only the owner may read/write the file. Returns False (and logs) if that could not be done."""
    path = Path(path)
    if not IS_WINDOWS:
        os.chmod(path, 0o600)
        return True
    sid = current_user_sid()
    principal = f"*{sid}" if sid else f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".lstrip("\\")
    try:
        r = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{principal}:F", f"*{SYSTEM_SID}:F"],
                           capture_output=True, text=True, timeout=15, creationflags=NO_WINDOW, errors="replace")
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("could not restrict %s: %s", path.name, exc)
        return False
    if r.returncode != 0:
        log.warning("could not restrict %s: %s", path.name, (r.stdout + r.stderr).strip()[:200])
        return False
    return True


def acl_sids(path: Path) -> tuple[bool, set[str]]:
    """Windows: (protected from inheritance?, SIDs that have an ACE). Read as SDDL via `icacls /save`."""
    path = Path(path)
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "acl.txt"
        subprocess.run(["icacls", path.name, "/save", str(out)], cwd=str(path.parent), capture_output=True,
                       timeout=15, creationflags=NO_WINDOW)
        raw = out.read_bytes() if out.exists() else b""
    text = raw.decode("utf-16-le", errors="replace") if raw[:2] != b"\xef\xbb" else raw.decode("utf-8", errors="replace")
    sddl = next((line for line in text.splitlines() if line.startswith("D:")), "")
    dacl = sddl.split("S:")[0]
    aliases = {"SY": SYSTEM_SID, "BA": "S-1-5-32-544", "BU": "S-1-5-32-545", "WD": "S-1-1-0", "AU": "S-1-5-11",
               "OW": "OWNER", "CO": "CREATOR"}
    sids = {aliases.get(ace.split(";")[-1], ace.split(";")[-1]) for ace in re.findall(r"\(([^)]*)\)", dacl)}
    return dacl.startswith("D:P"), sids


def is_private(path: Path) -> bool:
    path = Path(path)
    if not IS_WINDOWS:
        return path.stat().st_mode & 0o077 == 0
    protected, sids = acl_sids(path)
    allowed = {SYSTEM_SID, current_user_sid()}
    return protected and bool(sids) and sids <= allowed
