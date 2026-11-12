"""Config backups versioned with git: backups/_history/ is a git repository with one file per
device (R1.cfg), overwritten and committed on every changed backup. `/history R1` then shows
real line-by-line changes over time, and the folder can be pushed to a private remote. Off with NETAGENT_BACKUP_GIT=off.
Secrets are already masked before backups are written.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path

from ..config import settings
from ..result import Button, CommandError, Result
from ..osutil import NO_WINDOW

log = logging.getLogger("netagent.gitbackup")
_LOCK = threading.Lock()  # backups run in parallel threads; git allows one writer at a time


def enabled() -> bool:
    return os.getenv("NETAGENT_BACKUP_GIT", "on").lower() not in {"off", "0", "false", "no"} and bool(shutil.which("git"))


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_AUTHOR_NAME": "NetAgent", "GIT_AUTHOR_EMAIL": "netagent@localhost",
           "GIT_COMMITTER_NAME": "NetAgent", "GIT_COMMITTER_EMAIL": "netagent@localhost"}
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=60,
                          errors="replace", env=env, creationflags=NO_WINDOW)


def ensure_repo(root: Path) -> bool:
    if (root / ".git").exists():
        return True
    root.mkdir(parents=True, exist_ok=True)
    if _git(root, "init", "-q").returncode != 0:
        return False
    (root / ".gitattributes").write_text("*.cfg text eol=lf\n", encoding="utf-8")
    return True


REPO = "_history"


def _file(device: str) -> str:
    import re

    return re.sub(r"[^\w.-]", "_", device) + ".cfg"


def commit(root: Path, path: Path, device: str) -> None:
    """Commit one new backup. Never raises: backups must not fail because of git."""
    if not enabled():
        return
    try:
        with _LOCK:
            repo = root / REPO
            if not ensure_repo(repo):
                return
            (repo / _file(device)).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            _git(repo, "add", "--", _file(device), ".gitattributes")
            r = _git(repo, "commit", "-q", "-m", f"{device}: {path.stem}")
        if r.returncode != 0 and "nothing to commit" not in r.stdout + r.stderr:
            log.warning("git commit failed: %s", r.stderr.strip()[:200])
    except Exception:  # noqa: BLE001
        log.exception("git backup failed")


def history(device: str, limit: int = 15) -> list[dict]:
    import re

    repo = settings.backup_dir / REPO
    if not (repo / ".git").exists():
        return []
    r = _git(repo, "log", f"-n{limit}", "--format=%h|%cd|%s", "--date=format:%Y-%m-%d %H:%M", "--shortstat", "--", _file(device))
    out, cur = [], None
    for line in r.stdout.splitlines():
        if "|" in line:
            h, date, msg = line.split("|", 2)
            cur = {"commit": h, "date": date, "message": msg, "added": 0, "removed": 0}
            out.append(cur)
        elif cur and "changed" in line:
            a = re.search(r"(\d+) insertion", line)
            d = re.search(r"(\d+) deletion", line)
            cur["added"], cur["removed"] = int(a.group(1)) if a else 0, int(d.group(1)) if d else 0
    return out


def show_change(device: str, n: int) -> str:
    items = history(device, 50)
    if not 1 <= n <= len(items):
        raise CommandError(f"ცვლილება #{n} არ არსებობს (სულ {len(items)})")
    h = items[n - 1]["commit"]
    r = _git(settings.backup_dir / REPO, "show", "--format=", "--unified=1", h, "--", _file(device))
    diff = [ln for ln in r.stdout.splitlines() if ln[:1] in "+-" and not ln.startswith(("+++", "---"))]
    return "\n".join(diff[:60]) + (f"\n... (+{len(diff) - 60})" if len(diff) > 60 else "")


def history_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /history R1 · /history R1 2 (მე-2 ცვლილების diff)")
    name = s.inventory().get(args[0]).name
    if len(args) > 1:
        try:
            n = int(args[1])
        except ValueError:
            raise CommandError("ნომერი უნდა იყოს რიცხვი") from None
        return Result(f"📝 **{name}** — ცვლილება #{n}\n```diff\n{show_change(name, n) or '(ცვლილება ცარიელია)'}\n```")
    items = history(name)
    if not items:
        return Result(f"📝 {name}: ისტორია ჯერ არ არის — ჩაიწერება შემდეგი backup-იდან (/backup)")
    lines = [f"📝 **{name}** — config-ის ისტორია (git)"]
    lines += [f"{i}. {x['date']} · +{x['added']} / −{x['removed']}" for i, x in enumerate(items, 1)]
    return Result("\n".join(lines), buttons=[Button(f"#{i}", f"/history {name} {i}") for i in range(1, min(len(items), 5) + 1)])


COMMANDS = {"history": history_cmd}
HELP = ["/history R1 — config-ის ცვლილებების ისტორია (git) · /history R1 2 — diff"]
