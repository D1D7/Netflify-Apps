"""NetAgent itself: update from GitHub, backup of its own data, version.

Restart = the process exits with code 75; whatever started it brings it back:
autostart (netagent-background.vbs), start.bat (loops on 75), Docker/systemd (restart policy).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import zipfile
from datetime import datetime
from pathlib import Path

from ..config import PROJECT_ROOT, settings
from ..result import Button, CommandError, Result

log = logging.getLogger("netagent.selfmgmt")
RESTART_CODE = 75
SERVER_RUNNING = False  # set by server.amain; restart only makes sense for the server


def git(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(PROJECT_ROOT), *args], capture_output=True, text=True,
                          timeout=timeout, errors="replace")


def in_git() -> bool:
    try:
        return git("rev-parse", "--is-inside-work-tree").stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def version() -> dict:
    info = {"python": sys.version.split()[0]}
    if in_git():
        info["commit"] = git("rev-parse", "--short", "HEAD").stdout.strip()
        info["date"] = git("log", "-1", "--format=%cd", "--date=format:%Y-%m-%d %H:%M").stdout.strip()
        info["branch"] = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    return info


def pending_updates() -> list[str]:
    f = git("fetch", "--quiet", timeout=90)
    if f.returncode != 0:
        raise CommandError("GitHub-თან კავშირი ვერ მოხერხდა: " + (f.stderr.strip().splitlines() or ["?"])[-1][:200])
    up = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if up.returncode != 0:
        raise CommandError("ამ branch-ს GitHub-ზე წყვილი (upstream) არ აქვს")
    log_out = git("log", "--format=%s", "HEAD..@{u}", "-n", "15").stdout.strip()
    return [x for x in log_out.splitlines() if x]


def _schedule_restart(delay: float = 2.0) -> None:
    def go():
        log.warning("restarting after update (exit %s)", RESTART_CODE)
        logging.shutdown()
        os._exit(RESTART_CODE)

    threading.Timer(delay, go).start()


def update_cmd(s, args, user) -> Result:
    if not in_git():
        raise CommandError("NetAgent git-ით არ არის დაყენებული — განახლება ავტომატურად ვერ მოხერხდება. "
                           "ჩამოტვირთე ახალი ვერსია GitHub-იდან (.env, inventory და data დატოვე).")
    if not args or args[0].lower() != "now":
        v = version()
        commits = pending_updates()
        head = f"ℹ️ ვერსია: `{v.get('commit')}` ({v.get('date')}, {v.get('branch')})"
        if not commits:
            return Result(head + "\n✅ უახლესი ვერსია გაქვს.")
        lines = [head, f"⬆️ **ხელმისაწვდომია {len(commits)} განახლება:**"] + [f"• {c[:100]}" for c in commits[:10]]
        return Result("\n".join(lines), buttons=[Button("⬆️ განახლება და გადატვირთვა", "/update now")])
    dirty = git("status", "--porcelain", "--untracked-files=no").stdout.strip()
    if dirty:
        raise CommandError("კოდში ლოკალური ცვლილებებია, ავტომატური განახლება შეჩერდა:\n" + dirty[:400])
    old = git("rev-parse", "HEAD").stdout.strip()
    pull = git("pull", "--ff-only", timeout=180)
    if pull.returncode != 0:
        raise CommandError("git pull ვერ შესრულდა: " + pull.stderr.strip()[-300:])
    new = git("rev-parse", "HEAD").stdout.strip()
    if old == new:
        return Result("✅ უკვე უახლესი ვერსიაა.")
    changed = git("diff", "--name-only", old, new).stdout.split()
    notes = []
    if any(c.endswith("requirements.txt") for c in changed):
        pip = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", str(PROJECT_ROOT / "requirements.txt")],
                             capture_output=True, text=True, timeout=900, errors="replace")
        notes.append("📦 ბიბლიოთეკები განახლდა" if pip.returncode == 0 else "⚠️ pip install ვერ შესრულდა — გაუშვი install.bat")
    log_event_text = f"✅ განახლდა: {old[:7]} → {new[:7]} ({len(changed)} ფაილი)"
    if SERVER_RUNNING:
        _schedule_restart()
        notes.append("🔄 NetAgent გადაიტვირთება ~20 წამში — მერე გვერდი განაახლე")
    else:
        notes.append("🔄 გადატვირთე NetAgent, რომ ახალი ვერსია ჩაირთოს")
    return Result("\n".join([log_event_text, *notes]))


def backup_paths() -> list[tuple[Path, str]]:
    """(file, name in zip). .env is never included: it holds the API keys and passwords."""
    out = []
    skip_dirs = {"demo", "__pycache__", ".git"}
    for base, prefix in ((settings.data_dir, "data"), (settings.backup_dir, "backups")):
        if base.exists():
            for p in base.rglob("*"):
                rel = p.relative_to(base)
                if p.is_file() and not (set(rel.parts) & skip_dirs) and p.name not in {"oui.txt", "remotes.json"}:
                    out.append((p, f"{prefix}/{rel.as_posix()}"))
    if settings.inventory_path.exists():
        out.append((settings.inventory_path, "inventory/devices.yaml"))
    return out


def make_backup(dest_dir: Path | None = None) -> Path:
    dest_dir = dest_dir or settings.export_dir
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"netagent-backup-{datetime.now():%Y%m%d-%H%M%S}.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for f, name in backup_paths():
            try:
                if f.name == "web_auth.json":
                    # the session signing key would let anyone holding the ZIP forge a login: leave it out
                    # (a new one is created on restore; everyone just logs in again)
                    import json

                    data = json.loads(f.read_text(encoding="utf-8"))
                    data.pop("session_key", None)
                    z.writestr(name, json.dumps(data, indent=1))
                    continue
                z.write(f, name)
            except (OSError, ValueError):
                pass
        z.writestr("README.txt", "NetAgent backup. Restore: unzip into the NetAgent folder (stop NetAgent first).\n"
                                 ".env is NOT included - keep your API keys separately.\n")
    return path


def selfbackup_cmd(s, args, user) -> Result:
    path = make_backup()
    size = path.stat().st_size / 1e6
    return Result(f"💾 **NetAgent-ის backup** ({size:.1f} MB): შენიშვნები, ისტორია, ალერტები, პარამეტრები, "
                  "inventory და config backup-ები.\n⚠️ შეიცავს აპის პაროლის hash-ს, 2FA გასაღებს და მოწყობილობების config-ებს — "
                  "შეინახე უსაფრთხო ადგილას. `.env` (API key-ები) **არ** არის შიგნით.", files=[path])


def version_cmd(s, args, user) -> Result:
    v = version()
    return Result(f"ℹ️ NetAgent `{v.get('commit', '—')}` {v.get('date', '')} · Python {v['python']} · მოდელი {settings.model}",
                  buttons=[Button("⬆️ განახლების შემოწმება", "/update")] if "commit" in v else [])


COMMANDS = {"update": update_cmd, "selfbackup": selfbackup_cmd, "version": version_cmd}
HELP = ["/update — NetAgent-ის განახლება GitHub-იდან · /version · /selfbackup — NetAgent-ის მონაცემების backup"]
BOT_COMMANDS = [("update", "NetAgent-ის განახლება")]
