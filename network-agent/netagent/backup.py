"""Configuration backups and diffs.

Backups are stored as plain files: backups/<device>/<YYYYmmdd-HHMMSS>.cfg
A new file is written only when the configuration actually changed, so the
list of files for a device is its change history.

Secrets are masked before saving (the agent reads these files), so these
backups are for change tracking and documentation, not for a full restore.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .inventory import Device, Inventory
from .security import mask_secrets
from .tools import device as dev

_TS_FORMAT = "%Y%m%d-%H%M%S"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")

# Lines that change on every "show run" without a real config change.
_VOLATILE = [
    re.compile(r"^!\s*Last configuration change", re.I),
    re.compile(r"^!\s*NVRAM config last updated", re.I),
    re.compile(r"^!\s*Time:", re.I),
    re.compile(r"^Building configuration", re.I),
    re.compile(r"^Current configuration\s*:", re.I),
    re.compile(r"^\s*ntp clock-period", re.I),
    re.compile(r"^# \w{3}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} by RouterOS", re.I),  # MikroTik export header
    re.compile(r"^#\s*(?:\d{4}-\d{2}-\d{2}|\w{3}/\d{2}/\d{4}) .* by RouterOS", re.I),
    re.compile(r"^## Last commit:", re.I),  # Junos
    re.compile(r"^#config-version=", re.I),  # Fortinet
]


def normalize_config(text: str) -> str:
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    lines = [ln for ln in lines if not any(p.search(ln) for p in _VOLATILE)]
    while lines and not lines[-1]:
        lines.pop()
    while lines and not lines[0]:
        lines.pop(0)
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Snapshot:
    device: str
    path: Path
    taken_at: datetime

    def read(self) -> str:
        return self.path.read_text(encoding="utf-8")


class BackupStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _dir(self, device: str) -> Path:
        return self.root / _SAFE_NAME.sub("_", device)

    def snapshots(self, device: str) -> list[Snapshot]:
        d = self._dir(device)
        if not d.exists():
            return []
        out = []
        for p in sorted(d.glob("*.cfg")):
            try:
                ts = datetime.strptime(p.stem, _TS_FORMAT)
            except ValueError:
                continue
            out.append(Snapshot(device, p, ts))
        return out

    def latest(self, device: str) -> Snapshot | None:
        snaps = self.snapshots(device)
        return snaps[-1] if snaps else None

    def save(self, device: str, config: str, when: datetime | None = None) -> tuple[Snapshot | None, bool]:
        """Save if changed. Returns (latest snapshot, changed?)."""
        config = normalize_config(mask_secrets(config))
        last = self.latest(device)
        if last is not None and last.read() == config:
            return last, False
        when = when or datetime.now()
        d = self._dir(device)
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{when.strftime(_TS_FORMAT)}.cfg"
        path.write_text(config, encoding="utf-8")
        return Snapshot(device, path, when), True

    def snapshot_before(self, device: str, moment: datetime) -> Snapshot | None:
        """The newest snapshot taken at or before `moment`."""
        candidates = [s for s in self.snapshots(device) if s.taken_at <= moment]
        return candidates[-1] if candidates else None


def unified_diff(old: str, new: str, old_label: str, new_label: str, context: int = 2) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=old_label,
            tofile=new_label,
            n=context,
        )
    )


def diff_stats(diff: str) -> tuple[int, int]:
    added = sum(1 for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---"))
    return added, removed


def fetch_config(inventory: Inventory, device: Device) -> str:
    cmds = dev.commands_for(device, "running_config")
    if not cmds:
        raise ValueError(f"device_type '{device.device_type}'-ისთვის config-ის ბრძანება განსაზღვრული არ არის")
    results = dev.run_commands(inventory, device, cmds, parse=False, max_chars=None)
    errors = [r["error"] for r in results if "error" in r]
    text = "\n".join(r.get("output", "") for r in results)
    if errors and not text.strip():
        raise RuntimeError("; ".join(errors))
    return text


def backup_devices(inventory: Inventory, devices: list[Device], store: BackupStore) -> dict[str, dict]:
    """Back up many devices in parallel. Returns per-device status."""

    def one(device: Device) -> dict:
        config = fetch_config(inventory, device)
        before = store.latest(device.name)
        snap, changed = store.save(device.name, config)
        out: dict = {"saved": changed, "file": str(snap.path.name) if snap else None}
        if changed and before is not None:
            d = unified_diff(before.read(), snap.read(), before.path.name, snap.path.name)
            out["added"], out["removed"] = diff_stats(d)
            out["diff"] = d
        elif changed:
            out["first_backup"] = True
        return out

    return dev.run_on_devices(inventory, devices, one)


def changes_since(store: BackupStore, device: str, hours: float) -> dict | None:
    """Diff between the config `hours` ago and the latest backup (None if no backups)."""
    latest = store.latest(device)
    if latest is None:
        return None
    base = store.snapshot_before(device, datetime.now() - timedelta(hours=hours))
    if base is None:
        snaps = store.snapshots(device)
        base = snaps[0]
    if base.path == latest.path:
        return {"device": device, "changed": False, "since": base.taken_at.isoformat(timespec="minutes")}
    d = unified_diff(base.read(), latest.read(), base.path.name, latest.path.name)
    added, removed = diff_stats(d)
    return {
        "device": device,
        "changed": bool(d),
        "from": base.taken_at.isoformat(timespec="minutes"),
        "to": latest.taken_at.isoformat(timespec="minutes"),
        "added": added,
        "removed": removed,
        "diff": d,
    }
