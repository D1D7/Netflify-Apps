"""Small persistent key/value store (JSON file) for state that must survive restarts:
alert mutes, AI usage counters."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._data: dict[str, Any] = {}
        self._mtime = None
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                # Corrupt file: keep a copy for inspection and start fresh.
                try:
                    path.replace(path.with_suffix(".corrupt.json"))
                except OSError:
                    pass
                self._data = {}
        self._mtime = self._stamp()

    def _stamp(self):
        try:
            st = self.path.stat()
            return st.st_mtime_ns, st.st_size
        except OSError:
            return None

    def _refresh(self) -> None:
        """Another process (CLI, doctor, a second NetAgent) changed the file: take its version before writing,
        so this process does not overwrite those changes with its older in-memory copy."""
        stamp = self._stamp()
        if stamp is None or stamp == self._mtime:
            return
        try:
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
            self._mtime = stamp
        except (OSError, ValueError):
            pass  # half-written by the other process: keep ours, try again next time

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            self._refresh()
            value = self._data.get(key, default)
            # Return a copy so callers cannot mutate state without update().
            return json.loads(json.dumps(value)) if value is not None else default

    def update(self, key: str, fn) -> Any:
        """Atomically replace state[key] with fn(current_value) and persist."""
        with self._lock:
            current = self.get(key)
            new = fn(current)
            self._data[key] = new
            self._save()
            return new

    def set(self, key: str, value: Any) -> None:
        self.update(key, lambda _: value)

    def _save(self) -> None:
        from .osutil import atomic_write

        atomic_write(self.path, json.dumps(self._data, ensure_ascii=False, indent=1))
        self._mtime = self._stamp()
