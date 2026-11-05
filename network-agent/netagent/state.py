"""Small persistent key/value store (JSON file) for state that must survive restarts:
alert mutes, AI usage counters."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._data: dict[str, Any] = {}
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

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)
