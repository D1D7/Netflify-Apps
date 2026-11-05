"""Append-only audit log (JSON lines) of every tool the agent runs."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_lock = threading.Lock()


def log_event(path: Path, **event: Any) -> None:
    event = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **event}
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, ensure_ascii=False, default=str)
    with _lock, path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
