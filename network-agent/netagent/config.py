"""Settings loaded from environment variables / .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")


def _int_set(raw: str) -> set[int]:
    out: set[int] = set()
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if part:
            out.add(int(part))
    return out


@dataclass(frozen=True)
class Settings:
    model: str = field(default_factory=lambda: os.getenv("NETAGENT_MODEL", "claude-opus-5-5"))
    effort: str = field(default_factory=lambda: os.getenv("NETAGENT_EFFORT", "medium"))
    inventory_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("NETAGENT_INVENTORY", str(PROJECT_ROOT / "inventory" / "devices.yaml"))
        )
    )
    audit_log_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("NETAGENT_AUDIT_LOG", str(PROJECT_ROOT / "logs" / "audit.jsonl"))
        )
    )
    telegram_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))
    telegram_allowed_users: set[int] = field(
        default_factory=lambda: _int_set(os.getenv("TELEGRAM_ALLOWED_USERS", ""))
    )
    device_timeout: int = field(default_factory=lambda: int(os.getenv("NETAGENT_DEVICE_TIMEOUT", "20")))
    max_parallel_devices: int = field(default_factory=lambda: int(os.getenv("NETAGENT_MAX_PARALLEL", "10")))
    backup_dir: Path = field(
        default_factory=lambda: Path(os.getenv("NETAGENT_BACKUP_DIR", str(PROJECT_ROOT / "backups")))
    )
    export_dir: Path = field(
        default_factory=lambda: Path(os.getenv("NETAGENT_EXPORT_DIR", str(PROJECT_ROOT / "exports")))
    )
    # Reachability monitoring interval in minutes (0 = off)
    monitor_interval: int = field(default_factory=lambda: int(os.getenv("NETAGENT_MONITOR_INTERVAL", "5")))
    # Daily report + backup time "HH:MM" (empty = off)
    daily_report_time: str = field(default_factory=lambda: os.getenv("NETAGENT_DAILY_REPORT", "09:00").strip())
    timezone: str = field(default_factory=lambda: os.getenv("NETAGENT_TZ", "Asia/Tbilisi"))


settings = Settings()
