"""Run NetAgent on a simulated network:  python -m netagent demo   (or demo.bat)

Everything demo-related lives in data/demo/, so the real inventory, backups and
settings are never touched. The app runs on port 8090 (password: netagent-demo).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "data" / "demo"


def configure_env() -> None:
    # Must run before anything imports netagent.config (settings are read at import time).
    forced = {
        "NETAGENT_INVENTORY": str(DEMO / "devices.yaml"),
        "NETAGENT_DATA_DIR": str(DEMO / "data"),
        "NETAGENT_BACKUP_DIR": str(DEMO / "backups"),
        "NETAGENT_EXPORT_DIR": str(DEMO / "exports"),
        "NETAGENT_AUDIT_LOG": str(DEMO / "audit.jsonl"),
        "NETAGENT_DEMO_USER": "admin",
        "NETAGENT_DEMO_PASS": "demo",
        "NETAGENT_TELEGRAM": "off",  # never fight the real bot for the same token
        "NETAGENT_MONITOR_INTERVAL": "1",
        "NETAGENT_DEEP_MONITOR_INTERVAL": "1",
        "NETAGENT_CONFIG_WATCH_INTERVAL": "2",
        "NETAGENT_NEW_DEVICE_INTERVAL": "1",
        "NETAGENT_DAILY_REPORT": "",
        "NETAGENT_WEB_PASSWORD": os.environ.get("NETAGENT_DEMO_WEB_PASSWORD", "netagent-demo"),
        "NETAGENT_WEB_PORT": os.environ.get("NETAGENT_DEMO_WEB_PORT", "8090"),
        "NETAGENT_SYSLOG_HOST": "127.0.0.1",
        "NETAGENT_SYSLOG_PORT": os.environ.get("NETAGENT_DEMO_SYSLOG_PORT", "5514"),
        "NETAGENT_DEMO": "1",
        "NETAGENT_HOME_SCAN_INTERVAL": "0",
        "NETAGENT_SPEEDTEST_INTERVAL": "0",
        "NETAGENT_FLOW_HOST": "127.0.0.1",
        "NETAGENT_FLOW_PORT": os.environ.get("NETAGENT_DEMO_FLOW_PORT", "2056"),
        "PYTHONUTF8": "1",
    }
    os.environ.update(forced)
    DEMO.mkdir(parents=True, exist_ok=True)


def seed_history(services, lab) -> None:
    """A few hours of plausible latency so graphs and sparklines are not empty at start."""
    import math
    import random
    from datetime import datetime, timedelta

    from ..health import Reachability

    if any(services.history.root.glob("*.csv")):
        return
    base = {"R1": 1.8, "SW-Core-1": 0.9, "SW-Access-2": 1.2, "MT-Branch": 24.0}
    now = datetime.now()
    rnd = random.Random(7)
    for i in range(72):  # 6 hours, every 5 minutes
        t = now - timedelta(minutes=5 * (72 - i))
        results = []
        for name, b in base.items():
            d = lab.devices[name]
            spike = 30 if name == "MT-Branch" and 40 <= i < 44 else 0
            lat = round(b * (1 + 0.25 * math.sin(i / 7)) + rnd.random() * b * 0.3 + spike, 2)
            results.append(Reachability(name, d.ip, d.port, True, lat))
        services.history.record(results, when=t)


def main() -> None:
    configure_env()
    import asyncio
    import logging

    from ..server import amain, setup_logging
    from . import lab as lab_mod

    setup_logging(None)
    syslog_port = int(os.environ["NETAGENT_SYSLOG_PORT"])
    try:
        lab = lab_mod.start_lab(syslog_port)
    except OSError as exc:
        print(f"\n  ❌ დემო ქსელი ვერ გაეშვა ({exc}). დემო უკვე ხომ არ არის გაშვებული სხვა ფანჯარაში?\n")
        return 1
    (DEMO / "devices.yaml").write_text(lab_mod.inventory_yaml(lab), encoding="utf-8")

    from ..services import Services

    seed_history(Services.create(client=object()), lab)
    port = os.environ["NETAGENT_WEB_PORT"]
    banner = (
        "\n  ===== NetAgent DEMO =====\n"
        f"  App:       http://127.0.0.1:{port}\n"
        f"  Password:  {os.environ['NETAGENT_WEB_PASSWORD']}\n"
        "  Network:   R1, SW-Core-1, SW-Access-2, MT-Branch (simulated)\n"
        "  Try:       /demo  (failure scenarios), /status, /map, /runbook internet\n"
        "  Stop:      Ctrl+C\n"
    )
    print(banner, flush=True)
    import threading

    from .lab_extra import flow_sender

    stop = threading.Event()
    threading.Thread(target=flow_sender, args=(int(os.environ["NETAGENT_FLOW_PORT"]), stop), daemon=True).start()
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()


if __name__ == "__main__":
    sys.exit(main())
