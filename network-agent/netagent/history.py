"""Latency / reachability history, one CSV file per day: data/latency/YYYY-MM-DD.csv"""

from __future__ import annotations

import csv
import threading
from datetime import date, datetime, timedelta
from pathlib import Path

from .health import Reachability

KEEP_DAYS = 14
_lock = threading.Lock()


class LatencyHistory:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _file(self, day: date) -> Path:
        return self.root / f"{day.isoformat()}.csv"

    def record(self, results: list[Reachability], when: datetime | None = None) -> None:
        when = when or datetime.now()
        path = self._file(when.date())
        with _lock:
            new_file = not path.exists()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                for r in results:
                    w.writerow([when.isoformat(timespec="seconds"), r.device, int(r.up),
                                "" if r.latency_ms is None else r.latency_ms])
            if new_file:
                self._prune(when.date())

    def _prune(self, today: date) -> None:
        cutoff = today - timedelta(days=KEEP_DAYS)
        for f in self.root.glob("*.csv"):
            try:
                if date.fromisoformat(f.stem) < cutoff:
                    f.unlink()
            except ValueError:
                continue

    def read(self, device: str, hours: float = 24, now: datetime | None = None) -> list[tuple[datetime, bool, float | None]]:
        now = now or datetime.now()
        start = now - timedelta(hours=hours)
        points: list[tuple[datetime, bool, float | None]] = []
        day = start.date()
        while day <= now.date():
            path = self._file(day)
            if path.exists():
                with path.open(newline="", encoding="utf-8") as fh:
                    for row in csv.reader(fh):
                        if len(row) != 4 or row[1] != device:
                            continue
                        try:
                            ts = datetime.fromisoformat(row[0])
                        except ValueError:
                            continue
                        if start <= ts <= now:
                            points.append((ts, row[2] == "1", float(row[3]) if row[3] else None))
            day += timedelta(days=1)
        return sorted(points)

    def stats(self, device: str, hours: float = 24) -> dict:
        pts = self.read(device, hours)
        if not pts:
            return {"device": device, "samples": 0}
        lat = [p[2] for p in pts if p[1] and p[2] is not None]
        up = sum(1 for p in pts if p[1])
        out = {
            "device": device,
            "hours": hours,
            "samples": len(pts),
            "uptime_percent": round(100 * up / len(pts), 2),
        }
        if lat:
            lat_sorted = sorted(lat)
            out.update({
                "avg_ms": round(sum(lat) / len(lat), 1),
                "max_ms": round(max(lat), 1),
                "p95_ms": round(lat_sorted[min(len(lat_sorted) - 1, int(0.95 * len(lat_sorted)))], 1),
            })
        return out
