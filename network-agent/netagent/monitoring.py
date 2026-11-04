"""Background monitoring shared by all interfaces.

Each check produces Alert objects; `emit` stores them in the alert log (shown in the
app) and hands them to every registered notifier (Telegram, Web Push...).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Awaitable, Callable
from zoneinfo import ZoneInfo

from .alerts import format_duration
from .config import settings
from .health import check_many

log = logging.getLogger("netagent.monitoring")


@dataclass
class Alert:
    kind: str  # "down" | "up" | "watch" | "config" | "report"
    text: str  # Markdown-ish, same format as chat answers
    devices: list[str] = field(default_factory=list)
    mutable: bool = True  # show "mute" buttons

    @property
    def title(self) -> str:
        return {"down": "🔴 მოწყობილობა მიუწვდომელია", "up": "🟢 აღდგა", "watch": "🚨 ალერტი",
                "config": "📝 Config შეიცვალა", "report": "📊 დღიური რეპორტი",
                "syslog": "📜 ლოგის ალერტი", "newdevice": "🆕 ახალი მოწყობილობა ქსელში"}.get(self.kind, "NetAgent")


Notifier = Callable[[Alert], Awaitable[None]]


def diff_snippet(diff: str, max_lines: int = 15) -> str:
    changed = [ln for ln in diff.splitlines()
               if (ln.startswith("+") or ln.startswith("-")) and not ln.startswith(("+++", "---"))]
    more = len(changed) - max_lines
    return "\n".join(changed[:max_lines]) + (f"\n... (+{more} ხაზი)" if more > 0 else "")


class MonitoringService:
    def __init__(self, services) -> None:
        self.s = services
        self.notifiers: list[Notifier] = []

    def add_notifier(self, fn: Notifier) -> None:
        self.notifiers.append(fn)

    async def emit(self, alert: Alert) -> None:
        try:
            self.s.alerts.add(alert.kind, alert.text, alert.devices)
        except Exception:  # noqa: BLE001
            log.exception("alert log write failed")
        for notify in self.notifiers:
            try:
                await notify(alert)
            except Exception:  # noqa: BLE001 - one broken channel must not block the others
                log.exception("notifier failed")

    # -- checks --------------------------------------------------------------
    async def check_reachability(self) -> list[Alert]:
        inv = self.s.inventory()
        results = await asyncio.to_thread(check_many, list(inv.devices.values()))
        try:
            await asyncio.to_thread(self.s.history.record, results)
        except Exception:  # noqa: BLE001
            log.exception("history record failed")
        downtimes = {r.device: self.s.monitor.down_duration(r.device) for r in results if r.up}
        changes = [(r, st) for r, st in self.s.monitor.update(results) if not self.s.mutes.is_muted(r.device)]
        alerts: list[Alert] = []
        down = [r for r, st in changes if st == "down"]
        up = [r for r, st in changes if st == "up"]
        if down:
            alerts.append(Alert("down", "\n".join(
                f"🔴 **{r.device}** ({r.host}) მიუწვდომელია — {r.reason}" for r in down), [r.device for r in down]))
        if up:
            lines = []
            for r in up:
                took = downtimes.get(r.device)
                lines.append(f"🟢 **{r.device}** ({r.host}) ისევ ხელმისაწვდომია"
                             + (f" (გათიშული იყო {format_duration(took)})" if took else ""))
            alerts.append(Alert("up", "\n".join(lines), [r.device for r in up], mutable=False))
        for a in alerts:
            await self.emit(a)
        return alerts

    async def check_deep(self) -> list[Alert]:
        inv = self.s.inventory()
        found = await asyncio.to_thread(self.s.deep.run, inv, list(inv.devices.values()))
        found = [(d, a) for d, a in found if not self.s.mutes.is_muted(d)]
        if not found:
            return []
        alert = Alert("watch", "\n".join(a for _, a in found), sorted({d for d, _ in found}))
        await self.emit(alert)
        return [alert]

    async def check_config_changes(self) -> list[Alert]:
        from .backup import BackupStore, backup_devices

        def work():
            inv = self.s.inventory()
            reachable = [inv.devices[r.device] for r in check_many(list(inv.devices.values())) if r.up]
            if not reachable:
                return {}
            return backup_devices(inv, reachable, BackupStore(settings.backup_dir))

        results = await asyncio.to_thread(work)
        alerts = []
        for name, r in results.items():
            if not (r.get("saved") and not r.get("first_backup") and r.get("diff")) or self.s.mutes.is_muted(name):
                continue
            alert = Alert("config", (
                f"📝 **{name}**: კონფიგურაცია შეიცვალა (+{r.get('added', 0)} / −{r.get('removed', 0)})\n"
                f"```\n{diff_snippet(r['diff'])}\n```\nახსნისთვის მკითხე: „რა შეიცვალა {name}-ზე?“"), [name])
            await self.emit(alert)
            alerts.append(alert)
        return alerts

    async def check_new_devices(self) -> list[Alert]:
        from .newdevices import collect_arp, format_new

        arp = await asyncio.to_thread(collect_arp, self.s.inventory())
        new = await asyncio.to_thread(self.s.newdevices.process, arp)
        new = [e for e in new if not self.s.mutes.is_muted(e["seen_on"])]
        if not new:
            return []
        alert = Alert("newdevice", format_new(new), sorted({e["seen_on"] for e in new}), mutable=False)
        await self.emit(alert)
        return [alert]

    async def daily_report(self) -> Alert:
        from .report import build_report

        try:
            text = await asyncio.to_thread(build_report, self.s.inventory(), mutes=self.s.mutes, usage=self.s.usage)
        except Exception as exc:  # noqa: BLE001
            log.exception("daily report failed")
            text = f"⚠️ დღიური რეპორტი ვერ შედგა: {exc}"
        alert = Alert("report", text, mutable=False)
        await self.emit(alert)
        return alert


# --------------------------------------------------------------------------- asyncio scheduler (app server)


def parse_hhmm(value: str) -> tuple[int, int] | None:
    try:
        h, m = value.split(":")
        h, m = int(h), int(m)
        if 0 <= h < 24 and 0 <= m < 60:
            return h, m
    except ValueError:
        pass
    return None


def seconds_until(hhmm: tuple[int, int], tz: str, now: datetime | None = None) -> float:
    zone = ZoneInfo(tz)
    now = now.astimezone(zone) if now else datetime.now(zone)
    target = now.replace(hour=hhmm[0], minute=hhmm[1], second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


async def _every(seconds: float, first: float, fn, name: str) -> None:
    await asyncio.sleep(first)
    while True:
        try:
            await fn()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("%s failed", name)
        await asyncio.sleep(seconds)


async def _daily(hhmm: tuple[int, int], fn) -> None:
    while True:
        await asyncio.sleep(seconds_until(hhmm, settings.timezone))
        try:
            await fn()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("daily report failed")
        await asyncio.sleep(60)


def start_scheduler(monitoring: MonitoringService) -> list[asyncio.Task]:
    """Start all periodic checks as asyncio tasks (used by the app server)."""
    tasks = []
    if settings.monitor_interval > 0:
        tasks.append(asyncio.create_task(_every(settings.monitor_interval * 60, 20, monitoring.check_reachability, "monitor")))
    if settings.deep_monitor_interval > 0:
        tasks.append(asyncio.create_task(_every(settings.deep_monitor_interval * 60, 45, monitoring.check_deep, "deep")))
    if settings.new_device_interval > 0:
        tasks.append(asyncio.create_task(_every(settings.new_device_interval * 60, 60, monitoring.check_new_devices, "newdevices")))
    if settings.config_watch_interval > 0:
        tasks.append(asyncio.create_task(_every(settings.config_watch_interval * 60, 90, monitoring.check_config_changes, "config")))
    hhmm = parse_hhmm(settings.daily_report_time) if settings.daily_report_time else None
    if hhmm:
        tasks.append(asyncio.create_task(_daily(hhmm, monitoring.daily_report)))
    log.info("scheduler: monitor=%smin deep=%smin config=%smin report=%s",
             settings.monitor_interval, settings.deep_monitor_interval, settings.config_watch_interval,
             settings.daily_report_time or "off")
    return tasks
