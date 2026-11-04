"""Daily network report and security audit runner (deterministic, no AI cost)."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING

from .backup import BackupStore, backup_devices, changes_since
from .compliance import Finding, SEVERITY_ORDER, audit_config, find_duplicate_ips
from .config import settings
from .formatting import first_line
from .health import check_many
from .inventory import Device, Inventory

if TYPE_CHECKING:
    from .alerts import AlertMutes
    from .usage import UsageTracker


def run_security_audit(
    inventory: Inventory, devices: list[Device] | None = None, refresh: bool = True
) -> tuple[dict[str, list[Finding] | None], list[dict], dict[str, str]]:
    """Audit devices using their latest config backup.

    With refresh=True, reachable devices are backed up first so the audit sees the
    current configuration; unreachable ones fall back to their last backup.
    Returns (findings per device, duplicate IPs, errors per device).
    """
    devices = devices if devices is not None else list(inventory.devices.values())
    store = BackupStore(settings.backup_dir)
    errors: dict[str, str] = {}
    if refresh and devices:
        reach = {r.device: r for r in check_many(devices)}
        reachable = [d for d in devices if reach[d.name].up]
        for name, r in (backup_devices(inventory, reachable, store) if reachable else {}).items():
            if "error" in r:
                errors[name] = first_line(r["error"])[:120]
        for d in devices:
            if not reach[d.name].up:
                errors[d.name] = f"მიუწვდომელია ({reach[d.name].reason}) — გამოყენებულია ბოლო backup"

    results: dict[str, list[Finding] | None] = {}
    configs: dict[str, str] = {}
    for d in devices:
        snap = store.latest(d.name)
        if snap is None:
            reason = errors.get(d.name, "").split(" — ")[0]
            errors[d.name] = f"{reason} — backup არ არსებობს" if reason else "backup არ არსებობს"
            continue
        config = snap.read()
        configs[d.name] = config
        results[d.name] = audit_config(d.name, d.device_type, config)
    return results, find_duplicate_ips(configs), errors


def build_report(
    inventory: Inventory,
    run_backup: bool = True,
    hours: float = 24,
    mutes: "AlertMutes | None" = None,
    usage: "UsageTracker | None" = None,
) -> str:
    devices = list(inventory.devices.values())
    lines = [f"📊 **ქსელის რეპორტი** — {datetime.now().strftime('%Y-%m-%d %H:%M')}"]
    if not devices:
        return lines[0] + "\n\ninventory ცარიელია."

    reach = check_many(devices)
    up = [r for r in reach if r.up]
    down = [r for r in reach if not r.up]
    lines.append("")
    lines.append(f"🟢 ხელმისაწვდომი: {len(up)}/{len(reach)}")
    if down:
        lines.append("🔴 მიუწვდომელი:")
        for r in down:
            muted = " 🔕" if mutes and mutes.is_muted(r.device) else ""
            lines.append(f"   • {r.device} ({r.host}) — {r.reason}{muted}")
    slow = [r for r in up if r.latency_ms is not None and r.latency_ms > 200]
    if slow:
        lines.append("🐢 ნელი პასუხი: " + ", ".join(f"{r.device} {r.latency_ms:.0f}ms" for r in slow))

    store = BackupStore(settings.backup_dir)
    if run_backup:
        reachable = [inventory.devices[r.device] for r in up]
        results = backup_devices(inventory, reachable, store) if reachable else {}
        failed = {k: v["error"] for k, v in results.items() if "error" in v}
        lines.append("")
        lines.append(f"💾 Backup: {len(results) - len(failed)}/{len(reachable)} წარმატებით")
        for name, err in failed.items():
            lines.append(f"   ⚠️ {name}: {first_line(err)[:120]}")

    changed = []
    for d in devices:
        c = changes_since(store, d.name, hours)
        if c and c.get("changed"):
            changed.append(c)
    lines.append("")
    if changed:
        lines.append(f"📝 Config ცვლილებები ბოლო {hours:.0f} სთ-ში:")
        for c in changed:
            lines.append(f"   • {c['device']}: +{c['added']} / −{c['removed']} ხაზი")
    else:
        lines.append(f"📝 Config ცვლილებები ბოლო {hours:.0f} სთ-ში: არ ყოფილა")

    # Security summary from the backups just taken (no extra device connections).
    findings, duplicates, _ = run_security_audit(inventory, devices, refresh=False)
    counts = {s: 0 for s in SEVERITY_ORDER}
    for fs in findings.values():
        for f in fs or []:
            counts[f.severity] += 1
    lines.append("")
    lines.append(
        f"🛡 უსაფრთხოება: 🔴 {counts['high']}  🟠 {counts['medium']}  🟡 {counts['low']}"
        + ("  (დეტალები: /audit)" if any(counts.values()) else "")
    )
    if duplicates:
        lines.append("⚠️ დუბლირებული IP: " + ", ".join(d["ip"] for d in duplicates[:5]))

    if mutes:
        active = mutes.active()
        if active:
            lines.append("")
            lines.append("🔕 დადუმებული: " + ", ".join("ყველა" if k == "*" else k for k in active))
    if usage:
        lines.append("")
        y = usage.day(date.today() - timedelta(days=1))
        lines.append(f"💰 AI ხარჯი გუშინ: ${y['cost']:.2f} ({y['requests']} მოთხოვნა), თვეში: ${usage.month_cost():.2f}")
    return "\n".join(lines)
