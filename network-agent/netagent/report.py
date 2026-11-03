"""Daily network report: reachability + config changes (deterministic, no AI cost)."""

from __future__ import annotations

from datetime import datetime

from .backup import BackupStore, backup_devices, changes_since
from .config import settings
from .formatting import first_line
from .health import check_many
from .inventory import Inventory


def build_report(inventory: Inventory, run_backup: bool = True, hours: float = 24) -> str:
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
            lines.append(f"   • {r.device} ({r.host}) — {r.reason}")
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
        lines.append("დეტალებისთვის მკითხე: „რა შეიცვალა <მოწყობილობა>-ზე?“")
    else:
        lines.append(f"📝 Config ცვლილებები ბოლო {hours:.0f} სთ-ში: არ ყოფილა")
    return "\n".join(lines)
