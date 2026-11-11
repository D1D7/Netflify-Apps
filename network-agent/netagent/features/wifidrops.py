"""Wi-Fi drop log: when and how often this PC's Wi-Fi disconnected, and for how long.

Read from Windows' own WLAN log (Microsoft-Windows-WLAN-AutoConfig/Operational, no admin needed):
8001 connected · 8003 disconnected (with the reason) · 8002 failed to connect. Disconnects caused by
sleep / shutdown (Kernel-Power events at the same moment) or by the user are not counted as drops.

  /wifidrops        last 7 days: drops, total time without Wi-Fi, the worst hours, the latest drops
  /wifidrops 30     a longer period
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from datetime import datetime, timedelta

from ..osutil import NO_WINDOW
from ..result import Button, Result
from . import env_int

PS = r"""
$since = (Get-Date).AddDays(-%DAYS%)
$w = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; Id=8001,8002,8003; StartTime=$since} -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ ts=$_.TimeCreated.ToString('s'); id=$_.Id; msg=$_.Message } })
$p = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=42,506,107,109,41; StartTime=$since} -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ ts=$_.TimeCreated.ToString('s'); id=$_.Id } })
[pscustomobject]@{ wlan=$w; power=$p } | ConvertTo-Json -Depth 3 -Compress
"""

SLEEP_WINDOW = timedelta(seconds=90)


def read_events(days: int = 7, run=None) -> dict:
    def ps(script):
        return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True,
                              text=True, timeout=60, errors="replace", creationflags=NO_WINDOW).stdout

    out = (run or ps)(PS.replace("%DAYS%", str(int(days))))
    data = json.loads(out.strip() or "{}")
    for k in ("wlan", "power"):
        v = data.get(k)
        data[k] = [] if v is None else v if isinstance(v, list) else [v]
    return data


def field(msg: str, name: str) -> str:
    m = re.search(rf"^\s*{name}\s*:\s*(.+)$", msg or "", re.M)
    return m.group(1).strip() if m else ""


def analyse(data: dict, now: datetime | None = None) -> dict:
    """Drops (unexpected disconnects) with their duration, plus totals and the hours they happen in."""
    now = now or datetime.now()
    power = sorted(datetime.fromisoformat(p["ts"]) for p in data.get("power", []))
    events = sorted(({**e, "t": datetime.fromisoformat(e["ts"])} for e in data.get("wlan", [])), key=lambda e: e["t"])
    drops, failed = [], []
    for i, e in enumerate(events):
        if e["id"] == 8002:
            failed.append({"ts": e["ts"], "ssid": field(e["msg"], "SSID"), "reason": field(e["msg"], "Failure Reason")})
            continue
        if e["id"] != 8003:
            continue
        reason = field(e["msg"], "Reason")
        near_power = any(abs(p - e["t"]) <= SLEEP_WINDOW for p in power)
        by_user = "user" in reason.lower() or "explicitly" in reason.lower()
        back = next((x["t"] for x in events[i + 1:] if x["id"] == 8001), None)
        kind = "sleep" if near_power else "user" if by_user else "drop"
        secs = int(((back or now) - e["t"]).total_seconds())
        drops.append({"ts": e["ts"], "ssid": field(e["msg"], "SSID"), "reason": reason, "kind": kind,
                      "seconds": secs, "back": back.isoformat(timespec="seconds") if back else None})
    real = [d for d in drops if d["kind"] == "drop"]
    hours = Counter(datetime.fromisoformat(d["ts"]).hour for d in real)
    day_ago = (now - timedelta(days=1)).isoformat()
    return {"drops": real, "all": drops, "failed": failed, "count": len(real),
            "count_24h": sum(1 for d in real if d["ts"] >= day_ago),
            "down_seconds": sum(min(d["seconds"], 6 * 3600) for d in real if d["back"]),
            "worst_hours": hours.most_common(3), "sleep": sum(1 for d in drops if d["kind"] == "sleep"),
            "reasons": Counter(d["reason"] for d in real).most_common(3)}


def _dur(s: int) -> str:
    return f"{s} წმ" if s < 60 else f"{s // 60} წთ" if s < 3600 else f"{s // 3600} სთ {s % 3600 // 60} წთ"


REASON_KA = {"The network is disconnected by the driver.": "დრაივერმა გათიშა (სიგნალი დაიკარგა / ადაპტერი)",
             "The network is disconnected because the access point is no longer reachable.": "როუტერი აღარ ჩანს (სიგნალი დაიკარგა)",
             "The network is disconnected by the access point.": "როუტერმა გათიშა"}


def format_drops(r: dict, days: int) -> str:
    if not r["all"] and not r["failed"]:
        return f"📶 **Wi-Fi გაწყვეტები** — ბოლო {days} დღეში Wi-Fi არ გაწყვეტილა (ან ეს კომპიუტერი კაბელითაა)."
    lines = [f"📶 **Wi-Fi გაწყვეტები — ბოლო {days} დღე**",
             f"• გაწყვეტა: **{r['count']}** (24 სთ-ში {r['count_24h']}) · Wi-Fi-ის გარეშე ჯამში {_dur(r['down_seconds'])}"
             + (f" · ძილის/გამორთვის გამო (არ ითვლება): {r['sleep']}" if r["sleep"] else "")]
    if r["worst_hours"] and r["count"] >= 3:
        lines.append("• ყველაზე ხშირად: " + ", ".join(f"{h:02d}:00-{h + 1:02d}:00 ({n}-ჯერ)" for h, n in r["worst_hours"]))
    for reason, n in r["reasons"]:
        lines.append(f"• მიზეზი: {REASON_KA.get(reason, reason)} — {n}-ჯერ")
    if r["drops"]:
        lines.append("\n**ბოლო გაწყვეტები:**")
        for d in r["drops"][-6:][::-1]:
            lines.append(f"• {d['ts'][5:16].replace('T', ' ')} — {d['ssid']} · {_dur(d['seconds']) if d['back'] else 'ჯერ არ აღდგენილა'}")
    if r["failed"]:
        lines.append(f"\n⚠️ დაკავშირება ვერ მოხერხდა {len(r['failed'])}-ჯერ (ბოლო: {r['failed'][-1]['ssid']} — {r['failed'][-1]['reason']})")
    if r["count"] >= 5:
        lines.append("\n🔧 ხშირი გაწყვეტა: შეამოწმე სიგნალი (/wifiscan, მკვდარი ზონები), Wi-Fi ადაპტერის დრაივერი და "
                     "Device Manager → ადაპტერი → Power Management → მოხსენი „Allow the computer to turn off this device“.")
    return "\n".join(lines)


def wifidrops_cmd(s, args, user) -> Result:
    days = max(1, min(int(args[0]), 60)) if args and args[0].isdigit() else 7
    r = analyse(read_events(days))
    return Result(format_drops(r, days), buttons=[Button("📶 Wi-Fi არხები", "/wifiscan"), Button("📵 მკვდარი ზონები", "/deadzones")])


COMMANDS = {"wifidrops": wifidrops_cmd}
HELP = ["/wifidrops [დღეები] — Wi-Fi-ის გაწყვეტების ჟურნალი: რამდენჯერ, როდის, რამდენ ხანს, რატომ"]
BOT_COMMANDS = [("wifidrops", "Wi-Fi გაწყვეტების ჟურნალი")]
TOOLS = [
    ({"name": "wifi_drops", "description": "How often this PC's Wi-Fi disconnected (unexpected drops, not sleep), when, for how "
                                           "long and why, from the Windows WLAN log.",
      "input_schema": {"type": "object", "properties": {"days": {"type": "integer"}}, "required": []}},
     lambda ctx, days=7: {k: v for k, v in analyse(read_events(max(1, min(days, 60)))).items() if k != "all"}),
]


def jobs(monitoring):
    """Several drops within an hour -> one alert (then quiet for 6 hours)."""
    import os

    if os.name != "nt" or env_int("NETAGENT_WIFIDROP_ALERT", 3) <= 0:
        return []
    limit = env_int("NETAGENT_WIFIDROP_ALERT", 3)

    async def check():
        import asyncio

        from ..monitoring import Alert

        state = monitoring.s.state
        r = await asyncio.to_thread(lambda: analyse(read_events(1)))
        hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        recent = [d for d in r["drops"] if d["ts"] >= hour_ago]
        last = state.get("wifidrops_alerted") or ""
        if len(recent) >= limit and last < (datetime.now() - timedelta(hours=6)).isoformat():
            state.set("wifidrops_alerted", datetime.now().isoformat(timespec="seconds"))
            await monitoring.emit(Alert("isp", f"📶 **Wi-Fi ხშირად წყდება**: ბოლო საათში {len(recent)}-ჯერ "
                                               f"({REASON_KA.get(recent[-1]['reason'], recent[-1]['reason'])})",
                                        mutable=False, buttons=[Button("📶 გაწყვეტები", "/wifidrops")]))

    return [("wifidrops", 600, 300, check)]
