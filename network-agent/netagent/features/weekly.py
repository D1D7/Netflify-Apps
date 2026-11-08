"""Weekly report as PDF: availability, alerts, incidents, internet quality, config changes.

    /weekly         last 7 days
    /weekly 30      last 30 days
Schedule it: /schedule mon 09:00 /weekly
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from ..alerts import format_duration
from ..backup import BackupStore
from ..config import settings
from ..result import CommandError, Result


def build(s, days: int = 7) -> dict:
    since = datetime.now() - timedelta(days=days)
    since_s = since.isoformat()
    inv = s.inventory()
    hist = s.history.read_all(days * 24)
    availability = {}
    for name in inv.devices:
        pts = hist.get(name, [])
        if pts:
            lat = [p[2] for p in pts if p[1] and p[2] is not None]
            availability[name] = {"uptime": round(100 * sum(p[1] for p in pts) / len(pts), 2),
                                  "latency_avg": round(sum(lat) / len(lat), 1) if lat else None}
    alerts = [a for a in s.alerts.recent(200) if a["ts"] >= since_s]
    from .incidents import IncidentStore

    incidents = [i for i in IncidentStore(s.state).all() if i["opened"] >= since_s]
    closed = [i for i in incidents if i.get("closed")]
    store = BackupStore(settings.backup_dir)
    changes = {n: sum(1 for sn in store.snapshots(n) if sn.taken_at >= since) for n in inv.devices}
    from .isp import monitor_for

    isp = monitor_for(s).summary(days)
    return {
        "days": days, "from": since.strftime("%Y-%m-%d"), "to": datetime.now().strftime("%Y-%m-%d"),
        "devices": len(inv.devices), "availability": availability,
        "alerts_by_kind": dict(Counter(a["kind"] for a in alerts)),
        "alerts_by_day": dict(Counter(a["ts"][:10] for a in alerts)),
        "incidents": len(incidents), "open_incidents": sum(1 for i in incidents if not i.get("closed")),
        "mttr_seconds": int(sum(i["seconds"] for i in closed) / len(closed)) if closed else None,
        "top_incidents": sorted(closed, key=lambda i: -i["seconds"])[:5],
        "config_changes": {n: c for n, c in changes.items() if c},
        "isp": isp,
    }


KIND_LABEL = {"down": "გათიშვა", "up": "აღდგენა", "watch": "მონიტორინგი", "config": "config", "syslog": "syslog",
              "newdevice": "ახალი მოწყობ.", "isp": "ინტერნეტი", "site": "საიტი", "escalation": "შეხსენება",
              "report": "რეპორტი", "scheduled": "განრიგი"}


def summary_text(r: dict) -> str:
    lines = [f"📊 **ანგარიში {r['from']} — {r['to']}**"]
    if r["availability"]:
        avg = sum(v["uptime"] for v in r["availability"].values()) / len(r["availability"])
        worst = sorted(r["availability"].items(), key=lambda kv: kv[1]["uptime"])[:3]
        lines.append(f"ხელმისაწვდომობა: საშუალოდ {avg:.2f}% · ყველაზე ცუდი: "
                     + ", ".join(f"{n} {v['uptime']}%" for n, v in worst))
    lines.append(f"ალერტები: {sum(r['alerts_by_kind'].values())} ("
                 + ", ".join(f"{KIND_LABEL.get(k, k)} {v}" for k, v in sorted(r["alerts_by_kind"].items(), key=lambda kv: -kv[1])) + ")"
                 if r["alerts_by_kind"] else "ალერტები: 0")
    lines.append(f"ინციდენტები: {r['incidents']} (ღია {r['open_incidents']})"
                 + (f" · აღდგენის საშუალო დრო {format_duration(r['mttr_seconds'])}" if r["mttr_seconds"] else ""))
    if r["config_changes"]:
        lines.append("config ცვლილებები: " + ", ".join(f"{n} ×{c}" for n, c in r["config_changes"].items()))
    i = r["isp"]
    if i.get("uptime_percent") is not None:
        lines.append(f"ინტერნეტი: {i['uptime_percent']}% · გათიშვები {len(i['outages'])}"
                     + (f" · ჩამოტვირთვა {i['down_avg_mbps']} Mbps" if i.get("down_avg_mbps") else ""))
    return "\n".join(lines)


def render_pdf(s, r: dict, path: Path) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages

    with PdfPages(path) as pdf:
        fig = plt.figure(figsize=(8.27, 11.69))  # A4
        fig.text(0.07, 0.95, "NetAgent", fontsize=12, color="#2a78d6", weight="bold")
        fig.text(0.07, 0.92, f"ქსელის ანგარიში: {r['from']} — {r['to']}", fontsize=16, weight="bold")
        y = 0.87
        plain = summary_text(r).replace("**", "").splitlines()[1:]
        for line in plain:
            fig.text(0.07, y, line[:110], fontsize=10)
            y -= 0.028
        if r["availability"]:
            y -= 0.02
            fig.text(0.07, y, "მოწყობილობები", fontsize=12, weight="bold")
            y -= 0.03
            for n, v in sorted(r["availability"].items(), key=lambda kv: kv[1]["uptime"])[:22]:
                fig.text(0.09, y, f"{n}", fontsize=9)
                fig.text(0.45, y, f"{v['uptime']}%", fontsize=9, color="#e5484d" if v["uptime"] < 99 else "#1a7f37")
                fig.text(0.6, y, f"{v['latency_avg'] or '—'} ms", fontsize=9)
                y -= 0.024
        if r["top_incidents"]:
            y -= 0.02
            fig.text(0.07, y, "ყველაზე ხანგრძლივი ინციდენტები", fontsize=12, weight="bold")
            y -= 0.03
            for i in r["top_incidents"]:
                fig.text(0.09, y, f"#{i['id']} {i['opened'][:16].replace('T', ' ')} ({format_duration(i['seconds'])}) "
                         f"{i['title'][:70]}", fontsize=8.5)
                y -= 0.022
        pdf.savefig(fig)
        plt.close(fig)

        fig, axes = plt.subplots(2, 1, figsize=(8.27, 11.69))
        days = sorted(r["alerts_by_day"])
        axes[0].bar(days, [r["alerts_by_day"][d] for d in days], color="#2a78d6")
        axes[0].set_title("ალერტები დღეების მიხედვით", loc="left")
        axes[0].tick_params(axis="x", rotation=45, labelsize=8)
        hist = s.history.read_all(r["days"] * 24)
        for name, pts in sorted(hist.items())[:8]:
            xs = [p[0] for p in pts if p[1] and p[2] is not None]
            if xs:
                axes[1].plot(xs, [p[2] for p in pts if p[1] and p[2] is not None], lw=1, label=name)
        axes[1].set_title("Latency (ms)", loc="left")
        if hist:
            axes[1].legend(fontsize=7, frameon=False)
        for ax in axes:
            ax.grid(alpha=0.25)
            ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout(pad=3)
        pdf.savefig(fig)
        plt.close(fig)
    return path


def weekly_cmd(s, args, user) -> Result:
    try:
        days = int(args[0]) if args else 7
    except ValueError:
        raise CommandError("გამოყენება: /weekly · /weekly 30") from None
    days = max(1, min(days, 90))
    r = build(s, days)
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    path = render_pdf(s, r, settings.export_dir / f"netagent-report-{datetime.now():%Y%m%d-%H%M}.pdf")
    return Result(summary_text(r), files=[path])


COMMANDS = {"weekly": weekly_cmd}
HELP = ["/weekly — კვირის ანგარიში PDF-ად (/weekly 30 — თვის) · განრიგით: /schedule mon 09:00 /weekly"]
BOT_COMMANDS = [("weekly", "კვირის ანგარიში (PDF)")]
