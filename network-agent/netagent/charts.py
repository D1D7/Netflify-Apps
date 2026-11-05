"""Latency chart (PNG) for a device, readable on a phone screen.

Palette and marks follow the reference data-viz spec: one series in categorical
slot 1 (blue), 2px line, hairline grid, unreachable periods shaded with the
status "critical" color and labelled in text (never color alone).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

SURFACE = "#fcfcfb"
SERIES = "#2a78d6"
CRITICAL = "#d03b3b"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"


def _down_spans(points: list[tuple[datetime, bool, float | None]]) -> list[tuple[datetime, datetime]]:
    spans: list[tuple[datetime, datetime]] = []
    start = None
    for i, (ts, up, _) in enumerate(points):
        if not up and start is None:
            start = ts
        if up and start is not None:
            spans.append((start, ts))
            start = None
    if start is not None:
        spans.append((start, points[-1][0] + timedelta(minutes=1)))
    return spans


def latency_chart(
    device: str,
    points: list[tuple[datetime, bool, float | None]],
    path: Path,
    hours: float = 24,
    stats: dict | None = None,
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt

    if not points:
        raise ValueError(f"{device}: ისტორია ჯერ არ არის (მონიტორინგი უნდა მუშაობდეს)")

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11})
    fig, ax = plt.subplots(figsize=(8, 4.2), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    xs = [p[0] for p in points]
    # Gaps in the line where the device was unreachable (NaN breaks the line).
    ys = [p[2] if p[1] and p[2] is not None else float("nan") for p in points]
    ax.plot(xs, ys, color=SERIES, linewidth=2, solid_joinstyle="round", solid_capstyle="round")

    spans = _down_spans(points)
    for i, (a, b) in enumerate(spans):
        ax.axvspan(a, b, color=CRITICAL, alpha=0.14, linewidth=0)
        if i == 0:
            ax.text(a, 1.0, " მიუწვდომელი", transform=ax.get_xaxis_transform(), va="top", ha="left",
                    fontsize=9, color=TEXT_SECONDARY)

    # End label: last known value, in text ink beside a marker in the series color.
    last = next(((x, y) for x, y in zip(reversed(xs), reversed(ys)) if y == y), None)
    if last:
        ax.plot([last[0]], [last[1]], marker="o", markersize=8, color=SERIES,
                markeredgecolor=SURFACE, markeredgewidth=2)
        ax.annotate(f"{last[1]:.0f} ms", last, xytext=(8, 0), textcoords="offset points",
                    va="center", fontsize=10, color=TEXT_PRIMARY)

    title = f"{device} — latency (ms), ბოლო {hours:.0f} სთ"
    fig.text(0.06, 0.95, title, fontsize=13, color=TEXT_PRIMARY, weight="bold", va="top")
    if stats and stats.get("samples"):
        parts = [f"uptime {stats['uptime_percent']}%"]
        if "avg_ms" in stats:
            parts += [f"საშ. {stats['avg_ms']} ms", f"p95 {stats['p95_ms']} ms", f"მაქს. {stats['max_ms']} ms"]
        fig.text(0.06, 0.885, "  ·  ".join(parts), fontsize=10, color=TEXT_SECONDARY, va="top")

    ax.grid(axis="y", color=GRID, linewidth=1)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(colors=MUTED, length=0, labelsize=9)
    ax.set_ylim(bottom=0)
    # Always show the full requested window, so a short history reads as "recent data only".
    end = max(datetime.now(), xs[-1])
    ax.set_xlim(end - timedelta(hours=hours), end)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M" if hours <= 48 else "%m-%d"))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=3, maxticks=7))
    fig.subplots_adjust(left=0.08, right=0.9, top=0.8, bottom=0.12)

    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
    return path
