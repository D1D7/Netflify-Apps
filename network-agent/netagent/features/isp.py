"""Internet / ISP monitor: is the internet up, latency, packet loss, outages and speed tests.

Every minute: TCP connects to a few anycast resolvers (no admin rights needed, works on
Windows). Two failed rounds in a row = outage; the outage is recorded when the line comes
back. Speed tests use speed.cloudflare.com. `/isp report 30` writes a summary that can be
sent to the provider.
"""

from __future__ import annotations

import csv
import os
import socket
import statistics
import time
from datetime import datetime, timedelta
from pathlib import Path

from ..config import settings
from ..result import Button, CommandError, Result
from . import env_int

TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443)]
SPEED_URL = "https://speed.cloudflare.com"
# /meta answers 403 unless the request looks like it comes from Cloudflare's own speed page
SPEED_HEADERS = {"User-Agent": "NetAgent", "Referer": f"{SPEED_URL}/", "Origin": SPEED_URL}
PING_SAMPLES = 8
DOWN_MAX_BYTES = 50_000_000
DOWN_SECONDS = 8.0      # stop downloading after this long (counted from the first byte)
UP_PROBE_BYTES = 1_000_000
UP_TARGET_SECONDS = 5.0  # pick an upload size that takes about this long
UP_MAX_BYTES = 25_000_000
FAILS_FOR_OUTAGE = 2


def root() -> Path:
    p = settings.data_dir / "isp"
    p.mkdir(parents=True, exist_ok=True)
    return p


def probe(timeout: float = 2.0) -> dict:
    lat = []
    for host, port in TARGETS:
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                lat.append((time.monotonic() - start) * 1000)
        except OSError:
            pass
    loss = round(100 * (len(TARGETS) - len(lat)) / len(TARGETS))
    return {"online": bool(lat), "latency_ms": round(min(lat), 1) if lat else None, "loss": loss}



def _server_ms(headers) -> float:
    """Cloudflare's own processing time (Server-Timing: cfRequestDuration;dur=1.2), not part of the network delay."""
    for part in (headers.get("server-timing") or "").split(","):
        if "dur=" in part:
            try:
                return float(part.split("dur=", 1)[1].split(";", 1)[0])
            except ValueError:
                return 0.0
    return 0.0


def tcp_rtt_sampler(host: str = "speed.cloudflare.com", port: int = 443, timeout: float = 3.0):
    """Round-trip time as TCP connect time (SYN -> SYN/ACK). Timing tiny HTTP requests instead adds Windows'
    ~200 ms delayed-ACK stalls that are not on the network, so a "ping" of 250 ms could really be 5 ms."""
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except OSError:
        return lambda: None

    def sample() -> float | None:
        t0 = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return (time.monotonic() - t0) * 1000
        except OSError:
            return None

    return sample


def measure_speed(c, clock=time.monotonic, rtt=None) -> dict:
    """Latency, download and upload against speed.cloudflare.com with an httpx-like client `c`."""
    info = {"isp": "", "ip": "", "city": ""}
    try:
        meta = c.get(f"{SPEED_URL}/meta", timeout=10).json()
        info = {"isp": meta.get("asOrganization", ""), "ip": meta.get("clientIp", ""), "city": meta.get("city", "")}
    except Exception:  # noqa: BLE001 - the provider name is a bonus
        pass

    # latency: several TCP handshakes; the median ignores single Wi-Fi hiccups, jitter shows how much it jumps
    sample = rtt or tcp_rtt_sampler()
    lat = [x for x in (sample() for _ in range(PING_SAMPLES)) if x is not None]
    ping = statistics.median(lat) if lat else None
    jitter = statistics.mean(abs(a - b) for a, b in zip(lat, lat[1:])) if len(lat) > 1 else 0.0

    # download: count from the first byte (the request delay is latency, not bandwidth); stop after DOWN_SECONDS
    size, first, last = 0, None, None
    with c.stream("GET", f"{SPEED_URL}/__down?bytes={DOWN_MAX_BYTES}") as r:
        for chunk in r.iter_bytes():
            now = clock()
            if first is None:  # the clock starts at the first chunk, so its bytes are not counted either
                first = last = now
                continue
            size += len(chunk)
            last = now
            if now - first >= DOWN_SECONDS:
                break
    down = size * 8 / (last - first) / 1e6 if size and last > first else 0.0

    # upload: a 1 MB probe, then a size that takes about UP_TARGET_SECONDS
    def upload(n: int) -> float:
        body = os.urandom(n)
        t0 = clock()
        r = c.post(f"{SPEED_URL}/__up", content=body)
        return max(clock() - t0 - _server_ms(r.headers) / 1000, 1e-3)

    probe = UP_PROBE_BYTES * 8 / upload(UP_PROBE_BYTES)  # bits per second
    n = int(min(max(probe / 8 * UP_TARGET_SECONDS, UP_PROBE_BYTES), UP_MAX_BYTES))
    up = n * 8 / upload(n) / 1e6
    return {"down_mbps": round(down, 1), "up_mbps": round(up, 1), "ping_ms": round(ping, 1) if ping is not None else None,
            "jitter_ms": round(jitter, 1), **info}


class InternetMonitor:
    def __init__(self, state, directory: Path | None = None) -> None:
        self.state = state
        self.dir = directory or root()
        self.fails = 0

    # -- samples -------------------------------------------------------------------------
    def record(self, sample: dict, when: datetime | None = None) -> dict | None:
        """Store one probe; returns an event dict {"type": "down"|"up", ...} on a state change."""
        when = when or datetime.now()
        path = self.dir / f"{when.date().isoformat()}.csv"
        new = not path.exists()
        with path.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["ts", "online", "latency_ms", "loss"])
            w.writerow([when.isoformat(timespec="seconds"), int(sample["online"]), sample["latency_ms"] or "", sample["loss"]])
        self._prune(when)
        start = self.state.get("isp_outage_start")
        if sample["online"]:
            self.fails = 0
            if start:
                self.state.set("isp_outage_start", None)
                outage = {"start": start, "end": when.isoformat(timespec="seconds"),
                          "seconds": int((when - datetime.fromisoformat(start)).total_seconds())}
                self.state.update("isp_outages", lambda v: ((v or []) + [outage])[-300:])
                return {"type": "up", **outage}
            return None
        self.fails += 1
        if self.fails == FAILS_FOR_OUTAGE and not start:
            first = when - timedelta(minutes=FAILS_FOR_OUTAGE - 1)
            self.state.set("isp_outage_start", first.isoformat(timespec="seconds"))
            return {"type": "down", "start": first.isoformat(timespec="seconds")}
        return None

    def _prune(self, today: datetime, keep_days: int = 120) -> None:
        cutoff = (today - timedelta(days=keep_days)).date().isoformat()
        for f in self.dir.glob("20*.csv"):
            if f.stem < cutoff:
                f.unlink(missing_ok=True)

    def samples(self, since: datetime) -> list[tuple[datetime, bool, float | None, int]]:
        out = []
        day = since.date()
        while day <= datetime.now().date():
            path = self.dir / f"{day.isoformat()}.csv"
            if path.exists():
                with path.open(encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        ts = datetime.fromisoformat(row["ts"])
                        if ts >= since:
                            out.append((ts, row["online"] == "1", float(row["latency_ms"]) if row["latency_ms"] else None,
                                        int(row["loss"] or 0)))
            day += timedelta(days=1)
        return out

    # -- speed tests ------------------------------------------------------------------------
    def speedtest(self) -> dict:
        import httpx

        with httpx.Client(timeout=30, headers=SPEED_HEADERS) as c:
            m = measure_speed(c)
        result = {"ts": datetime.now().isoformat(timespec="seconds"), **m}
        self.state.update("isp_speedtests", lambda v: ((v or []) + [result])[-500:])
        return result

    # -- summaries ---------------------------------------------------------------------------
    def summary(self, days: float = 1) -> dict:
        since = datetime.now() - timedelta(days=days)
        rows = self.samples(since)
        lat = [r[2] for r in rows if r[2] is not None]
        outages = [o for o in (self.state.get("isp_outages") or []) if o["end"] >= since.isoformat()]
        current = self.state.get("isp_outage_start")
        speeds = [t for t in (self.state.get("isp_speedtests") or []) if t["ts"] >= since.isoformat()]
        res = {
            "days": days, "samples": len(rows),
            "uptime_percent": round(100 * sum(r[1] for r in rows) / len(rows), 2) if rows else None,
            "latency_avg_ms": round(statistics.mean(lat), 1) if lat else None,
            "latency_p95_ms": round(sorted(lat)[int(len(lat) * 0.95) - 1], 1) if len(lat) >= 20 else None,
            "loss_avg_percent": round(statistics.mean(r[3] for r in rows), 2) if rows else None,
            "outages": outages, "outage_total_seconds": sum(o["seconds"] for o in outages),
            "down_now_since": current,
            "speedtests": speeds[-10:],
        }
        if speeds:
            res["down_avg_mbps"] = round(statistics.mean(t["down_mbps"] for t in speeds), 1)
            res["down_min_mbps"] = min(t["down_mbps"] for t in speeds)
            res["up_avg_mbps"] = round(statistics.mean(t["up_mbps"] for t in speeds), 1)
        return res

    def chart(self, days: float, path: Path) -> Path | None:
        rows = self.samples(datetime.now() - timedelta(days=days))
        if len(rows) < 2:
            return None
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.dates as mdates
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(9, 3.4), dpi=130)
        xs = [r[0] for r in rows]
        ax.plot(xs, [r[2] if r[1] else None for r in rows], color="#2a78d6", lw=1.2)
        for r in rows:
            if not r[1]:
                ax.axvspan(r[0] - timedelta(seconds=30), r[0] + timedelta(seconds=30), color="#e5484d", alpha=0.35, lw=0)
        ax.set_ylabel("ms")
        ax.set_title("ინტერნეტის latency (წითელი = კავშირი არ იყო)", fontsize=10, loc="left")
        ax.grid(alpha=0.25)
        ax.spines[["top", "right"]].set_visible(False)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M" if days <= 1 else "%m-%d"))
        fig.tight_layout()
        fig.savefig(path)
        plt.close(fig)
        return path


def _fmt_dur(seconds: int) -> str:
    from ..alerts import format_duration

    return format_duration(seconds)


def format_summary(r: dict) -> str:
    period = "24 სთ" if r["days"] <= 1 else f"{int(r['days'])} დღე"
    if not r["samples"]:
        return "🌐 მონაცემები ჯერ არ არის — მონიტორინგი რამდენიმე წუთში დაიწყებს ჩაწერას."
    lines = [f"🌐 **ინტერნეტი — ბოლო {period}**"]
    if r["down_now_since"]:
        lines.append(f"🔴 **ახლა კავშირი არ არის** ({r['down_now_since'][11:16]}-დან)")
    lines.append(f"Uptime: **{r['uptime_percent']}%** · გათიშვები: {len(r['outages'])}"
                 + (f" (ჯამში {_fmt_dur(r['outage_total_seconds'])})" if r["outages"] else ""))
    if r["latency_avg_ms"] is not None:
        lines.append(f"Latency: საშუალო {r['latency_avg_ms']} ms" + (f", p95 {r['latency_p95_ms']} ms" if r["latency_p95_ms"] else "")
                     + f" · packet loss {r['loss_avg_percent']}%")
    if r.get("down_avg_mbps") is not None:
        last = r["speedtests"][-1]
        lines.append(f"სიჩქარე (საშუალო): ჩამოტვირთვა {r['down_avg_mbps']} · ატვირთვა {r['up_avg_mbps']} Mbps")
        lines.append(f"ბოლო ტესტი: ჩამოტვირთვა {last['down_mbps']} · ატვირთვა {last['up_mbps']} Mbps"
                     + (f" · {last['isp']}" if last.get("isp") else ""))
    for o in r["outages"][-8:]:
        lines.append(f"• {o['start'][5:16].replace('T', ' ')} → {o['end'][11:16]} ({_fmt_dur(o['seconds'])})")
    return "\n".join(lines)


def format_report(r: dict, plan_mbps: int = 0) -> str:
    start = (datetime.now() - timedelta(days=r["days"])).strftime("%Y-%m-%d")
    end = datetime.now().strftime("%Y-%m-%d")
    lines = [f"**ინტერნეტ-მომსახურების ხარისხის ანგარიში** ({start} — {end})", ""]
    if r["speedtests"]:
        lines.append(f"პროვაიდერი: {r['speedtests'][-1].get('isp') or '—'}, საჯარო IP: {r['speedtests'][-1].get('ip') or '—'}")
    lines += [f"გაზომვები: {r['samples']} (ყოველ წუთში)", f"ხელმისაწვდომობა: {r['uptime_percent']}%",
              f"გათიშვები: {len(r['outages'])}, ჯამური ხანგრძლივობა: {_fmt_dur(r['outage_total_seconds']) if r['outages'] else '0'}"]
    if r["latency_avg_ms"] is not None:
        lines.append(f"საშუალო დაყოვნება: {r['latency_avg_ms']} ms, დანაკარგი: {r['loss_avg_percent']}%")
    if r.get("down_avg_mbps") is not None:
        lines.append(f"სიჩქარე (საშუალო): ჩამოტვირთვა {r['down_avg_mbps']} Mbps, ატვირთვა {r['up_avg_mbps']} Mbps, "
                     f"მინიმალური ჩამოტვირთვა {r['down_min_mbps']} Mbps")
        if plan_mbps:
            lines.append(f"ტარიფი: {plan_mbps} Mbps → საშუალოდ მიღებულია {round(100 * r['down_avg_mbps'] / plan_mbps)}%")
    if r["outages"]:
        lines += ["", "გათიშვების სია:"]
        lines += [f"• {o['start'].replace('T', ' ')} — {o['end'].replace('T', ' ')} ({_fmt_dur(o['seconds'])})" for o in r["outages"]]
    lines += ["", "_გაზომილია ავტომატურად NetAgent-ით._"]
    return "\n".join(lines)


# -- commands / tools / jobs ------------------------------------------------------------------
_MONITORS: dict[int, InternetMonitor] = {}


def monitor_for(s) -> InternetMonitor:
    key = id(s.state)
    if key not in _MONITORS:
        _MONITORS[key] = InternetMonitor(s.state)
    return _MONITORS[key]


def isp_cmd(s, args, user) -> Result:
    m = monitor_for(s)
    report = bool(args) and args[0].lower() == "report"
    rest = args[1:] if report else args
    try:
        days = float(rest[0]) if rest else (30 if report else 1)
    except ValueError:
        raise CommandError("გამოყენება: /isp · /isp 7 · /isp report 30") from None
    days = max(1 / 24, min(days, 120))
    r = m.summary(days)
    if report:
        return Result(format_report(r, env_int("NETAGENT_ISP_PLAN_MBPS", 0)))
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    img = m.chart(days, settings.export_dir / f"internet-{datetime.now():%Y%m%d-%H%M%S}.png")
    return Result(format_summary(r), image=img,
                  buttons=[Button("⚡ სიჩქარის ტესტი", "/speedtest"), Button("📄 რეპორტი 30 დღე", "/isp report 30")])


def speedtest_cmd(s, args, user) -> Result:
    try:
        t = monitor_for(s).speedtest()
    except Exception as exc:  # noqa: BLE001
        raise CommandError(f"სიჩქარის ტესტი ვერ შესრულდა ({type(exc).__name__}: {exc})") from None
    return Result(format_speed(t), buttons=[Button("🩺 რატომ ნელია?", "/diagnose ინტერნეტი ნელია")]
                  if t["down_mbps"] and t["up_mbps"] > 3 * t["down_mbps"] else [])


def format_speed(t: dict) -> str:
    jitter = t.get("jitter_ms") or 0
    lines = ["⚡ **ინტერნეტის სიჩქარე**",
             f"ჩამოტვირთვა (download): **{t['down_mbps']}** Mbps",
             f"ატვირთვა (upload): **{t['up_mbps']}** Mbps",
             (f"დაყოვნება (ping): {t['ping_ms']} ms" if t.get("ping_ms") is not None else "დაყოვნება (ping): ვერ გაიზომა")
             + (f" · რყევა ±{jitter:.0f} ms" if jitter >= 1 else "")]
    if t.get("isp"):
        lines.append(f"პროვაიდერი: {t['isp']}" + (f", {t['city']}" if t.get("city") else ""))
    if jitter >= 30:
        lines.append("⚠️ დაყოვნება არასტაბილურია: ხან სწრაფია, ხან ძალიან ნელი (ხშირად Wi-Fi-ის ხმაურია, 2.4 GHz).")
    if t["down_mbps"] and t["up_mbps"] > 3 * t["down_mbps"]:
        lines.append("⚠️ ჩამოტვირთვა ატვირთვაზე ბევრად ნელია — ჩვეულებრივ პირიქით არის. "
                     "სხვა მოწყობილობა ხომ არ ტვირთავს რამეს? ან პროვაიდერის მხარეს არის შეზღუდვა.")
    return "\n".join(lines)


COMMANDS = {"isp": isp_cmd, "speedtest": speedtest_cmd}
HELP = ["/isp — ინტერნეტის მდგომარეობა (/isp 7 · /isp report 30 — პროვაიდერისთვის) · /speedtest — სიჩქარე"]
BOT_COMMANDS = [("isp", "ინტერნეტის მდგომარეობა და გათიშვები"), ("speedtest", "ინტერნეტის სიჩქარე")]
TOOLS = [
    ({"name": "internet_status",
      "description": "Internet/ISP quality measured by NetAgent itself every minute: uptime %, outages (start/end), "
                     "latency, packet loss and speed tests for the last N days. Use for 'was the internet down?', "
                     "'is my ISP slow?', or a report for the provider.",
      "input_schema": {"type": "object", "properties": {"days": {"type": "integer", "description": "1-120, default 1"}},
                       "required": []}},
     lambda ctx, days=1: monitor_for(ctx.services).summary(max(1, min(days, 120)))),
    ({"name": "run_speedtest",
      "description": "Measure internet download/upload speed now (~30 MB of traffic, 10-30 s).",
      "input_schema": {"type": "object", "properties": {}, "required": []}},
     lambda ctx: monitor_for(ctx.services).speedtest()),
]


def jobs(monitoring):
    import asyncio

    from ..monitoring import Alert

    out = []
    every = env_int("NETAGENT_ISP_INTERVAL", 1)
    if every > 0:
        async def check():
            m = monitor_for(monitoring.s)
            ev = await asyncio.to_thread(lambda: m.record(probe()))
            if ev and ev["type"] == "down":
                await monitoring.emit(Alert("isp", f"🔴 **ინტერნეტი გაითიშა** ({ev['start'][11:16]}-დან)", mutable=False))
            elif ev:
                await monitoring.emit(Alert("isp", f"🟢 **ინტერნეტი აღდგა** — არ იყო {_fmt_dur(ev['seconds'])} "
                                                   f"({ev['start'][11:16]} → {ev['end'][11:16]})", mutable=False))
        out.append(("isp", every * 60, 15, check))
    hours = env_int("NETAGENT_SPEEDTEST_INTERVAL", 12)
    if hours > 0:
        async def speed():
            m = monitor_for(monitoring.s)
            if monitoring.s.state.get("isp_outage_start"):
                return
            t = await asyncio.to_thread(m.speedtest)
            low = env_int("NETAGENT_ISP_PLAN_MBPS", 0)
            if low and t["down_mbps"] < low * 0.5:
                await monitoring.emit(Alert("isp", f"🐢 **ინტერნეტი ნელია:** ჩამოტვირთვა {t['down_mbps']} Mbps "
                                                   f"(ტარიფი {low}, ანუ {round(100 * t['down_mbps'] / low)}%)", mutable=False))
        out.append(("speedtest", hours * 3600, 600, speed))
    return out
