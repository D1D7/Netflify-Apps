"""Prometheus metrics at /metrics (for Grafana). Enabled by setting NETAGENT_METRICS_TOKEN in .env.

prometheus.yml:
  scrape_configs:
    - job_name: netagent
      scrape_interval: 60s
      authorization: {type: Bearer, credentials: <NETAGENT_METRICS_TOKEN>}
      static_configs: [{targets: ["127.0.0.1:8080"]}]
"""

from __future__ import annotations

from datetime import datetime, timedelta


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _labels(**kw) -> str:
    return "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in kw.items()) + "}" if kw else ""


def render(s) -> str:
    out: list[str] = []

    def metric(name: str, help_: str, kind: str, rows: list[tuple[dict, float]]) -> None:
        out.append(f"# HELP netagent_{name} {help_}")
        out.append(f"# TYPE netagent_{name} {kind}")
        for labels, value in rows:
            if value is not None:
                out.append(f"netagent_{name}{_labels(**labels)} {value}")

    inv = s.inventory()
    hist = s.history.read_all(0.5)
    up, lat = [], []
    for name, d in inv.devices.items():
        pts = hist.get(name) or []
        if pts:
            last = pts[-1]
            lab = {"device": name, "site": d.site, "type": d.device_type}
            up.append((lab, 1 if last[1] else 0))
            lat.append((lab, last[2]))
    metric("device_up", "Device reachable at the last check (1/0)", "gauge", up)
    metric("device_latency_ms", "Latency of the last check in ms", "gauge", lat)

    from .isp import monitor_for

    m = monitor_for(s)
    rows = m.samples(datetime.now() - timedelta(minutes=5))
    if rows:
        metric("internet_up", "Internet reachable at the last probe (1/0)", "gauge", [({}, 1 if rows[-1][1] else 0)])
        metric("internet_latency_ms", "Internet latency (last probe)", "gauge", [({}, rows[-1][2])])
        metric("internet_loss_percent", "Packet loss of the last probe", "gauge", [({}, rows[-1][3])])
    tests = s.state.get("isp_speedtests") or []
    if tests:
        metric("internet_download_mbps", "Last speed test download", "gauge", [({}, tests[-1]["down_mbps"])])
        metric("internet_upload_mbps", "Last speed test upload", "gauge", [({}, tests[-1]["up_mbps"])])

    from .ifstats import TRACKER, utilization

    bps_in, bps_out, errs, util = [], [], [], []
    for dev, sample in TRACKER.prev.items():
        for ifname, i in sample.get("interfaces", {}).items():
            lab = {"device": dev, "interface": ifname}
            bps_in.append((lab, i.get("in_bps")))
            bps_out.append((lab, i.get("out_bps")))
            errs.append((lab, (i.get("in_errors") or 0) + (i.get("out_errors") or 0)))
            util.append((lab, utilization(i)))
    metric("interface_in_bps", "Interface input rate", "gauge", bps_in)
    metric("interface_out_bps", "Interface output rate", "gauge", bps_out)
    metric("interface_errors", "Interface input+output error counter", "counter", errs)
    metric("interface_utilization_percent", "max(in,out)/bandwidth", "gauge", util)

    day_ago = (datetime.now() - timedelta(hours=24)).isoformat()
    counts: dict[str, int] = {}
    for a in s.alerts.recent(200):
        if a["ts"] >= day_ago:
            counts[a["kind"]] = counts.get(a["kind"], 0) + 1
    metric("alerts_24h", "Alerts in the last 24 hours", "gauge", [({"kind": k}, v) for k, v in sorted(counts.items())])
    from .incidents import IncidentStore

    metric("incidents_open", "Open incidents", "gauge", [({}, sum(1 for i in IncidentStore(s.state).all() if not i.get("closed")))])
    today = s.usage.day()
    metric("ai_cost_usd_today", "Approximate AI cost today", "gauge", [({}, round(today.get("cost", 0.0), 4))])

    from .flows import STATS

    w = STATS.window(5)
    hosts = {}
    for k in ("down", "up"):
        for ip, n in w.get(k, {}).items():
            hosts.setdefault(ip, {})[k] = n
    top = sorted(hosts.items(), key=lambda kv: -sum(kv[1].values()))[:20]
    metric("flow_host_bps", "Traffic per local host from NetFlow, last 5 min average", "gauge",
           [({"host": ip, "direction": d}, round(n * 8 / 300)) for ip, v in top for d, n in v.items()])
    return "\n".join(out) + "\n"
