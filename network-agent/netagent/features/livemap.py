"""Live network map for the app: devices and cables (CDP/LLDP), live up/down and link load.

The topology (who is cabled to whom) comes from /map's discovery, cached in data/topology.json and
rediscovered on request; status (reachability) and link load (last /traffic sample) are fresh on every request.
Positions come from the same force layout as the /map picture, so the drawing is stable between refreshes.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ..config import settings


def _cache() -> Path:
    return settings.data_dir / "topology.json"


def topology(inv, refresh: bool = False, discover=None) -> dict:
    """Cached topology (instant); rediscovered only when asked, or when there is no cache yet."""
    from ..topology import discover_topology

    path = _cache()
    if path.exists() and not (refresh and inv.devices):
        # cached cables load instantly; rediscovery (SSH to every device) only on request: devices that do not
        # answer would otherwise make the page wait for their timeouts
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    if not inv.devices:
        return {"devices": [], "links": [], "errors": {}, "generated": ""}
    return (discover or discover_topology)(inv, path)


def link_load(tracker, device: str, port: str) -> dict:
    """{util, in_bps, out_bps, bw_bps} of device's port from the last traffic sample (empty if unknown)."""
    from ..watch import ifname_matches

    sample = (getattr(tracker, "prev", {}) or {}).get(device) or {}
    for name, i in (sample.get("interfaces") or {}).items():
        if port and ifname_matches(port, name):
            from .ifstats import utilization

            return {"util": utilization(i), "in_bps": i.get("in_bps"), "out_bps": i.get("out_bps"), "bw_bps": i.get("bw_bps")}
    return {}


ROOT_HINT = ("router", "gateway", "edge", "fw", "firewall", "wan")  # a core switch sits below the router


def layered(names: list[str], edges: list[tuple[str, str]], roles: dict[str, str]) -> tuple[dict[str, tuple[float, float]], int]:
    """Network-style layout: the router/firewall on top, each hop one row lower, uncabled devices in the last row.
    Returns ({name: (x 0..1, y 0..1)}, number of rows)."""
    adj: dict[str, set[str]] = {n: set() for n in names}
    for a, b in edges:
        adj[a].add(b)
        adj[b].add(a)
    level: dict[str, int] = {}
    cabled = [n for n in names if adj[n]]
    while len(level) < len(cabled):  # one BFS per connected group, from its most "router-like" device
        rest = [n for n in cabled if n not in level]
        root = max(rest, key=lambda n: (any(h in f"{roles.get(n, '')} {n}".lower() for h in ROOT_HINT), len(adj[n]), -names.index(n)))
        level[root], queue = 0, [root]
        while queue:
            cur = queue.pop(0)
            for nb in sorted(adj[cur], key=names.index):
                if nb not in level:
                    level[nb] = level[cur] + 1
                    queue.append(nb)
    rows: list[list[str]] = [[] for _ in range((max(level.values()) + 1) if level else 0)]
    for n in names:
        if n in level:
            rows[level[n]].append(n)
    loose = [n for n in names if n not in level]
    if loose:
        rows.append(loose)
    pos = {}
    for r, row in enumerate(rows):
        for i, n in enumerate(row):
            pos[n] = ((i + 0.5) / len(row), (r + 0.5) / len(rows))
    return pos, len(rows)


def build_map(s, refresh: bool = False, check=None, tracker=None, discover=None) -> dict:
    from ..health import check_many
    from .ifstats import TRACKER

    inv = s.inventory()
    data = topology(inv, refresh, discover)
    tracker = tracker or TRACKER
    known = list(inv.devices)
    names = list(dict.fromkeys(known + [n for l in data.get("links", []) for n in (l["a"], l["b"])]))
    edges = [(l["a"], l["b"]) for l in data.get("links", []) if l["a"] in names and l["b"] in names]
    pos, n_rows = layered(names, edges, {n: getattr(d, "role", "") for n, d in inv.devices.items()}) if names else ({}, 0)
    status = {r.device: r for r in (check or check_many)(list(inv.devices.values()), 2.0, 0)} if inv.devices else {}
    nodes = []
    for n in names:
        d = inv.devices.get(n)
        r = status.get(n)
        x, y = pos.get(n, (0, 0))
        nodes.append({"id": n, "known": d is not None, "ip": d.host if d else next((l["b_ip"] for l in data.get("links", []) if l["b"] == n), ""),
                      "type": d.device_type if d else next((l["b_platform"] for l in data.get("links", []) if l["b"] == n), ""),
                      "role": d.role if d else "", "up": (r.up if r else None), "latency_ms": (r.latency_ms if r else None),
                      "x": round(x, 4), "y": round(y, 4)})
    links = []
    for l in data.get("links", []):
        load = link_load(tracker, l["a"], l["a_port"]) or link_load(tracker, l["b"], l["b_port"])
        links.append({"a": l["a"], "b": l["b"], "a_port": l["a_port"], "b_port": l["b_port"], "known": l["b_known"], **load})
    return {"generated": data.get("generated", ""), "checked": datetime.now().isoformat(timespec="seconds"),
            "nodes": nodes, "links": links, "errors": data.get("errors", {}),
            "up": sum(1 for x in nodes if x["up"]), "down": sum(1 for x in nodes if x["up"] is False), "rows": n_rows}
