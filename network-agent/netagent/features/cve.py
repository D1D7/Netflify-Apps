"""Known vulnerabilities (CVE) for the OS version each device runs, from the NIST NVD API.

The version is read from `show version` / `/system resource print`, mapped to a CPE
(e.g. cpe:2.3:o:cisco:ios_xe:17.9.4a) and looked up with NVD's version-range matching.
Results are cached for a day (NVD allows 5 requests / 30 s without a key; set
NVD_API_KEY in .env for more).
"""

from __future__ import annotations

import json
import os
import re
import time

from ..config import settings
from ..result import CommandError, Result
from ..tools import device as dev

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_SECONDS = 24 * 3600


def detect_os(device_type: str, version_text: str) -> tuple[str, str] | None:
    """-> (cpe product prefix, version) or None."""
    t = version_text
    dt = device_type.lower()
    if dt.startswith("mikrotik"):
        m = re.search(r"version:\s*(\d+\.\d+(?:\.\d+)?)", t)
        return ("cpe:2.3:o:mikrotik:routeros", m.group(1)) if m else None
    if dt.startswith("cisco_nxos"):
        m = re.search(r"(?:NXOS|system):\s+version\s+(\S+)", t, re.I)
        return ("cpe:2.3:o:cisco:nx-os", m.group(1).lower()) if m else None
    if dt.startswith(("cisco_ios", "cisco_xe")):
        if "IOS XE" in t or "IOS-XE" in t:
            m = re.search(r"Version\s+(\d+\.\d+\.\d+\w*)", t)
            if not m:
                return None
            ver = ".".join(re.sub(r"^0+(?=\d)", "", part) for part in m.group(1).lower().split("."))  # 17.09.04a -> 17.9.4a
            return ("cpe:2.3:o:cisco:ios_xe", ver)
        m = re.search(r"Version\s+(\d+\.\d+\([\w.]+\)\w*)", t)
        if m:
            ver = m.group(1).lower().replace("(", "\\(").replace(")", "\\)")  # CPE escaping
            return ("cpe:2.3:o:cisco:ios", ver)
        return None
    if dt.startswith("juniper"):
        m = re.search(r"Junos:\s*(\S+)", t) or re.search(r"JUNOS .*?\[(\S+)\]", t)
        return ("cpe:2.3:o:juniper:junos", m.group(1).lower()) if m else None
    if dt.startswith("arista"):
        m = re.search(r"Software image version:\s*(\S+)", t)
        return ("cpe:2.3:o:arista:eos", m.group(1).lower()) if m else None
    if dt.startswith("fortinet"):
        m = re.search(r"Version:\s*\S+\s+v(\d+\.\d+\.\d+)", t)
        return ("cpe:2.3:o:fortinet:fortios", m.group(1)) if m else None
    if dt.startswith("paloalto"):
        m = re.search(r"sw-version:\s*(\S+)", t)
        return ("cpe:2.3:o:paloaltonetworks:pan-os", m.group(1)) if m else None
    return None


def _severity(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or m.get("baseSeverity") or ""
            if score is not None:
                return float(score), sev.upper()
    return None, ""


def parse_nvd(payload: dict) -> list[dict]:
    out = []
    for item in payload.get("vulnerabilities", []):
        c = item.get("cve", {})
        score, sev = _severity(c.get("metrics", {}))
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append({"id": c.get("id"), "score": score, "severity": sev, "published": (c.get("published") or "")[:10],
                    "kev": bool(c.get("cisaExploitAdd")), "summary": desc[:240]})
    out.sort(key=lambda x: (x["kev"], x["score"] or 0), reverse=True)
    return out


def _cache_path():
    return settings.data_dir / "cve_cache.json"


def lookup(cpe: str, fetch=None) -> list[dict]:
    path = _cache_path()
    try:
        cache = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, ValueError):
        cache = {}
    hit = cache.get(cpe)
    if hit and time.time() - hit["at"] < CACHE_SECONDS:
        return hit["items"]
    if fetch is None:
        import httpx

        headers = {"User-Agent": "NetAgent"}
        if os.getenv("NVD_API_KEY"):
            headers["apiKey"] = os.environ["NVD_API_KEY"]

        def fetch(c):
            r = httpx.get(NVD, params={"virtualMatchString": c, "resultsPerPage": 200}, headers=headers, timeout=60)
            r.raise_for_status()
            return r.json()
    items = parse_nvd(fetch(cpe))
    cache[cpe] = {"at": time.time(), "items": items}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    return items


def check_device(inventory, device, fetch=None) -> dict:
    cmds = dev.commands_for(device, "version")
    if not cmds:
        return {"device": device.name, "error": "ვერსიის ბრძანება უცნობია"}
    res = dev.run_commands(inventory, device, cmds, parse=False, max_chars=None)
    text = "\n".join(r.get("output", "") for r in res)
    if not text.strip():
        return {"device": device.name, "error": "; ".join(r.get("error", "") for r in res)}
    os_info = detect_os(device.device_type, text)
    if not os_info:
        return {"device": device.name, "error": "OS-ის ვერსია ვერ ამოვიცანი"}
    cpe = f"{os_info[0]}:{os_info[1]}:*:*:*:*:*:*:*"
    items = lookup(cpe, fetch)
    counts = {k: sum(1 for i in items if i["severity"] == k) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    return {"device": device.name, "product": os_info[0].split(":")[-1], "version": os_info[1].replace("\\", ""),
            "cpe": cpe, "total": len(items), "counts": counts, "exploited": sum(i["kev"] for i in items), "top": items[:8]}


def format_result(r: dict) -> str:
    if "error" in r:
        return f"⚪ **{r['device']}** — {r['error']}"
    c = r["counts"]
    if not r["total"]:
        return f"✅ **{r['device']}** ({r['product']} {r['version']}) — ცნობილი CVE ვერ მოიძებნა"
    lines = [f"🛡 **{r['device']}** ({r['product']} {r['version']}): {r['total']} CVE — "
             f"🔴 {c['CRITICAL']} critical · 🟠 {c['HIGH']} high · 🟡 {c['MEDIUM']} medium"
             + (f" · ☠️ {r['exploited']} აქტიურად გამოიყენება (CISA KEV)" if r["exploited"] else "")]
    for i in r["top"][:5]:
        lines.append(f"• {'☠️ ' if i['kev'] else ''}{i['id']} ({i['score'] or '?'} {i['severity']}) — {i['summary'][:110]}")
    lines.append("→ განახლება: გადადი მწარმოებლის რეკომენდებულ ვერსიაზე (Cisco: Software Checker, MikroTik: stable/long-term)")
    return "\n".join(lines)


def cve_cmd(s, args, user) -> Result:
    inv = s.inventory()
    devices = inv.filter(args[0]) if args else list(inv.devices.values())
    if not devices:
        raise CommandError("მოწყობილობა ვერ მოიძებნა")
    results = dev.run_on_devices(inv, devices, lambda d: check_device(inv, d))
    parts = []
    for name, r in results.items():
        if isinstance(r, dict):
            parts.append(format_result(r))
        else:
            parts.append(f"⚪ **{name}** — {r}")
    return Result("🛡 **ცნობილი სისუსტეები (NVD)**\n\n" + "\n\n".join(parts))


COMMANDS = {"cve": cve_cmd}
HELP = ["/cve — ცნობილი სისუსტეები (CVE) მოწყობილობების OS ვერსიებზე · /cve R1"]
BOT_COMMANDS = [("cve", "ცნობილი სისუსტეები (CVE)")]
TOOLS = [({
    "name": "cve_check",
    "description": "Known vulnerabilities (CVE, from NIST NVD) for the OS version a device runs: counts by severity, "
                   "CISA known-exploited flag and the most severe items. Use for 'is R1 vulnerable', 'should I upgrade'.",
    "input_schema": {"type": "object", "properties": {"device": {"type": "string"}}, "required": ["device"]},
}, lambda ctx, device: check_device(ctx.inventory, ctx.inventory.get(device)))]
