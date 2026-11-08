"""Automatic diagnosis: describe the problem in your own words, NetAgent picks and runs the checks.

  /diagnose                                  „ინტერნეტი არ მუშაობს“ (default)
  /diagnose ოფისი 2-ში ინტერნეტი ნელია        slow internet, own devices of site "ოფისი 2" only
  /diagnose R1                               one inventory device
  /diagnose 192.168.1.50 · google.com · https://example.com     one host / service
  /diagnose wifi · vpn · dhcp                the matching runbook

The checks run layer by layer (this PC → Wi-Fi → router → internet → DNS → web → own devices).
The first layer that fails is named as the cause, together with what to do next. Recent config
changes, error logs, alerts, open incidents and maintenance windows are listed as clues.
Read-only and deterministic: no AI, nothing is changed anywhere.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlparse

from .. import runbooks as rbk
from ..health import check_many
from ..result import Button, Result
from ..tools import network as net
from . import env_int, homenet, isp

OK, WARN, FAIL, SKIP = "✅", "⚠️", "❌", "⏭️"
MAX_TEXT = 300
MAX_CHANGE_CHECKS = 8

_SLOW = ("ნელ", "slow", "lag", "ლაგ", "იჭედ", "ჭედავ", "დაყოვნ", "latency", "ბუფერ", "წყდება და", "ხან მუშაობს")
_WIFI = ("wi-fi", "wifi", "ვაი-ფაი", "ვაიფაი", "სიგნალ", "wlan")
_VPN = ("vpn", "ვპნ", "ipsec", "wireguard", "გვირაბ", "tunnel")
_DHCP = ("dhcp", "169.254", "ip არ ეძლევა", "ip-ს არ", "ip ვერ", "მისამართს არ", "მისამართი არ")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_HOST_RE = re.compile(r"(?<![\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![A-Za-z0-9])")


# -- network probes (one place, so tests can replace them) ---------------------------------------------
class Probes:
    def local_ip(self) -> str:
        try:
            return homenet.local_ip()
        except OSError:
            return ""

    def gateway(self) -> str | None:
        return homenet.default_gateway()

    def wifi(self) -> dict | None:
        from .morebooks import _windows_wifi

        return _windows_wifi()

    def ping(self, host: str, count: int = 4) -> dict:
        try:
            return net.ping(host, count)
        except ValueError as exc:
            return {"error": str(exc)}

    def tcp(self, host: str, port: int, timeout: float = 1.5) -> bool:
        return homenet._probe(host, port, timeout)  # noqa: SLF001

    def arp(self) -> dict[str, str]:
        return homenet.read_arp()

    def internet(self) -> dict:
        return isp.probe()

    def dns(self, name: str, server: str | None = None) -> dict:
        if server is None:
            return os_resolve(name)
        try:
            return net.dns_lookup(name, "A", server)
        except ValueError as exc:
            return {"error": str(exc)}

    def http(self, url: str, timeout: float = 8.0, follow: bool = False) -> dict:
        import httpx

        start = time.monotonic()
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=follow, headers={"User-Agent": "NetAgent diagnose"})
        except httpx.HTTPError as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:120]}"}
        return {"ok": True, "status": r.status_code, "ms": round((time.monotonic() - start) * 1000),
                "location": r.headers.get("location", "")}


def os_resolve(name: str, timeout: float = 6.0) -> dict:
    """Resolve like Windows and the browsers do. dnspython reads every adapter's DNS servers, stale ones too,
    and can wait seconds on a dead one the OS never asks, so it would report a slowness nobody feels."""
    import socket
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures import TimeoutError as FutureTimeout

    pool = ThreadPoolExecutor(max_workers=1)
    start = time.monotonic()
    try:
        infos = pool.submit(socket.getaddrinfo, name, 443, socket.AF_INET, socket.SOCK_STREAM).result(timeout=timeout)
    except FutureTimeout:
        return {"name": name, "error": f"პასუხი არ მოვიდა {timeout:.0f} წამში"}
    except socket.gaierror as exc:
        missing = exc.errno in {getattr(socket, "EAI_NONAME", -2), 11001}  # 11001 = WSAHOST_NOT_FOUND
        return {"name": name, "error": "NXDOMAIN (დომენი არ არსებობს)" if missing else str(exc.strerror or exc)}
    except (OSError, UnicodeError) as exc:
        return {"name": name, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        pool.shutdown(wait=False)
    return {"name": name, "records": list(dict.fromkeys(i[4][0] for i in infos)),
            "time_ms": round((time.monotonic() - start) * 1000, 1)}


# -- result --------------------------------------------------------------------------------------------
@dataclass
class Check:
    layer: str
    mark: str
    text: str


@dataclass
class Diagnosis:
    title: str
    understood: str = ""
    checks: list[Check] = field(default_factory=list)
    clues: list[str] = field(default_factory=list)
    cause: str = ""
    fix: list[str] = field(default_factory=list)
    buttons: list[Button] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)  # own devices whose config changed in the last 24 h

    def add(self, layer: str, mark: str, text: str) -> None:
        self.checks.append(Check(layer, mark, text))

    def found(self, cause: str, fix: list[str] | None = None, buttons: list[Button] | None = None) -> None:
        """Record the root cause; the first one found wins (it is the lowest failing layer)."""
        if not self.cause:
            self.cause = cause
            self.fix = list(fix or [])
            self.buttons += buttons or []

    @property
    def failed(self) -> bool:
        return any(c.mark == FAIL for c in self.checks)

    def format(self) -> str:
        lines = [f"🩺 **დიაგნოსტიკა: {self.title}**"]
        if self.understood:
            lines.append(f"_{self.understood}_")
        lines.append("")
        lines += [f"{c.mark} **{c.layer}:** {c.text}" for c in self.checks]
        if self.clues:
            lines += ["", "📎 **კონტექსტი**"] + [f"• {c}" for c in self.clues]
        if self.cause:
            lines += ["", f"🎯 **მიზეზი:** {self.cause}"]
        if self.fix:
            lines += ["🔧 **რა გავაკეთო:**"] + [f"{i}. {f}" for i, f in enumerate(self.fix, 1)]
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {"title": self.title, "understood": self.understood,
                "checks": [{"layer": c.layer, "result": c.mark, "text": c.text} for c in self.checks],
                "clues": self.clues, "root_cause": self.cause, "next_steps": self.fix}


# -- what did the user mean? -----------------------------------------------------------------------------
@dataclass
class Intent:
    kind: str  # internet | slow | device | target | wifi | vpn | dhcp
    target: str = ""
    site: str = ""


def _has(text: str, words: tuple[str, ...]) -> bool:
    return any(w in text for w in words)


def _device_in(text: str, inv) -> str:
    if inv is None:
        return ""
    for name in sorted(inv.devices, key=len, reverse=True):
        if re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(name)}(?![A-Za-z0-9_.])", text, re.I):
            return name
    hosts = {d.host: n for n, d in inv.devices.items()}
    for ip in _IP_RE.findall(text):
        if ip in hosts:
            return hosts[ip]
    return ""


def classify(text: str, inv=None) -> Intent:
    low = (text or "").lower()
    site = ""
    if inv is not None:
        for s in sorted({d.site for d in inv.devices.values() if d.site}, key=len, reverse=True):
            if s.lower() in low:
                site = s
                break
    if _has(low, _VPN):
        return Intent("vpn", _device_in(text, inv), site)
    if _has(low, _DHCP):
        return Intent("dhcp", site=site)
    name = _device_in(text, inv)
    if name:
        return Intent("device", name, site)
    if m := _URL_RE.search(text or ""):
        return Intent("target", m.group(0).rstrip(".,;)"), site)
    for ip in _IP_RE.findall(text or ""):
        try:
            ipaddress.ip_address(ip)
            return Intent("target", ip, site)
        except ValueError:
            continue
    if m := _HOST_RE.search(text or ""):
        return Intent("target", m.group(1).lower(), site)
    if _has(low, _WIFI) and not _has(low, _SLOW):
        return Intent("wifi", site=site)
    if _has(low, _SLOW):
        return Intent("slow", site=site)
    return Intent("internet", site=site)


# -- shared pieces --------------------------------------------------------------------------------------
def _signal(info: dict) -> int:
    return int(re.sub(r"\D", "", info.get("signal") or "0") or 0)


def _own_devices(s) -> tuple[object | None, list, str]:
    """(inventory, devices, note). Devices are empty when the inventory is missing or still the sample one."""
    from ..config import PROJECT_ROOT
    from ..doctor import _same_devices

    try:
        inv = s.inventory()
    except Exception as exc:  # noqa: BLE001 - a broken devices.yaml must not stop the diagnosis
        return None, [], f"inventory ვერ ჩაიტვირთა ({type(exc).__name__}) — ჩემი მოწყობილობები არ შემოწმდა"
    if not inv.devices:
        return inv, [], ""
    if _same_devices(PROJECT_ROOT / "inventory" / "devices.example.yaml", inv):
        return inv, [], "inventory ჯერ სანიმუშოა (devices.yaml) — ჩემი მოწყობილობები არ შემოწმდა"
    return inv, list(inv.devices.values()), ""


def _clues(d: Diagnosis, s, devices: list, hours: float = 24) -> None:
    from .ops import active_targets

    now = datetime.now()
    names = {x.name for x in devices}
    try:
        quiet = active_targets(s.state)
    except Exception:  # noqa: BLE001
        quiet = set()
    if quiet:
        d.clues.append("🛠 ახლა მიმდინარეობს დაგეგმილი სამუშაოები: " + ("ყველაფერზე" if "*" in quiet else ", ".join(sorted(quiet))))
    def relevant(devs) -> bool:  # alerts about devices outside this check (other site, sample inventory) are noise
        devs = [x for x in devs if x]
        return not devs or bool(names & set(devs))

    cutoff = (now - timedelta(hours=2)).isoformat(timespec="seconds")
    recent = [a for a in s.alerts.recent(30) if a.get("ts", "") >= cutoff and relevant(a.get("devices") or [])]
    for a in recent[:4]:
        d.clues.append(f"🔔 {a['ts'][11:16]} {a['text'].splitlines()[0][:110]}")
    try:
        from .incidents import IncidentStore, _line

        for i in [i for i in IncidentStore(s.state).search(open_only=True, limit=20) if relevant([i.get("device", "")])][:3]:
            d.clues.append("🗂 ღია ინციდენტი " + _line(i))
    except Exception:  # noqa: BLE001
        pass
    if not devices:
        return
    try:
        logs = s.syslog.search("", "", hours=1, max_severity=3, limit=200)
    except Exception:  # noqa: BLE001
        logs = []
    per: dict[str, list] = {}
    for e in logs:
        if e.get("device") in names:
            per.setdefault(e["device"], []).append(e)
    for name, items in sorted(per.items(), key=lambda kv: -len(kv[1]))[:3]:
        d.clues.append(f"📜 {name}: {len(items)} შეცდომა ლოგებში ბოლო 1 სთ — ბოლო: {items[-1]['message'][:90]}")
    from ..backup import BackupStore, changes_since
    from ..config import settings

    store = BackupStore(settings.backup_dir)
    order = list({x.name: x for x in rbk._routers(devices) + devices}.values())  # noqa: SLF001 - routers first, no repeats
    for dev in order[:MAX_CHANGE_CHECKS]:
        if dev.name in d.changed:
            continue
        try:
            ch = changes_since(store, dev.name, hours)
        except Exception:  # noqa: BLE001
            continue
        if ch and ch.get("changed"):
            d.changed.append(dev.name)
            d.clues.append(f"✏️ {dev.name}-ის კონფიგურაცია შეიცვალა ({ch['to'][5:16].replace('T', ' ')}, "
                           f"+{ch['added']}/−{ch['removed']} ხაზი)")


def _check_devices(d: Diagnosis, inv, devices: list, deep: bool) -> dict:
    """Reachability of own devices; with deep=True also the routers' default route and their own ping to 8.8.8.8."""
    from ..tools import device as dev

    out = {"down": [], "no_route": [], "no_internet": []}
    reach = {r.device: r for r in check_many(devices, timeout=2.0)}
    out["down"] = sorted(n for n, r in reach.items() if not r.up)
    d.add("ჩემი მოწყობილობები", OK if not out["down"] else WARN if len(out["down"]) < len(reach) else FAIL,
          f"{len(reach) - len(out['down'])}/{len(reach)} ხელმისაწვდომი"
          + (" — მიუწვდომელი: " + ", ".join(out["down"][:6]) if out["down"] else ""))
    if not deep:
        return out
    for r in rbk._routers(devices):  # noqa: SLF001
        if not reach[r.name].up:
            continue
        fam = rbk._family(r)  # noqa: SLF001
        cmds = [rbk._DEFAULT_ROUTE_CMD.get(fam, "show ip route 0.0.0.0")]  # noqa: SLF001
        if fam in rbk._DEVICE_PING_CMD:  # noqa: SLF001
            cmds.append(rbk._DEVICE_PING_CMD[fam])  # noqa: SLF001
        try:
            res = dev.run_commands(inv, r, cmds, parse=False)
        except Exception as exc:  # noqa: BLE001
            d.add(r.name, WARN, f"ბრძანებები ვერ გაეშვა ({type(exc).__name__})")
            continue
        text = res[0].get("output", "") if res else ""
        has_route = bool(re.search(r"0\.0\.0\.0(/0| 0\.0\.0\.0)|Gateway of last resort is \d|S\*|dst-address=0\.0\.0\.0/0", text)) \
            and "not set" not in text and "not in table" not in text
        d.add(r.name, OK if has_route else FAIL, "default route " + ("არის" if has_route else "ვერ ვიპოვე"))
        if not has_route:
            out["no_route"].append(r.name)
        if len(res) > 1:
            ok = rbk._ping_ok(res[1].get("output", ""))  # noqa: SLF001
            if ok is not None:
                d.add(r.name, OK if ok else FAIL, "თვითონ 8.8.8.8-მდე " + ("აღწევს" if ok else "ვერ აღწევს"))
                if not ok:
                    out["no_internet"].append(r.name)
    return out


def _skip(d: Diagnosis, layers: list[str], why: str) -> None:
    for layer in layers:
        d.add(layer, SKIP, why)


# -- chains -------------------------------------------------------------------------------------------
def internet_chain(d: Diagnosis, s, p: Probes, inv, devices: list, slow: bool = False) -> None:
    rest = ["Wi-Fi", "როუტერი", "ინტერნეტი", "DNS", "ვებ"]

    # 1. this PC has an address
    ip = p.local_ip()
    if not ip or ip.startswith("127."):
        d.add("ეს კომპიუტერი", FAIL, "ქსელის მისამართი არ აქვს")
        _skip(d, rest, "გამოტოვებულია")
        d.found("კომპიუტერი (სადაც NetAgent მუშაობს) ქსელთან მიერთებული არ არის.",
                ["შეამოწმე კაბელი ან ჩართულია თუ არა Wi-Fi", "Windows: ქსელის ხატულა (ქვედა მარჯვენა კუთხე) → ნახე, რომელ ქსელზე ხარ"])
        return
    if ip.startswith("169.254."):
        d.add("ეს კომპიუტერი", FAIL, f"IP {ip} — როუტერისგან მისამართი ვერ მიიღო (DHCP)")
        _skip(d, rest, "გამოტოვებულია")
        d.found("როუტერი IP მისამართს არ აძლევს (DHCP არ მუშაობს ან pool გავსებულია).",
                ["გადატვირთე როუტერი (30 წამით გამორთე დენიდან)", "კომპიუტერზე: `ipconfig /release` და `ipconfig /renew`",
                 "ოფისში: /diagnose dhcp — როუტერზე pool-ის შემოწმება"], [Button("🧾 DHCP", "/diagnose dhcp")])
        return
    d.add("ეს კომპიუტერი", OK, f"IP {ip}")

    # 2. Wi-Fi signal (Windows only)
    rest.pop(0)
    weak = False
    w = p.wifi()
    if w:
        sig = _signal(w)
        weak = sig < 40
        d.add("Wi-Fi", OK if sig >= 60 else WARN if sig >= 40 else FAIL,
              f"სიგნალი {sig}% ({w.get('ssid') or '?'}" + (f", არხი {w['channel']}" if w.get("channel") else "") + ")")
    elif w == {}:
        d.add("Wi-Fi", OK, "კაბელით ხარ მიერთებული (Wi-Fi არ გამოიყენება)")

    # 3. router
    rest.pop(0)
    gw = p.gateway()
    if not gw:
        d.add("როუტერი", FAIL, "default gateway არ არის")
        _skip(d, rest, "გამოტოვებულია")
        d.found("კომპიუტერმა არ იცის, სად არის როუტერი (default gateway არ აქვს).",
                ["`ipconfig /renew`", "თუ IP ხელით გაქვს დაწერილი — ჩაწერე Default gateway ან ჩართე „Obtain automatically“"])
        return
    pr = p.ping(gw, 10 if slow else 4)
    loss, avg = pr.get("packet_loss_percent"), pr.get("avg_rtt_ms")
    lan_bad = False
    if not pr.get("reachable"):
        alive = [port for port in (80, 443, 53) if p.tcp(gw, port)]
        if alive:
            d.add("როუტერი", OK, f"{gw}: ping-ს არ პასუხობს, მაგრამ ჩართულია (პორტი {alive[0]} ღიაა)")
        else:
            d.add("როუტერი", FAIL, f"{gw}: არ პასუხობს")
            _skip(d, rest, "გამოტოვებულია — როუტერამდეც ვერ მივდივარ")
            if weak:
                d.found("Wi-Fi სიგნალი ძალიან სუსტია და როუტერამდე კავშირი წყდება.",
                        ["როუტერთან ახლოს მიდი ან კაბელით შეაერთე", "კედლები/სართულები: დაამატე mesh ან წვდომის წერტილი"],
                        [Button("📶 Wi-Fi", "/diagnose wifi")])
            else:
                d.found(f"როუტერი ({gw}) არ პასუხობს — პრობლემა ლოკალურ ქსელშია, ინტერნეტამდე ჯერ არ მიდის.",
                        ["როუტერი ჩართულია? ნათურები ანთია?", "გადატვირთე როუტერი (30 წამით გამორთე დენიდან)",
                         "Wi-Fi-ზე: გაითიშე და ხელახლა შეუერთდი ქსელს · კაბელზე: სხვა პორტში ან სხვა კაბელით სცადე"])
            return
    else:
        lan_bad = (loss or 0) >= 10 or (avg or 0) > 30
        d.add("როუტერი", FAIL if (loss or 0) >= 30 else WARN if lan_bad else OK,
              f"{gw}: დანაკარგი {loss if loss is not None else '?'}%" + (f", საშუალოდ {avg:.0f} ms" if avg is not None else ""))

    # 4. internet by IP
    rest.pop(0)
    inet = p.internet()
    if not inet["online"]:
        d.add("ინტერნეტი", FAIL, "1.1.1.1, 8.8.8.8, 9.9.9.9 — არცერთი არ პასუხობს")
        _skip(d, rest, "გამოტოვებულია — ინტერნეტი არ არის")
        found = _check_devices(d, inv, devices, deep=True) if devices else {}
        _clues(d, s, devices)
        fix_first = [f"{n}-ის კონფიგურაცია ახლახან შეიცვალა — ჯერ ის ცვლილება შეამოწმე (`python -m netagent diff {n}`)"
                     for n in d.changed[:2]]
        if found.get("no_route"):
            d.found(f"{', '.join(found['no_route'])}-ზე default route არ არის — როუტერმა არ იცის, საით გაუშვას ინტერნეტის ტრაფიკი.",
                    fix_first + ["შეამოწმე WAN ინტერფეისი (up?) და მისი IP/DHCP პროვაიდერისგან",
                                 "სტატიკური route-ის შემთხვევაში: დაბრუნდა თუ არა `ip route 0.0.0.0 0.0.0.0 <ISP gw>`"],
                    [Button(f"🔎 {found['no_route'][0]}", f"/diagnose {found['no_route'][0]}")])
        else:
            who = f"როუტერს ({gw}) კავშირი აქვს" + (f", {', '.join(found['no_internet'])}-ს route აქვს, მაგრამ თვითონაც ვერ აღწევს"
                                                    if found.get("no_internet") else "")
            d.found(f"{who}, ინტერნეტი კი არ გადის — პრობლემა WAN-ზეა: პროვაიდერი, ONT/მოდემი ან WAN კაბელი.",
                    fix_first + ["როუტერზე ნახე WAN / Internet ნათურა", "ONT/მოდემი გადატვირთე (დენიდან 30 წამით)",
                                 "დაურეკე პროვაიდერს — /isp report 1 გაჩვენებს, როდის გაითიშა"],
                    [Button("🌐 ISP", "/isp"), Button("📄 რეპორტი", "/isp report 1")])
        return
    d.add("ინტერნეტი", OK if not inet["loss"] else WARN,
          f"პასუხობს ({inet['latency_ms']} ms" + (f", {inet['loss']}% სამიზნე არ პასუხობს" if inet["loss"] else "") + ")")

    # 5. DNS
    rest.pop(0)
    r = p.dns("google.com")
    if not r.get("records"):
        r2 = p.dns("google.com", "1.1.1.1")
        if r2.get("records"):
            d.add("DNS", FAIL, f"შენი DNS არ პასუხობს ({r.get('error', '?')}), 1.1.1.1 კი მუშაობს")
            d.found("ინტერნეტი არის, მაგრამ DNS სერვერი (ჩვეულებრივ როუტერი ან პროვაიდერი) არ პასუხობს — ამიტომ საიტები „არ იხსნება“.",
                    ["როუტერის DHCP/DNS პარამეტრებში ჩაწერე 1.1.1.1 და 8.8.8.8", "Windows-ში: `ipconfig /flushdns`",
                     "დროებით: ქსელის ბარათზე DNS ხელით 1.1.1.1"])
        else:
            d.add("DNS", FAIL, "არცერთი DNS არ პასუხობს (1.1.1.1-იც)")
            d.found("ინტერნეტი არის, მაგრამ DNS (პორტი 53) იბლოკება — firewall, ანტივირუსი ან პროვაიდერი.",
                    ["შეამოწმე firewall-ის წესები UDP/TCP 53-ზე", "ანტივირუსის „ვებ-დაცვა“ დროებით გამორთე და სცადე"])
        _skip(d, rest, "გამოტოვებულია — DNS არ მუშაობს")
        _clues(d, s, devices)
        return
    dns_ms = r.get("time_ms") or 0
    dns_slow = dns_ms > 500
    d.add("DNS", WARN if dns_slow else OK, f"google.com → {r['records'][0]} ({dns_ms:.0f} ms" + (" — ნელია" if dns_slow else "") + ")")

    # 6. web
    h = p.http("https://www.google.com/generate_204")
    if not h["ok"]:
        d.add("ვებ", FAIL, f"HTTPS არ იხსნება ({h['error']})")
        d.found("IP და DNS მუშაობს, მაგრამ ვებ-გვერდები არ იხსნება — ჩვეულებრივ proxy, firewall/ანტივირუსი ან "
                "შესვლის გვერდი (captive portal: სასტუმროს/ოფისის Wi-Fi).",
                ["ბრაუზერში გახსენი ნებისმიერი http:// საიტი — თუ შესვლის გვერდი გამოჩნდა, გაიარე", "Windows: Settings → Proxy → გამორთე",
                 "ანტივირუსის ვებ-დაცვა დროებით გამორთე"])
    elif h["status"] != 204:
        d.add("ვებ", WARN, f"პასუხი {h['status']} (უნდა იყოს 204) — სავარაუდოდ შესვლის გვერდი (captive portal) ან proxy")
        d.found("ქსელი ვებ-მოთხოვნებს სხვა გვერდზე გადამისამართებს (captive portal ან proxy).",
                ["ბრაუზერში გახსენი http://neverssl.com და გაიარე შესვლის გვერდი"])
    else:
        d.add("ვებ", OK, f"HTTPS მუშაობს ({h['ms']} ms)")

    # 7. ISP over the last 24 h (measured every minute by the ISP monitor)
    flaky = 0
    try:
        summ = isp.monitor_for(s).summary(1)
    except Exception:  # noqa: BLE001
        summ = {"samples": 0}
    if summ.get("samples"):
        flaky = len(summ["outages"])
        lat_bad = (summ["latency_avg_ms"] or 0) > 80 or (summ["loss_avg_percent"] or 0) > 2
        d.add("ISP 24 სთ", WARN if flaky >= 2 or lat_bad else OK,
              f"uptime {summ['uptime_percent']}%, გათიშვები {flaky}" + (f", საშუალოდ {summ['latency_avg_ms']} ms" if summ["latency_avg_ms"] else "")
              + (f", დანაკარგი {summ['loss_avg_percent']}%" if summ["loss_avg_percent"] else ""))
    else:
        lat_bad = False
    speed_low = False
    if slow:
        tests = s.state.get("isp_speedtests") or []
        plan = env_int("NETAGENT_ISP_PLAN_MBPS", 0)
        if tests:
            t = tests[-1]
            speed_low = bool(plan) and t["down_mbps"] < plan * 0.5
            d.add("სიჩქარე", WARN if speed_low else OK, f"ბოლო ტესტი ({t['ts'][5:16].replace('T', ' ')}): ⬇️ {t['down_mbps']} / ⬆️ {t['up_mbps']} Mbit/s"
                  + (f" — ტარიფის {round(100 * t['down_mbps'] / plan)}%" if plan else ""))
        d.buttons.append(Button("⚡ სიჩქარის ტესტი ახლა", "/speedtest"))

    # 8. own devices
    found = _check_devices(d, inv, devices, deep=False) if devices else {"down": []}
    slow_devs = []
    if slow and devices:
        for dev in devices:
            st = s.history.stats(dev.name, 1)
            if st.get("samples") and st.get("p95_ms", 0) >= 200:
                slow_devs.append(f"{dev.name} ({st['p95_ms']} ms)")
        if slow_devs:
            d.add("ჩემი მოწყობილობები", WARN, "ნელა პასუხობს (p95, 1 სთ): " + ", ".join(slow_devs[:5]))
    _clues(d, s, devices)

    # verdict when nothing hard-failed above
    if slow:
        if lan_bad:
            d.found("დაყოვნება/დანაკარგი უკვე როუტერამდე ჩნდება — პრობლემა Wi-Fi-ში ან ლოკალურ ქსელშია, არა პროვაიდერთან.",
                    ["როუტერთან ახლოს ან კაბელით სცადე", "ვინმე ბევრს ხომ არ წერს/ტვირთავს? — /traffic", "/diagnose wifi — არხი და სიგნალი"],
                    [Button("📶 Wi-Fi", "/diagnose wifi")])
        elif weak:
            d.found("Wi-Fi სიგნალი სუსტია — სიჩქარე ამის გამო ეცემა.", ["როუტერთან ახლოს მიდი ან 5 GHz ქსელს შეუერთდი"],
                    [Button("📶 Wi-Fi", "/diagnose wifi")])
        elif speed_low or lat_bad:
            d.found("ლოკალური ქსელი კარგადაა, ნელია პროვაიდერის მხარე" + (" (სიჩქარე ტარიფის ნახევარზე ნაკლებია)" if speed_low else
                                                                       " (დიდი დაყოვნება ან დანაკარგი)") + ".",
                    ["/isp report 30 — ანგარიში პროვაიდერისთვის", "დაურეკე პროვაიდერს და ანგარიში გაუგზავნე"],
                    [Button("📄 რეპორტი 30 დღე", "/isp report 30")])
        elif dns_slow:
            d.found(f"DNS ნელია ({dns_ms:.0f} ms ერთ სახელზე) — ყოველი ახალი საიტი დაყოვნებით იხსნება, თვითონ ინტერნეტი კი სწრაფია.",
                    ["როუტერის DHCP/DNS პარამეტრებში ჩაწერე 1.1.1.1 და 8.8.8.8"])
        elif slow_devs:
            d.found("ინტერნეტი ნორმალურია; ნელა პასუხობს ჩემი მოწყობილობები: " + ", ".join(slow_devs[:3]) + ".",
                    ["/runbook slow — CPU-ის შემოწმება", "შეამოწმე მათკენ მიმავალი link-ის დატვირთვა/შეცდომები (/traffic)"])
        else:
            d.found("ახლა ყველა გაზომვა ნორმალურია. თუ ნელია მხოლოდ ერთ მოწყობილობაზე ან ერთ საიტზე — პრობლემა იქ არის.",
                    ["გაუშვი სიჩქარის ტესტი ღილაკით", "/diagnose <საიტი ან IP> — კონკრეტული მისამართის შემოწმება"])
        return
    if flaky >= 2:
        d.found(f"ახლა მუშაობს, მაგრამ ბოლო 24 სთ-ში ინტერნეტი {flaky}-ჯერ გაითიშა — არასტაბილური პროვაიდერი ან WAN კავშირი.",
                ["/isp — როდის და რამდენ ხანს", "/isp report 30 — ანგარიში პროვაიდერისთვის"], [Button("🌐 ISP", "/isp")])
    elif found["down"]:
        d.found("ინტერნეტი მუშაობს; მიუწვდომელია: " + ", ".join(found["down"][:4]) + ".",
                [f"/diagnose {found['down'][0]} — დეტალური შემოწმება"], [Button(f"🔎 {found['down'][0]}", f"/diagnose {found['down'][0]}")])
    else:
        d.found("ამ კომპიუტერიდან ყველაფერი მუშაობს. თუ ინტერნეტი არ მუშაობს კონკრეტულ მოწყობილობაზე — პრობლემა იმ მოწყობილობაზეა "
                "(მისი Wi-Fi, IP, ან VLAN).",
                ["/scan — ჩანს თუ არა ის ქსელში", "/diagnose <მისი IP> — მისი შემოწმება"], [Button("🔍 სკანი", "/scan")])


def target_chain(d: Diagnosis, s, p: Probes, inv, devices: list, target: str) -> None:
    url = target if target.lower().startswith(("http://", "https://")) else ""
    parsed = urlparse(url) if url else None
    host = (parsed.hostname or "") if parsed else target
    try:
        port = parsed.port if parsed else None
    except ValueError:
        port = None
    if parsed and not port:
        port = 443 if parsed.scheme == "https" else 80
    try:
        ipaddress.ip_address(host)
        ip = host
    except ValueError:
        ip = ""
    if not ip:
        r = p.dns(host)
        if not r.get("records"):
            err = r.get("error", "ჩანაწერი არ არის")
            d.add("DNS", FAIL, f"{host}: {err}")
            if not p.dns("google.com").get("records"):  # first: does name resolution work at all?
                d.found("DNS საერთოდ არ მუშაობს — ჯერ ზოგადი შემოწმება გაუშვი.", ["/diagnose — ინტერნეტის შემოწმება"],
                        [Button("🩺 ინტერნეტი", "/diagnose")])
            elif "NXDOMAIN" in err:
                d.found(f"დომენი {host} არ არსებობს — ალბათ მისამართი არასწორადაა დაწერილი.", ["შეამოწმე მართლწერა"])
            else:
                d.found(f"DNS მუშაობს, მაგრამ {host}-ს ვერ პოულობს — პრობლემა ამ დომენის DNS-შია (მისი მფლობელის მხარე).",
                        ["სცადე მოგვიანებით; თუ შენი დომენია — შეამოწმე მისი DNS ჩანაწერები"])
            return
        ip = r["records"][0]
        d.add("DNS", OK, f"{host} → {ip}")
    try:
        private = ipaddress.ip_address(ip).is_private
    except ValueError:
        private = False

    from . import lan

    try:
        mac = lan._last_seen(s.state).get(ip, "")  # noqa: SLF001
        name = homenet.device_names(s.state).get(mac) or homenet.device_names(s.state).get(f"ip:{ip}", "")
    except Exception:  # noqa: BLE001
        mac, name = "", ""
    if name:
        d.understood += f" · ეს არის „{name}“"

    pr = p.ping(ip, 4)
    pinged = bool(pr.get("reachable"))
    d.add("ping", OK if pinged else WARN, f"{ip}: " + (f"პასუხობს ({pr['avg_rtt_ms']:.0f} ms, დანაკარგი {pr.get('packet_loss_percent', 0)}%)"
                                                       if pinged and pr.get("avg_rtt_ms") is not None else "პასუხობს" if pinged else "არ პასუხობს"))
    ports = [port] if port else [443, 80, 22, 3389, 445, 8080]
    open_ = [x for x in ports if p.tcp(ip, x)]
    if port:
        d.add("პორტი", OK if open_ else FAIL, f"{port}: " + ("ღიაა" if open_ else "დახურულია / არ პასუხობს"))
    else:
        d.add("პორტები", OK if open_ else WARN, ("ღიაა: " + ", ".join(map(str, open_))) if open_ else
              "არცერთი ხშირი პორტი (443, 80, 22, 3389, 445, 8080) არ პასუხობს")
    web = None
    if url and open_:
        web = p.http(url, timeout=10, follow=True)
        if web["ok"]:
            d.add("ვებ", OK if web["status"] < 500 else FAIL, f"HTTP {web['status']} ({web['ms']} ms)")
        else:
            d.add("ვებ", FAIL, web["error"])

    if private and devices and inv is not None:
        try:
            from .pathtrace import trace

            t = trace(inv, p.local_ip(), ip)
            hops = " → ".join(h["device"] for h in t.get("hops", []))
            d.add("გზა", OK if str(t.get("result", "")).startswith("✅") else WARN,
                  (f"{hops}: " if hops else "") + str(t.get("result", ""))[:160])
        except Exception:  # noqa: BLE001 - the path trace is a bonus, not required
            pass
    _clues(d, s, devices)

    who = f"„{name}“ ({ip})" if name else f"{host} ({ip})" if host != ip else ip
    if pinged or open_:
        if url and web is not None and (not web["ok"] or web["status"] >= 500):
            d.found(f"{who} ქსელში მისაწვდომია, მაგრამ ვებ-სერვისი შეცდომას აბრუნებს — პრობლემა თვითონ სერვისშია (სერვერი/აპლიკაცია).",
                    ["თუ შენია: გადატვირთე სერვისი, ნახე მისი ლოგები", "თუ სხვისია: ელოდე ან მიწერე მის ადმინს"])
        elif port and not open_:
            d.found(f"{who} ჩართულია, მაგრამ პორტი {port} დახურულია — სერვისი გათიშულია ან firewall ბლოკავს.",
                    ["შეამოწმე, მუშაობს თუ არა სერვისი", f"firewall-ზე დაუშვი {port}"])
        else:
            d.found(f"{who} მისაწვდომია" + ("" if pinged else " (ping-ს ბლოკავს, სერვისი კი პასუხობს)") + ". ქსელის მხრივ პრობლემა არ ჩანს.",
                    ["თუ მაინც არ მუშაობს — პრობლემა პროგრამაში/ანგარიშშია, არა ქსელში"])
        return
    # nothing answers: is it the device or the way to it?
    in_arp = bool(p.arp().get(ip)) if private else False
    gw = p.gateway()
    gw_ok = bool(gw) and (p.ping(gw, 2).get("reachable") or p.tcp(gw, 80))
    if not gw_ok:
        d.add("როუტერი", FAIL, f"{gw or '?'}: არ პასუხობს")
        d.found("ეს კომპიუტერი როუტერსაც ვერ წვდება — ჯერ ზოგადი შემოწმება.", ["/diagnose"], [Button("🩺 ინტერნეტი", "/diagnose")])
    elif in_arp:
        d.found(f"{who} ქსელშია (ARP-ში ჩანს), მაგრამ ყველაფერს ბლოკავს — მასზე firewall არის ჩართული.",
                ["Windows-ზე: Firewall → „File and Printer Sharing (Echo Request)“ დაუშვი ping-ისთვის",
                 "შეამოწმე, სწორ პორტს უკავშირდები თუ არა"])
    elif private:
        d.found(f"{who} არ პასუხობს და ქსელში არ ჩანს — გამორთულია, სხვა ქსელში/VLAN-შია, ან IP შეეცვალა.",
                ["/scan — სად არის ახლა (ახალი IP?)", "შეამოწმე დენი და კაბელი/Wi-Fi"], [Button("🔍 სკანი", "/scan")])
    else:
        d.found(f"{who} ინტერნეტში არ პასუხობს, ინტერნეტი კი მუშაობს — პრობლემა მის მხარესაა (სერვერი ან მისი პროვაიდერი).",
                ["სცადე მოგვიანებით", "შეამოწმე სხვა ქსელიდან (მობილური ინტერნეტით)"])


def runbook_chain(d: Diagnosis, s, name: str, args: list[str]) -> None:
    rb = rbk.run(s, name, args)
    for st in rb.steps:
        layer, _, text = st.text.partition(": ")
        if text and len(layer) <= 30:
            d.add(layer, st.mark, text)
        else:
            d.add("შემოწმება", st.mark, st.text)
    _, devices, _ = _own_devices(s)
    if name == "device" and args:
        try:
            devices = [s.inventory().get(args[0])]
        except Exception:  # noqa: BLE001
            devices = []
    _clues(d, s, devices)
    bad = [c for c in d.checks if c.mark in {FAIL, WARN}]
    d.found(rb.verdict or ("პრობლემა ვერ ვიპოვე." if not bad else "ყურადღება მიაქციე ⚠️/❌ პუნქტებს."))


TITLES = {"internet": "ინტერნეტი არ მუშაობს", "slow": "ქსელი/ინტერნეტი ნელია", "device": "მოწყობილობა {t}",
          "target": "{t}", "wifi": "Wi-Fi", "vpn": "VPN", "dhcp": "IP მისამართი არ ეძლევა (DHCP)"}


def diagnose(s, text: str = "", probes: Probes | None = None) -> Diagnosis:
    p = probes or Probes()
    text = (text or "").strip()[:MAX_TEXT]
    inv, devices, note = _own_devices(s)
    intent = classify(text, inv if devices else None)  # a sample inventory must not turn "R1" into an SSH session
    if intent.site:
        devices = [x for x in devices if x.site == intent.site]
    d = Diagnosis(TITLES[intent.kind].format(t=intent.target))
    d.understood = ("გავიგე: „" + text + "“ → " if text else "აღწერა არ მოგიცია → ") + {
        "internet": "ვამოწმებ ინტერნეტს ფენა-ფენა", "slow": "ვეძებ, სად ჩნდება დაყოვნება",
        "device": f"ვამოწმებ {intent.target}-ს", "target": f"ვამოწმებ {intent.target}-მდე კავშირს",
        "wifi": "Wi-Fi-ს შემოწმება", "vpn": "VPN გვირაბების შემოწმება", "dhcp": "DHCP-ის შემოწმება"}[intent.kind]
    if intent.site:
        d.understood += f" · მხოლოდ საიტი „{intent.site}“ ({len(devices)} მოწყობილობა)"
    if note and intent.kind in {"internet", "slow", "target"}:
        d.clues.append("ℹ️ " + note)
    try:
        if intent.kind in {"internet", "slow"}:
            internet_chain(d, s, p, inv, devices, slow=intent.kind == "slow")
        elif intent.kind == "target":
            target_chain(d, s, p, inv, devices, intent.target)
        elif intent.kind == "device":
            runbook_chain(d, s, "device", [intent.target])
        elif intent.kind in {"vpn", "dhcp"} and not devices:
            d.add("ჩემი მოწყობილობები", SKIP, note or "inventory ცარიელია")
            d.found(f"{intent.kind.upper()}-ის შესამოწმებლად როუტერი inventory-ში უნდა იყოს (inventory/devices.yaml).",
                    ["დაამატე როუტერი: /discover 192.168.1.0/24"])
        else:
            runbook_chain(d, s, intent.kind, [intent.target] if intent.target else [])
    except Exception as exc:  # noqa: BLE001 - always return what was found so far
        d.add("შეცდომა", WARN, f"შემოწმება შუაში შეწყდა ({type(exc).__name__}: {str(exc)[:120]})")
        d.found("დიაგნოსტიკა ბოლომდე ვერ დასრულდა — ზემოთ ნაჩვენებია, რაც მოვასწარი.")
    d.buttons.append(Button("🔁 თავიდან", "/diagnose " + text if text else "/diagnose"))
    return d


# -- command / AI tool -----------------------------------------------------------------------------------
def diagnose_cmd(s, args, user) -> Result:
    d = diagnose(s, " ".join(args))
    seen, buttons = set(), []
    for b in d.buttons:
        if b.command not in seen:
            seen.add(b.command)
            buttons.append(b)
    return Result(d.format(), buttons=buttons[:6])


COMMANDS = {"diagnose": diagnose_cmd}
HELP = ["/diagnose <რა არ მუშაობს> — ავტომატური დიაგნოსტიკა: თვითონ არჩევს შემოწმებებს და ასახელებს მიზეზს "
        "(მაგ. /diagnose ინტერნეტი ნელია · /diagnose R1 · /diagnose 192.168.1.50 · /diagnose google.com)"]
BOT_COMMANDS = [("diagnose", "ავტომატური დიაგნოსტიკა: რა არ მუშაობს და რატომ")]
TOOLS = [
    ({"name": "diagnose_problem",
      "description": "Root-cause diagnosis from the user's own description of a problem (e.g. 'internet does not work', "
                     "'internet is slow in office 2', 'R1', '192.168.1.50 is unreachable', 'google.com does not open', 'VPN is down'). "
                     "Picks the checks itself and runs them layer by layer (this PC, Wi-Fi, router, internet, DNS, web, "
                     "own devices, recent config changes/logs/alerts) and returns the first failing layer as root_cause "
                     "with next_steps. Read-only. Call it first whenever the user reports that something does not work.",
      "input_schema": {"type": "object", "properties": {"problem": {"type": "string", "description": "the user's words"}},
                       "required": []}},
     lambda ctx, problem="": diagnose(ctx.services, problem).as_dict()),
]


# -- automatic diagnosis when something goes down ----------------------------------------------------------
# A "device down" or "internet down" alert starts a diagnosis in the background; its root cause follows as a
# second alert a few seconds later. During an internet outage that alert cannot leave the house, so the cause
# is also kept and repeated with the "internet is back" alert.
AUTO_COOLDOWN = 600  # seconds between automatic diagnoses of the same target
ISP_KEY = "autodiag_isp"
_MONITORING = None
_RUNNING: set[str] = set()


def auto_enabled() -> bool:
    import os

    return os.getenv("NETAGENT_AUTODIAGNOSE", "on").strip().lower() not in {"off", "0", "false", "no"}


def jobs(monitoring) -> list:
    global _MONITORING
    _MONITORING = monitoring  # kept so on_alert can emit the follow-up alert
    return []


def auto_target(alert) -> str | None:
    """What to diagnose for this alert: a device name, "" for the internet, None for nothing."""
    if alert.kind == "down" and alert.devices:
        return alert.devices[0]
    if alert.kind == "isp" and "გაითიშა" in alert.text:
        return ""
    return None


def summary(d: Diagnosis, target: str, others: list[str] | None = None) -> str:
    head = f"🩺 **ავტოდიაგნოსტიკა — {target or 'ინტერნეტი'}**"
    if others:
        head += f" (ასევე მიუწვდომელია: {', '.join(others[:4])})"
    lines = [head, f"🎯 {d.cause or 'მიზეზი ვერ დადგინდა'}"]
    if d.fix:
        lines.append(f"🔧 {d.fix[0]}")
    return "\n".join(lines)


async def _auto(s, key: str, target: str, alert) -> None:
    import asyncio

    from ..monitoring import Alert

    try:
        d = await asyncio.to_thread(diagnose, s, target)
        if key == "internet":
            s.state.set(ISP_KEY, {"ts": datetime.now().isoformat(timespec="seconds"), "cause": d.cause})
        cmd = f"/diagnose {target}".strip()
        await _MONITORING.emit(Alert("diagnosis", summary(d, target, alert.devices[1:]), list(alert.devices),
                                     mutable=False, buttons=[Button("🩺 სრულად", cmd)]))
    except Exception:  # noqa: BLE001 - a failed diagnosis must never break alerting
        import logging

        logging.getLogger("netagent.diagnose").exception("auto diagnosis failed")
    finally:
        _RUNNING.discard(key)


def on_alert(s, alert) -> None:
    import asyncio

    if _MONITORING is None or not auto_enabled() or alert.kind == "diagnosis":
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if alert.kind == "isp" and "აღდგა" in alert.text:
        kept = s.state.get(ISP_KEY)
        if kept and kept.get("cause"):
            s.state.set(ISP_KEY, None)
            from ..monitoring import Alert

            loop.create_task(_MONITORING.emit(Alert(
                "diagnosis", f"🩺 **გათიშვის მიზეზი** (გაზომილი {kept['ts'][11:16]}-ზე)\n🎯 {kept['cause']}", [], mutable=False,
                buttons=[Button("📄 ISP რეპორტი", "/isp report 1")])))
        return
    target = auto_target(alert)
    if target is None:
        return
    key = target or "internet"
    last = (s.state.get("autodiag_last") or {}).get(key, 0)
    if key in _RUNNING or time.time() - last < AUTO_COOLDOWN:
        return
    _RUNNING.add(key)
    s.state.update("autodiag_last", lambda v: {**(v or {}), key: time.time()})
    loop.create_task(_auto(s, key, target, alert))
