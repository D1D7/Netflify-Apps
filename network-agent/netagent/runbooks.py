"""Runbooks: fixed diagnostic sequences that run step by step and end with a verdict.

  internet      — is the internet down, and where does it break?
  device <name> — everything about one device (reachability, health, logs, changes, notes)
  slow          — which devices respond slowly or are overloaded
Deterministic (no AI): each step is a tool call with a ✅/⚠️/❌ result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .health import check_many
from .inventory import Device
from .tools import device as dev
from .tools import network as net

OK, WARN, FAIL = "✅", "⚠️", "❌"


@dataclass
class Step:
    mark: str
    text: str


@dataclass
class RunbookResult:
    title: str
    steps: list[Step] = field(default_factory=list)
    verdict: str = ""

    def add(self, mark: str, text: str) -> None:
        self.steps.append(Step(mark, text))

    def format(self) -> str:
        lines = [f"📚 **{self.title}**", ""]
        lines += [f"{s.mark} {s.text}" for s in self.steps]
        if self.verdict:
            lines += ["", f"**დასკვნა:** {self.verdict}"]
        return "\n".join(lines)


RUNBOOKS = {
    "internet": "ინტერნეტი არ მუშაობს — სად წყდება?",
    "device": "მოწყობილობის სრული შემოწმება: /runbook device R1",
    "slow": "ქსელი ნელია — ვინ არის გადატვირთული?",
}


def _routers(devices: list[Device]) -> list[Device]:
    marked = [d for d in devices if any(k in f"{d.role} {d.name}".lower() for k in ("router", "gateway", "edge", "fw", "firewall"))]
    return marked or devices[:3]


_DEFAULT_ROUTE_CMD = {
    "mikrotik": "/ip route print where dst-address=0.0.0.0/0",
    "junos": "show route 0.0.0.0/0 exact",
    "huawei": "display ip routing-table 0.0.0.0 0",
    "fortinet": "get router info routing-table details 0.0.0.0",
}
_DEVICE_PING_CMD = {
    "ios": "ping 8.8.8.8 repeat 3 timeout 1",
    "junos": "ping 8.8.8.8 count 3 rapid",
    "huawei": "ping -c 3 8.8.8.8",
}


def _family(d: Device) -> str:
    from .watch import family

    fam = family(d.device_type)
    return "fortinet" if d.device_type.lower().startswith("fortinet") else fam


def _ping_ok(output: str) -> bool | None:
    m = re.search(r"Success rate is (\d+) percent", output) or re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
    if not m:
        return None
    value = float(m.group(1))
    return value > 0 if "Success" in m.group(0) else value < 100


def internet(s, args) -> RunbookResult:
    rb = RunbookResult("Runbook: ინტერნეტი")
    inv = s.inventory()
    devices = list(inv.devices.values())

    host = net.ping("8.8.8.8", 3)
    host_ok = host.get("reachable")
    if host.get("error"):
        rb.add(WARN, f"ამ კომპიუტერიდან ping ვერ შესრულდა: {host['error']}")
    else:
        rb.add(OK if host_ok else FAIL, f"ამ კომპიუტერიდან 8.8.8.8: {'პასუხობს' if host_ok else 'არ პასუხობს'}"
               + (f" ({host['avg_rtt_ms']:.0f} ms)" if host_ok and host.get("avg_rtt_ms") else ""))
    dns = net.dns_lookup("google.com")
    dns_ok = bool(dns.get("records"))
    rb.add(OK if dns_ok else FAIL, "DNS (google.com): " + ("მუშაობს" if dns_ok else f"არ მუშაობს — {dns.get('error', '')}"))
    if host_ok and not dns_ok:
        rb.verdict = "ინტერნეტი არის, მაგრამ DNS არ მუშაობს. შეამოწმე DNS სერვერები (როუტერზე ან DHCP-ში)."

    route_missing, device_ping_fail = [], []
    if devices:
        reach = {r.device: r for r in check_many(devices, timeout=2.0)}
        down = [r for r in reach.values() if not r.up]
        rb.add(OK if not down else WARN, f"მოწყობილობები: {len(reach) - len(down)}/{len(reach)} ხელმისაწვდომი"
               + (" — " + ", ".join(r.device for r in down[:5]) if down else ""))
        for d in _routers(devices):
            if not reach[d.name].up:
                rb.add(FAIL, f"{d.name}: მიუწვდომელია ({reach[d.name].reason})")
                continue
            fam = _family(d)
            cmds = []
            route_cmd = _DEFAULT_ROUTE_CMD.get(fam, "show ip route 0.0.0.0")
            cmds.append(route_cmd)
            if fam in _DEVICE_PING_CMD:
                cmds.append(_DEVICE_PING_CMD[fam])
            res = dev.run_commands(inv, d, cmds, parse=False)
            out = res[0].get("output", "") if res else ""
            has_route = bool(re.search(r"0\.0\.0\.0(/0| 0\.0\.0\.0)|Gateway of last resort is \d|S\*|dst-address=0\.0\.0\.0/0|0\.0\.0\.0/0", out)) \
                and "not set" not in out and "not in table" not in out
            rb.add(OK if has_route else FAIL, f"{d.name}: default route {'არის' if has_route else 'ვერ ვიპოვე'}")
            if not has_route:
                route_missing.append(d.name)
            if len(res) > 1:
                ok = _ping_ok(res[1].get("output", ""))
                if ok is not None:
                    rb.add(OK if ok else FAIL, f"{d.name}-დან 8.8.8.8: {'პასუხობს' if ok else 'არ პასუხობს'}")
                    if not ok:
                        device_ping_fail.append(d.name)

    if not rb.verdict:
        if host_ok and dns_ok:
            rb.verdict = "ინტერნეტი ამ კომპიუტერიდან მუშაობს. თუ ვინმესთან არ მუშაობს, შეამოწმე მისი VLAN/DHCP ან Wi-Fi."
        elif route_missing:
            rb.verdict = f"{', '.join(route_missing)}-ზე default route არ ჩანს — WAN/ISP კავშირი ან route-ის კონფიგურაცია შეამოწმე."
        elif device_ping_fail:
            rb.verdict = (f"{', '.join(device_ping_fail)}-დან ინტერნეტი არ ჩანს, route კი არის — სავარაუდოდ ISP-ის მხარეს "
                          "პრობლემაა. დაუკავშირდი ISP-ს (/notes-ში შეიძლება კონტაქტი გეწეროს).")
        else:
            rb.verdict = "ინტერნეტი არ ჩანს. შეამოწმე WAN კაბელი/ONT, როუტერის WAN ინტერფეისი და ISP."
    return rb


def device(s, args) -> RunbookResult:
    from .backup import BackupStore, changes_since
    from .config import settings
    from .watch import collect

    if not args:
        raise ValueError("გამოყენება: /runbook device R1")
    d = s.inventory().get(args[0])
    rb = RunbookResult(f"Runbook: {d.name}")
    r = check_many([d], timeout=3.0)[0]
    if not r.up:
        rb.add(FAIL, f"SSH ({d.host}:{d.port}) მიუწვდომელია — {r.reason}")
        ping = net.ping(d.host, 2)
        rb.add(OK if ping.get("reachable") else FAIL, f"ping {d.host}: {'პასუხობს' if ping.get('reachable') else 'არ პასუხობს'}")
        rb.verdict = ("მოწყობილობა ping-ს პასუხობს, მაგრამ SSH არა — შეამოწმე SSH სერვისი/ACL." if ping.get("reachable")
                      else "მოწყობილობა საერთოდ არ პასუხობს — დენი, კაბელი ან მის წინ მდგარი switch/router შეამოწმე.")
    else:
        rb.add(OK, f"SSH ხელმისაწვდომია ({r.latency_ms:.0f} ms)")
        snap = collect(s.inventory(), d, everything=True)
        downs = sorted(n for n, st in snap.interfaces.items() if st == "down")
        if snap.interfaces:
            rb.add(OK if not downs else WARN, f"ინტერფეისები: {sum(1 for x in snap.interfaces.values() if x == 'up')} up"
                   + (f", down: {', '.join(downs[:8])}" if downs else ""))
        for proto, data, good in (("BGP", snap.bgp, {"established"}), ("OSPF", snap.ospf, {"full", "2way", "2-way"})):
            if data:
                bad = [p for p, st in data.items() if st not in good]
                rb.add(OK if not bad else FAIL, f"{proto}: {len(data) - len(bad)}/{len(data)} OK" + (f" — {', '.join(bad)}" if bad else ""))
        if snap.cpu is not None:
            rb.add(OK if snap.cpu < 80 else WARN, f"CPU: {snap.cpu:.0f}%")
        problems = [x for x in rb.steps if x.mark != OK]
        rb.verdict = "მოწყობილობა ჯანმრთელია." if not problems else "ყურადღება მიაქციე ⚠️/❌ პუნქტებს ზემოთ."
    logs = s.syslog.search(d.name, "", hours=24, max_severity=3, limit=5)
    rb.add(OK if not logs else WARN, f"ლოგები 24 სთ (err+): {len(logs)}" + (f" — ბოლო: {logs[-1]['message'][:90]}" if logs else ""))
    change = changes_since(BackupStore(settings.backup_dir), d.name, 24)
    if change and change.get("changed"):
        rb.add(WARN, f"config შეიცვალა ბოლო 24 სთ-ში (+{change['added']}/−{change['removed']})")
    notes = s.notes.list(d.name)
    if notes:
        rb.add("📝", "შენიშვნა: " + notes[-1]["text"][:120])
    return rb


def slow(s, args) -> RunbookResult:
    from .watch import collect

    rb = RunbookResult("Runbook: ქსელი ნელია")
    inv = s.inventory()
    devices = list(inv.devices.values())
    worst = []
    for d in devices:
        st = s.history.stats(d.name, 1)
        if st.get("samples") and "p95_ms" in st:
            worst.append((st["p95_ms"], d.name, st))
    worst.sort(reverse=True)
    for p95, name, st in worst[:5]:
        rb.add(OK if p95 < 50 else WARN if p95 < 200 else FAIL, f"{name}: latency p95 {p95} ms, uptime {st['uptime_percent']}% (1 სთ)")
    if not worst:
        rb.add(WARN, "latency ისტორია ჯერ არ არის (მონიტორინგი აგროვებს რამდენიმე წუთში)")
    up = [inv.devices[r.device] for r in check_many(devices, timeout=2.0) if r.up]
    snaps = dev.run_on_devices(inv, up, lambda d: collect(inv, d, everything=True))
    hot = []
    for name, snap in snaps.items():
        cpu = getattr(snap, "cpu", None)
        if cpu is not None:
            rb.add(OK if cpu < 70 else WARN if cpu < 90 else FAIL, f"{name}: CPU {cpu:.0f}%")
            if cpu >= 70:
                hot.append(name)
    slow_names = [n for p, n, _ in worst if p >= 200]
    if hot:
        rb.verdict = f"{', '.join(hot)} გადატვირთულია (CPU). ნახე /cmd {hot[0]} show processes cpu sorted"
    elif slow_names:
        rb.verdict = f"{', '.join(slow_names)} ნელა პასუხობს — შეამოწმე მისკენ მიმავალი link-ის დატვირთვა/შეცდომები."
    else:
        rb.verdict = "მოწყობილობები ნორმალურად პასუხობენ. თუ ნელა მუშაობს ინტერნეტი — /runbook internet."
    return rb


HANDLERS = {"internet": internet, "device": device, "slow": slow}


def run(s, name: str, args: list[str]) -> RunbookResult:
    if name not in HANDLERS:
        raise ValueError("უცნობი runbook. ხელმისაწვდომია: " + ", ".join(RUNBOOKS))
    return HANDLERS[name](s, args)
