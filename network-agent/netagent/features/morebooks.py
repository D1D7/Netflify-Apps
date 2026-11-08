"""More runbooks: vpn, wifi, dhcp (registered into netagent.runbooks on install)."""

from __future__ import annotations

import platform
import re
import subprocess

from .. import runbooks as rbk
from ..health import check_many
from ..runbooks import FAIL, OK, WARN, RunbookResult
from ..tools import device as dev
from ..tools import network as net

VPN_CMDS = {
    "ios": ["show crypto isakmp sa", "show crypto ipsec sa | include peer|pkts encaps|pkts decaps", "show interfaces description | include Tu"],
    "mikrotik": ["/ip ipsec active-peers print", "/interface wireguard peers print"],
    "junos": ["show security ike security-associations", "show security ipsec security-associations"],
}
DHCP_CMDS = {
    "ios": ["show ip dhcp pool", "show ip dhcp conflict"],
    "mikrotik": ["/ip pool used print count-only", "/ip pool print", "/ip dhcp-server lease print count-only"],
}


def _run(inv, d, cmds) -> list[str]:
    return [r.get("output", "") for r in dev.run_commands(inv, d, cmds, parse=False, max_chars=None)]


def vpn(s, args) -> RunbookResult:
    rb = RunbookResult("Runbook: VPN")
    inv = s.inventory()
    devices = [inv.get(args[0])] if args else rbk._routers(list(inv.devices.values()))  # noqa: SLF001
    reach = {r.device: r for r in check_many(devices, timeout=2.0)}
    problems = []
    for d in devices:
        fam = rbk._family(d)  # noqa: SLF001
        if not reach[d.name].up:
            rb.add(FAIL, f"{d.name}: მიუწვდომელია")
            problems.append(f"{d.name} მიუწვდომელია")
            continue
        if fam not in VPN_CMDS:
            continue
        outs = _run(inv, d, VPN_CMDS[fam])
        if fam == "ios":
            sas = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\d+\s+(\S+)", outs[0])
            for dst, src, state, status in sas:
                good = state == "QM_IDLE" and status.upper() == "ACTIVE"
                rb.add(OK if good else FAIL, f"{d.name}: IKE {src} ↔ {dst} — {state} {status}")
                if not good:
                    problems.append(f"{d.name}: IKE {dst} {state}")
            enc = [int(x) for x in re.findall(r"pkts encaps: (\d+)", outs[1])]
            dec = [int(x) for x in re.findall(r"pkts decaps: (\d+)", outs[1])]
            if enc:
                one_way = any(e > 0 and dc == 0 for e, dc in zip(enc, dec))
                rb.add(WARN if one_way else OK, f"{d.name}: IPsec პაკეტები — გაგზავნილი {sum(enc)}, მიღებული {sum(dec)}")
                if one_way:
                    problems.append(f"{d.name}: ტრაფიკი მხოლოდ ერთი მიმართულებით მიდის (მეორე მხარე არ აბრუნებს)")
            for line in outs[2].splitlines():
                m = re.match(r"(Tu\S+)\s+(up|down|admin down)\s+(up|down)", line)
                if m:
                    good = m.group(2) == "up" and m.group(3) == "up"
                    rb.add(OK if good else FAIL, f"{d.name}: {m.group(1)} {m.group(2)}/{m.group(3)}")
                    if not good:
                        problems.append(f"{d.name}: {m.group(1)} down")
            if not sas and not enc:
                rb.add(WARN, f"{d.name}: IPsec სესია არ ჩანს")
        elif fam == "mikrotik":
            peers = len(re.findall(r"established", outs[0]))
            rb.add(OK if peers else WARN, f"{d.name}: IPsec აქტიური peer-ები: {peers}")
            hs = re.findall(r"last-handshake=(\S+)", outs[1])
            if hs:
                rb.add(OK, f"{d.name}: WireGuard peer-ები: {len(hs)} (ბოლო handshake: {', '.join(hs[:3])})")
    rb.verdict = ("VPN-ები რიგზეა." if not problems else
                  "პრობლემა: " + "; ".join(problems[:4]) + ". ხშირი მიზეზები: მეორე მხარის საჯარო IP შეიცვალა, "
                  "PSK/ფაზა 1-2 პარამეტრები არ ემთხვევა, ან firewall/NAT ბლოკავს UDP 500/4500-ს.")
    return rb


def _windows_wifi() -> dict | None:
    if platform.system() != "Windows":
        return None
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=10,
                             errors="replace").stdout
    except Exception:  # noqa: BLE001
        return None
    def field(*names):
        for n in names:
            m = re.search(rf"^\s*{n}\s*:\s*(.+)$", out, re.M | re.I)
            if m:
                return m.group(1).strip()
        return None
    if not field("SSID"):
        return {}
    return {"ssid": field("SSID"), "signal": field("Signal"), "channel": field("Channel"), "radio": field("Radio type"),
            "rx": field("Receive rate \\(Mbps\\)"), "tx": field("Transmit rate \\(Mbps\\)"), "band": field("Band")}


def wifi(s, args) -> RunbookResult:
    rb = RunbookResult("Runbook: Wi-Fi")
    from .homenet import default_gateway

    info = _windows_wifi()
    verdict = []
    if info is None:
        rb.add(WARN, "Wi-Fi-ს პარამეტრები მხოლოდ Windows-ზე იკითხება (netsh)")
    elif not info:
        rb.add(WARN, "ეს კომპიუტერი Wi-Fi-ით არ არის მიერთებული (ალბათ კაბელით)")
    else:
        sig = int(re.sub(r"\D", "", info["signal"] or "0") or 0)
        rb.add(OK if sig >= 60 else WARN if sig >= 40 else FAIL,
               f"სიგნალი: {sig}% ({info['ssid']}, არხი {info['channel']}, {info.get('band') or info.get('radio') or ''})")
        rb.add(OK, f"კავშირის სიჩქარე როუტერთან: მიღება {info['rx']} · გაგზავნა {info['tx']} Mbit/s")
        if sig < 50:
            verdict.append("სიგნალი სუსტია — როუტერთან ახლოს მიდი, ან დაამატე წვდომის წერტილი/mesh")
        if info.get("channel") and info["channel"].isdigit() and int(info["channel"]) <= 14:
            verdict.append("2.4 GHz-ზე ხარ — თუ შესაძლებელია, 5 GHz-ზე გადადი (ნაკლები ხმაური, მეტი სიჩქარე)")
    gw = default_gateway()
    if gw:
        p = net.ping(gw, 10)
        if p.get("error"):
            rb.add(WARN, f"ping როუტერამდე ვერ შესრულდა: {p['error']}")
        else:
            loss = p.get("packet_loss_percent", 0) or 0
            avg = p.get("avg_rtt_ms")
            rb.add(OK if loss == 0 and (avg or 0) < 15 else WARN if loss < 20 else FAIL,
                   f"როუტერი {gw}: დანაკარგი {loss}%" + (f", საშუალოდ {avg:.0f} ms" if avg else ""))
            if loss > 0 or (avg or 0) > 30:
                verdict.append("როუტერამდეც კი არის დანაკარგი/დაყოვნება — პრობლემა Wi-Fi-შია, არა ინტერნეტში")
    p = net.ping("8.8.8.8", 5)
    if not p.get("error"):
        rb.add(OK if p.get("reachable") else FAIL, f"ინტერნეტი (8.8.8.8): {'პასუხობს' if p.get('reachable') else 'არ პასუხობს'}"
               + (f", {p['avg_rtt_ms']:.0f} ms" if p.get("avg_rtt_ms") else ""))
    rb.verdict = "; ".join(verdict) or "Wi-Fi კარგად გამოიყურება. თუ კონკრეტულ ადგილას ნელია, იქ გაიმეორე /runbook wifi."
    return rb


def dhcp(s, args) -> RunbookResult:
    rb = RunbookResult("Runbook: DHCP (IP არ ეძლევა)")
    from .homenet import local_ip

    me = local_ip()
    if me.startswith("169.254."):
        rb.add(FAIL, f"ამ კომპიუტერს აქვს {me} — DHCP-დან მისამართი ვერ მიიღო")
    else:
        rb.add(OK, f"ამ კომპიუტერის IP: {me}")
    inv = s.inventory()
    devices = list(inv.devices.values())
    full = []
    for d in devices:
        fam = rbk._family(d)  # noqa: SLF001
        if fam not in DHCP_CMDS:
            continue
        outs = _run(inv, d, DHCP_CMDS[fam])
        if fam == "ios":
            for pool, block in re.findall(r"Pool (\S+) :(.*?)(?=\nPool |\Z)", outs[0], re.S):
                leased = re.search(r"Leased addresses\s*:\s*(\d+)", block)
                total = re.search(r"Total addresses\s*:\s*(\d+)", block)
                if leased and total and int(total.group(1)):
                    pct = round(100 * int(leased.group(1)) / int(total.group(1)))
                    rb.add(OK if pct < 85 else WARN if pct < 100 else FAIL, f"{d.name}: pool {pool} — {leased.group(1)}/{total.group(1)} ({pct}%)")
                    if pct >= 95:
                        full.append(f"{d.name}/{pool}")
            conflicts = [ln for ln in outs[1].splitlines() if re.match(r"\s*\d+\.\d+\.\d+\.\d+", ln)]
            if conflicts:
                rb.add(WARN, f"{d.name}: IP კონფლიქტები: {len(conflicts)} (ვიღაცას სტატიკური IP აქვს pool-დან)")
        elif fam == "mikrotik":
            used = re.search(r"(\d+)", outs[0] or "")
            rb.add(OK, f"{d.name}: გაცემული მისამართები: {used.group(1) if used else '?'}")
    if full:
        rb.verdict = f"DHCP pool გავსებულია: {', '.join(full)}. გაზარდე pool, შეამცირე lease time ან მოძებნე უცნობი მოწყობილობები (/newdevices)."
    elif me.startswith("169.254."):
        rb.verdict = "DHCP სერვერი არ პასუხობს: შეამოწმე კაბელი/Wi-Fi, VLAN და რომ DHCP სერვერი (როუტერი) ჩართულია."
    else:
        rb.verdict = "DHCP-ში პრობლემა არ ჩანს. თუ კონკრეტულ მოწყობილობას არ ეძლევა IP, შეამოწმე მისი VLAN და MAC ფილტრი."
    return rb


rbk.HANDLERS.update({"vpn": vpn, "wifi": wifi, "dhcp": dhcp})
rbk.RUNBOOKS.update({"vpn": "VPN/IPsec/WireGuard: რატომ არ მუშაობს გვირაბი?",
                     "wifi": "Wi-Fi ნელია ან წყდება (ამ კომპიუტერიდან)",
                     "dhcp": "მოწყობილობას IP არ ეძლევა / pool გავსებულია"})


def _extend_tool_schema() -> None:
    from .. import tools

    for t in tools.TOOL_SCHEMAS:
        if t["name"] == "run_runbook":
            t["description"] += " vpn (IPsec/WireGuard გვირაბები), wifi (Wi-Fi ამ კომპიუტერიდან), dhcp (IP არ ეძლევა / pool)."
            enum = t["input_schema"]["properties"]["name"].setdefault("enum", [])
            enum += [n for n in ("vpn", "wifi", "dhcp") if n not in enum]


_extend_tool_schema()
