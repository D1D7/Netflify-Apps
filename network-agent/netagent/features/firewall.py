"""Firewall rule analysis for Cisco ACLs and MikroTik filter rules.

  - shadowed rules: an earlier rule already matches everything this rule matches
    (different action = the rule never works; same action = redundant)
  - unused rules (Cisco hit counters = 0)
  - MikroTik chains without a final drop (RouterOS accepts by default)
  - "is tcp 10.0.0.5 -> 8.8.8.8:443 allowed?" first-match evaluation

Rules with conditions we do not model (interfaces, connection state, address lists,
object-groups, non-contiguous wildcards...) are marked `extra`: they never shadow others
and an evaluation that hits them says the answer depends on them.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ..result import CommandError, Result
from ..tools import device as dev
from ..watch import family

ANY = ipaddress.ip_network("0.0.0.0/0")
PORTS = {"www": 80, "http": 80, "https": 443, "ssh": 22, "telnet": 23, "domain": 53, "smtp": 25, "ftp": 21,
         "ftp-data": 20, "ntp": 123, "snmp": 161, "snmptrap": 162, "bootps": 67, "bootpc": 68, "tftp": 69,
         "pop3": 110, "imap": 143, "imap4": 143, "ldap": 389, "isakmp": 500, "non500-isakmp": 4500,
         "syslog": 514, "echo": 7, "bgp": 179, "sunrpc": 111, "netbios-ns": 137, "netbios-ss": 139,
         "cmd": 514, "lpd": 515, "pptp": 1723, "nntp": 119, "irc": 194, "talk": 517, "whois": 43}
TERMINAL_MT = {"accept", "drop", "reject", "fasttrack-connection", "tarpit"}


@dataclass
class Rule:
    index: int
    action: str  # permit / deny
    proto: str = "ip"
    src: ipaddress.IPv4Network = ANY
    dst: ipaddress.IPv4Network = ANY
    sports: list[tuple[int, int]] | None = None
    dports: list[tuple[int, int]] | None = None
    extra: list[str] = field(default_factory=list)
    hits: int | None = None
    text: str = ""
    seq: str = ""


def _port(tok: str) -> int:
    if tok.isdigit():
        return int(tok)
    if tok.lower() in PORTS:
        return PORTS[tok.lower()]
    raise ValueError(tok)


def wildcard_to_net(addr: str, wildcard: str) -> ipaddress.IPv4Network | None:
    w = int(ipaddress.ip_address(wildcard))
    if (w + 1) & w:  # non-contiguous wildcard
        return None
    prefix = 32 - w.bit_length()
    return ipaddress.ip_network(f"{addr}/{prefix}", strict=False)


# -- Cisco ---------------------------------------------------------------------------------------
def _cisco_addr(toks: list[str], i: int, rule: Rule) -> tuple[ipaddress.IPv4Network, int]:
    t = toks[i]
    if t == "any":
        return ANY, i + 1
    if t == "host":
        return ipaddress.ip_network(toks[i + 1] + "/32"), i + 2
    if t in {"object-group", "addrgroup"}:
        rule.extra.append(f"object-group {toks[i + 1]}")
        return ANY, i + 2
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", t):
        if i + 1 < len(toks) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", toks[i + 1]):
            net = wildcard_to_net(t, toks[i + 1])
            if net is None:
                rule.extra.append(f"wildcard {toks[i + 1]}")
                net = ANY
            return net, i + 2
        return ipaddress.ip_network(t + "/32"), i + 1
    raise ValueError(f"unknown address '{t}'")


def _cisco_ports(toks: list[str], i: int) -> tuple[list[tuple[int, int]] | None, int]:
    if i >= len(toks):
        return None, i
    op = toks[i]
    try:
        if op == "eq":
            ports, j = [], i + 1
            while j < len(toks):
                try:
                    p = _port(toks[j])
                except ValueError:
                    break
                ports.append((p, p))
                j += 1
            return ports, j
        if op == "range":
            return [(_port(toks[i + 1]), _port(toks[i + 2]))], i + 3
        if op == "gt":
            return [(_port(toks[i + 1]) + 1, 65535)], i + 2
        if op == "lt":
            return [(0, _port(toks[i + 1]) - 1)], i + 2
        if op == "neq":
            p = _port(toks[i + 1])
            return [(0, p - 1), (p + 1, 65535)], i + 2
    except (ValueError, IndexError):
        pass
    return None, i


def parse_cisco_entry(line: str, index: int, standard: bool) -> Rule | None:
    hits = re.search(r"\((\d+) matches?\)", line)
    body = re.sub(r"\(\d+ matches?\)", "", line).replace(", wildcard bits ", " ").strip()
    toks = body.split()
    seq = ""
    if toks and toks[0].isdigit():
        seq, toks = toks[0], toks[1:]
    if not toks or toks[0] not in {"permit", "deny"}:
        return None
    rule = Rule(index, toks[0], text=body, seq=seq, hits=int(hits.group(1)) if hits else (0 if "matches" not in line else None))
    try:
        if standard:
            rule.src, _ = _cisco_addr(toks, 1, rule)
            return rule
        rule.proto = toks[1].lower()
        i = 2
        rule.src, i = _cisco_addr(toks, i, rule)
        if rule.proto in {"tcp", "udp"}:
            rule.sports, i = _cisco_ports(toks, i)
        rule.dst, i = _cisco_addr(toks, i, rule)
        if rule.proto in {"tcp", "udp"}:
            rule.dports, i = _cisco_ports(toks, i)
        rest = [t for t in toks[i:] if t not in {"log", "log-input"}]
        if rest:
            rule.extra.append(" ".join(rest))
    except (ValueError, IndexError) as exc:
        rule.extra.append(f"unparsed: {exc}")
    return rule


def parse_cisco_acls(text: str) -> dict[str, list[Rule]]:
    """`show access-lists` → {acl name: rules}."""
    acls: dict[str, list[Rule]] = {}
    current, standard = None, False
    for line in text.splitlines():
        m = re.match(r"^(Standard|Extended) IP access list (\S+)", line.strip())
        if m:
            current, standard = m.group(2), m.group(1) == "Standard"
            acls[current] = []
            continue
        if current and line.startswith((" ", "\t")):
            r = parse_cisco_entry(line, len(acls[current]) + 1, standard)
            if r:
                acls[current].append(r)
    return acls


# -- MikroTik ------------------------------------------------------------------------------------
def _mt_ports(v: str) -> list[tuple[int, int]]:
    out = []
    for part in v.split(","):
        lo, _, hi = part.partition("-")
        out.append((int(lo), int(hi or lo)))
    return out


def _mt_addr(v: str, rule: Rule) -> ipaddress.IPv4Network:
    if v.startswith("!"):
        rule.extra.append(f"not {v[1:]}")
        return ANY
    if "-" in v:
        rule.extra.append(f"range {v}")
        return ANY
    return ipaddress.ip_network(v if "/" in v else v + "/32", strict=False)


def parse_mikrotik_filter(text: str) -> dict[str, list[Rule]]:
    chains: dict[str, list[Rule]] = {}
    text = re.sub(r"\\\r?\n\s*", "", text)  # join export line continuations
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("/"):
            section = line.split(" add ")[0] if " add " in line else line
            if " add " not in line:
                continue
            line = "add " + line.split(" add ", 1)[1]
        if "firewall filter" not in section or not line.startswith("add "):
            continue
        kv = dict((k, v.strip('"')) for k, v in re.findall(r'([\w-]+)=("[^"]*"|\S+)', line))
        if kv.get("disabled") == "yes":
            continue
        chain = kv.get("chain", "?")
        action = kv.get("action", "accept")
        rule = Rule(len(chains.get(chain, [])) + 1, "permit" if action in {"accept", "fasttrack-connection"} else
                    "deny" if action in {"drop", "reject", "tarpit"} else action, text=line[4:])
        rule.proto = kv.get("protocol", "ip")
        try:
            if "src-address" in kv:
                rule.src = _mt_addr(kv["src-address"], rule)
            if "dst-address" in kv:
                rule.dst = _mt_addr(kv["dst-address"], rule)
            if "dst-port" in kv:
                rule.dports = _mt_ports(kv["dst-port"])
            if "src-port" in kv:
                rule.sports = _mt_ports(kv["src-port"])
        except ValueError as exc:
            rule.extra.append(f"unparsed: {exc}")
        known = {"chain", "action", "protocol", "src-address", "dst-address", "dst-port", "src-port", "comment",
                 "disabled", "log", "log-prefix"}
        rule.extra += [f"{k}={v}" for k, v in kv.items() if k not in known]
        if action not in TERMINAL_MT:
            rule.extra.append(f"action={action}")
        chains.setdefault(chain, []).append(rule)
    return chains


# -- analysis --------------------------------------------------------------------------------------
def _ports_within(inner, outer) -> bool:
    if outer is None:
        return True
    if inner is None:
        return False
    return all(any(o[0] <= lo and hi <= o[1] for o in outer) for lo, hi in inner)


def covers(a: Rule, b: Rule) -> bool:
    """Does rule a match every packet that rule b matches?"""
    if a.extra:
        return False
    if a.proto not in {"ip", b.proto}:
        return False
    if a.proto != "ip" and b.proto == "ip":
        return False
    if not (b.src.subnet_of(a.src) and b.dst.subnet_of(a.dst)):
        return False
    return _ports_within(b.sports, a.sports) and _ports_within(b.dports, a.dports)


def analyze(rules: list[Rule], kind: str) -> dict:
    shadowed, redundant, unused, broad = [], [], [], []
    for j, b in enumerate(rules):
        for a in rules[:j]:
            if covers(a, b):
                (redundant if a.action == b.action else shadowed).append((b, a))
                break
        if b.hits == 0 and kind == "cisco":
            unused.append(b)
        if b.action == "permit" and b.proto == "ip" and b.src == ANY and b.dst == ANY and not b.extra and j < len(rules) - 1:
            broad.append(b)
    res = {"rules": len(rules), "shadowed": shadowed, "redundant": redundant, "unused": unused, "broad": broad}
    if kind == "mikrotik":
        last = rules[-1] if rules else None
        res["no_final_drop"] = not (last and last.action == "deny" and last.src == ANY and last.dst == ANY
                                    and last.proto == "ip" and not last.extra)
    return res


def evaluate(rules: list[Rule], proto: str, src: str, dst: str, port: int | None, kind: str) -> dict:
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    caveats = []
    for r in rules:
        if r.proto not in {"ip", proto}:
            continue
        if s not in r.src or d not in r.dst:
            continue
        if r.dports is not None and (port is None or not any(lo <= port <= hi for lo, hi in r.dports)):
            continue
        if r.extra:
            caveats.append(f"#{r.seq or r.index} ({', '.join(r.extra)[:80]})")
            continue
        return {"allowed": r.action == "permit", "rule": r.seq or r.index, "text": r.text, "depends_on": caveats}
    default = kind == "mikrotik"  # RouterOS accepts when no rule matches; Cisco ACLs end with an implicit deny
    return {"allowed": default, "rule": None, "text": "ნაგულისხმევი: " + ("accept (RouterOS)" if default else "implicit deny"),
            "depends_on": caveats}


# -- device I/O ------------------------------------------------------------------------------------
def load(inventory, device) -> tuple[str, dict[str, list[Rule]]]:
    fam = family(device.device_type)
    if fam in {"ios", "nxos", "arista"}:
        cmd, kind = "show access-lists", "cisco"
    elif fam == "mikrotik":
        cmd, kind = "/ip firewall filter export terse", "mikrotik"
    else:
        raise CommandError(f"{device.device_type}-ის firewall-ის ანალიზი ჯერ არ არის მხარდაჭერილი")
    res = dev.run_commands(inventory, device, [cmd], parse=False, max_chars=None)[0]
    if "error" in res and not res.get("output"):
        raise CommandError(res["error"])
    out = res.get("output", "")
    return kind, (parse_cisco_acls(out) if kind == "cisco" else parse_mikrotik_filter(out))


def format_analysis(name: str, kind: str, groups: dict[str, list[Rule]]) -> str:
    if not groups:
        return f"🧱 **{name}** — " + ("ACL-ები არ არის" if kind == "cisco" else "firewall filter წესები არ არის — ყველაფერი დაშვებულია!")
    label = "ACL" if kind == "cisco" else "chain"
    lines = [f"🧱 **{name}** — firewall-ის ანალიზი"]
    for gname, rules in groups.items():
        a = analyze(rules, kind)
        issues = []
        for b, by in a["shadowed"]:
            issues.append(f"  🔴 #{b.seq or b.index} არასდროს იმუშავებს — #{by.seq or by.index} უკვე {('უშვებს' if by.action == 'permit' else 'ბლოკავს')}: `{b.text[:70]}`")
        for b, by in a["redundant"]:
            issues.append(f"  🟡 #{b.seq or b.index} ზედმეტია (#{by.seq or by.index}-ის დუბლი): `{b.text[:70]}`")
        for b in a["broad"]:
            issues.append(f"  🟠 #{b.seq or b.index} ყველაფერს უშვებს და მის შემდეგ წესები აზრს კარგავს: `{b.text[:60]}`")
        if a.get("no_final_drop") and gname in {"input", "forward"}:
            issues.append(f"  🟠 chain {gname}-ს ბოლოს drop არ აქვს — RouterOS დანარჩენს უშვებს")
        if a["unused"]:
            issues.append("  ⚪ არასდროს გამოყენებული (0 matches): " + ", ".join(f"#{r.seq or r.index}" for r in a["unused"][:10]))
        lines.append(f"• {label} **{gname}** ({a['rules']} წესი)" + ("" if issues else " — ✅ პრობლემა არ ჩანს"))
        lines += issues
    return "\n".join(lines)


def firewall_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /firewall R1 · /firewall R1 test tcp 10.0.0.5 8.8.8.8 443 [ACL ან chain]")
    d = s.inventory().get(args[0])
    kind, groups = load(s.inventory(), d)
    if len(args) >= 5 and args[1] == "test":
        proto, src, dst = args[2].lower(), args[3], args[4]
        port = int(args[5]) if len(args) > 5 and args[5].isdigit() else None
        name = args[6] if len(args) > 6 else (args[5] if len(args) > 5 and not args[5].isdigit() else None)
        targets = {name: groups[name]} if name and name in groups else (
            {"forward": groups.get("forward", [])} if kind == "mikrotik" else groups)
        if name and name not in groups:
            raise CommandError(f"'{name}' ვერ ვიპოვე. არის: {', '.join(groups) or '—'}")
        lines = [f"🧪 **{d.name}**: {proto} {src} → {dst}" + (f":{port}" if port else "")]
        for g, rules in targets.items():
            r = evaluate(rules, proto, src, dst, port, kind)
            lines.append(f"• {g}: {'✅ დაშვებულია' if r['allowed'] else '⛔ იბლოკება'} — "
                         + (f"წესი #{r['rule']}: `{r['text'][:70]}`" if r["rule"] else r["text"])
                         + (f"\n  ⚠️ დამოკიდებულია: {', '.join(r['depends_on'])}" if r["depends_on"] else ""))
        return Result("\n".join(lines))
    return Result(format_analysis(d.name, kind, groups))


def _tool(ctx, device: str, protocol: str = "", source: str = "", destination: str = "", port: int = 0, acl: str = ""):
    d = ctx.inventory.get(device)
    try:
        kind, groups = load(ctx.inventory, d)
    except CommandError as exc:
        raise ValueError(str(exc)) from None
    if source and destination:
        targets = {acl: groups.get(acl, [])} if acl else groups
        return {g: evaluate(r, protocol or "ip", source, destination, port or None, kind) for g, r in targets.items()}
    out = {}
    for g, rules in groups.items():
        a = analyze(rules, kind)
        out[g] = {"rules": a["rules"], "shadowed": [{"rule": b.seq or b.index, "by": x.seq or x.index, "text": b.text} for b, x in a["shadowed"]],
                  "redundant": [{"rule": b.seq or b.index, "by": x.seq or x.index} for b, x in a["redundant"]],
                  "unused": [r.seq or r.index for r in a["unused"]], "no_final_drop": a.get("no_final_drop")}
    return {"kind": kind, "groups": out}


COMMANDS = {"firewall": firewall_cmd}
HELP = ["/firewall R1 — ACL/firewall-ის ანალიზი · /firewall R1 test tcp 10.0.0.5 8.8.8.8 443 — დაშვებულია?"]
TOOLS = [({
    "name": "firewall_analyze",
    "description": "Analyse ACLs (Cisco `show access-lists`) or MikroTik firewall filter rules: shadowed/redundant "
                   "rules, unused rules (0 hits), chains without a final drop. With source+destination it answers "
                   "whether that traffic is allowed and by which rule (first match).",
    "input_schema": {"type": "object", "properties": {
        "device": {"type": "string"}, "protocol": {"type": "string", "description": "tcp/udp/icmp/ip"},
        "source": {"type": "string"}, "destination": {"type": "string"}, "port": {"type": "integer"},
        "acl": {"type": "string", "description": "ACL name or MikroTik chain (default: all / forward)"}},
        "required": ["device"]},
}, _tool)]
