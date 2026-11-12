"""Security / best-practice audit of device configurations, plus network-wide checks
(duplicate IP addresses). Deterministic: no AI involved.

Rules work on the (masked) running configuration text, so they can run on backups.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    fix: str
    check: Callable[[str], bool]  # True = problem found


@dataclass(frozen=True)
class Finding:
    device: str
    rule_id: str
    severity: str
    title: str
    fix: str

    def as_dict(self) -> dict:
        return {"device": self.device, "rule": self.rule_id, "severity": self.severity, "title": self.title, "fix": self.fix}


# --------------------------------------------------------------------------- helpers


def join_continuations(config: str) -> str:
    """RouterOS exports wrap long lines with a trailing backslash; join them back."""
    return re.sub(r"\\\r?\n\s*", "", config.replace("\r\n", "\n"))


def _has(pattern: str, flags: int = re.M | re.I) -> Callable[[str], bool]:
    rx = re.compile(pattern, flags)
    return lambda cfg: bool(rx.search(cfg))


def _missing(pattern: str, flags: int = re.M | re.I) -> Callable[[str], bool]:
    rx = re.compile(pattern, flags)
    return lambda cfg: not rx.search(cfg)


def _blocks(cfg: str, header: str) -> list[str]:
    """Cisco-style blocks: a header line and the indented lines that follow it."""
    rx = re.compile(rf"^({header}.*)\n((?:[ \t]+.*\n?)*)", re.M | re.I)
    return [m.group(1) + "\n" + m.group(2) for m in rx.finditer(cfg)]


def _vty_telnet(cfg: str) -> bool:
    return any(re.search(r"transport input .*\b(telnet|all)\b", b, re.I) for b in _blocks(cfg, r"line vty"))


def _vty_no_acl(cfg: str) -> bool:
    blocks = _blocks(cfg, r"line vty")
    return bool(blocks) and any(not re.search(r"^\s+access-class\s+\S+\s+in", b, re.M | re.I) for b in blocks)


def _no_exec_timeout(cfg: str) -> bool:
    blocks = _blocks(cfg, r"line (?:vty|con)")
    return any(re.search(r"^\s+exec-timeout 0 0?\s*$", b, re.M | re.I) for b in blocks)


def _snmp_rw(cfg: str) -> bool:
    return bool(re.search(r"^snmp-server community \S+ (?:view \S+ )?RW\b", cfg, re.M | re.I))


def _mikrotik_service_enabled(name: str) -> Callable[[str], bool]:
    # Enabled services do not appear in an export; disabled ones show "disabled=yes".
    rx = re.compile(rf"^set (?:\[ find name=)?{name}\b\s*\]?.*\bdisabled=yes", re.M | re.I)
    return lambda cfg: not rx.search(cfg)


def _mikrotik_mac_server_open(cfg: str) -> bool:
    section = re.search(r"^/tool mac-server\n((?:(?!/).*\n?)*)", cfg, re.M)
    if not section:
        return True
    return "allowed-interface-list=" not in section.group(1) or "allowed-interface-list=all" in section.group(1)


# --------------------------------------------------------------------------- rules per platform

CISCO_IOS_RULES = [
    Rule("telnet", "high", "Telnet დაშვებულია VTY ხაზებზე (პაროლები ღია ტექსტით გადის)",
         "line vty 0 15\n transport input ssh", _vty_telnet),
    Rule("enable-password", "high", "'enable password' გამოიყენება 'enable secret'-ის ნაცვლად",
         "no enable password\nenable algorithm-type scrypt secret <PASSWORD>", _has(r"^enable password")),
    Rule("user-password", "high", "მომხმარებლის პაროლი შენახულია 'password'-ით (სუსტი/შექცევადი)",
         "username <USER> algorithm-type scrypt secret <PASSWORD>", _has(r"^username \S+ .*\bpassword\b")),
    Rule("snmp-default", "high", "SNMP community 'public' ან 'private' (ნაგულისხმევი მნიშვნელობა)",
         "no snmp-server community public\nsnmp-server community <STRONG> RO <ACL>",
         _has(r"^snmp-server community (?:public|private)\b")),
    Rule("snmp-rw", "high", "SNMP community RW წვდომით", "გამოიყენე RO ან SNMPv3", _snmp_rw),
    Rule("http-server", "medium", "HTTP სერვერი ჩართულია", "no ip http server\nno ip http secure-server",
         _has(r"^ip http (?:secure-)?server\s*$")),
    Rule("ssh-v2", "medium", "SSH v2 ცალსახად არ არის მოთხოვნილი", "ip ssh version 2", _missing(r"^ip ssh version 2")),
    Rule("vty-acl", "medium", "VTY ხაზებზე access-class (IP ფილტრი) არ არის",
         "ip access-list standard MGMT\n permit <MGMT-NET>\nline vty 0 15\n access-class MGMT in", _vty_no_acl),
    Rule("ntp", "medium", "NTP სერვერი არ არის კონფიგურირებული (ლოგების დრო არასწორი იქნება)",
         "ntp server <NTP-IP>", _missing(r"^ntp server ")),
    Rule("aaa", "low", "AAA ჩართული არ არის", "aaa new-model\naaa authentication login default local",
         _missing(r"^aaa new-model")),
    Rule("password-encryption", "low", "'service password-encryption' გამორთულია",
         "service password-encryption", _missing(r"^service password-encryption")),
    Rule("syslog", "low", "გარე syslog სერვერი არ არის", "logging host <SYSLOG-IP>",
         _missing(r"^logging (?:host )?\d+\.\d+\.\d+\.\d+")),
    Rule("exec-timeout", "low", "exec-timeout 0 0 — სესია არასდროს იხურება", "exec-timeout 10 0", _no_exec_timeout),
    Rule("banner", "low", "Login banner არ არის", "banner login ^Authorized access only^",
         _missing(r"^banner (?:login|motd)")),
]

CISCO_NXOS_RULES = [
    Rule("telnet", "high", "Telnet ჩართულია (feature telnet)", "no feature telnet", _has(r"^feature telnet")),
    Rule("snmp-default", "high", "SNMP community 'public' ან 'private'", "no snmp-server community public",
         _has(r"^snmp-server community (?:public|private)\b")),
    Rule("ntp", "medium", "NTP სერვერი არ არის", "ntp server <NTP-IP> use-vrf management", _missing(r"^ntp server ")),
    Rule("syslog", "low", "გარე syslog სერვერი არ არის", "logging server <SYSLOG-IP>", _missing(r"^logging server ")),
]

JUNOS_RULES = [
    Rule("telnet", "high", "Telnet სერვისი ჩართულია", "delete system services telnet", _has(r"^set system services telnet")),
    Rule("ftp", "medium", "FTP სერვისი ჩართულია", "delete system services ftp", _has(r"^set system services ftp")),
    Rule("http", "medium", "J-Web HTTP (დაუშიფრავი) ჩართულია", "delete system services web-management http",
         _has(r"^set system services web-management http\b")),
    Rule("snmp-default", "high", "SNMP community 'public' ან 'private'", "delete snmp community public",
         _has(r"^set snmp community \"?(?:public|private)\"?\s")),
    Rule("root-ssh", "medium", "root-ს შეუძლია SSH-ით შესვლა", "set system services ssh root-login deny",
         _missing(r"^set system services ssh root-login deny")),
    Rule("ntp", "medium", "NTP სერვერი არ არის", "set system ntp server <NTP-IP>", _missing(r"^set system ntp server ")),
    Rule("syslog", "low", "გარე syslog სერვერი არ არის", "set system syslog host <IP> any notice",
         _missing(r"^set system syslog host ")),
]

MIKROTIK_RULES = [
    Rule("telnet", "high", "Telnet სერვისი ჩართულია", "/ip service set telnet disabled=yes", _mikrotik_service_enabled("telnet")),
    Rule("ftp", "medium", "FTP სერვისი ჩართულია", "/ip service set ftp disabled=yes", _mikrotik_service_enabled("ftp")),
    Rule("www", "medium", "WebFig HTTP (დაუშიფრავი) ჩართულია", "/ip service set www disabled=yes",
         _mikrotik_service_enabled("www")),
    Rule("api", "medium", "API სერვისი ჩართულია", "/ip service set api disabled=yes", _mikrotik_service_enabled("api")),
    Rule("mac-server", "medium", "MAC-Telnet/Winbox ყველა ინტერფეისზეა ღია",
         "/tool mac-server set allowed-interface-list=LAN\n/tool mac-server mac-winbox set allowed-interface-list=LAN",
         _mikrotik_mac_server_open),
    Rule("snmp-default", "high", "SNMP community 'public'", "/snmp community set [find name=public] name=<STRONG>",
         _has(r"^/snmp community\n(?:(?!/).*\n)*?.*\bname=public\b")),
    Rule("dns-open", "medium", "DNS სერვერი იღებს გარე მოთხოვნებს — შეამოწმე firewall (open resolver რისკი)",
         "/ip dns set allow-remote-requests=no  (ან firewall-ით დაბლოკე WAN-იდან 53)",
         _has(r"allow-remote-requests=yes")),
    Rule("ntp", "medium", "NTP კლიენტი გამორთულია", "/system ntp client set enabled=yes servers=<NTP-IP>",
         _missing(r"^/system ntp client\n(?:(?!/).*\n)*?.*enabled=yes")),
    Rule("syslog", "low", "გარე syslog არ არის", "/system logging action add name=remote target=remote remote=<IP>",
         _missing(r"target=remote")),
]

PLATFORM_RULES: dict[str, list[Rule]] = {
    "cisco_ios": CISCO_IOS_RULES,
    "cisco_xe": CISCO_IOS_RULES,
    "cisco_nxos": CISCO_NXOS_RULES,
    "juniper_junos": JUNOS_RULES,
    "mikrotik_routeros": MIKROTIK_RULES,
}


def rules_for(device_type: str) -> list[Rule] | None:
    dt = device_type.lower()
    if dt in PLATFORM_RULES:
        return PLATFORM_RULES[dt]
    for key, rules in PLATFORM_RULES.items():
        if dt.startswith(key):  # e.g. cisco_ios_telnet, mikrotik_routeros_telnet
            return rules
    return None


def audit_config(device: str, device_type: str, config: str) -> list[Finding] | None:
    rules = rules_for(device_type)
    if rules is None:
        return None
    config = join_continuations(config)
    findings = []
    for rule in rules:
        try:
            if rule.check(config):
                findings.append(Finding(device, rule.id, rule.severity, rule.title, rule.fix))
        except re.error:
            continue
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])


# --------------------------------------------------------------------------- interface IPs / duplicates

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_CISCO_IFACE = re.compile(r"^interface\s+(\S+)\s*\n((?:[ \t]+.*\n?)*)", re.M | re.I)
_CISCO_ADDR = re.compile(rf"^\s+ip(?:v4)? address\s+({_IPV4})(?:\s+({_IPV4})|/(\d{{1,2}}))", re.M | re.I)
_JUNOS_ADDR = re.compile(rf"^set interfaces (\S+) (?:unit (\d+) )?family inet address ({_IPV4})/(\d{{1,2}})", re.M)
_MT_ADDR = re.compile(rf"^add\b(?=.*\binterface=(\S+))(?=.*\baddress=({_IPV4})/(\d{{1,2}})).*$", re.M)
_FORTI_IFACE = re.compile(r'^\s*edit "([^"]+)"\n((?:(?!\s*next\b).*\n)*)', re.M)
_FORTI_ADDR = re.compile(rf"^\s*set ip ({_IPV4}) ({_IPV4})", re.M)


def interface_addresses(config: str) -> list[tuple[str, ipaddress.IPv4Interface]]:
    """Return (interface, address) pairs configured on interfaces, across vendor syntaxes."""
    out: list[tuple[str, ipaddress.IPv4Interface]] = []
    config = join_continuations(config)

    def add(iface: str, ip: str, mask_or_len: str) -> None:
        try:
            out.append((iface, ipaddress.IPv4Interface(f"{ip}/{mask_or_len}")))
        except ValueError:
            pass

    for name, body in _CISCO_IFACE.findall(config):
        for ip, mask, plen in _CISCO_ADDR.findall(body):
            add(name, ip, mask or plen)
    for iface, unit, ip, plen in _JUNOS_ADDR.findall(config):
        add(f"{iface}.{unit}" if unit else iface, ip, plen)
    mt_section = re.search(r"^/ip address\n((?:(?!/).*\n?)*)", config, re.M)
    if mt_section:
        for iface, ip, plen in _MT_ADDR.findall(mt_section.group(1)):
            add(iface, ip, plen)
    forti = re.search(r"^config system interface\n(.*?)^end", config, re.M | re.S)
    if forti:
        for name, body in _FORTI_IFACE.findall(forti.group(1)):
            for ip, mask in _FORTI_ADDR.findall(body):
                if ip != "0.0.0.0":
                    add(name, ip, mask)
    return out


def find_duplicate_ips(configs: dict[str, str]) -> list[dict]:
    """IP addresses configured on more than one interface (same or different devices)."""
    seen: dict[str, list[str]] = defaultdict(list)
    for device, cfg in configs.items():
        for iface, addr in interface_addresses(cfg):
            ip = addr.ip
            if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
                continue
            seen[str(ip)].append(f"{device} {iface}")
    dups = [{"ip": ip, "where": where} for ip, where in seen.items() if len(where) > 1]
    return sorted(dups, key=lambda d: ipaddress.ip_address(d["ip"]))


# --------------------------------------------------------------------------- formatting


def format_findings(results: dict[str, list[Finding] | None], duplicates: list[dict], errors: dict[str, str]) -> str:
    total = {s: 0 for s in SEVERITY_ORDER}
    for findings in results.values():
        for f in findings or []:
            total[f.severity] += 1
    lines = [
        "🛡 **უსაფრთხოების აუდიტი**",
        f"🔴 მაღალი: {total['high']}   🟠 საშუალო: {total['medium']}   🟡 დაბალი: {total['low']}",
    ]
    for device, findings in sorted(results.items()):
        lines.append("")
        if findings is None:
            lines.append(f"⚪ **{device}** — ამ პლატფორმისთვის წესები ჯერ არ არის")
        elif not findings:
            lines.append(f"✅ **{device}** — პრობლემა არ მოიძებნა")
        else:
            lines.append(f"**{device}**")
            for f in findings:
                lines.append(f"{SEVERITY_ICON[f.severity]} {f.title}")
    if duplicates:
        lines.append("")
        lines.append("⚠️ **დუბლირებული IP მისამართები:**")
        for d in duplicates:
            lines.append(f"• {d['ip']}: " + ", ".join(d["where"]))
    for device, err in sorted(errors.items()):
        lines.append(f"⚠️ {device}: {err}")
    if any(results.values()):
        lines.append("")
        lines.append("გამოსწორების ბრძანებებისთვის მკითხე: „როგორ გავასწორო <მოწყობილობა>-ს აუდიტის შედეგები?“")
    return "\n".join(lines)
