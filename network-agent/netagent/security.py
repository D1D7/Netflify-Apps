"""Read-only command guard and secret masking.

Every command that reaches a device goes through `validate_command`.
Every piece of text that goes to the LLM or to the chat goes through `mask_secrets`.
"""

from __future__ import annotations

import re

MAX_COMMAND_LEN = 300

# Words that change state on at least one platform. A command containing any of
# these as a separate token is rejected, regardless of vendor.
_FORBIDDEN_TOKENS = {
    "reload", "reboot", "restart", "shutdown", "halt", "poweroff",
    "write", "wr", "erase", "delete", "del", "remove", "format", "copy",
    "configure", "conf", "config-mode", "commit", "rollback", "save",
    "set", "unset", "add", "edit", "undo", "reset", "clear", "debug",
    "request", "install", "upgrade", "load", "rename", "move", "enable",
    "disable", "system-view", "flush", "change", "replace", "kill",
    "import", "execute", "exec", "tclsh", "bash", "shell", "start",
}

# Allowed first word per platform family.
_ALLOWED_VERBS = {
    "default": {"show", "display", "get", "ping", "traceroute", "tracert"},
}

_LINUX_ALLOWED_FIRST = {
    "ip", "ss", "hostname", "uname", "uptime", "df", "free",
    "ifconfig", "route", "arp", "netstat", "ping", "traceroute",
}
_SHELL_META = re.compile(r"[;&|<>`$\\\n\r]")


class CommandRejected(ValueError):
    """Raised when a command is not allowed to run on a device."""


def _platform_family(device_type: str) -> str:
    dt = device_type.lower()
    if dt.startswith("mikrotik"):
        return "mikrotik"
    if dt.startswith("linux") or dt in {"generic_termserver", "ubiquiti_edgeos_linux"}:
        return "linux"
    return "default"


def validate_command(command: str, device_type: str) -> str:
    """Return the normalized command or raise CommandRejected."""
    cmd = " ".join(command.strip().split())
    if not cmd:
        raise CommandRejected("ცარიელი ბრძანება")
    if len(cmd) > MAX_COMMAND_LEN:
        raise CommandRejected("ბრძანება ძალიან გრძელია")
    if "\n" in command or "\r" in command:
        raise CommandRejected("მრავალხაზიანი ბრძანება აკრძალულია")

    family = _platform_family(device_type)
    lowered = cmd.lower()
    # Only the part before a pipe filter is checked for forbidden verbs on network
    # OSes; the filter part (include/exclude/begin/match) is harmless there.
    head = lowered.split("|", 1)[0] if family == "default" else lowered
    tokens = set(re.split(r"[\s/=]+", head)) - {""}

    bad = tokens & _FORBIDDEN_TOKENS
    if bad:
        raise CommandRejected(f"აკრძალული სიტყვა ბრძანებაში: {', '.join(sorted(bad))}")

    if family == "mikrotik":
        # RouterOS read commands end with "print" (optionally with args) or "export".
        if not cmd.startswith("/"):
            raise CommandRejected("RouterOS ბრძანება უნდა იწყებოდეს '/'-ით")
        if "print" not in tokens and "export" not in tokens:
            raise CommandRejected("RouterOS-ზე დაშვებულია მხოლოდ 'print' და 'export'")
        if "show-sensitive" in tokens:
            raise CommandRejected("show-sensitive აკრძალულია")
        return cmd

    if family == "linux":
        if _SHELL_META.search(cmd):
            raise CommandRejected("shell სიმბოლოები (; | & > ...) აკრძალულია")
        first = lowered.split()[0]
        if first not in _LINUX_ALLOWED_FIRST:
            raise CommandRejected(f"Linux-ზე '{first}' არ არის დაშვებულ სიაში")
        return cmd

    first = lowered.split()[0]
    if first not in _ALLOWED_VERBS["default"]:
        raise CommandRejected(
            "დაშვებულია მხოლოდ წაკითხვის ბრძანებები (show / display / get / ping / traceroute)"
        )
    return cmd


_MASK = "<masked>"
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Fortinet (before the generic "password" rule so "ENC" is not the only thing masked)
    (re.compile(r"(\bset\s+(?:password|passwd|psksecret|secret)\s+)(?:ENC\s+)?\S+", re.I), r"\1" + _MASK),
    # Cisco IOS / NX-OS / ASA
    (re.compile(r"(\b(?:enable\s+)?(?:secret|password)\s+(?:\d+\s+)?)\S+", re.I), r"\1" + _MASK),
    # Well-known default communities ("public"/"private") are not secrets and stay visible
    # so the security audit can flag them.
    (re.compile(r"(\bsnmp-server\s+community\s+)(?!(?:public|private)\b)\S+", re.I), r"\1" + _MASK),
    (re.compile(r"(\b(?:key-string|pre-shared-key)\s+(?:\d+\s+)?)\S+", re.I), r"\1" + _MASK),
    (re.compile(r"(\bkey\s+\d\s+)\S+", re.I), r"\1" + _MASK),
    (re.compile(r"(\b(?:tacacs|radius)-server\b.*?\bkey\s+(?:\d+\s+)?)\S+", re.I), r"\1" + _MASK),
    (re.compile(r"(\bauthentication-key\s+(?:\d+\s+)?)\S+", re.I), r"\1" + _MASK),
    # Juniper
    (re.compile(r'(\b(?:encrypted-password|secret|community)\s+)"(?!(?:public|private)")[^"]*"', re.I), r"\1" + _MASK),
    (re.compile(r"(\bencrypted-password\s+)(?!<masked>)[^;\s]+", re.I), r"\1" + _MASK),
    (re.compile(r"(\bcommunity\s+)(?!<masked>|(?:public|private)\b)\S+", re.I), r"\1" + _MASK),
    (re.compile(r"\$9\$\S+"), _MASK),
    # MikroTik / generic key=value
    (re.compile(r"(\b(?:password|secret|passphrase|wpa2?-pre-shared-key|authentication-key|community)=)\S+", re.I), r"\1" + _MASK),
    # Huawei cipher
    (re.compile(r"(\bcipher\s+)\S+", re.I), r"\1" + _MASK),
    # Private keys
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), _MASK),
]


def mask_secrets(text: str) -> str:
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text
