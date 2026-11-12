"""Network discovery: find SSH-reachable devices in a subnet and detect their platform.

Steps per address: TCP check on the SSH port -> Netmiko SSHDetect -> own prompt-based
fallback (MikroTik and others SSHDetect does not know) -> hostname from the prompt.
Only read-only commands are sent ("show version" and similar, chosen by Netmiko).
"""

from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

from .config import settings
from .inventory import Device, Inventory

MAX_SCAN_ADDRESSES = 1024  # /22
SCAN_WORKERS = 64


@dataclass
class Candidate:
    host: str
    port: int = 22
    device_type: str | None = None
    hostname: str | None = None
    error: str = ""
    already_in_inventory: str | None = None  # name of the existing entry
    extra: dict | None = None  # more inventory fields, e.g. {"baudrate": 9600} for a console cable

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "", {})}


def scan_ssh(network: str, port: int = 22, timeout: float = 1.0) -> list[str]:
    net = ipaddress.ip_network(network.strip(), strict=False)
    if net.version != 4:
        raise ValueError("მხოლოდ IPv4 ქსელებია მხარდაჭერილი")
    if net.num_addresses > MAX_SCAN_ADDRESSES:
        raise ValueError("ქსელი ძალიან დიდია (მაქს. /22). დაყავი პატარა ნაწილებად.")
    hosts = [str(h) for h in (net.hosts() if net.prefixlen < 31 else net)]

    def probe(host: str) -> str | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return host
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        return [h for h in pool.map(probe, hosts) if h]


_PROMPT_PLATFORMS = [
    (re.compile(r"\[[^\]@]+@[^\]]+\]\s*>\s*$"), "mikrotik_routeros"),
    (re.compile(r"^<[^>]+>\s*$"), "huawei"),
    (re.compile(r"@[\w.-]+[>#]\s*$"), "juniper_junos"),
]


def hostname_from_prompt(prompt: str) -> str | None:
    p = prompt.strip()
    for pattern in (
        r"^\[[^@\]]+@([^\]]+)\]\s*>$",  # MikroTik [admin@MikroTik] >
        r"^<([^>]+)>$",  # Huawei / H3C <SW1>
        r"^[\w.-]+@([\w.-]+)[>#%]$",  # Junos user@router>
        r"^([\w.-]+)(?:\(.*\))?[>#$%]$",  # Cisco/Arista/etc R1# R1> R1(config)#
        r"^([\w.-]+)\s+[#$]$",  # FortiGate "FGT60F #"
    ):
        m = re.match(pattern, p)
        if m:
            return m.group(1)
    return None


def _connect_params(inventory: Inventory, host: str, port: int, credentials: str, device_type: str) -> dict:
    cred = inventory.credential_for(Device(name=host, host=host, device_type=device_type, credentials=credentials))
    params = {
        "device_type": device_type,
        "host": host,
        "port": port,
        "username": cred.username,
        "password": cred.password,
        "conn_timeout": settings.device_timeout,
        "auth_timeout": settings.device_timeout,
        "banner_timeout": settings.device_timeout,
    }
    if cred.secret:
        params["secret"] = cred.secret
    return params


def detect(inventory: Inventory, host: str, port: int = 22, credentials: str = "default") -> Candidate:
    from netmiko import ConnectHandler, SSHDetect

    cand = Candidate(host=host, port=port)
    try:
        guesser = SSHDetect(**_connect_params(inventory, host, port, credentials, "autodetect"))
        cand.device_type = guesser.autodetect()
        try:
            prompt = guesser.connection.find_prompt()
            cand.hostname = hostname_from_prompt(prompt)
            if cand.device_type is None:
                for pattern, platform in _PROMPT_PLATFORMS:
                    if pattern.search(prompt):
                        cand.device_type = platform
                        break
        finally:
            try:
                guesser.connection.disconnect()
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        cand.error = f"{type(exc).__name__}: {msg}"[:200]
        # SSHDetect can fail on devices with unusual banners; try a plain session for the prompt.
        try:
            conn = ConnectHandler(**_connect_params(inventory, host, port, credentials, "generic"))
            try:
                prompt = conn.find_prompt()
            finally:
                conn.disconnect()
            cand.hostname = hostname_from_prompt(prompt)
            for pattern, platform in _PROMPT_PLATFORMS:
                if pattern.search(prompt):
                    cand.device_type = platform
                    cand.error = ""
                    break
        except Exception:  # noqa: BLE001
            pass
    if cand.device_type is None and not cand.error:
        cand.error = "პლატფორმა ვერ ამოვიცანი — device_type ხელით მიუთითე"
    return cand


def discover(
    inventory: Inventory, network: str, port: int = 22, credentials: str = "default", workers: int = 8
) -> list[Candidate]:
    known = {(d.host, d.port): d.name for d in inventory.devices.values()}
    hosts = scan_ssh(network, port)

    def one(host: str) -> Candidate:
        if (host, port) in known:
            return Candidate(host=host, port=port, already_in_inventory=known[(host, port)])
        return detect(inventory, host, port, credentials)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(one, hosts))
    return sorted(results, key=lambda c: ipaddress.ip_address(c.host))


# ---------------------------------------------------------------------------
# Writing to the inventory file
# ---------------------------------------------------------------------------

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _unique_name(base: str, taken: set[str]) -> str:
    base = _SAFE_NAME.sub("-", base).strip("-") or "device"
    name, i = base, 2
    while name.lower() in taken:
        name = f"{base}-{i}"
        i += 1
    taken.add(name.lower())
    return name


def add_to_inventory(path: Path, candidates: list[Candidate], credentials: str = "default", site: str = "") -> list[str]:
    """Append detected devices to the inventory YAML. Returns the names added.

    Appends text so comments in the file are preserved; falls back to a full rewrite
    (keeping a .bak copy) when 'devices:' is not the last top-level section.
    """
    to_add = [c for c in candidates if c.device_type and not c.already_in_inventory]
    if not to_add:
        return []
    text = path.read_text(encoding="utf-8") if path.exists() else "devices:\n"
    data = yaml.safe_load(text) or {}
    devices = data.get("devices") or {}
    taken = {n.lower() for n in devices}
    known_hosts = {(str(v.get("host")), int(v.get("port", 22))) for v in devices.values() if isinstance(v, dict)}

    new: dict[str, dict] = {}
    for c in to_add:
        if (c.host, c.port) in known_hosts:
            continue
        name = _unique_name(c.hostname or c.host.replace(".", "-"), taken)
        entry: dict = {"host": c.host, "device_type": c.device_type}
        if c.port != 22:
            entry["port"] = c.port
        if credentials != "default":
            entry["credentials"] = credentials
        if site:
            entry["site"] = site
        entry["description"] = "auto-discovered"
        entry.update(c.extra or {})
        new[name] = entry
    if not new:
        return []

    top_keys = re.findall(r"^([A-Za-z_][\w-]*):", text, re.M)
    if re.search(r"^devices:\s*\{\s*\}\s*$", text, re.M):
        text = re.sub(r"^devices:\s*\{\s*\}\s*$", "devices:", text, flags=re.M)
        top_keys = re.findall(r"^([A-Za-z_][\w-]*):", text, re.M)
    if top_keys and top_keys[-1] == "devices":
        dumped = yaml.safe_dump(new, allow_unicode=True, sort_keys=False, default_flow_style=False)
        block = "".join(f"  {line}\n" for line in dumped.splitlines())
        if not text.endswith("\n"):
            text += "\n"
        text += f"\n  # auto-discovered {datetime.now().strftime('%Y-%m-%d %H:%M')}\n" + block
    else:
        path.with_suffix(path.suffix + ".bak").write_text(text, encoding="utf-8")
        data.setdefault("devices", {}).update(new)
        text = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    # Validate the result parses back to what we expect.
    check = yaml.safe_load(path.read_text(encoding="utf-8"))
    missing = [n for n in new if n not in (check.get("devices") or {})]
    if missing:
        raise RuntimeError(f"inventory ჩაწერა ვერ მოხერხდა: {missing}")
    return list(new)


def format_candidates(cands: list[Candidate]) -> str:
    if not cands:
        return "🔍 SSH-ით ხელმისაწვდომი მოწყობილობა ვერ ვიპოვე."
    new = [c for c in cands if c.device_type and not c.already_in_inventory]
    lines = [f"🔍 **ნაპოვნია {len(cands)}** (ახალი, ამოცნობილი: {len(new)})", "```"]
    for c in cands:
        if c.already_in_inventory:
            lines.append(f"✅ {c.host:<15} უკვე არის: {c.already_in_inventory}")
        elif c.device_type:
            lines.append(f"🆕 {c.host:<15} {c.device_type:<18} {c.hostname or ''}")
        else:
            lines.append(f"❔ {c.host:<15} {c.error[:45]}")
    lines.append("```")
    return "\n".join(lines)
