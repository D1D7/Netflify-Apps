"""Diagnostics run from the agent's own host: ping, traceroute, DNS, TCP port check."""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import time
from typing import Any

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-\.]*[A-Za-z0-9])?$")


def _valid_host(host: str) -> str:
    host = host.strip()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        raise ValueError(f"არასწორი ჰოსტი: {host!r}")
    return host


def _run(cmd: list[str], timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"error": f"'{cmd[0]}' ამ სერვერზე დაყენებული არ არის"}
    except subprocess.TimeoutExpired:
        return {"error": f"დრო ამოიწურა ({timeout} წმ)"}
    return {"exit_code": proc.returncode, "output": (proc.stdout + proc.stderr).strip()[-6000:]}


def ping(host: str, count: int = 4) -> dict[str, Any]:
    host = _valid_host(host)
    count = max(1, min(int(count), 10))
    binary = "ping6" if ":" in host and shutil.which("ping6") else "ping"
    res = _run([binary, "-c", str(count), "-W", "2", host], timeout=count * 3 + 5)
    res["host"] = host
    if "output" in res:
        m = re.search(r"(\d+)% packet loss", res["output"])
        if m:
            res["packet_loss_percent"] = int(m.group(1))
        m = re.search(r"= [\d.]+/([\d.]+)/", res["output"])
        if m:
            res["avg_rtt_ms"] = float(m.group(1))
        res["reachable"] = res.get("exit_code") == 0
    return res


def traceroute(host: str, max_hops: int = 20) -> dict[str, Any]:
    host = _valid_host(host)
    max_hops = max(1, min(int(max_hops), 30))
    if shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-w", "2", "-q", "1", "-m", str(max_hops), host]
    elif shutil.which("tracepath"):
        cmd = ["tracepath", "-n", "-m", str(max_hops), host]
    else:
        return {"error": "traceroute/tracepath დაყენებული არ არის"}
    res = _run(cmd, timeout=max_hops * 3 + 10)
    res["host"] = host
    return res


def dns_lookup(name: str, record_type: str = "A", server: str | None = None) -> dict[str, Any]:
    import dns.resolver
    import dns.reversename

    record_type = record_type.upper()
    allowed = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"}
    if record_type not in allowed:
        raise ValueError(f"record_type უნდა იყოს ერთ-ერთი: {', '.join(sorted(allowed))}")
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    if server:
        resolver.nameservers = [_valid_host(server)]
    qname = name.strip()
    if record_type == "PTR":
        qname = str(dns.reversename.from_address(qname))
    start = time.monotonic()
    try:
        answer = resolver.resolve(qname, record_type)
    except dns.resolver.NXDOMAIN:
        return {"name": name, "type": record_type, "error": "NXDOMAIN (დომენი არ არსებობს)"}
    except dns.resolver.NoAnswer:
        return {"name": name, "type": record_type, "records": []}
    except Exception as exc:  # noqa: BLE001
        return {"name": name, "type": record_type, "error": f"{type(exc).__name__}: {exc}"}
    return {
        "name": name,
        "type": record_type,
        "server": resolver.nameservers[0] if resolver.nameservers else None,
        "ttl": answer.rrset.ttl if answer.rrset else None,
        "records": [r.to_text() for r in answer],
        "time_ms": round((time.monotonic() - start) * 1000, 1),
    }


def tcp_port_check(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    host = _valid_host(host)
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("პორტი უნდა იყოს 1-65535 შუალედში")
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"host": host, "port": port, "open": True,
                    "time_ms": round((time.monotonic() - start) * 1000, 1)}
    except socket.timeout:
        return {"host": host, "port": port, "open": False, "reason": "timeout (შესაძლოა firewall)"}
    except ConnectionRefusedError:
        return {"host": host, "port": port, "open": False, "reason": "connection refused (პორტი დახურულია)"}
    except OSError as exc:
        return {"host": host, "port": port, "open": False, "reason": str(exc)}
