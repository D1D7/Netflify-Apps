"""Website and service checks: up/down, response time, TLS certificate and domain expiry.

    /site add https://example.com [name]    /site add tcp://10.0.0.5:3389 RDP
    /sites                                   check all now
    /site del 2
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..result import Button, CommandError, Result
from . import env_int

KEY = "sites"
EXPIRY_WARN_DAYS = 14
_SECOND_LEVEL = {"co", "com", "org", "net", "edu", "gov", "ac", "ltd", "school", "pvt"}


def normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in {"http", "https", "tcp"} or not p.hostname:
        raise CommandError("მისამართი უნდა იყოს https://..., http://... ან tcp://host:port")
    if p.scheme == "tcp" and not p.port:
        raise CommandError("tcp-ს სჭირდება პორტი, მაგ. tcp://10.0.0.5:3389")
    return url


def registrable_domain(host: str) -> str | None:
    if not host or host.replace(".", "").isdigit() or "." not in host:
        return None
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def cert_expiry(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Days until the TLS certificate expires; also says whether it is trusted."""
    from cryptography import x509

    trusted, error = True, ""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        trusted, error = False, exc.verify_message or str(exc)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    not_after = cert.not_valid_after_utc
    days = (not_after - datetime.now(timezone.utc)).days
    issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    return {"cert_days_left": days, "cert_expires": not_after.date().isoformat(), "cert_trusted": trusted,
            "cert_error": error, "cert_issuer": issuer[0].value if issuer else ""}


def domain_expiry(domain: str, timeout: float = 10.0) -> dict:
    import httpx

    try:
        r = httpx.get(f"https://rdap.org/domain/{domain}", timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "NetAgent", "Accept": "application/rdap+json"})
        if r.status_code != 200:
            return {"domain": domain, "domain_expires": None}
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "expiration":
                exp = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return {"domain": domain, "domain_expires": exp.date().isoformat(),
                        "domain_days_left": (exp - datetime.now(timezone.utc)).days}
    except Exception:  # noqa: BLE001 - many ccTLDs (incl. .ge) have no RDAP
        pass
    return {"domain": domain, "domain_expires": None}


def check(url: str, deep: bool = False) -> dict:
    url = normalize_url(url)
    p = urlparse(url)
    res: dict = {"url": url}
    start = time.monotonic()
    if p.scheme == "tcp":
        try:
            with socket.create_connection((p.hostname, p.port), timeout=8):
                res.update(up=True)
        except OSError as exc:
            res.update(up=False, error=exc.strerror or str(exc))
    else:
        import httpx

        try:
            r = httpx.get(url, timeout=15, follow_redirects=True, headers={"User-Agent": "NetAgent uptime check"})
            res.update(up=r.status_code < 500, status=r.status_code)
            if r.status_code >= 500:
                res["error"] = f"HTTP {r.status_code}"
        except httpx.HTTPError as exc:
            res.update(up=False, error=f"{type(exc).__name__}: {str(exc)[:120]}")
    res["ms"] = round((time.monotonic() - start) * 1000)
    if deep and p.scheme == "https":
        try:
            res.update(cert_expiry(p.hostname, p.port or 443))
        except Exception as exc:  # noqa: BLE001
            res["cert_error"] = f"{type(exc).__name__}: {exc}"
        dom = registrable_domain(p.hostname)
        if dom:
            res.update(domain_expiry(dom))
    return res


def format_check(r: dict, name: str = "") -> str:
    label = name or r["url"]
    if not r["up"]:
        return f"🔴 **{label}** — არ მუშაობს ({r.get('error', '')})"
    line = f"🟢 **{label}** — {r.get('status', 'OK')} · {r['ms']} ms"
    if "cert_days_left" in r:
        d = r["cert_days_left"]
        icon = "🔴" if d < 0 or not r.get("cert_trusted", True) else "🟠" if d <= EXPIRY_WARN_DAYS else "🔒"
        line += f"\n  {icon} სერტიფიკატი: {d} დღე ({r['cert_expires']})" + ("" if r.get("cert_trusted", True) else f" — არასანდო: {r['cert_error']}")
    if r.get("domain_expires"):
        d = r["domain_days_left"]
        line += f"\n  {'🟠' if d <= 30 else '🌐'} დომენი {r['domain']}: {d} დღე ({r['domain_expires']})"
    return line


# -- store ---------------------------------------------------------------------------------
def sites(state) -> list[dict]:
    return state.get(KEY) or []


def site_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /site add https://example.com [სახელი] · /site del 2 · /sites")
    action = args[0].lower()
    if action == "add" and len(args) >= 2:
        url = normalize_url(args[1])
        if any(x["url"] == url for x in sites(s.state)):
            raise CommandError("ეს მისამართი უკვე დამატებულია")
        name = " ".join(args[2:])[:40]
        s.state.update(KEY, lambda v: (v or []) + [{"url": url, "name": name, "added": datetime.now().isoformat(timespec="seconds")}])
        r = check(url, deep=True)
        return Result("✅ დაემატა მონიტორინგში\n" + format_check(r, name))
    if action in {"del", "rm", "delete"} and len(args) == 2:
        items = sites(s.state)
        idx = next((i for i, x in enumerate(items) if args[1] in (str(i + 1), x["url"], x["name"])), None)
        if idx is None:
            raise CommandError("ვერ ვიპოვე. სია: /sites")
        removed = items.pop(idx)
        s.state.set(KEY, items)
        return Result(f"🗑 წაიშალა: {removed['name'] or removed['url']}")
    raise CommandError("გამოყენება: /site add URL [სახელი] · /site del N")


def sites_cmd(s, args, user) -> Result:
    from concurrent.futures import ThreadPoolExecutor

    items = sites(s.state)
    if not items:
        return Result("🌐 საიტები ჯერ არ არის. დამატება: /site add https://example.com", buttons=[])
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda x: check(x["url"], deep=True), items))
    lines = [f"{i + 1}. " + format_check(r, x["name"]) for i, (x, r) in enumerate(zip(items, results))]
    return Result("🌐 **საიტები და სერვისები**\n" + "\n".join(lines), buttons=[Button("🔄 შემოწმება", "/sites")])


COMMANDS = {"site": site_cmd, "sites": sites_cmd}
HELP = ["/sites — საიტების/სერვისების, SSL-ის და დომენის ვადის შემოწმება · /site add https://example.com"]
BOT_COMMANDS = [("sites", "საიტები, SSL და დომენები")]
TOOLS = [({
    "name": "check_website",
    "description": "Check a website or TCP service: up/down, HTTP status, response time, TLS certificate expiry and "
                   "trust, domain expiry (RDAP). url like https://example.com or tcp://10.0.0.5:3389. "
                   "Empty url = all monitored sites.",
    "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": []},
}, lambda ctx, url="": check(url, deep=True) if url else
    [dict(check(x["url"], deep=True), name=x["name"]) for x in sites(ctx.services.state)])]


def jobs(monitoring):
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    from ..monitoring import Alert

    every = env_int("NETAGENT_SITE_INTERVAL", 5)
    if every <= 0:
        return []
    fails: dict[str, int] = {}
    down: set[str] = set()
    last_deep = {"t": 0.0}

    async def run():
        s = monitoring.s
        items = sites(s.state)
        if not items:
            return
        deep = time.time() - last_deep["t"] > 12 * 3600
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = await asyncio.to_thread(lambda: list(pool.map(lambda x: check(x["url"], deep=deep), items)))
        if deep:
            last_deep["t"] = time.time()
        for x, r in zip(items, results):
            label = x["name"] or x["url"]
            if r["up"]:
                fails[x["url"]] = 0
                if x["url"] in down:
                    down.discard(x["url"])
                    await monitoring.emit(Alert("site", f"🟢 **{label}** ისევ მუშაობს ({r['ms']} ms)", mutable=False))
            else:
                fails[x["url"]] = fails.get(x["url"], 0) + 1
                if fails[x["url"]] == 2:  # two checks in a row, no alert for a single blip
                    down.add(x["url"])
                    await monitoring.emit(Alert("site", f"🔴 **{label}** არ მუშაობს — {r.get('error', '')}", mutable=False))
            warn = []
            if r.get("cert_days_left") is not None and (r["cert_days_left"] <= EXPIRY_WARN_DAYS or not r.get("cert_trusted", True)):
                warn.append(f"🔒 სერტიფიკატს {r['cert_days_left']} დღე დარჩა ({r['cert_expires']})"
                            + ("" if r.get("cert_trusted", True) else f", არასანდოა: {r['cert_error']}"))
            if r.get("domain_days_left") is not None and r["domain_days_left"] <= 30:
                warn.append(f"🌐 დომენს {r['domain']} {r['domain_days_left']} დღე დარჩა ({r['domain_expires']})")
            if warn:
                await monitoring.emit(Alert("site", f"⏳ **{label}**\n" + "\n".join(warn), mutable=False))

    return [("sites", every * 60, 75, run)]
