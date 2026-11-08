"""Feature modules (v0.9+): each adds commands, AI tools, background jobs or notifiers.

`install()` plugs them into the shared command table and tool list once per process,
so the core modules do not need to know about every feature.

A feature module may define:
    COMMANDS   {name: fn(services, args, user) -> Result}
    HELP       ["/cmd — description", ...]
    BOT_COMMANDS [(name, description)]           Telegram menu
    TOOLS      [(schema, handler(ctx, **kwargs))]  AI tools
    jobs(monitoring) -> [(name, every_seconds, first_delay, coroutine_fn)]
    notifiers(services) -> [async fn(alert)]
    suppress(services, alert) -> bool              keep an alert quiet (still logged)
    on_alert(services, alert)                      sees every alert (e.g. incident memory)
    prompt_extra(services) -> str                  appended to the AI system prompt
"""

from __future__ import annotations

import importlib
import logging
import os

log = logging.getLogger("netagent.features")

MODULES = ("homenet", "isp", "sites", "ops", "notify", "selfmgmt", "teach", "ifstats", "cve", "golden", "gitbackup",
           "firewall", "pathtrace", "morebooks", "incidents", "passport", "weekly", "ipam", "changes", "flows", "snmp", "importers", "metrics", "lan", "activity", "remote", "presence", "diagnose", "secwatch")
_installed = False


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip() or default)
    except ValueError:
        return default


def modules() -> list:
    return [importlib.import_module(f".{m}", __name__) for m in MODULES]


def install() -> None:
    global _installed
    if _installed:
        return
    from .. import commands, tools

    extra_help = []
    for m in modules():
        commands.COMMANDS.update(getattr(m, "COMMANDS", {}))
        extra_help += getattr(m, "HELP", [])
        for schema, handler in getattr(m, "TOOLS", []):
            if schema["name"] not in tools._HANDLERS:  # noqa: SLF001 - registry owned by tools
                tools.TOOL_SCHEMAS.append(schema)
                tools._HANDLERS[schema["name"]] = handler  # noqa: SLF001
                tools._SCHEMA_BY_NAME[schema["name"]] = schema  # noqa: SLF001
    if extra_help:
        marker = "\n\nყველაფერი დანარჩენი"
        head, sep, tail = commands.HELP.partition(marker)
        commands.HELP = head + "\n" + "\n".join(extra_help) + sep + tail
    _installed = True


def _collect(attr: str, *args) -> list:
    out = []
    for m in modules():
        fn = getattr(m, attr, None)
        if fn is not None:
            try:
                out += fn(*args)
            except Exception:  # noqa: BLE001 - one broken feature must not stop the server
                log.exception("%s.%s failed", m.__name__, attr)
    return out


def jobs(monitoring) -> list:
    return _collect("jobs", monitoring)


def notifiers(services) -> list:
    return _collect("notifiers", services)


async def start(services, monitoring) -> list:
    """Start network listeners of features (e.g. NetFlow). Returns transports to close on shutdown."""
    out = []
    for m in modules():
        fn = getattr(m, "start", None)
        if fn is not None:
            try:
                out += await fn(services, monitoring)
            except OSError as exc:
                log.warning("%s: listener could not start (%s)", m.__name__, exc)
            except Exception:  # noqa: BLE001
                log.exception("%s.start failed", m.__name__)
    return out


def bot_commands() -> list[tuple[str, str]]:
    return [c for m in modules() for c in getattr(m, "BOT_COMMANDS", [])]


def suppress(services, alert) -> bool:
    for m in modules():
        fn = getattr(m, "suppress", None)
        try:
            if fn is not None and fn(services, alert):
                return True
        except Exception:  # noqa: BLE001
            log.exception("%s.suppress failed", m.__name__)
    return False


def on_alert(services, alert) -> None:
    for m in modules():
        fn = getattr(m, "on_alert", None)
        if fn is not None:
            try:
                fn(services, alert)
            except Exception:  # noqa: BLE001
                log.exception("%s.on_alert failed", m.__name__)


def prompt_extra(services) -> str:
    parts = []
    for m in modules():
        fn = getattr(m, "prompt_extra", None)
        if fn is not None and services is not None:
            try:
                parts.append(fn(services) or "")
            except Exception:  # noqa: BLE001
                log.exception("%s.prompt_extra failed", m.__name__)
    return "".join(parts)
