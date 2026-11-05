"""Deterministic commands (no AI): one implementation shared by Telegram and the app.

Each command returns a Result; the interface decides how to show it
(Telegram message/photo/document, or a chat bubble in the app).
"""

from __future__ import annotations

import secrets
import shlex
from datetime import datetime, timedelta
from typing import Callable

from .alerts import ALL, format_duration, parse_duration
from .audit import log_event
from .config import settings
from .formatting import first_line
from .health import check_many
from .inventory import InventoryError
from .result import Button, CommandError, Result  # noqa: F401 - re-exported for interfaces
from .security import CommandRejected, validate_command
from .tools import device as dev

MAX_INLINE_CMD_OUTPUT = 3500
DEFAULT_MUTE = 3600


def mute_buttons(devices: list[str]) -> list[Button]:
    buttons = [Button(f"🔕 {name} — 1 სთ", f"/mute {name} 1h") for name in devices[:6]]
    if len(devices) > 1:
        buttons.append(Button("🔕 ყველა — 1 სთ", "/mute all 1h"))
    return buttons


# --------------------------------------------------------------------------- commands


def status(s, args, user) -> Result:
    results = check_many(list(s.inventory().devices.values()))
    if not results:
        return Result("inventory ცარიელია.")
    up = sum(r.up for r in results)
    lines = [f"🩺 **სტატუსი**: {up}/{len(results)} ხელმისაწვდომი", "```"]
    for r in sorted(results, key=lambda r: (r.up, r.device)):
        mark = "🟢" if r.up else "🔴"
        extra = f"{r.latency_ms:.0f}ms" if r.up and r.latency_ms is not None else r.reason
        muted = " 🔕" if s.mutes.is_muted(r.device) else ""
        lines.append(f"{mark} {r.device:<14} {r.host:<15} {extra}{muted}")
    lines.append("```")
    return Result("\n".join(lines))


def devices(s, args, user) -> Result:
    inv = s.inventory()
    if not inv.devices:
        return Result("inventory ცარიელია. მოწყობილობების საპოვნელად: /discover 10.0.0.0/24")
    lines = [f"{d.name:<14} {d.host:<15} {d.device_type}" for d in inv.devices.values()]
    return Result(f"📋 მოწყობილობები ({len(lines)}):\n```\n" + "\n".join(lines) + "\n```")


def backup(s, args, user) -> Result:
    from .backup import BackupStore, backup_devices

    inv = s.inventory()
    devs = inv.filter(" ".join(args)) if args else list(inv.devices.values())
    if not devs:
        return Result("მოწყობილობები ვერ მოიძებნა.")
    reach = {r.device: r for r in check_many(devs)}
    reachable = [d for d in devs if reach[d.name].up]
    results = backup_devices(inv, reachable, BackupStore(settings.backup_dir)) if reachable else {}
    lines = ["💾 **Backup**", "```"]
    for d in devs:
        if not reach[d.name].up:
            lines.append(f"🔴 {d.name:<14} მიუწვდომელია ({reach[d.name].reason})")
    for name, r in results.items():
        if "error" in r:
            lines.append(f"⚠️ {name:<14} {first_line(r['error'])[:60]}")
        elif r.get("first_backup"):
            lines.append(f"🆕 {name:<14} პირველი backup")
        elif r.get("saved"):
            lines.append(f"📝 {name:<14} შეიცვალა +{r.get('added', 0)}/-{r.get('removed', 0)}")
        else:
            lines.append(f"✅ {name:<14} ცვლილება არ არის")
    lines.append("```")
    return Result("\n".join(lines))


def report(s, args, user) -> Result:
    from .report import build_report

    return Result(build_report(s.inventory(), mutes=s.mutes, usage=s.usage))


def audit(s, args, user) -> Result:
    from .compliance import format_findings
    from .report import run_security_audit

    inv = s.inventory()
    devs = inv.filter(" ".join(args)) if args else None
    results, duplicates, errors = run_security_audit(inv, devs)
    if not results and not errors:
        return Result("inventory ცარიელია.")
    return Result(format_findings(results, duplicates, errors))


def usage(s, args, user) -> Result:
    return Result(s.usage.summary())


def mutes(s, args, user) -> Result:
    return Result(s.mutes.describe())


def _device(s, name: str):
    try:
        return s.inventory().get(name)
    except InventoryError as exc:
        raise CommandError(str(exc)) from None


def health(s, args, user) -> Result:
    from .watch import collect, format_health_text

    if not args:
        raise CommandError("გამოყენება: /health R1")
    d = _device(s, args[0])
    return Result(format_health_text(d.name, collect(s.inventory(), d, everything=True)))


def graph(s, args, user) -> Result:
    from .charts import latency_chart

    if not args:
        raise CommandError("გამოყენება: /graph R1  ან  /graph R1 48")
    d = _device(s, args[0])
    try:
        hours = max(1, min(336, int(args[1]))) if len(args) > 1 else 24
    except ValueError:
        raise CommandError("საათების რაოდენობა რიცხვი უნდა იყოს, მაგ. /graph R1 48") from None
    points = s.history.read(d.name, hours)
    if not points:
        return Result(f"📈 {d.name}: ისტორია ჯერ არ არის. მონიტორინგი ყოველ {settings.monitor_interval} წუთში აგროვებს მონაცემებს.")
    stats = s.history.stats(d.name, hours)
    path = settings.export_dir / f"latency-{d.name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.png"
    latency_chart(d.name, points, path, hours, stats)
    caption = f"{d.name}: uptime {stats['uptime_percent']}%" + (
        f", საშ. {stats['avg_ms']} ms, მაქს. {stats['max_ms']} ms" if "avg_ms" in stats else "")
    return Result(caption, image=path)


def cmd(s, args, user) -> Result:
    """Run one read-only command on a device, a filter match, or all devices."""
    if len(args) < 2:
        raise CommandError("გამოყენება:\n/cmd R1 show ip interface brief\n/cmd all show clock\n/cmd HQ show version")
    target, command = args[0], " ".join(args[1:])
    inv = s.inventory()
    if target.lower() in {"all", "*", "ყველა"}:
        devs = list(inv.devices.values())
    else:
        try:
            devs = [inv.get(target)]
        except InventoryError as exc:
            devs = inv.filter(target)
            if not devs:
                raise CommandError(str(exc)) from None
    try:
        for d in devs:
            validate_command(command, d.device_type)
    except CommandRejected as exc:
        raise CommandError(f"⛔ {exc}") from None

    results = dev.run_on_devices(inv, devs, lambda d: dev.run_commands(inv, d, [command], parse=False, max_chars=200_000))
    for d in devs:
        r = results[d.name]
        ok = isinstance(r, list) and bool(r) and "error" not in r[0]
        log_event(settings.audit_log_path, user=user, tool="cmd", args={"device": d.name, "command": command},
                  ok=ok, device_access=True)

    def body(r) -> str:
        if isinstance(r, dict):
            return f"⚠️ {first_line(r.get('error', ''))}"
        return (r[0].get("output") if "output" in r[0] else f"⚠️ {first_line(r[0].get('error', ''))}") or "(ცარიელი)"

    text = "\n\n".join(f"📟 **{name}** › `{command}`\n```\n{body(r).rstrip()}\n```" for name, r in results.items())
    if len(text) <= MAX_INLINE_CMD_OUTPUT:
        return Result(text)
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    path = settings.export_dir / f"cmd-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
    path.write_text("\n\n".join(f"===== {name}: {command} =====\n{body(r)}" for name, r in results.items()), encoding="utf-8")
    return Result(f"📟 `{command}` — {len(devs)} მოწყობილობა, output დიდია, გიგზავნი ფაილად.", files=[path])


def _mute_target(s, name: str) -> str:
    return ALL if name.lower() in {"all", "*", "ყველა"} else _device(s, name).name


def mute(s, args, user) -> Result:
    if not args:
        return Result("გამოყენება: /mute R1 2h  ·  /mute all 30m  ·  /mute R1 (1 სთ)\n\n" + s.mutes.describe())
    target = _mute_target(s, args[0])
    try:
        seconds = parse_duration(args[1]) if len(args) > 1 else DEFAULT_MUTE
    except ValueError as exc:
        raise CommandError(str(exc)) from None
    s.mutes.mute(target, seconds)
    name = "ყველა მოწყობილობა" if target == ALL else target
    return Result(f"🔕 {name}: ალერტები დადუმებულია {format_duration(seconds)}-ით. მოხსნა: /unmute {args[0]}")


def unmute(s, args, user) -> Result:
    if not args or args[0].lower() in {"all", "*", "ყველა"}:
        s.mutes.unmute_all()
        return Result("🔔 ყველა დადუმება მოიხსნა.")
    target = _mute_target(s, args[0])
    return Result(f"🔔 {target}: დადუმება მოიხსნა." if s.mutes.unmute(target) else f"{target} დადუმებული არ იყო.")


def _split_target(s, args: list[str]) -> tuple[str, list[str]]:
    """First argument is a device if it exists in the inventory, otherwise the note is general."""
    if args:
        try:
            return s.inventory().get(args[0]).name, args[1:]
        except InventoryError:
            pass
    return "", args


def notes_overview(s) -> str:
    from .notes import GENERAL

    data = s.notes.all()
    if not data:
        return "📝 შენიშვნები ჯერ არ არის.\nდამატება: /note R1 ტექსტი  ან უბრალოდ მომწერე „დაიმახსოვრე ...“"
    lines = ["📝 **შენიშვნები:**"]
    for target, items in sorted(data.items()):
        name = "ზოგადი" if target == GENERAL else target
        lines.append(f"• {name}: {len(items)}  → /notes {'' if target == GENERAL else target}".rstrip())
    return "\n".join(lines)


def note(s, args, user) -> Result:
    target, rest = _split_target(s, args)
    text = " ".join(rest).strip()
    if not text:
        raise CommandError("გამოყენება: /note R1 ISP: Magti, circuit 12345\nზოგადი: /note ოფისის ქსელი 10.0.0.0/16")
    try:
        count = s.notes.add(target, text, author=user)
    except ValueError as exc:
        raise CommandError(str(exc)) from None
    return Result(f"📝 შენახულია ({target or 'ზოგადი'}, სულ {count}).")


def notes(s, args, user) -> Result:
    if not args:
        return Result(notes_overview(s))
    target, _ = _split_target(s, args)
    if not target and args[0].lower() not in {"general", "ზოგადი"}:
        raise CommandError(f"მოწყობილობა '{args[0]}' ვერ ვიპოვე")
    return Result(s.notes.format(target))


def delnote(s, args, user) -> Result:
    target, rest = _split_target(s, args)
    try:
        number = int(rest[0])
    except (IndexError, ValueError):
        raise CommandError("გამოყენება: /delnote R1 2") from None
    try:
        removed = s.notes.delete(target, number)
    except ValueError as exc:
        raise CommandError(str(exc)) from None
    return Result(f"🗑 წაიშალა: {removed.get('text', '')[:100]}")


def discover(s, args, user) -> Result:
    from .discovery import discover as run_discovery
    from .discovery import format_candidates

    if not args:
        raise CommandError("გამოყენება: /discover 10.0.0.0/24\nსხვა credentials პროფილით: /discover 10.0.0.0/24 mikrotik")
    network, cred = args[0], (args[1] if len(args) > 1 else "default")
    try:
        cands = run_discovery(s.inventory(), network, 22, cred)
    except ValueError as exc:
        raise CommandError(str(exc)) from None
    result = Result(format_candidates(cands))
    new = [c for c in cands if c.device_type and not c.already_in_inventory]
    if new:
        token = secrets.token_hex(4)
        s.pending_discovery[token] = (new, cred)
        result.buttons = [Button(f"➕ დამატება ({len(new)})", f"/discover-add {token}"),
                          Button("❌ არა", f"/discover-cancel {token}")]
    return result


def discover_add(s, args, user) -> Result:
    from .discovery import add_to_inventory

    pending = s.pending_discovery.pop(args[0], None) if args else None
    if not pending:
        return Result("ეს სია ვადაგასულია, თავიდან გაუშვი /discover.")
    cands, cred = pending
    added = add_to_inventory(settings.inventory_path, cands, cred)
    if not added:
        return Result("ახალი არაფერი დაემატა.")
    return Result(f"✅ დაემატა {len(added)}: " + ", ".join(added) + "\nსახელები შეგიძლია შეცვალო inventory/devices.yaml-ში.")


def discover_cancel(s, args, user) -> Result:
    if args:
        s.pending_discovery.pop(args[0], None)
    return Result("გაუქმდა.")


def map_cmd(s, args, user) -> Result:
    from .topology import discover_topology, draw_map, format_links

    inv = s.inventory()
    if not inv.devices:
        return Result("inventory ცარიელია. მოწყობილობების საპოვნელად: /discover 10.0.0.0/24")
    data = discover_topology(inv, settings.data_dir / "topology.json")
    down = {r.device for r in check_many(list(inv.devices.values()), timeout=2.0, retries=0) if not r.up}
    path = settings.export_dir / f"map-{datetime.now().strftime('%Y%m%d-%H%M%S')}.png"
    draw_map(data, path, down)
    text = format_links(data)
    if len(text) > 900:  # Telegram photo captions are short: send the list separately
        return Result(text, image=None, files=[path])
    return Result(text, image=path)


def logs(s, args, user) -> Result:
    from .syslogd import SEVERITY

    device, words = "", list(args)
    if words:
        try:
            device = s.inventory().get(words[0]).name
            words = words[1:]
        except InventoryError:
            pass
    rows = s.syslog.search(device, " ".join(words), hours=24, limit=25)
    if not rows:
        return Result("📜 ლოგები არ არის (ბოლო 24 სთ)."
                      + ("" if device or words else "\nმოწყობილობებზე syslog მიმართე ამ კომპიუტერზე: udp/"
                         + str(settings.syslog_port) + ". მაგ. Cisco: logging host <IP>"))
    icon = {s_: i for s_, i in zip(SEVERITY, ["🔥", "🔥", "🔥", "🔴", "⚠️", "🔹", "▫️", "▫️"])}
    lines = [f"📜 **ლოგები**{' — ' + device if device else ''} (ბოლო {len(rows)})", "```"]
    for r in rows:
        lines.append(f"{icon.get(r['severity'], '▫️')} {r['ts'][11:16]} {r['device']:<10} {r['message'][:110]}")
    lines.append("```")
    return Result("\n".join(lines))


def runbook_cmd(s, args, user) -> Result:
    from .runbooks import RUNBOOKS, run

    if not args:
        return Result("📚 **Runbook-ები:**\n" + "\n".join(f"• /runbook {k} — {v}" for k, v in RUNBOOKS.items()),
                      buttons=[Button("🌐 ინტერნეტი", "/runbook internet"), Button("🐢 ნელია", "/runbook slow")])
    try:
        rb = run(s, args[0].lower(), args[1:])
    except (ValueError, InventoryError) as exc:
        raise CommandError(str(exc)) from None
    return Result(rb.format())


def mac_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /mac a4:5e:60:12:ab:cd   ·   ბაზის განახლება: /mac update")
    if args[0].lower() == "update":
        try:
            n, src = s.vendors.update()
        except RuntimeError as exc:
            raise CommandError(str(exc)) from None
        return Result(f"✅ MAC ბაზა განახლდა: {n:,} მწარმოებელი ({src})")
    lines = []
    for mac in args[:10]:
        vendor = s.vendors.lookup(mac)
        lines.append(f"`{mac}` → {vendor or 'უცნობი'}")
    if not s.vendors.size:
        lines.append("\n(MAC ბაზა ჯერ არ არის — /mac update)")
    return Result("🔎 " + "\n".join(lines))


def newdevices_cmd(s, args, user) -> Result:
    from .newdevices import format_new

    hours = int(args[0]) if args and args[0].isdigit() else 24
    since = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    items = s.newdevices.recent(since)
    total = len(s.newdevices.known())
    if not total:
        return Result("🆕 ჯერ არ შემიმოწმებია. პირველი სკანირება ქმნის საწყის სიას, შემდეგ ახალი MAC-ები ალერტად მოვა.")
    if not items:
        return Result(f"🆕 ბოლო {hours} სთ-ში ახალი მოწყობილობა არ გამოჩენილა (ცნობილია {total}).")
    return Result(f"🆕 **ახალი მოწყობილობები** — ბოლო {hours} სთ ({len(items)})\n" + format_new(items))


def demo_cmd(s, args, user) -> Result:
    from .demo import lab

    if lab.LAB is None:
        raise CommandError("დემო რეჟიმი ჩართული არ არის (გაუშვი demo.bat ან python -m netagent demo)")
    return lab.LAB.command(args)


HELP = """**სწრაფი ბრძანებები (AI-ს გარეშე, უფასო):**
/status — რომელი მოწყობილობაა ჩართული/გათიშული
/health R1 — ინტერფეისები, BGP, OSPF, CPU
/graph R1 — latency გრაფიკი (ბოლო 24 სთ)
/cmd R1 show ip route — ბრძანება მოწყობილობაზე
/cmd all show clock — ყველა მოწყობილობაზე
/audit — უსაფრთხოების აუდიტი
/backup — config-ების backup
/report — ქსელის რეპორტი
/discover 10.0.0.0/24 — ახალი მოწყობილობების ძებნა
/mute R1 2h · /mute all 30m · /unmute R1
/note R1 ტექსტი · /notes R1 · /delnote R1 2
/usage — AI ხარჯი
/runbook internet — „ინტერნეტი არ მუშაობს“ შემოწმება (/runbook slow, /runbook device R1)
/newdevices — ქსელში ახლად გამოჩენილი მოწყობილობები
/mac a4:5e:60:12:ab:cd — MAC-ის მწარმოებელი
/map — ქსელის რუკა (CDP/LLDP)
/logs R1 — ბოლო ლოგები (/logs R1 UPDOWN — ძებნით)
/devices — მოწყობილობების სია

ყველაფერი დანარჩენი — უბრალოდ დაწერე ჩვეულებრივად, მაგ. „R1-ის IP-ები მაჩვენე“."""


def help_cmd(s, args, user) -> Result:
    return Result(HELP)


COMMANDS: dict[str, Callable] = {
    "status": status,
    "devices": devices,
    "backup": backup,
    "report": report,
    "audit": audit,
    "usage": usage,
    "mutes": mutes,
    "health": health,
    "graph": graph,
    "cmd": cmd,
    "mute": mute,
    "unmute": unmute,
    "note": note,
    "notes": notes,
    "delnote": delnote,
    "discover": discover,
    "discover-add": discover_add,
    "discover-cancel": discover_cancel,
    "map": map_cmd,
    "runbook": runbook_cmd,
    "mac": mac_cmd,
    "newdevices": newdevices_cmd,
    "demo": demo_cmd,
    "logs": logs,
    "help": help_cmd,
}


def parse(line: str) -> tuple[str, list[str]] | None:
    """'/cmd R1 show ip route' -> ('cmd', ['R1', 'show', 'ip', 'route']); None if not a known command."""
    line = line.strip()
    if not line.startswith("/"):
        return None
    head, _, rest = line[1:].partition(" ")
    name = head.split("@", 1)[0].lower()  # Telegram adds @botname in groups
    if name not in COMMANDS:
        return None
    try:
        args = shlex.split(rest) if name not in {"cmd", "note"} else rest.split()
    except ValueError:
        args = rest.split()
    return name, args


def run(s, line: str, user: str) -> Result | None:
    """Execute a command line. Returns None when the line is not a known command."""
    parsed = parse(line)
    if parsed is None:
        return None
    name, args = parsed
    try:
        return COMMANDS[name](s, args, user)
    except CommandError as exc:
        return Result(str(exc) if str(exc).startswith(("⛔", "⚠️")) else f"⚠️ {exc}")
