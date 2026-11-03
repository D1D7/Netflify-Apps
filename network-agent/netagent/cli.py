"""Terminal interface.

  python -m netagent.cli                      # interactive chat
  python -m netagent.cli ask "R1-ის IP-ები"   # one question
  cat running.cfg | python -m netagent.cli ask "ამოიღე VLAN-ები"
  python -m netagent.cli devices              # inventory list
  python -m netagent.cli status               # which devices are up/down
  python -m netagent.cli backup               # back up all configs
  python -m netagent.cli diff R1 --hours 24   # what changed in R1's config
  python -m netagent.cli report               # daily report
  python -m netagent.cli audit                # security audit + duplicate IPs
  python -m netagent.cli ips 10.1.1.0/24      # used / free IPs in a subnet
  python -m netagent.cli cmd R1 show clock    # run one read-only command (no AI)
  python -m netagent.cli usage                # AI cost
  python -m netagent.cli extract file.cfg     # offline IP/VLAN extraction, no AI
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from .config import settings
from .formatting import first_line
from .state import StateStore
from .usage import UsageTracker
from .inventory import Inventory
from .security import mask_secrets
from .tools.extract import extract_network_data

console = Console()
MAX_STDIN_CHARS = 60_000


def _usage_tracker() -> UsageTracker:
    return UsageTracker(StateStore(settings.data_dir / "state.json"), settings.daily_budget_usd)


def _user() -> str:
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:  # noqa: BLE001
        return "cli:unknown"


def _on_tool(name: str, args: dict[str, Any]) -> None:
    shown = ", ".join(f"{k}={v}" for k, v in args.items())
    console.print(f"  [dim]🔧 {name}({shown})[/dim]")


def _content_with_stdin(question: str) -> str | list[dict[str, Any]]:
    if sys.stdin.isatty():
        return question
    data = mask_secrets(sys.stdin.read())
    if not data.strip():
        return question
    extracted = extract_network_data(data)
    return [
        {"type": "text", "text": question or "გააანალიზე ეს ტექსტი."},
        {"type": "text", "text": f"<uploaded_file name=\"stdin\">\n{data[:MAX_STDIN_CHARS]}\n</uploaded_file>"},
        {
            "type": "text",
            "text": "Automatic extraction from the full input (exact, deterministic):\n"
            + json.dumps(extracted, ensure_ascii=False, indent=1),
        },
    ]


def cmd_ask(args: argparse.Namespace) -> int:
    from .agent import NetAgent

    agent = NetAgent(usage=_usage_tracker())
    content = _content_with_stdin(" ".join(args.question))
    with console.status("ვამუშავებ..."):
        reply = agent.chat("cli-oneshot", content, user=_user(), channel="cli", on_tool=_on_tool)
    _print_reply(reply)
    return 0


def _print_reply(reply) -> None:
    console.print(Markdown(reply.text))
    for f in reply.files:
        console.print(f"[green]📎 ფაილი შეინახა:[/green] {f}")


def cmd_chat(args: argparse.Namespace) -> int:
    from .agent import NetAgent

    agent = NetAgent(usage=_usage_tracker())
    console.print(
        "[bold]NetAgent[/bold] — ქსელის ასისტენტი (read-only). "
        "[dim]/reset — თავიდან, /devices — სია, /exit — გასვლა[/dim]\n"
    )
    session = "cli-chat"
    while True:
        try:
            question = console.input("[bold cyan]შენ ›[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return 0
        if not question:
            continue
        if question in {"/exit", "/quit", "exit", "quit"}:
            return 0
        if question == "/reset":
            agent.reset(session)
            console.print("[green]🔄 საუბარი თავიდან დაიწყო[/green]")
            continue
        if question == "/devices":
            cmd_devices(args)
            continue
        with console.status("ვამუშავებ..."):
            reply = agent.chat(session, question, user=_user(), channel="cli", on_tool=_on_tool)
        console.print()
        _print_reply(reply)
        console.print()


def cmd_devices(args: argparse.Namespace) -> int:
    try:
        inv = Inventory.load(settings.inventory_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]⚠️ {exc}[/red]")
        return 1
    table = Table(title=f"მოწყობილობები ({len(inv.devices)})")
    for col in ("name", "host", "device_type", "site", "role"):
        table.add_column(col)
    for d in inv.devices.values():
        table.add_row(d.name, d.host, d.device_type, d.site, d.role)
    console.print(table)
    return 0


def _load_inventory() -> Inventory | None:
    try:
        return Inventory.load(settings.inventory_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]⚠️ {exc}[/red]")
        return None


def cmd_status(args: argparse.Namespace) -> int:
    from .health import check_many

    inv = _load_inventory()
    if inv is None:
        return 1
    with console.status("ვამოწმებ..."):
        results = check_many(list(inv.devices.values()))
    table = Table(title=f"სტატუსი: {sum(r.up for r in results)}/{len(results)} ხელმისაწვდომი")
    for col in ("", "device", "host", "port", "latency / reason"):
        table.add_column(col)
    for r in sorted(results, key=lambda r: (r.up, r.device)):
        detail = f"{r.latency_ms:.0f} ms" if r.up and r.latency_ms is not None else r.reason
        table.add_row("🟢" if r.up else "🔴", r.device, r.host, str(r.port), detail)
    console.print(table)
    return 0 if all(r.up for r in results) else 2


def cmd_backup(args: argparse.Namespace) -> int:
    from .backup import BackupStore, backup_devices

    inv = _load_inventory()
    if inv is None:
        return 1
    devices = inv.filter(args.filter or "")
    with console.status(f"backup: {len(devices)} მოწყობილობა..."):
        results = backup_devices(inv, devices, BackupStore(settings.backup_dir))
    failed = 0
    for name, r in results.items():
        if "error" in r:
            failed += 1
            console.print(f"⚠️  {name}: [red]{first_line(r['error'])}[/red]")
        elif r.get("first_backup"):
            console.print(f"🆕 {name}: პირველი backup ({r['file']})")
        elif r.get("saved"):
            console.print(f"📝 {name}: შეიცვალა [green]+{r.get('added', 0)}[/green] [red]-{r.get('removed', 0)}[/red] ({r['file']})")
        else:
            console.print(f"✅ {name}: ცვლილება არ არის")
    console.print(f"[dim]backups: {settings.backup_dir}[/dim]")
    return 1 if failed else 0


def cmd_diff(args: argparse.Namespace) -> int:
    from rich.syntax import Syntax

    from .backup import BackupStore, changes_since

    inv = _load_inventory()
    if inv is None:
        return 1
    try:
        device = inv.get(args.device)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return 1
    result = changes_since(BackupStore(settings.backup_dir), device.name, args.hours)
    if result is None:
        console.print("backup ჯერ არ არსებობს. გაუშვი: python -m netagent backup")
        return 1
    if not result.get("changed"):
        console.print(f"✅ {device.name}: ბოლო {args.hours} სთ-ში ცვლილება არ ყოფილა")
        return 0
    console.print(f"📝 {device.name}: {result['from']} → {result['to']}  +{result['added']} / -{result['removed']}")
    console.print(Syntax(result["diff"], "diff"))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from .compliance import format_findings
    from .report import run_security_audit

    inv = _load_inventory()
    if inv is None:
        return 1
    devices = inv.filter(args.filter or "")
    with console.status("ვამოწმებ კონფიგურაციებს..."):
        results, duplicates, errors = run_security_audit(inv, devices, refresh=not args.offline)
    console.print(Markdown(format_findings(results, duplicates, errors).replace("\n", "  \n")))
    if args.fix:
        for name, findings in sorted(results.items()):
            for f in findings or []:
                console.print(f"\n[bold]{name}[/bold] — {f.title}")
                console.print(f.fix, style="green")
    high = sum(1 for fs in results.values() for f in (fs or []) if f.severity == "high")
    return 2 if high else 0


def cmd_ips(args: argparse.Namespace) -> int:
    from .tools import device as dev

    inv = _load_inventory()
    if inv is None:
        return 1
    try:
        with console.status(f"ვაგროვებ ARP/ინტერფეისის ცხრილებს ({args.network})..."):
            r = dev.subnet_usage(inv, inv.filter(args.filter or ""), args.network)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    console.print(f"[bold]{r['network']}[/bold]: დაკავებული {r['used_count']} / თავისუფალი {r['free_count']} (სულ {r['usable_hosts']})")
    table = Table(title="დაკავებული")
    table.add_column("IP")
    table.add_column("სად ჩანს")
    for u in r["used"]:
        table.add_row(u["ip"], ", ".join(u["seen_on"]))
    console.print(table)
    console.print("[green]თავისუფალი:[/green] " + ", ".join(r["free_ranges"]))
    for name, err in r["errors"].items():
        console.print(f"⚠️ {name}: [red]{first_line(err)}[/red]")
    console.print(f"[dim]{r['note']}[/dim]")
    return 0


def cmd_cmd(args: argparse.Namespace) -> int:
    from .audit import log_event
    from .inventory import InventoryError
    from .security import CommandRejected, validate_command
    from .tools import device as dev

    inv = _load_inventory()
    if inv is None:
        return 1
    command = " ".join(args.command)
    try:
        if args.target.lower() in {"all", "*"}:
            devices = list(inv.devices.values())
        else:
            try:
                devices = [inv.get(args.target)]
            except InventoryError:
                devices = inv.filter(args.target)
                if not devices:
                    raise
        for d in devices:
            validate_command(command, d.device_type)
    except (CommandRejected, InventoryError) as exc:
        console.print(f"[red]⛔ {exc}[/red]")
        return 1
    with console.status(f"{command} → {len(devices)} მოწყობილობა..."):
        results = dev.run_on_devices(
            inv, devices, lambda d: dev.run_commands(inv, d, [command], parse=False, max_chars=None)
        )
    rc = 0
    for name, r in results.items():
        console.rule(f"[bold]{name}[/bold] › {command}")
        if isinstance(r, dict):
            console.print(f"[red]{first_line(r.get('error', ''))}[/red]")
            rc = 1
        else:
            console.print(r[0].get("output") or f"[red]{first_line(r[0].get('error', ''))}[/red]", markup=False, highlight=False)
        log_event(settings.audit_log_path, user=_user(), tool="cli_cmd",
                  args={"device": name, "command": command}, ok=not isinstance(r, dict), device_access=True)
    return rc


def cmd_usage(args: argparse.Namespace) -> int:
    console.print(Markdown(_usage_tracker().summary().replace("\n", "  \n")))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .report import build_report

    inv = _load_inventory()
    if inv is None:
        return 1
    with console.status("ვამზადებ რეპორტს..."):
        text = build_report(inv, run_backup=not args.no_backup, usage=_usage_tracker())
    console.print(Markdown(text.replace("\n", "  \n")))
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8", errors="replace").read()
    result = extract_network_data(mask_secrets(text))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    c = result["counts"]
    console.print(
        f"[bold]IPv4:[/bold] {c['ipv4']}  [bold]ქსელები:[/bold] {c['networks']}  "
        f"[bold]MAC:[/bold] {c['mac']}  [bold]VLAN:[/bold] {c['vlans']}"
    )
    if result["interfaces"]:
        t = Table(title="ინტერფეისები")
        for col in ("interface", "ip_addresses", "access_vlan", "description", "status"):
            t.add_column(col)
        for i in result["interfaces"]:
            t.add_row(
                i["interface"],
                "\n".join(i.get("ip_addresses", [])),
                str(i.get("access_vlan", "")),
                i.get("description", ""),
                "🔴 shutdown" if i.get("shutdown") else "",
            )
        console.print(t)
    if result["networks"]:
        console.print("[bold]ქსელები:[/bold] " + ", ".join(result["networks"]))
    if result["ipv4_addresses"]:
        console.print("[bold]IPv4:[/bold] " + ", ".join(result["ipv4_addresses"]))
    if result["vlans"]:
        names = result["vlan_names"]
        console.print(
            "[bold]VLAN:[/bold] " + ", ".join(f"{v} ({names[v]})" if v in names else str(v) for v in result["vlans"])
        )
    if result["mac_addresses"]:
        console.print("[bold]MAC:[/bold] " + ", ".join(result["mac_addresses"]))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netagent", description="NetAgent — AI ქსელის ასისტენტი")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("chat", help="ინტერაქტიული ჩატი (default)")
    p_ask = sub.add_parser("ask", help="ერთი კითხვა")
    p_ask.add_argument("question", nargs="*")
    sub.add_parser("devices", help="inventory-ს სია")
    sub.add_parser("status", help="რომელი მოწყობილობაა ჩართული/გათიშული")
    p_bk = sub.add_parser("backup", help="config-ების backup")
    p_bk.add_argument("filter", nargs="?", default="", help="არასავალდებულო ფილტრი (სახელი/საიტი/როლი)")
    p_diff = sub.add_parser("diff", help="რა შეიცვალა მოწყობილობის config-ში")
    p_diff.add_argument("device")
    p_diff.add_argument("--hours", type=int, default=24)
    p_aud = sub.add_parser("audit", help="უსაფრთხოების აუდიტი + დუბლირებული IP-ები")
    p_aud.add_argument("filter", nargs="?", default="")
    p_aud.add_argument("--offline", action="store_true", help="მხოლოდ არსებული backup-ებით, მოწყობილობებთან დაკავშირების გარეშე")
    p_aud.add_argument("--fix", action="store_true", help="გამოსწორების ბრძანებების ჩვენება")
    p_ips = sub.add_parser("ips", help="დაკავებული/თავისუფალი IP-ები ქსელში")
    p_ips.add_argument("network")
    p_ips.add_argument("--filter", default="")
    p_cmd = sub.add_parser("cmd", help="ერთი read-only ბრძანება (AI-ს გარეშე)")
    p_cmd.add_argument("target", help="მოწყობილობა, ფილტრი ან all")
    p_cmd.add_argument("command", nargs="+")
    sub.add_parser("usage", help="AI ხარჯი")
    p_rep = sub.add_parser("report", help="ქსელის რეპორტი")
    p_rep.add_argument("--no-backup", action="store_true", help="backup-ის გარეშე")
    p_ex = sub.add_parser("extract", help="ფაილიდან IP/VLAN/MAC ამოღება AI-ს გარეშე")
    p_ex.add_argument("file", help="ფაილი ან '-' stdin-ისთვის")
    p_ex.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    handlers = {
        "chat": cmd_chat,
        "ask": cmd_ask,
        "devices": cmd_devices,
        "status": cmd_status,
        "backup": cmd_backup,
        "diff": cmd_diff,
        "report": cmd_report,
        "audit": cmd_audit,
        "ips": cmd_ips,
        "cmd": cmd_cmd,
        "usage": cmd_usage,
        "extract": cmd_extract,
        None: cmd_chat,
    }
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
