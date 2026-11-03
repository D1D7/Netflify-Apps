"""Terminal interface.

  python -m netagent.cli                      # interactive chat
  python -m netagent.cli ask "R1-ის IP-ები"   # one question
  cat running.cfg | python -m netagent.cli ask "ამოიღე VLAN-ები"
  python -m netagent.cli devices              # inventory list
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
from .inventory import Inventory
from .security import mask_secrets
from .tools.extract import extract_network_data

console = Console()
MAX_STDIN_CHARS = 60_000


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

    agent = NetAgent()
    content = _content_with_stdin(" ".join(args.question))
    with console.status("ვამუშავებ..."):
        answer = agent.chat("cli-oneshot", content, user=_user(), channel="cli", on_tool=_on_tool)
    console.print(Markdown(answer))
    return 0


def cmd_chat(args: argparse.Namespace) -> int:
    from .agent import NetAgent

    agent = NetAgent()
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
            answer = agent.chat(session, question, user=_user(), channel="cli", on_tool=_on_tool)
        console.print()
        console.print(Markdown(answer))
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
    p_ex = sub.add_parser("extract", help="ფაილიდან IP/VLAN/MAC ამოღება AI-ს გარეშე")
    p_ex.add_argument("file", help="ფაილი ან '-' stdin-ისთვის")
    p_ex.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    handlers = {"chat": cmd_chat, "ask": cmd_ask, "devices": cmd_devices, "extract": cmd_extract, None: cmd_chat}
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
