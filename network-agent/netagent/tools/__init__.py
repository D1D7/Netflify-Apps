"""Tool definitions exposed to Claude and the dispatcher that executes them."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..audit import log_event
from ..config import settings
from ..inventory import Inventory, InventoryError
from ..security import CommandRejected, mask_secrets
from . import device as dev
from . import network as net
from .extract import extract_network_data
from .subnet import ip_in_network, subnet_info

MAX_RESULT_CHARS = 20000


@dataclass
class ToolContext:
    inventory: Inventory
    user: str  # who asked: "telegram:<id>" or "cli:<username>"
    files: list[Path] = field(default_factory=list)  # files produced this turn (sent to the user)


def _obj(properties: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


_DEVICE = {"type": "string", "description": "მოწყობილობის სახელი inventory-დან (list_devices აჩვენებს)."}
_FILTER = {
    "type": "string",
    "description": "არასავალდებულო ფილტრი: სახელის, საიტის, როლის, device_type-ის ან tag-ის ნაწილი. ცარიელი = ყველა.",
}
_INTENT = {
    "type": "string",
    "enum": list(dev.INTENTS),
    "description": (
        "რა მონაცემი გჭირდება: interfaces (სტატუსი/აღწერა), ip_addresses, arp, mac_table, routes, "
        "version (მოდელი/OS/uptime), neighbors (CDP/LLDP), vlans, running_config."
    ),
}

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_devices",
        "description": "აბრუნებს inventory-ში არსებულ მოწყობილობებს (სახელი, IP, device_type, საიტი, როლი). "
        "გამოიძახე, როცა არ იცი რომელ მოწყობილობაზეა საუბარი.",
        "input_schema": _obj({"filter": _FILTER}, []),
    },
    {
        "name": "get_device_data",
        "description": "უკავშირდება ერთ მოწყობილობას SSH-ით და აბრუნებს მონაცემს vendor-ისთვის შესაფერისი "
        "show ბრძანებით (როცა შესაძლებელია, TextFSM-ით დაპარსულ JSON-ად). მხოლოდ კითხულობს.",
        "input_schema": _obj({"device": _DEVICE, "data": _INTENT}, ["device", "data"]),
    },
    {
        "name": "get_data_from_many",
        "description": "იგივე, რაც get_device_data, მაგრამ პარალელურად რამდენიმე/ყველა მოწყობილობაზე. "
        "გამოიყენე მაგ. 'ყველა მოწყობილობის OS ვერსია' ან 'ყველა switch-ის VLAN-ები'.",
        "input_schema": _obj({"data": _INTENT, "filter": _FILTER}, ["data"]),
    },
    {
        "name": "run_show_command",
        "description": "ასრულებს ერთ კონკრეტულ წაკითხვის ბრძანებას მოწყობილობაზე (show/display/get, RouterOS-ზე "
        "'... print'). ცვლილების ბრძანებები ავტომატურად იბლოკება. გამოიყენე, როცა get_device_data-ს "
        "intent-ები არ კმარა. დიდი output-ისთვის გამოიყენე ფილტრი (მაგ. '| include', '| match').",
        "input_schema": _obj(
            {"device": _DEVICE, "command": {"type": "string", "description": "ბრძანება, მაგ. 'show ip ospf neighbor'"}},
            ["device", "command"],
        ),
    },
    {
        "name": "find_on_network",
        "description": "ეძებს IP მისამართს, ქსელს (CIDR) ან MAC მისამართს ყველა მოწყობილობის ინტერფეისებში, "
        "ARP ცხრილში (და MAC-ის შემთხვევაში MAC ცხრილში). პასუხობს კითხვებზე: 'სადაა X ჩართული?', "
        "'რომელ მოწყობილობაზეა 10.1.0.0/24?'.",
        "input_schema": _obj(
            {"query": {"type": "string", "description": "IP (10.1.1.5), ქსელი (10.1.0.0/24) ან MAC"}, "filter": _FILTER},
            ["query"],
        ),
    },
    {
        "name": "device_config_summary",
        "description": "კითხულობს მოწყობილობის running-config-ს და აბრუნებს ამოღებულ მონაცემებს: ყველა IP, "
        "ქსელები, VLAN-ები, ინტერფეისები IP-ებით/აღწერებით, MAC-ები. პაროლები დაფარულია.",
        "input_schema": _obj({"device": _DEVICE}, ["device"]),
    },
    {
        "name": "ping",
        "description": "ping აგენტის სერვერიდან (არა მოწყობილობიდან).",
        "input_schema": _obj(
            {"host": {"type": "string"}, "count": {"type": "integer", "minimum": 1, "maximum": 10}}, ["host"]
        ),
    },
    {
        "name": "traceroute",
        "description": "traceroute აგენტის სერვერიდან.",
        "input_schema": _obj(
            {"host": {"type": "string"}, "max_hops": {"type": "integer", "minimum": 1, "maximum": 30}}, ["host"]
        ),
    },
    {
        "name": "dns_lookup",
        "description": "DNS ჩანაწერის მოძიება (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA). PTR-ისთვის name = IP.",
        "input_schema": _obj(
            {
                "name": {"type": "string"},
                "record_type": {"type": "string"},
                "server": {"type": "string", "description": "არასავალდებულო DNS სერვერი, მაგ. 8.8.8.8"},
            },
            ["name"],
        ),
    },
    {
        "name": "tcp_port_check",
        "description": "ამოწმებს, ღიაა თუ არა TCP პორტი ჰოსტზე (აგენტის სერვერიდან).",
        "input_schema": _obj(
            {"host": {"type": "string"}, "port": {"type": "integer", "minimum": 1, "maximum": 65535}}, ["host", "port"]
        ),
    },
    {
        "name": "subnet_calculator",
        "description": "Subnet კალკულატორი: network, broadcast, mask, wildcard, ჰოსტების რაოდენობა; "
        "split_prefix-ით ყოფს პატარა ქსელებად. თუ address მითითებულია, ამოწმებს, ეკუთვნის თუ არა ქსელს.",
        "input_schema": _obj(
            {
                "network": {"type": "string", "description": "მაგ. 192.168.1.0/24 ან '10.0.0.0 255.255.0.0'"},
                "split_prefix": {"type": "integer"},
                "address": {"type": "string", "description": "არასავალდებულო: შესამოწმებელი IP"},
            },
            ["network"],
        ),
    },
    {
        "name": "check_reachability",
        "description": "სწრაფად ამოწმებს, ხელმისაწვდომია თუ არა მოწყობილობები (TCP კავშირი მართვის პორტზე, "
        "ჩვეულებრივ SSH 22). აბრუნებს up/down-ს და latency-ს. გამოიყენე 'რომელი მოწყობილობაა გათიშული?' "
        "ტიპის კითხვებზე ან სანამ ბევრ მოწყობილობას დაუკავშირდები.",
        "input_schema": _obj({"filter": _FILTER}, []),
    },
    {
        "name": "backup_configs",
        "description": "იღებს running-config-ის backup-ს (ერთ, რამდენიმე ან ყველა მოწყობილობაზე). ახალი ფაილი "
        "ინახება მხოლოდ მაშინ, როცა config შეიცვალა. აბრუნებს, სად იყო ცვლილება (+/- ხაზები).",
        "input_schema": _obj({"filter": _FILTER}, []),
    },
    {
        "name": "config_changes",
        "description": "აჩვენებს, რა შეიცვალა მოწყობილობის კონფიგურაციაში: diff ბოლო backup-სა და `hours` "
        "საათის წინანდელ backup-ს შორის (default 24). ასევე აბრუნებს backup-ების ისტორიას. ახალი "
        "მდგომარეობისთვის ჯერ გამოიძახე backup_configs.",
        "input_schema": _obj(
            {"device": _DEVICE, "hours": {"type": "integer", "minimum": 1, "maximum": 8760}}, ["device"]
        ),
    },
    {
        "name": "export_excel",
        "description": "ქმნის Excel (.xlsx) ფაილს მოწოდებული ცხრილებიდან და მომხმარებელს უგზავნის. გამოიყენე, "
        "როცა მომხმარებელი ითხოვს ექსპორტს/Excel-ს/ფაილს, ან როცა ცხრილი ჩატისთვის ძალიან დიდია. "
        "მონაცემები ჯერ tool-ებით შეაგროვე და ზუსტად ის ჩაწერე, რაც მიიღე.",
        "input_schema": _obj(
            {
                "filename": {"type": "string", "description": "ფაილის სახელი გაფართოების გარეშე, მაგ. ip_addresses"},
                "sheets": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "columns": {"type": "array", "items": {"type": "string"}},
                            "rows": {"type": "array", "items": {"type": "array"}},
                        },
                        "required": ["name", "columns", "rows"],
                        "additionalProperties": False,
                    },
                },
            },
            ["filename", "sheets"],
        ),
    },
]

DEVICE_TOOLS = {
    "get_device_data",
    "get_data_from_many",
    "run_show_command",
    "find_on_network",
    "device_config_summary",
    "backup_configs",
}


def _intent_commands(device, intent: str) -> list[str]:
    cmds = dev.commands_for(device, intent)
    if not cmds:
        raise CommandRejected(
            f"'{intent}' ბრძანება device_type '{device.device_type}'-ისთვის განსაზღვრული არ არის — "
            "გამოიყენე run_show_command შესაბამისი ბრძანებით."
        )
    return cmds


def _get_device_data(ctx: ToolContext, device: str, data: str) -> Any:
    d = ctx.inventory.get(device)
    return {"device": d.name, "device_type": d.device_type, "results": dev.run_commands(ctx.inventory, d, _intent_commands(d, data))}


def _get_data_from_many(ctx: ToolContext, data: str, filter: str = "") -> Any:
    devices = ctx.inventory.filter(filter)
    if not devices:
        return {"error": f"ფილტრს '{filter}' არცერთი მოწყობილობა არ შეესაბამება"}
    return dev.run_on_devices(
        ctx.inventory, devices, lambda d: dev.run_commands(ctx.inventory, d, _intent_commands(d, data))
    )


def _run_show_command(ctx: ToolContext, device: str, command: str) -> Any:
    d = ctx.inventory.get(device)
    return {"device": d.name, "results": dev.run_commands(ctx.inventory, d, [command])}


def _find_on_network(ctx: ToolContext, query: str, filter: str = "") -> Any:
    devices = ctx.inventory.filter(filter)
    if not devices:
        return {"error": "მოწყობილობები ვერ მოიძებნა"}
    return dev.search_devices(ctx.inventory, devices, query)


def _device_config_summary(ctx: ToolContext, device: str) -> Any:
    d = ctx.inventory.get(device)
    res = dev.run_commands(ctx.inventory, d, _intent_commands(d, "running_config"), parse=False)
    text = "\n".join(r.get("output", "") for r in res)
    errors = [r["error"] for r in res if "error" in r]
    out = {"device": d.name, "summary": extract_network_data(text)}
    if errors:
        out["errors"] = errors
    return out


def _subnet(ctx: ToolContext, network: str, split_prefix: int | None = None, address: str | None = None) -> Any:
    out = subnet_info(network, split_prefix)
    if address:
        out["address_check"] = ip_in_network(address, out["cidr"])
    return out


def _check_reachability(ctx: ToolContext, filter: str = "") -> Any:
    from ..health import check_many

    devices = ctx.inventory.filter(filter)
    if not devices:
        return {"error": "მოწყობილობები ვერ მოიძებნა"}
    results = check_many(devices)
    return {
        "up": sum(r.up for r in results),
        "down": sum(not r.up for r in results),
        "devices": [r.as_dict() for r in results],
    }


def _backup_configs(ctx: ToolContext, filter: str = "") -> Any:
    from ..backup import BackupStore, backup_devices

    devices = ctx.inventory.filter(filter)
    if not devices:
        return {"error": "მოწყობილობები ვერ მოიძებნა"}
    return backup_devices(ctx.inventory, devices, BackupStore(settings.backup_dir))


MAX_DIFF_CHARS = 8000


def _config_changes(ctx: ToolContext, device: str, hours: int = 24) -> Any:
    from ..backup import BackupStore, changes_since

    d = ctx.inventory.get(device)
    store = BackupStore(settings.backup_dir)
    result = changes_since(store, d.name, hours)
    if result is None:
        return {"device": d.name, "error": "backup ჯერ არ არსებობს — ჯერ გამოიძახე backup_configs"}
    diff = result.get("diff", "")
    if len(diff) > MAX_DIFF_CHARS:
        result["diff"] = diff[:MAX_DIFF_CHARS] + "\n... [diff შემოკლდა]"
    result["history"] = [s.taken_at.isoformat(timespec="minutes") for s in store.snapshots(d.name)][-20:]
    return result


def _export_excel(ctx: ToolContext, filename: str, sheets: list) -> Any:
    from ..export import write_xlsx

    path = write_xlsx(settings.export_dir, filename, sheets)
    ctx.files.append(path)
    rows = sum(len(s.get("rows", [])) for s in sheets)
    return {"file": path.name, "sheets": len(sheets), "rows": rows, "status": "ფაილი შეიქმნა და მომხმარებელს გაეგზავნება"}


_HANDLERS: dict[str, Callable[..., Any]] = {
    "list_devices": lambda ctx, filter="": [d.public_info() for d in ctx.inventory.filter(filter)],
    "get_device_data": _get_device_data,
    "get_data_from_many": _get_data_from_many,
    "run_show_command": _run_show_command,
    "find_on_network": _find_on_network,
    "device_config_summary": _device_config_summary,
    "ping": lambda ctx, **kw: net.ping(**kw),
    "traceroute": lambda ctx, **kw: net.traceroute(**kw),
    "dns_lookup": lambda ctx, **kw: net.dns_lookup(**kw),
    "tcp_port_check": lambda ctx, **kw: net.tcp_port_check(**kw),
    "subnet_calculator": _subnet,
    "check_reachability": _check_reachability,
    "backup_configs": _backup_configs,
    "config_changes": _config_changes,
    "export_excel": _export_excel,
}

_SCHEMA_BY_NAME = {t["name"]: t for t in TOOL_SCHEMAS}


def _validate_input(name: str, args: Any) -> dict:
    if not isinstance(args, dict):
        raise ValueError("tool input უნდა იყოს JSON ობიექტი")
    schema = _SCHEMA_BY_NAME[name]["input_schema"]
    props = schema["properties"]
    unknown = set(args) - set(props)
    if unknown:
        raise ValueError(f"უცნობი პარამეტრ(ებ)ი: {', '.join(sorted(unknown))}")
    missing = [k for k in schema["required"] if k not in args]
    if missing:
        raise ValueError(f"აკლია პარამეტრ(ებ)ი: {', '.join(missing)}")
    for key, value in args.items():
        expected = props[key].get("type")
        if expected == "string" and not isinstance(value, str):
            raise ValueError(f"'{key}' უნდა იყოს string")
        if expected == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            raise ValueError(f"'{key}' უნდა იყოს integer")
        if expected == "array" and not isinstance(value, list):
            raise ValueError(f"'{key}' უნდა იყოს სია (array)")
        if "enum" in props[key] and value not in props[key]["enum"]:
            raise ValueError(f"'{key}' უნდა იყოს ერთ-ერთი: {', '.join(props[key]['enum'])}")
    return args


def execute_tool(name: str, args: Any, ctx: ToolContext) -> tuple[str, bool]:
    """Run a tool. Returns (result_text, is_error). Never raises."""
    handler = _HANDLERS.get(name)
    if handler is None:
        return f"უცნობი ხელსაწყო: {name}", True
    is_error = False
    try:
        args = _validate_input(name, args)
        result = handler(ctx, **args)
        text = json.dumps(result, ensure_ascii=False, default=str, indent=1)
    except (CommandRejected, InventoryError, ValueError) as exc:
        text, is_error = f"შეცდომა: {exc}", True
    except Exception as exc:  # noqa: BLE001 - every failure goes back to the model as a tool error
        text, is_error = f"შეცდომა ({type(exc).__name__}): {exc}", True

    text = mask_secrets(text)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + "\n... [შედეგი შემოკლდა — დააზუსტე მოთხოვნა ან გამოიყენე ფილტრი]"

    log_event(
        settings.audit_log_path,
        user=ctx.user,
        tool=name,
        args=args if isinstance(args, dict) else str(args),
        ok=not is_error,
        device_access=name in DEVICE_TOOLS,
    )
    return text, is_error
