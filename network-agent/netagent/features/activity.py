"""Who did what: /activity reads the audit log (logins, commands, AI actions, device changes) · /users lists accounts.

Accounts are managed on the NetAgent computer (passwords never go through the chat):
    python -m netagent user-add gio --role viewer      (or users.bat)
    python -m netagent user-del gio
"""

from __future__ import annotations

import json
from datetime import datetime

from ..config import settings
from ..permissions import display_name
from ..result import Button, CommandError, Result

TAIL_BYTES = 512 * 1024
AI_TOOL_LABELS = {"run_show_command": "ბრძანება მოწყობილობაზე", "propose_config_change": "ცვლილების შეთავაზება",
                  "scan_local_network": "ქსელის სკანი", "backup_configs": "backup", "save_note": "შენიშვნა",
                  "delete_note": "შენიშვნის წაშლა", "ipam_set": "IPAM ჩანაწერი", "ping": "ping", "traceroute": "traceroute"}


def read_events(limit: int = 500) -> list[dict]:
    path = settings.audit_log_path
    if not path.exists():
        return []
    with path.open("rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - TAIL_BYTES))
        chunk = fh.read().decode("utf-8", "replace")
    lines = chunk.splitlines()[1:] if size > TAIL_BYTES else chunk.splitlines()  # first line may be cut
    out = []
    for line in lines[-limit:]:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict):
            out.append(ev)
    return out


def _when(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts).astimezone().strftime("%m-%d %H:%M")
    except (TypeError, ValueError):
        return ts[:16]


def describe(ev: dict) -> str:
    tool, args, ok = ev.get("tool", ""), ev.get("args") or {}, ev.get("ok", True)
    args = args if isinstance(args, dict) else {"": str(args)}
    who = ev.get("user", "?")
    mark = "" if ok else " ❌"
    if tool == "login":
        name = who.partition(":")[2] or "admin"
        device = f"{args['device']} · " if args.get("device") else ""
        return f"🔑 **{name}** — შესვლა{' ✅' if ok else ' ❌ (არასწორი)'} · {device}{args.get('from', '')}"
    if tool == "logout":
        everywhere = " (ყველა მოწყობილობიდან)" if args.get("everywhere") else ""
        return f"🚪 **{display_name(who)}** — გასვლა{everywhere} · {args.get('from', '')}"
    if tool == "command":
        return f"⌨️ **{display_name(who)}** — `{str(args.get('line', ''))[:80]}`{mark}"
    if tool in {"cmd", "cli_cmd"}:
        return f"📟 **{display_name(who)}** — {args.get('device', '')}: `{str(args.get('command', ''))[:70]}`{mark}"
    if tool.startswith("config_change"):
        step = tool.removeprefix("config_change_")
        return f"🛠️ **{display_name(who)}** — ცვლილება #{args.get('id', '?')} {step} {args.get('device', '')}{mark}"
    label = AI_TOOL_LABELS.get(tool, tool)
    target = args.get("device") or args.get("host") or args.get("target") or ""
    return f"🤖 **{display_name(who)}** (AI) — {label}{' · ' + str(target) if target else ''}{mark}"


def activity_cmd(s, args, user) -> Result:
    limit, who = 25, ""
    for a in args:
        if a.isdigit():
            limit = max(1, min(int(a), 200))
        else:
            who = a.lower()
    events = read_events()
    if who:
        events = [e for e in events if who in str(e.get("user", "")).lower()]
    # AI read-only lookups are noisy: keep logins, commands, changes and AI actions that touch devices/data
    events = [e for e in events if e.get("tool") in {"login", "logout", "command", "cmd", "cli_cmd"}
              or str(e.get("tool", "")).startswith("config_change") or e.get("device_access")
              or e.get("tool") in AI_TOOL_LABELS]
    if not events:
        return Result("ჟურნალი ჯერ ცარიელია" + (f" ({who})" if who else ""))
    lines = [f"📜 **ვინ რა გააკეთა** — ბოლო {min(limit, len(events))}" + (f" · {who}" if who else "")]
    for ev in events[-limit:][::-1]:
        lines.append(f"`{_when(ev.get('ts', ''))}` {describe(ev)}")
    return Result("\n".join(lines), buttons=[Button("🔄 განახლება", "/activity"), Button("👥 მომხმარებლები", "/users")])


def users_cmd(s, args, user) -> Result:
    from ..web.auth import WebAuth

    users = WebAuth(settings.data_dir / "web_auth.json").list_users()
    if not users:
        raise CommandError("ანგარიშები ჯერ არ არის: setup-password.bat")
    lines = ["👥 **მომხმარებლები**"]
    for u in users:
        role = "ადმინი" if u["role"] == "admin" else "მხოლოდ ნახვა"
        lines.append(f"• **{u['name']}** — {role} · 2FA {'✅' if u['totp'] else '❌ არ არის'}")
    lines.append("\nდამატება/წაშლა NetAgent-ის კომპიუტერზე: **users.bat** (პაროლი ჩატში არასდროს იწერება)")
    return Result("\n".join(lines), buttons=[Button("📜 ჟურნალი", "/activity")])


def _auth():
    from ..web import auth as auth_module

    return auth_module.ACTIVE or auth_module.WebAuth(settings.data_dir / "web_auth.json")


def _ago(ts: float) -> str:
    minutes = int((datetime.now().timestamp() - ts) // 60)
    if minutes < 2:
        return "ახლა"
    if minutes < 60:
        return f"{minutes} წთ წინ"
    if minutes < 48 * 60:
        return f"{minutes // 60} სთ წინ"
    return f"{minutes // 1440} დღის წინ"


def sessions_cmd(s, args, user) -> Result:
    from ..web.auth import device_label

    sessions = _auth().list_sessions()
    if not sessions:
        return Result("აქტიური სესია არ არის (ან სერვერი ახლახან გადაიტვირთა და ჯერ არავინ შესულა)")
    lines = [f"👥 **ვინ არის შესული** — {len(sessions)} სესია"]
    for x in sessions:
        active = "🟢" if datetime.now().timestamp() - x["last_seen"] < 15 * 60 else "⚪"
        since = datetime.fromtimestamp(x.get("created", 0)).strftime("%m-%d %H:%M")
        lines.append(f"{active} **{x.get('u', 'admin')}** — {device_label(x.get('ua', ''))} · {x.get('ip', '')} · "
                     f"ბოლოს: {_ago(x['last_seen'])} · შევიდა {since} · `{x['sid'][:6]}`")
    lines.append("\n🟢 ბოლო 15 წუთში აქტიური · გამოგდება: `/kick gio` (ყველა მისი სესია) ან `/kick <კოდი>`")
    people = sorted({x.get("u", "admin") for x in sessions} - {"admin"})
    return Result("\n".join(lines), buttons=[Button(f"🚫 გამოაგდე {p}", f"/kick {p}") for p in people][:4]
                  + [Button("🔄 განახლება", "/sessions")])


def kick_cmd(s, args, user) -> Result:
    if not args:
        raise CommandError("გამოყენება: /kick gio  ან  /kick <სესიის კოდი /sessions-დან>")
    n = _auth().revoke(args[0])
    if not n:
        raise CommandError(f"'{args[0]}' — ასეთი აქტიური სესია ვერ ვიპოვე (/sessions)")
    note = "\nℹ️ თავიდან შესვლა მაინც შეუძლია პაროლით. სამუდამოდ: users.bat → წაშლა." if args[0].lower() != "admin" else ""
    return Result(f"🚫 გამოგდებულია: {args[0]} — {n} სესია დაიხურა.{note}", buttons=[Button("👥 სესიები", "/sessions")])


COMMANDS = {"activity": activity_cmd, "users": users_cmd, "sessions": sessions_cmd, "kick": kick_cmd}
HELP = ["/activity — ვინ რა გააკეთა (შესვლები, ბრძანებები, AI) · /activity gio · /users — მომხმარებლები",
        "/sessions — ვინ არის ახლა შესული (მოწყობილობა, IP) · /kick gio — გამოგდება"]
BOT_COMMANDS = [("activity", "ვინ რა გააკეთა"), ("sessions", "ვინ არის შესული")]
