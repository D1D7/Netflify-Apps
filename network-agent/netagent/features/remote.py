"""Several networks in one app: talk to other NetAgents (e.g. a friend's or the office's) over Tailscale.

On the OTHER NetAgent (once):  .env →  NETAGENT_API_TOKEN=<token from /remote token>   then restart it.
                                (it answers as view-only; NETAGENT_API_ROLE=admin there allows changes too)
Here:
  /remote add office https://office-pc.tailXXXX.ts.net <token>
  /remote                         status of every network (up / total devices)
  /remote office /scan            run a command over there
  /remote del office
Tokens are kept in data/remotes.json (not in the chat history of the other side, not in /selfbackup).
"""

from __future__ import annotations

import json
import re
import secrets
from concurrent.futures import ThreadPoolExecutor

from ..config import settings
from ..permissions import DENIED, is_viewer
from ..result import Button, CommandError, Result

_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}$")
_URL = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?$")
TIMEOUT = 25


def _path():
    return settings.data_dir / "remotes.json"


def load() -> dict[str, dict]:
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    from ..osutil import atomic_write

    atomic_write(_path(), json.dumps(data, indent=1), private=True)  # API tokens of other NetAgents


def _call(peer: dict, method: str, path: str, body: dict | None = None) -> dict:
    import httpx

    headers = {"Authorization": f"Bearer {peer['token']}", "X-NetAgent": "1", "User-Agent": "NetAgent-remote"}
    try:
        r = httpx.request(method, peer["url"] + path, json=body, headers=headers, timeout=TIMEOUT)
    except httpx.HTTPError as exc:
        raise CommandError(f"კავშირი ვერ დამყარდა ({type(exc).__name__}) — ის კომპიუტერი ჩართულია? Tailscale-ში ჩანს?") from exc
    if r.status_code == 401:
        raise CommandError("token არ ემთხვევა — იქ .env-ში NETAGENT_API_TOKEN შეამოწმე და NetAgent გადატვირთე")
    try:
        data = r.json()
    except ValueError as exc:
        raise CommandError(f"უცნაური პასუხი (HTTP {r.status_code}) — ეს NetAgent-ის მისამართია?") from exc
    if r.status_code >= 400 and "error" in data:
        raise CommandError(str(data["error"])[:300])
    return data


def _status_line(name: str, peer: dict) -> str:
    try:
        o = _call(peer, "GET", "/api/overview")
    except CommandError as exc:
        return f"🔴 **{name}** — {exc}"
    down = o.get("total", 0) - o.get("up", 0)
    isp = o.get("isp") or {}
    net = " · 🌐 ინტერნეტი არ არის" if isp.get("down_now") else ""
    return (f"{'🟢' if not down else '🟠'} **{name}** — {o.get('up', 0)}/{o.get('total', 0)} მოწყობილობა"
            + (f" · {down} მიუწვდომელი" if down else "") + net)


def remote_cmd(s, args, user) -> Result:
    peers = load()
    if not args:
        if not peers:
            return Result("სხვა ქსელი ჯერ არ არის დამატებული.\n" + HOWTO, buttons=[Button("🔑 token-ის შექმნა", "/remote token")])
        with ThreadPoolExecutor(max_workers=8) as pool:
            lines = list(pool.map(lambda kv: _status_line(*kv), sorted(peers.items())))
        return Result("🌐 **ქსელები**\n" + "\n".join(lines) + "\n\nბრძანება იქ: `/remote <სახელი> /scan`",
                      buttons=[Button(f"🔍 {n}: სკანი", f"/remote {n} /scan") for n in sorted(peers)][:4])
    sub = args[0].lower()
    if sub == "token":
        return Result("🔑 **ახალი token** (ერთხელ გამოიყენე):\n" f"`{secrets.token_urlsafe(32)}`\n\n" + HOWTO)
    if sub in {"add", "del"} and is_viewer(user):
        return Result(DENIED)
    if sub == "add":
        if len(args) != 4:
            raise CommandError("გამოყენება: /remote add <სახელი> <https://...ts.net> <token>")
        name, url, token = args[1].lower(), args[2].rstrip("/"), args[3]
        if not _NAME.match(name) or name in {"add", "del", "token"}:
            raise CommandError("სახელი: ლათინური ასოები/ციფრები, მაგ. office")
        if not _URL.match(url):
            raise CommandError("მისამართი: https://კომპიუტერი.tailXXXX.ts.net (ბოლოში / და გზის გარეშე)")
        if len(token) < 24:
            raise CommandError("token ძალიან მოკლეა — შექმენი: /remote token")
        peer = {"url": url, "token": token}
        line = _status_line(name, peer)
        peers[name] = peer
        _save(peers)
        return Result(f"✅ დაემატა: {line}", buttons=[Button(f"🔍 {name}: სკანი", f"/remote {name} /scan")])
    if sub == "del":
        if len(args) < 2 or peers.pop(args[1].lower(), None) is None:
            raise CommandError("ასეთი ქსელი არ არის. სია: /remote")
        _save(peers)
        return Result(f"🗑️ {args[1]} წაიშალა")
    peer = peers.get(sub)
    if peer is None:
        raise CommandError(f"'{args[0]}' არ ვიცი. სია: /remote · დამატება: /remote add ...")
    line = " ".join(args[1:]).strip() or "/status"
    if not line.startswith("/"):
        line = "/" + line
    if line.split()[0].lower() == "/remote":
        raise CommandError("ჯაჭვი (/remote იქიდან კიდევ სხვაგან) არ შეიძლება")
    data = _call(peer, "POST", "/api/command", {"line": line})
    text = str(data.get("text") or data.get("error") or "(ცარიელი პასუხი)")
    if data.get("files"):
        text += "\n\n📎 ფაილები იქ შეიქმნა: " + ", ".join(str(f) for f in data["files"])
    buttons = [Button(b["label"], f"/remote {sub} {b['command']}") for b in data.get("buttons", [])
               if isinstance(b, dict) and str(b.get("command", "")).startswith("/")][:6]
    return Result(f"🌐 **{sub}** — `{line}`\n\n{text}", buttons=buttons)


HOWTO = ("**როგორ დავაკავშირო:**\n"
         "1. იმ კომპიუტერზე, სადაც მეორე NetAgent მუშაობს: `.env`-ში ჩაწერე `NETAGENT_API_TOKEN=<token>` და გადატვირთე.\n"
         "   (იქიდან მხოლოდ ნახვა იქნება; ცვლილებებისთვის იქვე `NETAGENT_API_ROLE=admin`)\n"
         "2. ორივე კომპიუტერი ერთ Tailscale ქსელში უნდა იყოს, იქ ჩართული `tailscale serve`.\n"
         "3. აქ: `/remote add office https://მისი-კომპიუტერი.tailXXXX.ts.net <token>`")

COMMANDS = {"remote": remote_cmd}
HELP = ["/remote — სხვა ქსელები (სხვა NetAgent-ები) ერთ აპში · /remote office /scan · /remote add · /remote token"]
BOT_COMMANDS = [("remote", "სხვა ქსელები")]
