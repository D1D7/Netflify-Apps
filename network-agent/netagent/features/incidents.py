"""Incident memory: every outage/problem alert opens an incident, the recovery closes it.

The AI can look them up ("why did R1 go down last time and how was it fixed?") and you
can add what fixed it: /incident 12 note Magti-მ კაბელი შეცვალა.
"""

from __future__ import annotations

import re
from datetime import datetime

from ..alerts import format_duration
from ..result import Button, CommandError, Result

KEY = "incidents"
MAX = 500
OPEN_MARKS = ("🔴", "🔥", "⚡", "📈", "🧠", "🔁", "🐢")
CLOSE_MARK = "🟢"


def _key(device: str, rest: str) -> str:
    toks = rest.lstrip(": ").split()
    if not toks:
        return device
    k = toks[0]
    if len(toks) > 2 and toks[1].lower() == "neighbor":
        k += " " + toks[2]
    return f"{device} {k}"


def parse_lines(alert) -> list[tuple[str, str, str, str]]:
    """-> [(open|close, key, device, line)] from an alert's text."""
    out = []
    if alert.kind in {"isp"}:
        mark = "close" if CLOSE_MARK in alert.text else "open" if any(m in alert.text for m in OPEN_MARKS) else None
        if mark:
            out.append((mark, "ინტერნეტი", "ინტერნეტი", alert.text.splitlines()[0]))
        return out
    for line in alert.text.splitlines():
        m = re.match(r"^(\S+)\s+\*\*(.+?)\*\*(.*)$", line.strip())
        if not m:
            continue
        mark, name, rest = m.groups()
        if alert.kind in {"down", "up", "site"}:
            key = name
        else:
            key = _key(name, re.sub(r"\*\*", "", rest))
        if mark.startswith(CLOSE_MARK):
            out.append(("close", key, name, line.strip()))
        elif mark.startswith(OPEN_MARKS):
            out.append(("open", key, name, line.strip()))
    return out


class IncidentStore:
    def __init__(self, state) -> None:
        self.state = state

    def all(self) -> list[dict]:
        return self.state.get(KEY) or []

    def _save(self, items: list[dict]) -> None:
        self.state.set(KEY, items[-MAX:])

    def record(self, alert, now: datetime | None = None) -> None:
        now_s = (now or datetime.now()).isoformat(timespec="seconds")
        items = self.all()
        changed = False
        for action, key, device, line in parse_lines(alert):
            current = next((i for i in reversed(items) if i["key"] == key and not i.get("closed")), None)
            if action == "open":
                if current:
                    current["events"].append([now_s, line])
                else:
                    items.append({"id": (items[-1]["id"] + 1) if items else 1, "key": key, "device": device,
                                  "title": re.sub(r"\*\*", "", line)[:160], "kind": alert.kind, "opened": now_s,
                                  "closed": None, "events": [[now_s, line]], "notes": []})
                changed = True
            elif current:
                current["closed"] = now_s
                current["seconds"] = int((datetime.fromisoformat(now_s) - datetime.fromisoformat(current["opened"])).total_seconds())
                current["events"].append([now_s, line])
                changed = True
        if alert.kind in {"syslog", "escalation", "config"}:  # context for whatever is open on that device
            for d in alert.devices:
                for i in items:
                    if i["device"] == d and not i.get("closed"):
                        i["events"].append([now_s, alert.text.splitlines()[0][:200]])
                        changed = True
        if changed:
            for i in items:
                i["events"] = i["events"][-30:]
            self._save(items)

    def add_note(self, incident_id: int, text: str, user: str) -> dict:
        items = self.all()
        inc = next((i for i in items if i["id"] == incident_id), None)
        if inc is None:
            raise CommandError(f"ინციდენტი #{incident_id} ვერ მოიძებნა")
        inc["notes"].append({"ts": datetime.now().isoformat(timespec="seconds"), "by": user, "text": text[:500]})
        self._save(items)
        return inc

    def search(self, device: str = "", text: str = "", limit: int = 10, open_only: bool = False) -> list[dict]:
        out = []
        for i in reversed(self.all()):
            if device and device.lower() not in i["device"].lower():
                continue
            blob = " ".join([i["title"], *[n["text"] for n in i["notes"]], *[e[1] for e in i["events"]]]).lower()
            if text and text.lower() not in blob:
                continue
            if open_only and i.get("closed"):
                continue
            out.append(i)
            if len(out) >= limit:
                break
        return out


def on_alert(s, alert) -> None:
    IncidentStore(s.state).record(alert)


def _line(i: dict) -> str:
    state = f"✅ {format_duration(i['seconds'])}" if i.get("closed") else "🔴 ღიაა"
    note = f" — 📝 {i['notes'][-1]['text'][:60]}" if i["notes"] else ""
    return f"#{i['id']} {i['opened'][5:16].replace('T', ' ')} {state} · {i['title'][:80]}{note}"


def incidents_cmd(s, args, user) -> Result:
    store = IncidentStore(s.state)
    open_only = bool(args) and args[0] == "open"
    device = "" if open_only or not args else args[0]
    items = store.search(device=device, limit=12, open_only=open_only)
    if not items:
        return Result("📒 ინციდენტები არ არის" + (f" ({device})" if device else "") + " — ისინი ავტომატურად იქმნება ალერტებიდან.")
    return Result("📒 **ინციდენტები**\n" + "\n".join(_line(i) for i in items),
                  buttons=[Button(f"#{i['id']}", f"/incident {i['id']}") for i in items[:5]])


def incident_cmd(s, args, user) -> Result:
    if not args or not args[0].lstrip("#").isdigit():
        raise CommandError("გამოყენება: /incident 12 · /incident 12 note რა გამოასწორა")
    iid = int(args[0].lstrip("#"))
    store = IncidentStore(s.state)
    if len(args) > 2 and args[1] == "note":
        store.add_note(iid, " ".join(args[2:]), user)
        return Result(f"📝 შენიშვნა დაემატა #{iid}-ს. მომავალში AI ამას გაიხსენებს მსგავს შემთხვევაში.")
    inc = next((i for i in store.all() if i["id"] == iid), None)
    if inc is None:
        raise CommandError(f"ინციდენტი #{iid} ვერ მოიძებნა")
    lines = [f"📒 **#{inc['id']} {inc['title']}**", f"გაიხსნა: {inc['opened'].replace('T', ' ')}"
             + (f" · დაიხურა: {inc['closed'].replace('T', ' ')} ({format_duration(inc['seconds'])})" if inc.get("closed") else " · 🔴 ღიაა")]
    lines += [f"• {e[0][11:16]} {e[1][:150]}" for e in inc["events"][-10:]]
    lines += [f"📝 {n['ts'][:16].replace('T', ' ')}: {n['text']}" for n in inc["notes"]]
    if not inc["notes"]:
        lines.append(f"\nრა გამოასწორა? დაწერე: /incident {iid} note ...")
    return Result("\n".join(lines))


COMMANDS = {"incidents": incidents_cmd, "incident": incident_cmd}
HELP = ["/incidents — ინციდენტების ისტორია (/incidents R1 · /incidents open) · /incident 12 note რა გამოასწორა"]
BOT_COMMANDS = [("incidents", "ინციდენტების ისტორია")]
TOOLS = [({
    "name": "incident_history",
    "description": "Past and open incidents (outages, interface/BGP/CPU problems, internet/site downtime) recorded "
                   "from alerts, with duration, related log events and notes about what fixed them. Use when a problem "
                   "happens to check if it happened before and how it was solved.",
    "input_schema": {"type": "object", "properties": {
        "device": {"type": "string"}, "text": {"type": "string", "description": "search in titles/notes/events"},
        "open_only": {"type": "boolean"}, "limit": {"type": "integer"}}, "required": []},
}, lambda ctx, device="", text="", open_only=False, limit=10:
    IncidentStore(ctx.services.state).search(device, text, max(1, min(limit, 30)), open_only))]
