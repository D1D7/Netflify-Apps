"""Self-healing with your approval: known problems on routers/switches get a ready fix.

  /heal               look for known problems now (also runs every NETAGENT_SELFHEAL_INTERVAL minutes, default 15)
  /heal fix 2         turn problem #2 (or its id) into a change proposal -> /approve <id> <PIN>

Nothing is changed without your PIN. The fix goes through the change system (features/changes.py), so it gets the
same safety net: backup before/after, Cisco `reload in 10` dead-man switch, reachability check, automatic rollback
if the device stops answering. Self-healing adds one more step: after the fix it checks whether the problem is
really gone. If it is not (e.g. the port fell back into err-disabled because the loop is still there), the change is
rolled back automatically (Cisco: configure replace) and you get told why.

Known problems (read-only checks):
  err-disabled port (Cisco)     `shutdown` / `no shutdown` on the port, after the cause has been looked at
  forbidden global line (Cisco) a line your golden config forbids (e.g. `ip http server`) -> `no <line>`
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime

from ..result import Button, CommandError, Result
from ..watch import family
from . import env_int

KEY = "selfheal"
REALERT = 6 * 3600
ERRDISABLE_ADVICE = {
    "bpduguard": "BPDU Guard: ამ პორტზე switch-ი/როუტერი შეაერთეს (ან loop-ია). ჯერ გამორთე ის მოწყობილობა.",
    "psecure-violation": "Port security: უცნობი MAC. შეამოწმე, ვინ შეაერთეს.",
    "loopback": "Loop დაფიქსირდა — შეამოწმე კაბელები.",
    "link-flap": "Link ხშირად ითიშებოდა — ცუდი კაბელი/პორტი.",
    "udld": "UDLD: ერთმხრივი ბმული — შეამოწმე ბოჭკო/კაბელი.",
}


# -- detection -----------------------------------------------------------------------------------------------
def parse_errdisabled(text: str) -> list[dict]:
    """`show interfaces status err-disabled` -> [{"port", "name", "reason"}]."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(.*?)\s*err-disabled\s+(\S+)", line)
        if m and not line.lower().startswith("port"):
            out.append({"port": m.group(1), "name": m.group(2).strip(), "reason": m.group(3)})
    return out


def detect_device(s, inv, d, run=None) -> list[dict]:
    """Known problems on one device (read-only commands)."""
    from ..tools import device as dev

    run = run or (lambda cmds: [r.get("output", "") for r in dev.run_commands(inv, d, cmds, parse=False, max_chars=None)])
    fam = family(d.device_type)
    issues: list[dict] = []
    if fam != "ios":
        return issues
    out = run(["show interfaces status err-disabled"])[0]
    for e in parse_errdisabled(out):
        advice = ERRDISABLE_ADVICE.get(e["reason"].lower(), "ჯერ გაარკვიე მიზეზი, თორემ პორტი ისევ გაითიშება.")
        issues.append({"id": f"{d.name}:{e['port']}:errdisable", "device": d.name, "kind": "errdisable", "target": e["port"],
                       "title": f"{d.name} {e['port']}" + (f" ({e['name']})" if e["name"] else "") + f" — err-disabled ({e['reason']})",
                       "advice": advice, "fix": [f"interface {e['port']}", "shutdown", "no shutdown"]})
    try:  # golden config: a forbidden *global* line can simply be negated
        from .golden import load_rules, rules_for

        config = run(["show running-config"])[0]
        for kind, rule in rules_for(d, load_rules()):
            if kind != "forbidden":
                continue
            for m in re.finditer(rule["pattern"], config, re.M | re.I):
                start = config.rfind("\n", 0, m.start()) + 1
                end = config.find("\n", m.start())
                line = config[start: end if end >= 0 else len(config)].rstrip()  # the whole line that matched
                if not line or line.startswith((" ", "!")) or line.lower().startswith("no "):
                    continue  # only top-level lines: sub-mode lines need their context
                issues.append({"id": f"{d.name}:golden:{line[:40]}", "device": d.name, "kind": "golden", "target": line,
                               "title": f"{d.name}: აკრძალული ხაზი — {rule['name']} (`{line[:60]}`)",
                               "advice": "golden config-ის წესი კრძალავს.", "fix": [f"no {line}"]})
    except Exception as exc:  # noqa: BLE001 - golden check is optional, but say why it was skipped
        import logging

        logging.getLogger("netagent.selfheal").info("golden check skipped for %s: %s", d.name, exc)
    return issues


def scan(s, run_for=None) -> list[dict]:
    """All known problems on reachable devices of the inventory."""
    from ..health import check_many
    from ..tools import device as dev

    inv = s.inventory()
    devices = [d for d in inv.devices.values() if family(d.device_type) == "ios"]
    reach = [inv.devices[r.device] for r in check_many(devices, timeout=2.0) if r.up] if devices else []
    results = dev.run_on_devices(inv, reach, lambda d: detect_device(s, inv, d, run_for(d) if run_for else None)) if reach else {}
    issues = sorted((i for v in results.values() if isinstance(v, list) for i in v), key=lambda i: i["kind"] != "errdisable")
    s.state.set(KEY, {**(s.state.get(KEY) or {}), "ts": datetime.now().isoformat(timespec="seconds"), "issues": issues})
    return issues


def _issue(s, ref: str) -> dict:
    issues = (s.state.get(KEY) or {}).get("issues") or []
    if ref.isdigit() and 1 <= int(ref) <= len(issues):
        return issues[int(ref) - 1]
    for i in issues:
        if i["id"] == ref:
            return i
    raise CommandError("ეს პრობლემა ბოლო შემოწმებაში აღარ ჩანს — გაუშვი /heal")


# -- after an approved fix: is the problem really gone? ---------------------------------------------------------
def still_there(s, issue: dict, run=None) -> bool:
    inv = s.inventory()
    d = inv.get(issue["device"])
    return any(i["id"] == issue["id"] for i in detect_device(s, inv, d, run))


def after_apply(s, c: dict, res: dict, run=None, rollback=None, wait: float | None = None) -> dict:
    """Called by /approve for self-healing changes. Verifies the fix; rolls back automatically if it did not work."""
    from .changes import rollback_change

    if res.get("status") not in {"applied", "saved"}:
        return res
    log = list(res.get("log", []))
    time.sleep(float(os.getenv("NETAGENT_HEAL_VERIFY_WAIT", "5")) if wait is None else wait)  # port comes up / fails again
    try:
        bad = still_there(s, c["heal"], run)
    except Exception as exc:  # noqa: BLE001
        log.append(f"⚠️ შედეგის შემოწმება ვერ მოხერხდა: {type(exc).__name__}")
        return {**res, "log": log}
    if not bad:
        log.append("🩺 შემოწმება: პრობლემა მოგვარდა ✅")
        return {**res, "log": log}
    log.append("🩺 შემოწმება: პრობლემა ისევ არის — " + c["heal"].get("advice", ""))
    try:
        (rollback or (lambda: rollback_change(s, c)))()
        log.append("↩️ ცვლილება ავტომატურად დაბრუნდა (უშედეგო იყო)")
        return {**res, "status": "rolledback", "log": log}
    except Exception as exc:  # noqa: BLE001
        log.append(f"⚠️ ავტომატური დაბრუნება ვერ მოხერხდა ({type(exc).__name__}) — /undo {c['id']}")
        return {**res, "log": log}


# -- commands, job --------------------------------------------------------------------------------------------
def format_issues(issues: list[dict]) -> str:
    if not issues:
        return "🩺 ცნობილი პრობლემა ვერ ვიპოვე (err-disabled პორტები, აკრძალული ხაზები)."
    lines = [f"🩺 **ავტომატურად გამოსწორებადი პრობლემები** ({len(issues)})"]
    for n, i in enumerate(issues, 1):
        lines.append(f"\n**{n}. {i['title']}**\n{i['advice']}\nშემოთავაზებული: `" + " ; ".join(i["fix"]) + "`")
    lines.append("\n_ცვლილება მხოლოდ შენი PIN-ით გატარდება; შემდეგ შევამოწმებ და თუ არ უშველა — თვითონ დავაბრუნებ._")
    return "\n".join(lines)


def heal_cmd(s, args, user) -> Result:
    from ..permissions import DENIED, is_viewer
    from . import changes

    if args and args[0].lower() == "fix":
        if is_viewer(user):
            return Result(DENIED)
        if len(args) < 2:
            raise CommandError("გამოყენება: /heal fix 1")
        issue = _issue(s, args[1])
        c = changes.propose(s, issue["device"], issue["fix"], f"თვითაღდგენა: {issue['title']}", user)
        c = changes._update(s.state, c["id"], heal=issue)  # noqa: SLF001
        return Result(changes.preview(c) + "\n\n🩺 დადასტურების შემდეგ შევამოწმებ, მოგვარდა თუ არა; თუ არა — ავტომატურად დავაბრუნებ.",
                      buttons=[Button("✅ დადასტურება (PIN)", f"/approve {c['id']}"), Button("✖ გაუქმება", f"/reject {c['id']}")])
    issues = scan(s)
    return Result(format_issues(issues), buttons=[Button(f"🛠 გამოსწორება {n}", f"/heal fix {n}") for n in range(1, len(issues) + 1)][:6])


def jobs(monitoring):
    from ..monitoring import Alert

    every = env_int("NETAGENT_SELFHEAL_INTERVAL", 15)
    if every <= 0:
        return []

    async def check():
        import asyncio

        s = monitoring.s
        issues = await asyncio.to_thread(scan, s)
        sent = dict((s.state.get(KEY) or {}).get("alerted") or {})
        now = time.time()
        fresh = [i for i in issues if now - sent.get(i["id"], 0) > REALERT]
        for i in fresh:
            sent[i["id"]] = now
        s.state.update(KEY, lambda v: {**(v or {}), "alerted": sent})
        if fresh:
            await monitoring.emit(Alert("watch", "🩺 **გამოსწორებადი პრობლემა**\n" + "\n".join(f"• {i['title']}" for i in fresh),
                                        sorted({i["device"] for i in fresh}),
                                        buttons=[Button("🛠 გამოსწორება", "/heal")]))

    return [("selfheal", every * 60, 180, check)]


COMMANDS = {"heal": heal_cmd}
HELP = ["/heal — თვითაღდგენა: err-disabled პორტები, აკრძალული ხაზები → გამოსწორება შენი PIN-ით და ავტომატური დაბრუნებით"]
BOT_COMMANDS = [("heal", "ავტომატურად გამოსწორებადი პრობლემები")]
