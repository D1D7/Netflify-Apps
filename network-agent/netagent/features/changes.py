"""Configuration changes with human approval, PIN and automatic rollback.

OFF unless NETAGENT_CHANGES=on in .env and a PIN is set (python -m netagent change-pin).

  1. Proposal: the AI (tool propose_config_change) or `/change R1 cmd1 ; cmd2` creates a pending
     change. Nothing is sent to the device; you see the exact commands and the risks.
  2. Approval: `/approve 7 <PIN>` (button pre-fills /approve 7). 5 wrong PINs = 15 min lock.
  3. Apply with a safety net:
       Cisco IOS/XE  copy running-config → flash:netagent-rollback.cfg, `reload in 10` dead-man switch,
                     apply, reconnect check, `reload cancel`; if the check fails but the device still
                     answers: `configure replace flash:netagent-rollback.cfg force`.
       Junos         `commit confirmed 5`, reconnect check, `commit`.
       MikroTik      `/export file=netagent-rollback`, apply, reconnect check (no automatic undo).
  4. Not saved yet on Cisco: 💾 save (`write memory`) or ↩️ undo (/undo 7 <PIN>).
Every step goes to the audit log, and a backup is taken before and after.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta

from ..audit import log_event
from ..config import settings
from ..result import Button, CommandError, Result
from ..watch import family

KEY = "changes"
PENDING_MINUTES = 30
MAX_LINES = 60
ROLLBACK_FILE = "flash:netagent-rollback.cfg"
FORBIDDEN = [
    r"\breload\b", r"\berase\b", r"\bformat\b", r"^\s*delete\b", r"^\s*do\b", r"\bzeroize\b", r"^\s*boot\b",
    r"config-register", r"^\s*(no\s+)?username\b", r"^\s*enable\s+(secret|password)", r"^\s*(no\s+)?aaa\b",
    r"\blicense\b", r"\btclsh\b", r"\bshell\b", r"/system\s+(reset-configuration|reboot|shutdown|package|license)",
    r"^/user\b", r"^/file\b", r"^/certificate\b", r"^/system\s+backup", r"\brequest\s+system\b", r"system\s+(login|root-authentication)",
    r"\bcrypto\s+key\b", r"\bwrite\b", r"\bcopy\b",
]
_PIN_LOCK = "change_pin_lock"


def enabled() -> bool:
    return os.getenv("NETAGENT_CHANGES", "off").lower() in {"on", "1", "yes", "true"}


def pin_path():
    return settings.data_dir / "change_pin.json"


def set_pin(pin: str) -> None:
    from ..web.auth import hash_password

    if not re.fullmatch(r"\d{6,12}", pin):
        raise ValueError("PIN უნდა იყოს 6–12 ციფრი")
    from ..osutil import atomic_write

    atomic_write(pin_path(), json.dumps(hash_password(pin)), private=True)  # was world-readable on every OS


def check_pin(state, pin: str) -> None:
    from ..web.auth import check_password

    if not pin_path().exists():
        raise CommandError("PIN ჯერ არ არის დაყენებული: python -m netagent change-pin")
    lock = state.get(_PIN_LOCK) or {"fails": 0, "until": 0}
    if lock["until"] > time.time():
        raise CommandError(f"⛔ ძალიან ბევრი არასწორი PIN. სცადე {int((lock['until'] - time.time()) // 60) + 1} წუთში.")
    if not pin or not check_password(pin, json.loads(pin_path().read_text(encoding="utf-8"))):
        lock["fails"] += 1
        if lock["fails"] >= 5:
            lock = {"fails": 0, "until": time.time() + 900}
        state.set(_PIN_LOCK, lock)
        raise CommandError("⛔ PIN არასწორია")
    state.set(_PIN_LOCK, {"fails": 0, "until": 0})


def validate(device, commands: list[str]) -> list[str]:
    if not commands:
        raise CommandError("ბრძანებები ცარიელია")
    if len(commands) > MAX_LINES:
        raise CommandError(f"მაქსიმუმ {MAX_LINES} ხაზი ერთ ცვლილებაში")
    fam = family(device.device_type)
    if fam not in {"ios", "junos", "mikrotik"}:
        raise CommandError(f"{device.device_type}-ზე ცვლილებები ჯერ არ არის მხარდაჭერილი (Cisco IOS/XE, Junos, MikroTik)")
    clean = []
    for c in commands:
        c = c.rstrip()
        if not c.strip():
            continue
        if len(c) > 250 or re.search(r"[\x00-\x08\x0b-\x1f\x7f]", c):
            raise CommandError(f"არასწორი ხაზი: {c[:60]}")
        check = c.strip()
        if fam == "mikrotik":
            # one command per line: ";" chains, ":execute"/":do" scripts and [..] substitutions would hide what runs
            plain = re.sub(r"\[\s*find\b[^\[\];:]*\]", "", check)  # "[find name=ether1]" is the normal idiom
            if re.search(r"[;\[\]]|(?:^|[\s{(]):[a-z]", plain, re.I):
                raise CommandError(f"⛔ RouterOS: ერთ ხაზზე ერთი ბრძანება, სკრიპტინგის გარეშე (; : [ ]): `{check[:80]}`")
            # RouterOS v7 also accepts "/system/reboot" and "/user/add": check the space form too
            check = re.sub(r"(?<=[\w-])/(?=[a-z])", " ", check)
        for pat in FORBIDDEN:
            if re.search(pat, check, re.I) or re.search(pat, c.strip(), re.I):
                raise CommandError(f"⛔ ეს ბრძანება ცვლილებებში დაშვებული არ არის (ზედმეტად სახიფათოა): `{c.strip()[:80]}`")
        if fam == "mikrotik" and not c.strip().startswith("/"):
            raise CommandError("RouterOS ბრძანება უნდა იწყებოდეს '/'-ით (სრული გზით, მაგ. /ip address add ...)")
        if fam == "junos" and not re.match(r"^\s*(set|delete|deactivate|activate)\s", c):
            raise CommandError("Junos-ზე მხოლოდ set / delete / activate / deactivate ხაზებია დაშვებული")
        if fam == "ios" and re.match(r"^\s*(configure|conf|end)\b", c, re.I):
            continue  # added automatically
        clean.append(c)
    return clean


def risks(device, commands: list[str]) -> list[str]:
    text = "\n".join(commands).lower()
    out = []
    if device.host in text:
        out.append("🔴 ბრძანებებში მართვის IP-ა (" + device.host + ") — შეიძლება NetAgent-მა წვდომა დაკარგოს")
    if re.search(r"^\s*shutdown\b", text, re.M) or "disabled=yes" in text:
        out.append("🟠 ინტერფეისი ითიშება")
    if re.search(r"\bip route\b|/ip route|routing-options|router (bgp|ospf)", text):
        out.append("🟠 routing იცვლება — შეამოწმე, რომ გზა NetAgent-მდე არ დაიკარგება")
    if re.search(r"access-group|access-list|firewall filter|ip access-list|security policies", text):
        out.append("🟠 ACL/firewall იცვლება — არასწორი წესი წვდომას ჩაკეტავს")
    if re.search(r"^\s*line\s+(vty|con)|transport input|/ip service", text, re.M):
        out.append("🟠 მართვის წვდომა (VTY/SSH) იცვლება — არასწორი პარამეტრი SSH-ს ჩაკეტავს")
    if re.search(r"\bvlan\b|switchport", text):
        out.append("🟡 VLAN/პორტის რეჟიმი იცვლება")
    if re.search(r"^\s*no\s(?!shutdown)", text, re.M) or "remove" in text or text.lstrip().startswith("delete"):
        out.append("🟡 შეიცავს წაშლას (no / remove / delete)")
    return out


# -- store ---------------------------------------------------------------------------------------
def _all(state) -> list[dict]:
    return state.get(KEY) or []


def _save(state, items) -> None:
    state.set(KEY, items[-200:])


def get(state, cid: int) -> dict:
    c = next((x for x in _all(state) if x["id"] == cid), None)
    if c is None:
        raise CommandError(f"ცვლილება #{cid} ვერ მოიძებნა")
    return c


def _update(state, cid: int, **fields) -> dict:
    items = _all(state)
    for x in items:
        if x["id"] == cid:
            x.update(fields)
            _save(state, items)
            return x
    raise CommandError(f"ცვლილება #{cid} ვერ მოიძებნა")


def propose(s, device_name: str, commands: list[str], reason: str, user: str) -> dict:
    if not enabled():
        raise CommandError("ცვლილებები გამორთულია. ჩასართავად .env-ში: NETAGENT_CHANGES=on, მერე: python -m netagent change-pin")
    d = s.inventory().get(device_name)
    clean = validate(d, commands)
    items = _all(s.state)
    c = {"id": (max((x["id"] for x in items), default=0) + 1), "device": d.name, "commands": clean,
         "reason": reason[:300], "by": user, "created": datetime.now().isoformat(timespec="seconds"),
         "expires": (datetime.now() + timedelta(minutes=PENDING_MINUTES)).isoformat(timespec="seconds"),
         "status": "pending", "risks": risks(d, clean), "log": []}
    items.append(c)
    _save(s.state, items)
    log_event(settings.audit_log_path, user=user, tool="config_change_proposed", args={"id": c["id"], "device": d.name,
              "commands": clean}, ok=True, device_access=False)
    return c


def preview(c: dict) -> str:
    lines = [f"🛠 **ცვლილება #{c['id']} — {c['device']}** (" + {"pending": "ელოდება დადასტურებას", "applied": "გატარებულია, არ არის შენახული",
             "saved": "შენახულია", "rolledback": "დაბრუნებულია", "rejected": "უარყოფილია", "failed": "ვერ შესრულდა",
             "expired": "ვადა გაუვიდა"}.get(c["status"], c["status"]) + ")"]
    if c.get("reason"):
        lines.append(f"მიზეზი: {c['reason']}")
    lines.append("```\n" + "\n".join(c["commands"]) + "\n```")
    lines += c.get("risks") or ["🟢 აშკარა რისკი ვერ ვიპოვე"]
    if c["status"] == "pending":
        lines.append(f"\nდასადასტურებლად: `/approve {c['id']} <PIN>` · გაუქმება: `/reject {c['id']}` ({PENDING_MINUTES} წთ-ში ვადა გასდის)")
    if c.get("log"):
        lines.append("\n" + "\n".join(c["log"][-8:]))
    return "\n".join(lines)


# -- apply ----------------------------------------------------------------------------------------
def _reachable(inventory, device) -> bool:
    from ..tools import device as dev

    for _ in range(3):
        try:
            conn = dev._connect(inventory, device)  # noqa: SLF001
            try:
                conn.send_command_timing("\n")
                return True
            finally:
                conn.disconnect()
        except Exception:  # noqa: BLE001
            time.sleep(3)
    return False


def _answer_prompts(conn, out: str) -> str:
    for _ in range(4):
        low = out.lower()
        if "save?" in low or "[yes/no]" in low:
            out = conn.send_command_timing("no")
        elif "?" in out.strip()[-3:] or "[confirm]" in low or "destination filename" in low:
            out = conn.send_command_timing("\n")
        else:
            break
    return out


def apply_change(s, c: dict) -> dict:
    from ..backup import BackupStore, backup_devices
    from ..tools import device as dev

    inv = s.inventory()
    d = inv.get(c["device"])
    fam = family(d.device_type)
    log = []
    store = BackupStore(settings.backup_dir)
    try:
        backup_devices(inv, [d], store)
        log.append("💾 backup ცვლილებამდე")
    except Exception as exc:  # noqa: BLE001
        log.append(f"⚠️ backup ვერ მოხერხდა: {exc}")
    guard = os.getenv("NETAGENT_CHANGE_RELOAD_GUARD", "on").lower() not in {"off", "0", "no"}
    conn = dev._connect(inv, d)  # noqa: SLF001
    status = "applied"
    try:
        if fam == "ios":
            _answer_prompts(conn, conn.send_command_timing(f"copy running-config {ROLLBACK_FILE}"))
            log.append(f"📦 rollback ასლი: {ROLLBACK_FILE}")
            if guard:
                _answer_prompts(conn, conn.send_command_timing("reload in 10"))
                log.append("⏱ დამცავი ტაიმერი: reload in 10 (წვდომის დაკარგვისას 10 წთ-ში ძველ კონფიგზე დაბრუნდება)")
            out = conn.send_config_set(c["commands"], cmd_verify=False)
            if re.search(r"% ?(Invalid|Incomplete|Ambiguous)", out):
                bad = [ln for ln in out.splitlines() if "%" in ln][:3]
                log.append("❌ მოწყობილობამ ბრძანება არ მიიღო: " + " | ".join(bad))
                status = "failed"
        elif fam == "junos":
            conn.config_mode()
            out = conn.send_config_set(c["commands"], exit_config_mode=False, cmd_verify=False)
            if "error" in out.lower() or "syntax" in out.lower():
                log.append("❌ " + out.strip()[-200:])
                conn.send_command_timing("rollback 0")
                conn.exit_config_mode()
                status = "failed"
            else:
                conn.commit(confirm=True, confirm_delay=5, comment=f"netagent change {c['id']}")
                conn.exit_config_mode()
                log.append("⏱ commit confirmed 5 (წვდომის დაკარგვისას 5 წთ-ში დაბრუნდება)")
        else:  # mikrotik
            conn.send_command_timing("/export file=netagent-rollback")
            log.append("📦 rollback ასლი: netagent-rollback.rsc (ავტომატური დაბრუნება RouterOS-ზე არ ხდება)")
            for cmd in c["commands"]:
                out = conn.send_command_timing(cmd)
                if re.search(r"failure|bad command|syntax error|expected end|invalid value", out, re.I):
                    log.append(f"❌ `{cmd}` → {out.strip()[:150]}")
                    status = "failed"
                    break
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001
            pass

    ok = _reachable(inv, d)
    log.append("✅ წვდომა ცვლილების შემდეგ შენარჩუნებულია" if ok else "🔴 ცვლილების შემდეგ მოწყობილობას ვეღარ ვუკავშირდები")
    if fam == "ios":
        if ok:
            conn = dev._connect(inv, d)  # noqa: SLF001
            try:
                if status == "failed":
                    _answer_prompts(conn, conn.send_command_timing(f"configure replace {ROLLBACK_FILE} force"))
                    status = "rolledback"
                    log.append("↩️ შეცდომის გამო ძველი კონფიგურაცია აღდგა")
                if guard:
                    conn.send_command_timing("reload cancel")
                    log.append("⏱ დამცავი ტაიმერი გაუქმდა")
            finally:
                conn.disconnect()
        else:
            status = "failed"
            log.append("⏳ 10 წუთში მოწყობილობა თავისით გადაიტვირთება ძველი (შენახული) კონფიგურაციით")
    elif fam == "junos":
        if ok and status == "applied":
            conn = dev._connect(inv, d)  # noqa: SLF001
            try:
                conn.config_mode()
                conn.commit(comment=f"netagent change {c['id']} confirmed")
                conn.exit_config_mode()
                status = "saved"
                log.append("✅ commit დადასტურდა")
            finally:
                conn.disconnect()
        elif not ok:
            status = "failed"
            log.append("⏳ 5 წუთში Junos თვითონ დააბრუნებს წინა კონფიგურაციას")
    elif fam == "mikrotik" and status == "applied":
        status = "saved"  # RouterOS saves immediately
    if ok:
        try:
            backup_devices(inv, [d], store)
            log.append("💾 backup ცვლილების შემდეგ (/history " + d.name + ")")
        except Exception:  # noqa: BLE001
            pass
    return {"status": status, "log": log}


# -- commands ---------------------------------------------------------------------------------------
def _split(args: list[str]) -> list[str]:
    return [x.strip() for x in " ".join(args).split(";") if x.strip()]


def change_cmd(s, args, user) -> Result:
    if len(args) < 2:
        raise CommandError("გამოყენება: /change R1 interface Gi0/5 ; description Printer ; no shutdown\n"
                           "(ბრძანებები ;-ით გამოყავი) · ან უბრალოდ სთხოვე AI-ს")
    c = propose(s, args[0], _split(args[1:]), "", user)
    return Result(preview(c), buttons=[Button("✅ დადასტურება (PIN)", f"/approve {c['id']}"), Button("❌ გაუქმება", f"/reject {c['id']}")])


def approve_cmd(s, args, user) -> Result:
    if not args or not args[0].isdigit():
        raise CommandError("გამოყენება: /approve 7 <PIN>")
    c = get(s.state, int(args[0]))
    if c["status"] != "pending":
        raise CommandError(f"ცვლილება #{c['id']} უკვე {c['status']}-ია")
    if c["expires"] < datetime.now().isoformat():
        _update(s.state, c["id"], status="expired")
        raise CommandError("ვადა გაუვიდა — შექმენი ახლიდან")
    if len(args) < 2:
        return Result(f"🔐 დასადასტურებლად ჩაწერე PIN: `/approve {c['id']} 123456`")
    if not enabled():
        raise CommandError("ცვლილებები გამორთულია (NETAGENT_CHANGES)")
    check_pin(s.state, args[1])
    _update(s.state, c["id"], status="applying", approved_by=user, approved=datetime.now().isoformat(timespec="seconds"))
    try:
        res = apply_change(s, c)
    except Exception as exc:  # noqa: BLE001
        res = {"status": "failed", "log": [f"❌ {type(exc).__name__}: {exc}"]}
    if c.get("heal"):  # self-healing fix: check the problem is gone, roll back automatically if not
        from .selfheal import after_apply

        res = after_apply(s, c, res)
    c = _update(s.state, c["id"], **res)
    log_event(settings.audit_log_path, user=user, tool="config_change_applied", args={"id": c["id"], "device": c["device"],
              "commands": c["commands"], "status": c["status"]}, ok=c["status"] in {"applied", "saved"}, device_access=True)
    buttons = []
    if c["status"] == "applied":
        buttons = [Button("💾 შენახვა (write memory)", f"/save-change {c['id']}"), Button("↩️ დაბრუნება", f"/undo {c['id']}")]
    return Result(preview(c), buttons=buttons)


def reject_cmd(s, args, user) -> Result:
    c = get(s.state, int(args[0])) if args and args[0].isdigit() else None
    if c is None or c["status"] != "pending":
        raise CommandError("გამოყენება: /reject 7 (მხოლოდ მოლოდინში მყოფი ცვლილება)")
    _update(s.state, c["id"], status="rejected")
    return Result(f"❌ ცვლილება #{c['id']} გაუქმდა — მოწყობილობას არაფერი შეხებია.")


def save_cmd(s, args, user) -> Result:
    from ..tools import device as dev

    c = get(s.state, int(args[0])) if args and args[0].isdigit() else None
    if c is None or c["status"] != "applied":
        raise CommandError("შესანახი ცვლილება ვერ ვიპოვე")
    d = s.inventory().get(c["device"])
    conn = dev._connect(s.inventory(), d)  # noqa: SLF001
    try:
        out = conn.save_config()
    finally:
        conn.disconnect()
    c = _update(s.state, c["id"], status="saved", log=c["log"] + ["💾 write memory: " + ("OK" if "OK" in out or "[OK]" in out else out.strip()[-60:])])
    log_event(settings.audit_log_path, user=user, tool="config_change_saved", args={"id": c["id"]}, ok=True, device_access=True)
    return Result(f"💾 ცვლილება #{c['id']} შენახულია {c['device']}-ზე (startup-config).")


def rollback_change(s, c: dict) -> str:
    """Restore the configuration saved before change c (Cisco: configure replace; Junos: rollback 1)."""
    from ..tools import device as dev

    d = s.inventory().get(c["device"])
    fam = family(d.device_type)
    if fam == "mikrotik":
        raise CommandError("RouterOS-ზე ავტომატური დაბრუნება არ არის. ასლი: netagent-rollback.rsc (Files) — ან სთხოვე AI-ს საპირისპირო ბრძანებები.")
    conn = dev._connect(s.inventory(), d)  # noqa: SLF001
    try:
        if fam == "ios":
            return _answer_prompts(conn, conn.send_command_timing(f"configure replace {ROLLBACK_FILE} force"))
        conn.config_mode()
        conn.send_command_timing("rollback 1")
        out = conn.commit(comment=f"netagent undo {c['id']}")
        conn.exit_config_mode()
        return out
    finally:
        conn.disconnect()


def undo_cmd(s, args, user) -> Result:
    if not args or not args[0].isdigit():
        raise CommandError("გამოყენება: /undo 7 <PIN>")
    c = get(s.state, int(args[0]))
    if c["status"] not in {"applied", "saved"}:
        raise CommandError(f"#{c['id']} {c['status']}-ია, დასაბრუნებელი არაფერია")
    if len(args) < 2:
        return Result(f"🔐 დასაბრუნებლად ჩაწერე PIN: `/undo {c['id']} 123456`")
    check_pin(s.state, args[1])
    out = rollback_change(s, c)
    c = _update(s.state, c["id"], status="rolledback", log=c["log"] + [f"↩️ დაბრუნდა ({user})"])
    log_event(settings.audit_log_path, user=user, tool="config_change_undo", args={"id": c["id"]}, ok=True, device_access=True)
    return Result(f"↩️ ცვლილება #{c['id']} დაბრუნდა {c['device']}-ზე.\n{out.strip()[-200:]}")


def changes_cmd(s, args, user) -> Result:
    items = list(reversed(_all(s.state)))[:10]
    if not enabled():
        head = "🔒 ცვლილებები გამორთულია (მხოლოდ წაკითხვის რეჟიმი). ჩასართავად: .env → NETAGENT_CHANGES=on და `python -m netagent change-pin`"
    else:
        head = "🛠 **ცვლილებები**" + ("" if pin_path().exists() else "\n⚠️ PIN ჯერ არ არის: python -m netagent change-pin")
    if args and args[0].isdigit():
        return Result(preview(get(s.state, int(args[0]))))
    if not items:
        return Result(head + "\nჯერ არცერთი. სთხოვე AI-ს, მაგ.: „Gi0/5-ს description დაუწერე Printer“")
    return Result(head + "\n" + "\n".join(f"#{c['id']} {c['created'][5:16].replace('T', ' ')} {c['device']} — {c['status']} "
                                          f"({len(c['commands'])} ხაზი)" for c in items),
                  buttons=[Button(f"#{c['id']}", f"/changes {c['id']}") for c in items[:5]])


def prompt_extra(s) -> str:
    if not enabled():
        return ""
    return ("\n\nცვლილებები ჩართულია მხოლოდ დადასტურებით: კონფიგურაციის შესაცვლელად გამოიყენე propose_config_change. "
            "ის მხოლოდ შეთავაზებას ქმნის. არასდროს თქვა, რომ ცვლილება გატარდა: მომხმარებელმა უნდა დააჭიროს "
            "„დადასტურებას“ და შეიყვანოს PIN. შესთავაზე მინიმალური ბრძანებები და ახსენი რისკები.")


def _tool(ctx, device: str, commands: list, reason: str = ""):
    try:
        c = propose(ctx.services, device, [str(x) for x in commands], reason, ctx.user)
    except CommandError as exc:
        raise ValueError(str(exc)) from None
    ctx.buttons += [Button(f"✅ დადასტურება #{c['id']} (PIN)", f"/approve {c['id']}"), Button("❌ გაუქმება", f"/reject {c['id']}")]
    return {"id": c["id"], "status": "pending — NOT applied; the user must approve with PIN", "commands": c["commands"],
            "risks": c["risks"], "how_to_approve": f"/approve {c['id']} <PIN>"}


COMMANDS = {"change": change_cmd, "approve": approve_cmd, "reject": reject_cmd, "save-change": save_cmd,
            "undo": undo_cmd, "changes": changes_cmd}
HELP = ["/changes — კონფიგურაციის ცვლილებები (დადასტურებით, PIN-ით) · /approve 7 PIN · /undo 7 PIN"]
BOT_COMMANDS = [("changes", "კონფიგურაციის ცვლილებები")]
TOOLS = [({
    "name": "propose_config_change",
    "description": "Propose a configuration change on a device. Creates a PENDING change only: nothing is sent to the "
                   "device until the user approves it with their PIN (buttons are shown automatically). Use the "
                   "minimal set of config-mode lines (Cisco: lines inside configure terminal, e.g. 'interface Gi0/5', "
                   "' description Printer'; Junos: set/delete lines; MikroTik: full commands like "
                   "'/ip address add address=10.0.0.1/24 interface=ether3'). Dangerous commands are refused.",
    "input_schema": {"type": "object", "properties": {
        "device": {"type": "string"}, "commands": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string", "description": "why, in one sentence"}}, "required": ["device", "commands"]},
}, _tool)]
