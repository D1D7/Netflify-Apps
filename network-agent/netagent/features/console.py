"""Console cable (COM port): find a switch / router plugged in with a console cable and add it to NetAgent.

  /console                 COM ports and what is on them
  /console probe COM3      press Enter, find the speed (9600, 115200, ...), read the prompt
  /console add COM3        identify read-only (show version, show ip interface brief) and add to devices.yaml
  /console login COM3      the console asks for a login: use the credentials from .env (CONSOLE_USER /
                           CONSOLE_PASS, otherwise NET_USER / NET_PASS)
  /console skipsetup COM3  a new / erased device asks "initial configuration dialog? [yes/no]": answer "no"

Nothing is configured: the probe only presses Enter and reads; identification runs "terminal length 0"
(this session only) and show commands. Answering the setup dialog or logging in happens only when you press
the button. A COM port has one user at a time: if PuTTY / Tera Term has it open, NetAgent says so and waits.
COM ports are listed every 5 seconds; a newly plugged cable is probed at once, and a device that sits at a
prompt is identified and added by itself (other states: one notification with the right button).
"""

from __future__ import annotations

import logging
import os
import re
import time

from ..result import Button, CommandError, Result

log = logging.getLogger("netagent.console")
BAUDS = (9600, 115200, 38400, 57600, 19200)
TRIED_KEY = "console_tried"
SKIP_DESC = re.compile(r"bluetooth", re.I)
# how soon a port is looked at again, by its last state (seconds): a port PuTTY holds is free again as soon as
# PuTTY closes; a silent one costs ~10 s of probing; prompts that wait for you only need a fresh look now and then
RETRY = {"busy": 10, "error": 10, "unsupported": 600, "silent": 30, "garbage": 30, "unknown": 30, "press_return": 10,
         "setup_dialog": 60, "autoinstall": 60, "login_user": 60, "login_password": 60, "rommon": 120, "more": 30}
PACE = 1.0  # multiplier for every wait on the console (tests with a simulated device set it close to 0)

PROMPTS = [  # (state, regex on the last line), first match wins
    ("setup_dialog", re.compile(r"initial configuration dialog\?\s*\[yes/no\]", re.I)),
    ("autoinstall", re.compile(r"terminate autoinstall\?\s*\[yes\]", re.I)),
    ("login_user", re.compile(r"(user ?name|login)\s*:\s*$", re.I)),
    ("login_password", re.compile(r"password\s*:\s*$", re.I)),
    ("rommon", re.compile(r"(rommon\s*\d*\s*>|switch:\s*$|loader>)", re.I)),
    ("more", re.compile(r"--more--", re.I)),
    ("config", re.compile(r"^[\w.\-/]+\(config[^)]*\)#\s*$", re.M)),
    ("enable", re.compile(r"^[\w.\-/]+#\s*$", re.M)),
    ("exec", re.compile(r"^[\w.\-/]+>\s*$", re.M)),
    ("press_return", re.compile(r"press return to get started", re.I)),
]
STATE_TEXT = {
    "exec": "მზადაა (user exec, „>“)", "enable": "მზადაა (privileged, „#“)", "config": "კონფიგურაციის რეჟიმშია („(config)#“)",
    "setup_dialog": "ახალი/წაშლილი მოწყობილობაა — კითხულობს initial configuration dialog-ს",
    "autoinstall": "autoinstall-ს ელოდება", "login_user": "მომხმარებელს ითხოვს", "login_password": "პაროლს ითხოვს",
    "rommon": "ROMMON / bootloader რეჟიმშია (IOS არ ჩაიტვირთა)", "more": "გვერდის გადაფურცვლას ელოდება (--More--)",
    "press_return": "„Press RETURN“", "busy": "პორტი სხვა პროგრამას უჭირავს (PuTTY / Tera Term?)",
    "error": "პორტი ვერ გაიხსნა (კაბელი გამოერთებულია?)",
    "unsupported": "prompt-ზეა, მაგრამ Cisco IOS არ არის — ჯერ მხარდაჭერილი არ არის", "unknown": "პასუხობს, მაგრამ prompt ვერ ამოვიცანი",
    "silent": "არაფერს პასუხობს (სხვა სიჩქარე? კაბელი ბოლომდე არაა შესული? მოწყობილობა ჩართულია?)", "garbage": "გაუგებარი სიმბოლოები (სიჩქარე არ ემთხვევა)",
}


def list_ports() -> list[dict]:
    from serial.tools import list_ports as lp

    out = []
    for p in sorted(lp.comports(), key=lambda p: p.device):
        out.append({"port": p.device, "description": p.description or "", "hwid": p.hwid or "",
                    "vid": f"{p.vid:04X}" if p.vid is not None else "", "pid": f"{p.pid:04X}" if p.pid is not None else "",
                    "usb": p.vid is not None})
    return out


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text)


def detect_state(text: str) -> tuple[str, str]:
    """(state, prompt line) from what the console printed."""
    lines = [ln.rstrip() for ln in re.split(r"[\r\n]+", text) if ln.strip()]
    tail = "\n".join(lines[-3:])
    last = lines[-1] if lines else ""
    for state, rx in PROMPTS:
        if state in {"config", "enable", "exec"}:
            if rx.search(last):
                return state, last.strip()
        elif rx.search(tail):
            return state, last.strip()
    if not text.strip():
        return "silent", ""
    if printable_ratio(text) < 0.85:
        return "garbage", ""
    return "unknown", last.strip()


def hostname_from(prompt: str) -> str:
    m = re.match(r"^([\w.\-/]+?)(?:\(config[^)]*\))?[>#]\s*$", prompt.strip())
    return m.group(1) if m else ""


class Console:
    """A raw console session (pyserial). Used for the probe, identification, login and the setup dialog."""

    def __init__(self, port: str, baud: int, opener=None):
        import serial

        self.port, self.baud = port, baud
        self.s = (opener or serial.Serial)(port, baud, timeout=0.3, write_timeout=2)

    def close(self) -> None:
        try:
            self.s.close()
        except Exception:  # noqa: BLE001
            pass

    def send(self, text: str) -> None:
        self.s.write(text.encode("ascii", "replace"))
        self.s.flush()

    def read_for(self, seconds: float, until: re.Pattern | None = None) -> str:
        buf, end = b"", time.monotonic() + seconds * PACE
        while time.monotonic() < end:
            chunk = self.s.read(self.s.in_waiting or 1)
            if chunk:
                buf += chunk
                text = buf.decode("ascii", "replace")
                if until is not None and until.search(text.rstrip()[-200:]):
                    return text
                if "--More--" in text[-40:]:
                    self.s.write(b" ")
        return buf.decode("ascii", "replace")

    def poke(self) -> str:
        """Press Enter (twice, the first may only wake it) and return what came back."""
        try:
            self.s.reset_input_buffer()
        except Exception:  # noqa: BLE001
            pass
        out = ""
        for _ in range(2):
            self.send("\r")
            out += self.read_for(1.2)
        return out

    def command(self, cmd: str, timeout: float = 25) -> str:
        """Run one command at an exec/enable prompt and return its output (prompt and echo removed)."""
        prompt_rx = re.compile(r"[\w.\-/]+(\([^)]*\))?[>#]\s*$")
        self.send(cmd + "\r")
        text = self.read_for(timeout, until=prompt_rx)
        text = re.sub(r"\s*--More--\s*(\x08+ *\x08+)?", "\n", text).replace("\r", "")
        lines = text.split("\n")
        if lines and cmd.strip() in lines[0]:  # the echo of what we typed (keep anything printed after it)
            rest = lines[0].split(cmd.strip(), 1)[1].strip()
            lines = ([rest] if rest else []) + lines[1:]
        if lines and prompt_rx.search(lines[-1]):
            lines = lines[:-1]
        return "\n".join(lines).strip()


def probe(port: str, bauds=BAUDS, opener=None) -> dict:
    """Press Enter on each speed until the console answers with readable text."""
    import serial

    best = {"port": port, "state": "silent", "baud": None, "prompt": "", "text": ""}
    for baud in bauds:
        try:
            c = Console(port, baud, opener)
        except (serial.SerialException, OSError) as exc:
            if "denied" in str(exc).lower() or "PermissionError" in repr(exc):
                return {**best, "state": "busy", "error": str(exc)}
            return {**best, "state": "error", "error": str(exc)}
        try:
            text = c.poke()
        finally:
            c.close()
        state, prompt = detect_state(text)
        if state not in {"silent", "garbage"}:
            return {"port": port, "state": state, "baud": baud, "prompt": prompt, "hostname": hostname_from(prompt),
                    "text": text[-400:]}
        if state == "garbage" and best["state"] == "silent":
            best = {**best, "state": "garbage", "baud": baud, "text": text[-200:]}
    return best


# ---------------------------------------------------------------------------------------------------------
def parse_show_version(text: str) -> dict:
    out = {}
    m = re.search(r"Cisco IOS(?: XE)? Software.*?Version ([\w.()\-]+)", text, re.S) or re.search(r"Version ([\d.()A-Za-z\-]+),", text)
    if m:
        out["version"] = m.group(1).rstrip(",")
    m = re.search(r"\(([\w\-]+)-[\w]+-M\)", text)
    if m:
        out["image"] = m.group(1)
    m = re.search(r"^(?:Model [Nn]umber|Model number)\s*:\s*(\S+)", text, re.M) or \
        re.search(r"^[Cc]isco (\S+) \([^)]*\) processor", text, re.M)
    if m:
        out["model"] = m.group(1)
    m = re.search(r"^(\S+) uptime is (.+)$", text, re.M)
    if m:
        out["hostname"], out["uptime"] = m.group(1), m.group(2).strip()
    m = re.search(r"(?:System [Ss]erial [Nn]umber|Processor board ID)\s*:?\s*(\S+)", text)
    if m:
        out["serial"] = m.group(1)
    out["vendor"] = "cisco" if re.search(r"\bCisco\b", text) else ""
    return out


def parse_ip_brief(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[0] not in {"Interface"} and re.match(r"[A-Za-z]", parts[0]):
            status = " ".join(parts[4:-1])
            rows.append({"name": parts[0], "ip": parts[1], "status": status, "protocol": parts[-1]})
    return rows


def identify(port: str, baud: int, opener=None) -> dict:
    """Read-only: at an exec/enable prompt run terminal length 0, show version, show ip interface brief."""
    c = Console(port, baud, opener)
    try:
        state, prompt = detect_state(c.poke())
        if state not in {"exec", "enable"}:
            return {"port": port, "baud": baud, "state": state, "prompt": prompt}
        c.command("terminal length 0", 8)
        ver = c.command("show version", 40)
        brief = c.command("show ip interface brief", 40)
    finally:
        c.close()
    info = parse_show_version(ver)
    info.setdefault("hostname", hostname_from(prompt))
    return {"port": port, "baud": baud, "state": state, "prompt": prompt, **info, "interfaces": parse_ip_brief(brief)}


def console_credentials() -> tuple[str, str]:
    user = os.getenv("CONSOLE_USER") or os.getenv("NET_USER") or ""
    pw = os.getenv("CONSOLE_PASS") or os.getenv("NET_PASS") or ""
    return user, pw


def login(port: str, baud: int, opener=None) -> dict:
    """Answer Username: / Password: with the console credentials from .env (never typed in chat)."""
    user, pw = console_credentials()
    if not pw:
        raise CommandError("კონსოლის პაროლი .env-ში არ არის: დაამატე CONSOLE_PASS (და საჭიროების შემთხვევაში CONSOLE_USER), "
                           "გადატვირთე NetAgent. ჩატში პაროლი არ დაწერო.")
    c = Console(port, baud, opener)
    try:
        state, _ = detect_state(c.poke())
        for _ in range(3):
            if state == "login_user":
                c.send(user + "\r")
            elif state == "login_password":
                c.send(pw + "\r")
            else:
                break
            state, prompt = detect_state(c.read_for(4))
    finally:
        c.close()
    if state in {"login_user", "login_password"}:
        raise CommandError("შესვლა ვერ მოხერხდა — .env-ის მომხმარებელი/პაროლი არ ემთხვევა.")
    return {"port": port, "state": state}


def skip_setup(port: str, baud: int, opener=None) -> dict:
    """Answer "no" to the initial configuration dialog and "yes" to terminating autoinstall."""
    c = Console(port, baud, opener)
    try:
        state, _ = detect_state(c.poke())
        if state == "setup_dialog":
            c.send("no\r")
            text = c.read_for(15, until=re.compile(r"(terminate autoinstall\?\s*\[yes\]|[>#]\s*$|RETURN)", re.I))
            state, _ = detect_state(text)
        if state == "autoinstall":
            c.send("\r")
            state, _ = detect_state(c.read_for(10))
        if state == "press_return":
            state, _ = detect_state(c.poke())
    finally:
        c.close()
    return {"port": port, "state": state}


# ---------------------------------------------------------------------------------------------------------
def device_type_for(info: dict) -> str | None:
    if info.get("vendor") == "cisco":
        return "cisco_ios_serial"
    return None


def add_device(s, port: str, info: dict) -> str:
    from ..config import settings
    from ..discovery import Candidate, add_to_inventory

    inv = s.inventory()
    for d in inv.devices.values():
        if d.host.upper() == port.upper():
            return d.name
    dt = device_type_for(info)
    if not dt:
        raise CommandError("მოწყობილობა ვერ ამოვიცანი როგორც Cisco IOS — სხვა მწარმოებლის კონსოლი ჯერ მხარდაჭერილი არ არის.")
    name = info.get("hostname") or f"console-{port}"
    names = add_to_inventory(settings.inventory_path, [Candidate(host=port.upper(), device_type=dt, hostname=name,
                                                                 extra={"baudrate": info["baud"], "role": "console"})])
    return names[0] if names else name




def _with_port(fn, *a, **kw):
    """Probe / identify only when NetAgent itself is not already talking to that port."""
    from ..tools.device import port_lock

    lock = port_lock(a[0])
    if not lock.acquire(timeout=30):
        raise CommandError(f"{a[0]} ახლა დაკავებულია NetAgent-ის სხვა სესიით")
    try:
        return fn(*a, **kw)
    finally:
        lock.release()


def scan(s) -> list[dict]:
    """Every COM port with its state (for /console and the app)."""
    inv_ports = {d.host.upper(): d.name for d in s.inventory().devices.values() if d.is_serial}
    out = []
    for p in list_ports():
        row = dict(p)
        row["device"] = inv_ports.get(p["port"].upper(), "")
        out.append(row)
    return out


def format_ports(rows: list[dict], probes: dict | None = None) -> str:
    if not rows:
        return ("🔌 COM პორტი ვერ ვიპოვე — console კაბელი (USB) შეაერთე. თუ შეერთებულია და მაინც არ ჩანს, "
                "Device Manager-ში დრაივერი შეამოწმე (FTDI / Prolific / CH340 / Cisco USB console).")
    lines = ["🔌 **Console კაბელი / COM პორტები**"]
    for r in rows:
        p = (probes or {}).get(r["port"]) or {}
        state = STATE_TEXT.get(p.get("state", ""), p.get("state", ""))
        lines.append(f"• **{r['port']}** — {r['description']}" + (f" · NetAgent-ში: **{r['device']}**" if r["device"] else "")
                     + (f"\n   {state}" + (f" · {p['baud']} baud" if p.get("baud") else "") + (f" · `{p['prompt']}`" if p.get("prompt") else "")
                        if p else ""))
    return "\n".join(lines)


def _buttons_for(port: str, state: str) -> list[Button]:
    return {"exec": [Button(f"➕ დაამატე ({port})", f"/console add {port}")],
            "enable": [Button(f"➕ დაამატე ({port})", f"/console add {port}")],
            "setup_dialog": [Button("⏭ setup-ის გამოტოვება (no)", f"/console skipsetup {port}")],
            "autoinstall": [Button("⏭ autoinstall-ის შეწყვეტა", f"/console skipsetup {port}")],
            "login_user": [Button("🔑 შესვლა (.env-ის credentials)", f"/console login {port}")],
            "login_password": [Button("🔑 შესვლა (.env-ის credentials)", f"/console login {port}")],
            "busy": [Button("🔄 თავიდან", f"/console probe {port}")],
            "error": [Button("🔄 თავიდან", f"/console probe {port}")],
            "silent": [Button("🔄 თავიდან", f"/console probe {port}")]}.get(state, [])


def console_cmd(s, args, user) -> Result:
    from ..permissions import DENIED, is_viewer

    sub = args[0].lower() if args else ""
    port = args[1].upper() if len(args) > 1 else ""
    if sub and sub != "probe" and is_viewer(user):
        raise CommandError(DENIED)
    if sub in {"probe", "add", "login", "skipsetup"} and not port:
        ports = [p["port"] for p in list_ports()]
        if len(ports) != 1:
            raise CommandError(f"მიუთითე პორტი, მაგ. /console {sub} COM3")
        port = ports[0]
    if sub == "probe":
        p = _with_port(probe, port)
        return Result(format_ports([r for r in scan(s) if r["port"].upper() == port] or [{"port": port, "description": "", "device": ""}], {port: p})
                      + (f"\n\n```\n{p['text'].strip()[-300:]}\n```" if p.get("text") and p["state"] == "unknown" else ""),
                      buttons=_buttons_for(port, p["state"]))
    if sub == "add":
        p = _with_port(probe, port)
        if p["state"] not in {"exec", "enable"}:
            return Result(f"{port}: {STATE_TEXT.get(p['state'], p['state'])} — ჯერ ეს უნდა მოგვარდეს.", buttons=_buttons_for(port, p["state"]))
        info = _with_port(identify, port, p["baud"])
        name = add_device(s, port, info)
        s.state.update(TRIED_KEY, lambda v: {**(v or {}), port: {"ts": time.time(), "result": f"დაემატა: {name}"}})
        ifs = info.get("interfaces", [])
        up = sum(1 for i in ifs if i["status"] == "up")
        return Result(f"✅ **{name}** დაემატა NetAgent-ს console კაბელით ({port}, {p['baud']} baud)\n"
                      f"• მოდელი: {info.get('model') or '?'} · IOS {info.get('version') or '?'}"
                      + (f" · S/N {info['serial']}" if info.get("serial") else "")
                      + (f"\n• ჩართულია {info['uptime']}" if info.get("uptime") else "")
                      + (f"\n• ინტერფეისები: {len(ifs)} (up: {up})" if ifs else "")
                      + "\nახლა ჩანს „ქსელი“ ჩანართზე და ტერმინალში (show ...).",
                      buttons=[Button("🩺 სტატუსი", f"/status {name}"), Button("💻 ინტერფეისები", f"/cmd {name} show ip interface brief")])
    if sub == "login":
        r = _with_port(login, port, (_with_port(probe, port).get("baud") or 9600))
        return Result(f"🔑 {port}: {STATE_TEXT.get(r['state'], r['state'])}", buttons=_buttons_for(port, r["state"]))
    if sub == "skipsetup":
        r = _with_port(skip_setup, port, (_with_port(probe, port).get("baud") or 9600))
        return Result(f"⏭ {port}: {STATE_TEXT.get(r['state'], r['state'])}", buttons=_buttons_for(port, r["state"]))
    if sub:
        raise CommandError("გამოყენება: /console · /console probe|add|login|skipsetup COM3")
    rows = scan(s)
    return Result(format_ports(rows), buttons=[Button(f"🔎 {r['port']}", f"/console probe {r['port']}") for r in rows if not r["device"]][:4])


COMMANDS = {"console": console_cmd}
HELP = ["/console — console კაბელით (COM) მიერთებული სვიჩი/როუტერი: /console probe COM3 · /console add COM3 · "
        "/console login COM3 · /console skipsetup COM3"]
BOT_COMMANDS = [("console", "Console კაბელი (COM პორტი)")]


def jobs(monitoring):
    from . import env_int

    if env_int("NETAGENT_CONSOLE_INTERVAL", 5) <= 0:
        return []

    async def check():
        """A new console device sitting at a prompt is identified and added; other states get one notification."""
        import asyncio

        from ..monitoring import Alert

        s = monitoring.s
        rows = await asyncio.to_thread(scan, s)
        tried = s.state.get(TRIED_KEY) or {}
        now = time.time()
        present = {r["port"].upper() for r in rows}
        for r in rows:
            port = r["port"].upper()
            if r["device"] or SKIP_DESC.search(r["description"]):
                continue
            last = tried.get(port) or {}
            if now - last.get("ts", 0) < RETRY.get(last.get("state", ""), 30):
                continue
            try:
                p = await asyncio.to_thread(_with_port, probe, port)
                if p["state"] in {"exec", "enable"}:
                    info = await asyncio.to_thread(_with_port, identify, port, p["baud"])
                    name = await asyncio.to_thread(add_device, s, port, info)
                    result = f"დაემატა: {name}"
                    await monitoring.emit(Alert("newdevice", f"🔌 **console კაბელით დაემატა: {name}** ({port})\n"
                                                             f"{info.get('model') or ''} · IOS {info.get('version') or '?'}",
                                                [name], mutable=False, buttons=[Button("🩺 სტატუსი", f"/status {name}")]))
                else:
                    result = STATE_TEXT.get(p["state"], p["state"])
                    if p["state"] in {"setup_dialog", "autoinstall", "login_user", "login_password", "rommon"} and last.get("state") != p["state"]:
                        await monitoring.emit(Alert("newdevice", f"🔌 **{port}: მოწყობილობა console კაბელზე** — {result}",
                                                    mutable=False, buttons=_buttons_for(port, p["state"])))
                tried[port] = {"ts": now, "state": p["state"], "result": result}
            except CommandError as exc:
                unsupported = "Cisco" in str(exc)
                tried[port] = {"ts": now, "state": "unsupported" if unsupported else "error", "result": str(exc)}
            except Exception as exc:  # noqa: BLE001 - one odd port must not stop the others
                log.info("console %s: %s", port, exc)
                tried[port] = {"ts": now, "state": "error", "result": str(exc)[:200]}
        for port in list(tried):
            if port not in present:
                tried.pop(port)  # unplugged: look at it again right away when it comes back
        s.state.set(TRIED_KEY, tried)

    return [("console", env_int("NETAGENT_CONSOLE_INTERVAL", 5), 15, check)]
