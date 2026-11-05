"""Setup checker: `python -m netagent doctor` — tells what is missing and how to fix it."""

from __future__ import annotations

import importlib
import os
import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import PROJECT_ROOT, settings

OK, WARN, FAIL = "ok", "warn", "fail"
ICON = {OK: "✅", WARN: "⚠️ ", FAIL: "❌"}


@dataclass
class Check:
    status: str
    title: str
    hint: str = ""


REQUIRED_MODULES = {
    "anthropic": "anthropic", "netmiko": "netmiko", "telegram": "python-telegram-bot", "fastapi": "fastapi",
    "uvicorn": "uvicorn", "python_multipart": "python-multipart", "matplotlib": "matplotlib", "openpyxl": "openpyxl",
    "yaml": "PyYAML", "dotenv": "python-dotenv", "rich": "rich", "dns": "dnspython",
}


def _tailscale_path() -> str | None:
    found = shutil.which("tailscale")
    if found:
        return found
    if platform.system() == "Windows":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", "")):
            candidate = Path(base) / "Tailscale" / "tailscale.exe"
            if base and candidate.exists():
                return str(candidate)
    return None


def run_checks(online: bool = True) -> list[Check]:
    checks: list[Check] = []
    add = checks.append

    # -- Python & packages ---------------------------------------------------------------
    v = sys.version_info
    if v >= (3, 10):
        add(Check(OK, f"Python {v.major}.{v.minor}.{v.micro}"))
    else:
        add(Check(FAIL, f"Python {v.major}.{v.minor} ძალიან ძველია", "საჭიროა Python 3.10+ (რეკომენდებული 3.12): python.org/downloads"))
    missing = []
    for module, package in REQUIRED_MODULES.items():
        try:
            importlib.import_module(module)
        except Exception:  # noqa: BLE001
            missing.append(package)
    if missing:
        add(Check(FAIL, "აკლია ბიბლიოთეკები: " + ", ".join(missing), "გაუშვი: pip install -r requirements.txt  (Windows: install.bat)"))
    else:
        add(Check(OK, "ყველა ბიბლიოთეკა დაყენებულია"))

    # -- .env --------------------------------------------------------------------------------
    env_file = PROJECT_ROOT / ".env"
    if not env_file.exists():
        add(Check(FAIL, ".env ფაილი არ არსებობს", "დააკოპირე .env.example → .env და შეავსე (Windows: install.bat ამას თვითონ აკეთებს)"))

    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not key or key.endswith("..."):
        add(Check(FAIL, "ANTHROPIC_API_KEY არ არის მითითებული", "console.anthropic.com → API Keys → Create Key, ჩაწერე .env-ში"))
    elif online:
        try:
            import anthropic

            model = anthropic.Anthropic(max_retries=1, timeout=20).models.retrieve(settings.model)
            add(Check(OK, f"Anthropic API მუშაობს (მოდელი: {getattr(model, 'id', settings.model)})"))
        except Exception as exc:  # noqa: BLE001
            name = type(exc).__name__
            hint = {
                "AuthenticationError": "API key არასწორია — შეამოწმე .env-ში (სფეისების/ბრჭყალების გარეშე)",
                "PermissionDeniedError": "API key-ს ამ მოდელზე წვდომა არ აქვს, ან Billing-ში თანხა არ არის",
                "NotFoundError": f"მოდელი '{settings.model}' ვერ მოიძებნა — შეამოწმე NETAGENT_MODEL",
                "APIConnectionError": "ინტერნეტთან/Anthropic-თან კავშირი ვერ დამყარდა (firewall/proxy?)",
            }.get(name, str(exc)[:160])
            add(Check(FAIL, f"Anthropic API: {name}", hint))
    else:
        add(Check(OK, "ANTHROPIC_API_KEY მითითებულია (შემოწმება გამოტოვებულია)"))

    if settings.daily_budget_usd > 0:
        add(Check(OK, f"დღიური AI ლიმიტი: ${settings.daily_budget_usd:.2f}"))
    else:
        add(Check(WARN, "დღიური AI ლიმიტი არ არის", "რეკომენდებულია .env-ში: NETAGENT_DAILY_BUDGET=2"))

    # -- app login -------------------------------------------------------------------------
    auth_file = settings.data_dir / "web_auth.json"
    if auth_file.exists() or os.getenv("NETAGENT_WEB_PASSWORD"):
        add(Check(OK, "აპის პაროლი დაყენებულია"))
    else:
        add(Check(WARN, "აპის პაროლი ჯერ არ არის", "გაუშვი: python -m netagent web-setup --totp  (Windows: setup-password.bat)"))

    # -- Telegram (optional) ----------------------------------------------------------------
    token = settings.telegram_token
    if not token or token.endswith("..."):
        add(Check(WARN, "Telegram ბოტი არ არის მითითებული (არასავალდებულო)", "TELEGRAM_BOT_TOKEN .env-ში, თუ Telegram-იც გინდა"))
    else:
        if online:
            try:
                import httpx

                r = httpx.get(f"https://api.telegram.org/bot{token}/getMe", timeout=15).json()
                if r.get("ok"):
                    add(Check(OK, f"Telegram ბოტი: @{r['result'].get('username')}"))
                else:
                    add(Check(FAIL, "Telegram ტოკენი არასწორია", "BotFather-ის ტოკენი ხელახლა დააკოპირე .env-ში"))
            except Exception as exc:  # noqa: BLE001
                add(Check(WARN, f"Telegram-თან კავშირი ვერ შემოწმდა ({type(exc).__name__})"))
        if not settings.telegram_allowed_users:
            add(Check(WARN, "TELEGRAM_ALLOWED_USERS ცარიელია", "მიწერე ბოტს /id და ჩაწერე ID .env-ში"))

    from .features.notify import channels

    extra = [k for k, on in channels().items() if on]
    if extra:
        add(Check(OK, "დამატებითი ალერტების არხები: " + ", ".join(extra) + " (შემოწმება: /notify test)"))

    from .features import changes

    if changes.enabled():
        add(Check(OK if changes.pin_path().exists() else FAIL, "კონფიგურაციის ცვლილებები ჩართულია (დადასტურებით)"
                  + ("" if changes.pin_path().exists() else " — PIN არ არის"), "გაუშვი: python -m netagent change-pin"))

    # -- inventory & devices ----------------------------------------------------------------
    inv_path = settings.inventory_path
    if not inv_path.exists():
        add(Check(FAIL, "inventory/devices.yaml არ არსებობს", "დააკოპირე inventory/devices.example.yaml → inventory/devices.yaml"))
    else:
        from .health import check_many
        from .inventory import Inventory

        try:
            inv = Inventory.load(inv_path)
        except Exception as exc:  # noqa: BLE001
            add(Check(FAIL, f"inventory ვერ წავიკითხე: {exc}", "შეამოწმე YAML ფორმატი (ჩაწევები სფეისებით, არა Tab-ით)"))
            inv = None
        if inv is not None:
            example = PROJECT_ROOT / "inventory" / "devices.example.yaml"
            if example.exists() and example.read_bytes() == inv_path.read_bytes():
                add(Check(WARN, "devices.yaml ჯერ მაგალითია", "ჩაწერე შენი მოწყობილობები, ან ჩატში: /discover 192.168.1.0/24"))
            elif not inv.devices:
                add(Check(WARN, "inventory ცარიელია", "ჩატში: /discover 192.168.1.0/24 ან ჩაწერე devices.yaml-ში"))
            else:
                add(Check(OK, f"inventory: {len(inv.devices)} მოწყობილობა"))
            for name in sorted({d.credentials for d in inv.devices.values()}):
                ref = inv._credential_refs.get(name)  # noqa: SLF001 - read-only diagnostic
                if ref is None:
                    add(Check(FAIL, f"credentials '{name}' აღწერილი არ არის devices.yaml-ში"))
                    continue
                empty = [ref.get(k) for k in ("username_env", "password_env") if ref.get(k) and not os.getenv(ref[k])]
                if empty:
                    add(Check(FAIL, f"credentials '{name}': ცარიელია {', '.join(empty)}", "ჩაწერე username/პაროლი .env-ში"))
                else:
                    add(Check(OK, f"credentials '{name}' მითითებულია"))
            if inv.devices:
                results = check_many(list(inv.devices.values()), timeout=2.0, retries=0)
                up = [r for r in results if r.up]
                down = [r for r in results if not r.up]
                if not down:
                    add(Check(OK, f"ყველა მოწყობილობა ხელმისაწვდომია SSH-ზე ({len(up)})"))
                else:
                    add(Check(WARN if up else FAIL, f"SSH-ზე მიუწვდომელი: {', '.join(r.device + ' (' + r.host + ')' for r in down[:6])}",
                              "შეამოწმე IP, პორტი და რომ ეს კომპიუტერი მართვის ქსელში წვდება (ping)"))

    # -- server port & data dir --------------------------------------------------------------
    try:
        with socket.socket() as s:
            s.bind((settings.web_host, settings.web_port))
        add(Check(OK, f"პორტი {settings.web_port} თავისუფალია"))
    except OSError:
        add(Check(WARN, f"პორტი {settings.web_port} დაკავებულია", "NetAgent უკვე ხომ არ არის გაშვებული? ან შეცვალე NETAGENT_WEB_PORT"))
    if settings.syslog_port > 0:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind((settings.syslog_host, settings.syslog_port))
            add(Check(OK, f"syslog პორტი udp/{settings.syslog_port} თავისუფალია"))
        except OSError:
            add(Check(WARN, f"syslog პორტი udp/{settings.syslog_port} ვერ გაიხსნა",
                      "დაკავებულია ან სჭირდება ადმინისტრატორი (Linux). შეცვალე NETAGENT_SYSLOG_PORT, მაგ. 5514"))
    try:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        probe = settings.data_dir / ".write-test"
        probe.write_text("ok")
        probe.unlink()
        add(Check(OK, "data საქაღალდეში ჩაწერა შესაძლებელია"))
    except OSError as exc:
        add(Check(FAIL, f"data საქაღალდეში ჩაწერა ვერ ხერხდება: {exc}"))

    oui = settings.data_dir / "oui.txt"
    if oui.exists():
        add(Check(OK, "MAC მწარმოებლების ბაზა ჩამოტვირთულია"))
    else:
        add(Check(WARN, "MAC მწარმოებლების ბაზა ჯერ არ არის", "ჩამოიტვირთება serve-ის პირველ გაშვებაზე, ან ჩატში: /mac update"))

    # -- Tailscale (phone access) ------------------------------------------------------------
    ts = _tailscale_path()
    if not ts:
        add(Check(WARN, "Tailscale არ არის დაყენებული", "ტელეფონიდან წვდომისთვის: tailscale.com/download"))
    else:
        try:
            out = subprocess.run([ts, "serve", "status"], capture_output=True, text=True, timeout=10, errors="replace")
            text = (out.stdout + out.stderr).strip()
            if str(settings.web_port) in text and "https://" in text:
                url = next((w for w in text.split() if w.startswith("https://")), "")
                add(Check(OK, f"Tailscale serve: {url}"))
            else:
                add(Check(WARN, "Tailscale დაყენებულია, მაგრამ serve ჩართული არ არის", f"გაუშვი: tailscale serve --bg {settings.web_port}"))
        except Exception as exc:  # noqa: BLE001
            add(Check(WARN, f"Tailscale-ის შემოწმება ვერ მოხერხდა ({type(exc).__name__})"))
    return checks


def print_report(checks: list[Check], console) -> int:
    console.print("\n[bold]NetAgent — შემოწმება[/bold]\n")
    for c in checks:
        console.print(f"{ICON[c.status]} {c.title}")
        if c.hint and c.status != OK:
            console.print(f"   [dim]→ {c.hint}[/dim]")
    fails = sum(c.status == FAIL for c in checks)
    warns = sum(c.status == WARN for c in checks)
    console.print()
    if fails:
        console.print(f"[red]❌ {fails} პრობლემა უნდა გასწორდეს[/red]" + (f", ⚠️  {warns} რჩევა" if warns else ""))
    elif warns:
        console.print(f"[yellow]⚠️  მუშაობს, {warns} რჩევით[/yellow] — გაშვება: python -m netagent serve")
    else:
        console.print("[green]✅ ყველაფერი მზადაა[/green] — გაშვება: python -m netagent serve")
    return 1 if fails else 0
