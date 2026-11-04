"""First-time setup of a MikroTik CHR lab router, and adding it to NetAgent.

    python -m netagent.demo.chr_init [--host 127.0.0.1] [--port 2230]

Run by lab/mikrotik-chr.ps1 after the VM boots. It
  1. logs in as admin with the empty factory password and sets a new random one
     (RouterOS asks for this on first login),
  2. sets identity CHR-Lab, a lab bridge with an IP, and remote syslog to this PC
     (10.0.2.2 is the host as seen from a VirtualBox NAT guest),
  3. writes LAB_USER / LAB_PASS into .env (the password is never printed) and adds the
     "lab" credentials + the CHR-Lab device to inventory/devices.yaml.

Read-only stays the rule for NetAgent itself; this script is the one place that
configures a device, and only the lab VM it just created.
"""

from __future__ import annotations

import argparse
import re
import secrets
import string
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SETUP = [
    "/system identity set name=CHR-Lab",
    "/interface bridge add name=bridge-lab comment=NetAgent-lab",
    "/ip address add address=10.99.0.1/24 interface=bridge-lab comment=NetAgent-lab",
    "/system logging action set [find name=remote] remote=10.0.2.2 remote-port=514",
    "/system logging add topics=info action=remote",
    "/system logging add topics=warning action=remote",
    "/system logging add topics=error action=remote",
    "/system logging add topics=critical action=remote",
]


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Lab-" + "".join(secrets.choice(alphabet) for _ in range(16))


def _read_until(chan, patterns: list[str], timeout: float = 30.0) -> tuple[int, str]:
    buf = ""
    end = time.time() + timeout
    while time.time() < end:
        if chan.recv_ready():
            buf += chan.recv(65535).decode(errors="replace")
            for i, p in enumerate(patterns):
                if re.search(p, buf, re.I):
                    return i, buf
        else:
            time.sleep(0.2)
    raise TimeoutError(f"RouterOS did not answer as expected (last output: {buf[-200:]!r})")


def first_login(host: str, port: int, new_password: str, wait: int = 180) -> None:
    import paramiko

    deadline = time.time() + wait
    client = None
    while True:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # "+cte": no colours, no terminal auto-detection, dumb terminal -> clean output
            client.connect(host, port, username="admin+cte", password="", look_for_keys=False,
                           allow_agent=False, timeout=10, banner_timeout=30, auth_timeout=30)
            break
        except paramiko.AuthenticationException:
            raise SystemExit("❌ admin-ის პაროლი უკვე შეცვლილია — ეს CHR უკვე მომზადებულია. "
                             "ახლიდან დასაწყებად წაშალე VM (lab-mikrotik.bat -Reset).") from None
        except Exception as exc:  # noqa: BLE001 - still booting
            if time.time() > deadline:
                raise SystemExit(f"❌ CHR-თან SSH ვერ დამყარდა {wait} წამში ({type(exc).__name__}: {exc})") from None
            print("   … ველოდები RouterOS-ის ჩატვირთვას", flush=True)
            time.sleep(5)

    chan = client.invoke_shell(width=200, height=50)
    prompt = r"\] >\s*$"
    while True:
        i, _ = _read_until(chan, [r"license\?\s*\[y/n\]", r"repeat new password>", r"new password>", prompt], 60)
        if i == 0:
            chan.send("n\r")
        elif i == 1:
            chan.send(new_password + "\r")
        elif i == 2:
            chan.send(new_password + "\r")
        else:
            break
    for cmd in SETUP:
        chan.send(cmd + "\r")
        _, out = _read_until(chan, [prompt], 30)
        if "failure" in out.lower() or "bad command" in out.lower() or "syntax error" in out.lower():
            print(f"   ⚠️ {cmd}: {out.strip().splitlines()[-2] if len(out.strip().splitlines()) > 1 else out.strip()}")
    client.close()


def update_env(env_path: Path, user: str, password: str) -> None:
    text = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    marker = "# MikroTik CHR lab (written by lab-mikrotik.bat)"
    lines = [ln for ln in text.splitlines() if not ln.startswith(("LAB_USER=", "LAB_PASS=")) and ln != marker]
    while lines and not lines[-1].strip():
        lines.pop()
    lines += ["", marker, f"LAB_USER={user}", f"LAB_PASS={password}"]
    env_path.write_text("\n".join(lines).strip("\n") + "\n", encoding="utf-8")


def update_inventory(inv_path: Path, host: str, port: int) -> str:
    import yaml

    from ..discovery import Candidate, add_to_inventory

    if not inv_path.exists():
        inv_path.parent.mkdir(parents=True, exist_ok=True)
        inv_path.write_text("credentials:\n  default:\n    username_env: NET_USER\n    password_env: NET_PASS\n"
                            "devices:\n", encoding="utf-8")
    text = inv_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if "lab" not in (data.get("credentials") or {}):
        block = "  lab:\n    username_env: LAB_USER\n    password_env: LAB_PASS\n"
        if re.search(r"^credentials:\s*$", text, re.M):
            text = re.sub(r"^credentials:\s*\n", "credentials:\n" + block, text, count=1, flags=re.M)
        else:
            text = "credentials:\n" + block + text
        inv_path.write_text(text, encoding="utf-8")
    added = add_to_inventory(inv_path, [Candidate(host=host, port=port, device_type="mikrotik_routeros",
                                                  hostname="CHR-Lab")], credentials="lab", site="Lab")
    return added[0] if added else "CHR-Lab (უკვე იყო)"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="MikroTik CHR lab: first login + add to NetAgent")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2230)
    ap.add_argument("--wait", type=int, default=180, help="seconds to wait for the VM to boot")
    args = ap.parse_args(argv)

    password = _password()
    print(f"🔧 CHR-ის პირველი გაშვება ({args.host}:{args.port}) …", flush=True)
    first_login(args.host, args.port, password, args.wait)
    update_env(ROOT / ".env", "admin", password)
    print("✅ ახალი admin პაროლი დაყენდა და ჩაიწერა .env-ში (LAB_PASS) — ეკრანზე არ ვაჩვენებ")
    name = update_inventory(ROOT / "inventory" / "devices.yaml", args.host, args.port)
    print(f"✅ inventory-ში დაემატა: {name} (site: Lab, credentials: lab)")
    print("✅ CHR syslog-ს უგზავნის ამ კომპიუტერს (10.0.2.2:514)")
    print("\nშემდეგი ნაბიჯი: start.bat (ან თუ უკვე გაშვებულია — გადატვირთე), მერე აპში: /status, /health CHR-Lab")
    return 0


if __name__ == "__main__":
    sys.exit(main())
