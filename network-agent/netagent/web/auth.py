"""Login for the app: password (scrypt hash) + optional TOTP 2FA, signed session cookies.

Setup:  python -m netagent web-setup        (asks for a password, optionally enables 2FA)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import threading
import time
from pathlib import Path

SESSION_DAYS = 30
LOGIN_WINDOW = 15 * 60
LOGIN_MAX_FAILURES = 5
ACTIVE = None                   # the running server's WebAuth (set by create_app), for /sessions and /kick
OWNER = "admin"                 # the original single account (password from web-setup / .env)
ROLES = ("admin", "viewer")     # viewer: sees everything, changes nothing
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,31}")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- TOTP (RFC 6238)


def totp_code(secret_b32: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((at if at is not None else time.time()) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret_b32: str, code: str, at: float | None = None, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    now = at if at is not None else time.time()
    return any(hmac.compare_digest(totp_code(secret_b32, now + i * 30), code) for i in range(-window, window + 1))


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_uri(secret_b32: str, account: str = "netagent") -> str:
    return f"otpauth://totp/NetAgent:{account}?secret={secret_b32}&issuer=NetAgent"


# --------------------------------------------------------------------------- password hashing


def hash_password(password: str) -> dict:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024)
    return {"alg": "scrypt", "n": 2 ** 15, "r": 8, "p": 1, "salt": _b64(salt), "hash": _b64(digest)}


def check_password(password: str, record: dict) -> bool:
    try:
        digest = hashlib.scrypt(password.encode(), salt=_unb64(record["salt"]), n=record["n"], r=record["r"],
                                p=record["p"], maxmem=64 * 1024 * 1024)
    except (KeyError, ValueError):
        return False
    return hmac.compare_digest(digest, _unb64(record["hash"]))


def device_label(ua: str) -> str:
    """'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 ...) ... Safari' -> 'iPhone · Safari'."""
    ua = ua or ""
    system = next((name for key, name in (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"),
                                          ("Windows", "Windows"), ("Macintosh", "Mac"), ("Linux", "Linux"))
                   if key in ua), "")
    browser = next((name for key, name in (("Edg/", "Edge"), ("OPR/", "Opera"), ("SamsungBrowser", "Samsung Internet"),
                                           ("CriOS", "Chrome"), ("Chrome/", "Chrome"), ("FxiOS", "Firefox"),
                                           ("Firefox/", "Firefox"), ("Safari/", "Safari")) if key in ua), "")
    return " · ".join(x for x in (system, browser) if x) or "უცნობი მოწყობილობა"


class _Dummy(dict):
    """Hash record for unknown user names (created on first use), so a wrong name costs the same time."""

    def __missing__(self, key):
        self.update(hash_password(secrets.token_hex(8)))
        return self[key]


_DUMMY_HASH = _Dummy()


# --------------------------------------------------------------------------- auth store


class WebAuth:
    """State lives in data/web_auth.json (password hash, TOTP secret, session signing key)."""

    def __init__(self, path: Path, env_password: str = "") -> None:
        self.path = path
        self.env_password = env_password
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = {}
        self._seen: dict[str, float] = {}  # session id -> last request (memory only: no disk write per request)
        self._mtime = 0.0
        self._data = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            self._mtime = self.path.stat().st_mtime
            return json.loads(self.path.read_text(encoding="utf-8"))
        return {}

    def _refresh(self) -> None:
        """Pick up accounts added/removed by `python -m netagent user-add` while the server runs."""
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if mtime != self._mtime:
            with self._lock:
                try:
                    self._data = self._load()
                except (OSError, ValueError):
                    pass  # half-written file: try again on the next request

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=1), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        self._mtime = self.path.stat().st_mtime

    @property
    def configured(self) -> bool:
        return bool(self._data.get("password") or self.env_password or self._data.get("users"))

    @property
    def totp_enabled(self) -> bool:
        """Show the 2FA field on the login page: any account has 2FA."""
        return bool(self._data.get("totp_secret")) or any(u.get("totp_secret") for u in self._users().values())

    # -- extra accounts (the original password is the "admin" account) -----------
    def _users(self) -> dict[str, dict]:
        return self._data.get("users") or {}

    def list_users(self) -> list[dict]:
        out = [{"name": OWNER, "role": "admin", "totp": bool(self._data.get("totp_secret"))}] if (
            self._data.get("password") or self.env_password) else []
        return out + [{"name": n, "role": u.get("role", "viewer"), "totp": bool(u.get("totp_secret"))}
                      for n, u in sorted(self._users().items())]

    def add_user(self, name: str, password: str, role: str = "viewer") -> None:
        name = name.strip().lower()
        if not USERNAME_RE.fullmatch(name) or name == OWNER:
            raise ValueError("სახელი: 2-32 სიმბოლო (a-z, 0-9, . _ -), არა 'admin'")
        if role not in ROLES:
            raise ValueError("როლი: admin ან viewer")
        if len(password) < 10:
            raise ValueError("პაროლი მინიმუმ 10 სიმბოლო უნდა იყოს")
        with self._lock:
            users = self._data.setdefault("users", {})
            old = users.get(name, {})
            users[name] = {"password": hash_password(password), "role": role, "totp_secret": old.get("totp_secret"),
                           "gen": int(old.get("gen", 0)) + 1}  # new password logs this user out everywhere
            self._save()

    def enable_user_totp(self, name: str) -> str:
        with self._lock:
            user = self._users().get(name)
            if user is None:
                raise ValueError(f"მომხმარებელი '{name}' არ არსებობს")
            user["totp_secret"] = new_totp_secret()
            user["gen"] = int(user.get("gen", 0)) + 1
            self._save()
            return user["totp_secret"]

    def delete_user(self, name: str) -> bool:
        with self._lock:
            removed = self._users().pop(name, None) is not None
            if removed:
                for sid in [k for k, s in self._sessions().items() if s.get("u") == name]:
                    self._sessions().pop(sid)
                self._save()
            return removed

    def set_password(self, password: str) -> None:
        if len(password) < 10:
            raise ValueError("პაროლი მინიმუმ 10 სიმბოლო უნდა იყოს")
        with self._lock:
            self._data["password"] = hash_password(password)
            self._rotate_sessions()
            self._save()

    def enable_totp(self) -> str:
        with self._lock:
            secret = new_totp_secret()
            self._data["totp_secret"] = secret
            self._save()
            return secret

    def disable_totp(self) -> None:
        with self._lock:
            self._data.pop("totp_secret", None)
            self._save()

    def _rotate_sessions(self) -> None:
        self._data["session_key"] = _b64(secrets.token_bytes(32))
        self._data["generation"] = int(self._data.get("generation", 0)) + 1

    def _session_key(self) -> bytes:
        if "session_key" not in self._data:
            with self._lock:
                self._rotate_sessions()
                self._save()
        return _unb64(self._data["session_key"])

    def logout_everywhere(self) -> None:
        with self._lock:
            self._rotate_sessions()
            self._data["sessions"] = {}
            self._save()

    # -- server-side session list: who is logged in where; kick one person ----------
    def _sessions(self) -> dict[str, dict]:
        return self._data.setdefault("sessions", {})

    def list_sessions(self) -> list[dict]:
        self._refresh()
        now = time.time()
        out = []
        for sid, s in self._sessions().items():
            if s.get("exp", 0) > now:
                out.append({"sid": sid, **s, "last_seen": max(self._seen.get(sid, 0), s.get("created", 0))})
        return sorted(out, key=lambda s: s["last_seen"], reverse=True)

    def logout(self, token: str | None) -> None:
        """Ends this one session on the server too (not only the cookie)."""
        sid = self._token_sid(token)
        if sid:
            self.revoke(sid)

    def revoke(self, who: str) -> int:
        """Kick by user name (all of their sessions) or by session id (prefix). Returns how many ended."""
        self._refresh()
        who = who.strip().lower()
        with self._lock:
            sessions = self._sessions()
            gone = [sid for sid, s in sessions.items() if s.get("u", OWNER) == who or (len(who) >= 4 and sid.startswith(who))]
            for sid in gone:
                sessions.pop(sid, None)
                self._seen.pop(sid, None)
            if gone:
                self._save()
        return len(gone)

    def note_login(self, user: str, ip: str) -> str:
        """Remember where an account logs in from. Returns "first", "new" (new device/IP) or ""."""
        with self._lock:
            known = self._data.setdefault("known_logins", {}).setdefault(user, [])
            status = "first" if not known else ("new" if ip not in known else "")
            if ip not in known:
                known.append(ip)
                del known[:-20]
                self._save()
        return status

    def failures(self, client: str) -> int:
        now = time.time()
        return sum(1 for t in self._failures.get(client, []) if now - t < LOGIN_WINDOW)

    @staticmethod
    def _token_sid(token: str | None) -> str:
        try:
            return str(json.loads(_unb64(token.rsplit(".", 1)[0])).get("n", ""))
        except (AttributeError, ValueError, TypeError):
            return ""

    # -- login ---------------------------------------------------------------
    def _too_many_failures(self, client: str) -> bool:
        now = time.time()
        recent = [t for t in self._failures.get(client, []) if now - t < LOGIN_WINDOW]
        self._failures[client] = recent
        return len(recent) >= LOGIN_MAX_FAILURES

    def login(self, password: str, totp: str, client: str, username: str = "",
              meta: dict | None = None) -> tuple[str | None, str]:
        """Returns (session_token, error_message). Empty username or "admin" = the original account."""
        self._refresh()
        if not self.configured:
            return None, "პაროლი ჯერ არ არის დაყენებული: სერვერზე გაუშვი python -m netagent web-setup"
        if self._too_many_failures(client):
            return None, "ბევრი წარუმატებელი ცდა. სცადე 15 წუთში."
        name = (username or "").strip().lower() or OWNER
        if name == OWNER:
            record = self._data.get("password")
            ok = check_password(password, record) if record else bool(self.env_password) and hmac.compare_digest(
                password.encode(), self.env_password.encode())
            secret = self._data.get("totp_secret")
        else:
            user = self._users().get(name)
            # unknown user: still hash, so the answer time doesn't reveal which names exist
            ok = check_password(password, user["password"] if user else _DUMMY_HASH) and user is not None
            secret = user.get("totp_secret") if user else None
        if ok and secret:
            ok = totp_verify(secret, totp)
        if not ok:
            self._failures.setdefault(client, []).append(time.time())
            return None, "არასწორი მომხმარებელი, პაროლი ან კოდი"
        self._failures.pop(client, None)
        return self.issue_session(user=name, meta={"ip": client, **(meta or {})}), ""

    def issue_session(self, days: int = SESSION_DAYS, user: str = OWNER, meta: dict | None = None) -> str:
        key = self._session_key()  # first: creating the key bumps the generation the token must carry
        now = int(time.time())
        sid = secrets.token_hex(8)
        body = {"exp": now + days * 86400, "gen": self._data.get("generation", 0), "n": sid}
        if user != OWNER:
            body.update(u=user, ug=int(self._users().get(user, {}).get("gen", 0)))
        with self._lock:
            sessions = self._sessions()
            for old in [k for k, s in sessions.items() if s.get("exp", 0) <= now]:
                sessions.pop(old)  # expired
            sessions[sid] = {"u": user, "created": now, "exp": body["exp"],
                             "ip": str((meta or {}).get("ip", ""))[:64], "ua": str((meta or {}).get("ua", ""))[:200]}
            self._save()
        payload = _b64(json.dumps(body).encode())
        sig = _b64(hmac.new(key, payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{sig}"

    def session_user(self, token: str | None) -> dict | None:
        """{"name", "role", "sid"} for a valid session, else None. Logout, /kick, a deleted user or a changed
        password end a session."""
        if not token or "." not in token:
            return None
        self._refresh()
        payload, sig = token.rsplit(".", 1)
        expected = _b64(hmac.new(self._session_key(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            data = json.loads(_unb64(payload))
        except (ValueError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict) or data.get("exp", 0) <= time.time() or data.get("gen") != self._data.get("generation", 0):
            return None
        sid = str(data.get("n", ""))
        if sid not in self._sessions():
            return None  # logged out / kicked (or issued before the session list existed)
        self._seen[sid] = time.time()
        name = data.get("u") or OWNER
        if name == OWNER:
            return {"name": OWNER, "role": "admin", "sid": sid}
        user = self._users().get(name)
        if user is None or int(user.get("gen", 0)) != data.get("ug"):
            return None
        return {"name": name, "role": user.get("role", "viewer"), "sid": sid}

    def verify_session(self, token: str | None) -> bool:
        return self.session_user(token) is not None
