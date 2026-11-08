"""HTTP API + static files for the NetAgent app (Android / desktop, installable PWA)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from .. import commands
from ..audit import log_event
from ..config import settings
from ..permissions import web_user
from ..content import UploadError, build_content
from ..formatting import describe_tool
from ..health import check_many
from . import auth as auth_module
from .auth import LOGIN_MAX_FAILURES, WebAuth, device_label
from .push import PushSender

log = logging.getLogger("netagent.web")

STATIC = Path(__file__).parent / "static"
COOKIE = "na_session"
SESSION_ID = "app"  # single-user app: one conversation
MAX_FILES = 5
SPARK_POINTS = 24  # 2 hours at the default 5-minute monitoring interval
_SAFE_FILE = re.compile(r"^[\w.-]+$")
PUBLIC_API = {"/api/login", "/api/me"}
TOKEN_API = {"/api/command", "/api/overview"}  # reachable with NETAGENT_API_TOKEN (another NetAgent, /remote)

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(self), microphone=(), geolocation=()",
}


def isp_overview(services) -> dict | None:
    from datetime import datetime as _dt
    from datetime import timedelta as _td

    from ..features.isp import monitor_for

    m = monitor_for(services)
    rows = m.samples(_dt.now() - _td(hours=24))
    if not rows:
        return None
    step = max(1, len(rows) // 120)
    points = [[r[0].isoformat(timespec="minutes"), r[2] if r[1] else None] for r in rows[::step]]
    s = m.summary(1)
    tests = s.get("speedtests") or []
    return {"points": points, "uptime": s["uptime_percent"], "latency": rows[-1][2], "outages": len(s["outages"]),
            "down_now": bool(s["down_now_since"]), "last_speed": tests[-1] if tests else None}


def security_overview(services) -> dict:
    from ..features.secwatch import load

    w = load(services.state)
    day_ago = (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds")
    found = [e for e in (w.get("events") or []) if e["ts"] >= day_ago]
    return {"ok": not found, "findings_24h": len(found), "checked_at": w.get("checked_at")}


def create_app(services, monitoring, auth: WebAuth, push: PushSender | None) -> FastAPI:
    app = FastAPI(title="NetAgent", docs_url=None, redoc_url=None, openapi_url=None)
    auth_module.ACTIVE = auth  # /sessions and /kick use the running server's session list

    def client_id(request: Request) -> str:
        # Not X-Forwarded-For: its first entry is whatever the client wrote, so a new fake IP per try would
        # dodge the login lockout. uvicorn already sets client.host from the trusted local proxy (Tailscale serve).
        return request.client.host if request.client else "?"

    async def security_alert(text: str) -> None:
        """Push/Telegram notification about logins (never breaks the login itself)."""
        if monitoring is None:
            return
        try:
            from ..monitoring import Alert
            from ..result import Button

            await monitoring.emit(Alert("security", text, [], mutable=False,
                                        buttons=[Button("👥 სესიები", "/sessions"), Button("📜 ჟურნალი", "/activity")]))
        except Exception:  # noqa: BLE001
            log.exception("security alert failed")

    def api_token_user(request: Request) -> str | None:
        """Another NetAgent (see /remote) calls with "Authorization: Bearer <NETAGENT_API_TOKEN>"."""
        import hmac as _hmac

        token = os.getenv("NETAGENT_API_TOKEN", "").strip()
        given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if len(token) < 24 or not given or not _hmac.compare_digest(given, token):
            return None
        # view-only unless the owner of THIS NetAgent sets NETAGENT_API_ROLE=admin in its .env
        admin = os.getenv("NETAGENT_API_ROLE", "viewer").strip().lower() == "admin"
        return f"{'app' if admin else 'view'}:remote-{client_id(request)}"

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            # CSRF: browsers cannot add custom headers cross-site without a CORS preflight we never allow.
            if request.method not in ("GET", "HEAD") and request.headers.get("x-netagent") != "1":
                return JSONResponse({"error": "missing X-NetAgent header"}, status_code=403)
            if path not in PUBLIC_API:
                account = auth.session_user(request.cookies.get(COOKIE))
                if account is not None:
                    request.state.who = web_user(account["name"], account["role"])
                elif path in TOKEN_API and (remote := api_token_user(request)):
                    request.state.who = remote
                else:
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # -- Prometheus metrics for Grafana (bearer token, off unless NETAGENT_METRICS_TOKEN is set) --
    @app.get("/metrics")
    async def metrics(request: Request):
        import hmac as _hmac

        from ..features.metrics import render

        token = os.getenv("NETAGENT_METRICS_TOKEN", "")
        given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not token or not _hmac.compare_digest(given, token):
            return Response(status_code=404 if not token else 401)
        return Response(await asyncio.to_thread(render, services), media_type="text/plain; version=0.0.4")

    # -- static / PWA shell ----------------------------------------------------
    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/sw.js")
    async def service_worker():
        return FileResponse(STATIC / "sw.js", media_type="text/javascript",
                            headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"})

    @app.get("/manifest.webmanifest")
    async def manifest():
        return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")

    @app.get("/static/{name}")
    async def static(name: str):
        path = STATIC / name
        if not _SAFE_FILE.match(name) or not path.is_file():
            return Response(status_code=404)
        return FileResponse(path, headers={"Cache-Control": "no-cache"})

    # -- auth --------------------------------------------------------------------
    @app.get("/api/me")
    async def me(request: Request):
        account = auth.session_user(request.cookies.get(COOKIE))
        return {"authenticated": account is not None, "configured": auth.configured, "totp": auth.totp_enabled,
                "user": account["name"] if account else None, "role": account["role"] if account else None,
                "multiuser": len(auth.list_users()) > 1}

    @app.post("/api/login")
    async def login(request: Request):
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        username = str(body.get("username", "")).strip().lower()[:32]
        ip, ua = client_id(request), request.headers.get("user-agent", "")
        token, error = await asyncio.to_thread(
            auth.login, str(body.get("password", "")), str(body.get("totp", "")), ip, username, {"ua": ua})
        name = username or "admin"
        log_event(settings.audit_log_path, user=f"login:{name}", tool="login",
                  args={"from": ip, "device": device_label(ua)}, ok=bool(token))
        if not token:
            fails = auth.failures(ip)
            if fails in (3, LOGIN_MAX_FAILURES):  # once at 3, once at the lockout
                locked = fails >= LOGIN_MAX_FAILURES
                await security_alert(f"⚠️ **{fails} წარუმატებელი შესვლა** ({name}) · {device_label(ua)} · {ip}"
                                     + ("\n🔒 ეს მისამართი 15 წუთით დაიბლოკა." if locked else ""))
            status = 429 if "15 წუთში" in error else 401
            return JSONResponse({"error": error}, status_code=status)
        seen = await asyncio.to_thread(auth.note_login, name, ip)
        if seen:
            what = "პირველად შევიდა" if seen == "first" else "შევიდა **ახალი მოწყობილობიდან**"
            await security_alert(f"🔐 **{name}** {what}: {device_label(ua)} · {ip}\nთუ ეს შენ/თქვენ არ ხართ: /kick {name}")
        resp = JSONResponse({"ok": True})
        secure = request.url.scheme == "https"
        resp.set_cookie(COOKIE, token, max_age=30 * 86400, httponly=True, samesite="strict", secure=secure, path="/")
        return resp

    @app.post("/api/logout")
    async def logout(request: Request):
        body = await _json(request)
        account = auth.session_user(request.cookies.get(COOKIE))
        if account is not None:
            log_event(settings.audit_log_path, user=web_user(account["name"], account["role"]), tool="logout",
                      args={"from": client_id(request), "everywhere": bool(body.get("everywhere"))}, ok=True)
        if body.get("everywhere"):
            auth.logout_everywhere()
        else:
            auth.logout(request.cookies.get(COOKIE))  # the old cookie stops working on the server too
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    # -- dashboard ---------------------------------------------------------------
    @app.get("/api/overview")
    async def overview():
        inv = services.inventory()
        results = await asyncio.to_thread(check_many, list(inv.devices.values()), 2.0, 0)
        history = await asyncio.to_thread(services.history.read_all, 2)
        devices = []
        for r in sorted(results, key=lambda r: (r.up, r.device)):
            d = inv.devices[r.device]
            points = history.get(r.device, [])[-SPARK_POINTS:]
            devices.append({"name": r.device, "host": r.host, "type": d.device_type, "site": d.site, "role": d.role,
                            "up": r.up, "latency_ms": r.latency_ms, "reason": r.reason,
                            "muted": services.mutes.is_muted(r.device), "watched": bool(d.watch),
                            "spark": [p[2] if p[1] else None for p in points]})
        today = services.usage.day()
        alerts = services.alerts.recent(50)
        day_ago = (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds")
        return {
            "devices": devices,
            "up": sum(r.up for r in results),
            "total": len(results),
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "alerts_24h": sum(1 for a in alerts if a["ts"] >= day_ago and a["kind"] in {"down", "watch", "config", "syslog", "newdevice", "isp", "site", "escalation", "security"}),
            "alerts": alerts[:30],
            "mutes": services.mutes.active(),
            "usage": {"today": round(today.get("cost", 0.0), 3), "requests": today.get("requests", 0),
                      "month": services.usage.month_cost(), "budget": services.usage.daily_budget_usd},
            "model": settings.model,
            "demo": os.getenv("NETAGENT_DEMO") == "1",
            "isp": await asyncio.to_thread(isp_overview, services),
            "security": security_overview(services),
        }

    # -- commands & chat -----------------------------------------------------------
    @app.post("/api/command")
    async def command(request: Request):
        line = str((await _json(request)).get("line", "")).strip()[:2000]
        who = request.state.who
        result = await asyncio.to_thread(commands.run, services, line, who)
        if result is None:
            return JSONResponse({"error": "უცნობი ბრძანება. /help"}, status_code=400)
        logged = re.sub(r"^(/remote\s+add\s+\S+\s+\S+\s+)\S+", r"\1<token>", line, flags=re.I)  # no tokens in the log
        log_event(settings.audit_log_path, user=who, tool="command", args={"line": logged[:300]},
                  ok=not result.text.startswith(("⛔", "⚠️")))
        return result.as_dict()

    @app.get("/api/interfaces")
    async def interfaces(device: str = ""):
        """Interface names of a device, for Tab completion in the terminal (cached for 10 minutes)."""
        from ..features.ifnames import interface_names

        try:
            names = await asyncio.to_thread(interface_names, services, device)
        except Exception as exc:  # noqa: BLE001 - completion is optional: never break the terminal
            log.info("interface names for %s: %s", device, exc)
            names = []
        return {"device": device, "interfaces": names}

    @app.post("/api/chat")
    async def chat(request: Request, text: str = Form(""), files: list[UploadFile] = File(default=[])):
        who = request.state.who
        if len(files) > MAX_FILES:
            return JSONResponse({"error": f"მაქსიმუმ {MAX_FILES} ფაილი"}, status_code=400)
        uploads = [(f.filename or "file", (f.content_type or "").lower(), await f.read()) for f in files]
        try:
            content = build_content(text, uploads)
        except UploadError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        if not uploads and not text.strip():
            return JSONResponse({"error": "ცარიელი შეტყობინება"}, status_code=400)

        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()

        def on_tool(name: str, args: dict) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, ("step", {"label": describe_tool(name, args)}))

        async def run() -> None:
            try:
                # each account has its own conversation with the AI
                reply = await asyncio.to_thread(services.agent.chat, f"{SESSION_ID}:{who}", content, user=who,
                                                channel="web", on_tool=on_tool)
                await queue.put(("answer", {"text": reply.text, "files": [p.name for p in reply.files],
                                             "buttons": [{"label": b.label, "command": b.command} for b in reply.buttons]}))
            except Exception as exc:  # noqa: BLE001
                log.exception("chat failed")
                await queue.put(("answer", {"text": f"⚠️ შიდა შეცდომა: {type(exc).__name__}", "files": []}))
            finally:
                await queue.put(None)

        task = asyncio.create_task(run())

        async def events():
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                if item is None:
                    break
                kind, data = item
                yield f"event: {kind}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            await task

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.post("/api/reset")
    async def reset(request: Request):
        services.agent.reset(f"{SESSION_ID}:{request.state.who}")
        return {"ok": True}

    @app.get("/api/files/{name}")
    async def files(name: str, download: int = 0):
        path = (settings.export_dir / name).resolve()
        if not _SAFE_FILE.match(name) or path.parent != settings.export_dir.resolve() or not path.is_file():
            return Response(status_code=404)
        return FileResponse(path, filename=name if download else None)

    # -- push notifications --------------------------------------------------------
    @app.get("/api/push/key")
    async def push_key():
        if push is None:
            return JSONResponse({"error": "push disabled"}, status_code=404)
        return {"key": push.keys.public_b64, "subscriptions": len(push.subscriptions())}

    @app.post("/api/push/subscribe")
    async def push_subscribe(request: Request):
        if push is None:
            return JSONResponse({"error": "push disabled"}, status_code=404)
        try:
            push.subscribe(await _json(request))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return {"ok": True}

    @app.post("/api/push/unsubscribe")
    async def push_unsubscribe(request: Request):
        if push is not None:
            push.unsubscribe(str((await _json(request)).get("endpoint", "")))
        return {"ok": True}

    @app.post("/api/push/test")
    async def push_test():
        if push is None:
            return JSONResponse({"error": "push disabled"}, status_code=404)
        sent = await push.send("NetAgent", "✅ შეტყობინებები მუშაობს", tag="test")
        return {"sent": sent}

    return app


async def _json(request: Request) -> dict:
    try:
        data = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}
