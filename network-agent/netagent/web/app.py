"""HTTP API + static files for the NetAgent app (Android / desktop, installable PWA)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from .. import commands
from ..config import settings
from ..content import UploadError, build_content
from ..formatting import describe_tool
from ..health import check_many
from .auth import WebAuth
from .push import PushSender

log = logging.getLogger("netagent.web")

STATIC = Path(__file__).parent / "static"
COOKIE = "na_session"
SESSION_ID = "app"  # single-user app: one conversation
MAX_FILES = 5
_SAFE_FILE = re.compile(r"^[\w.-]+$")
PUBLIC_API = {"/api/login", "/api/me"}

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


def create_app(services, monitoring, auth: WebAuth, push: PushSender | None) -> FastAPI:
    app = FastAPI(title="NetAgent", docs_url=None, redoc_url=None, openapi_url=None)

    def client_id(request: Request) -> str:
        return request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
            request.client.host if request.client else "?")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            # CSRF: browsers cannot add custom headers cross-site without a CORS preflight we never allow.
            if request.method not in ("GET", "HEAD") and request.headers.get("x-netagent") != "1":
                return JSONResponse({"error": "missing X-NetAgent header"}, status_code=403)
            if path not in PUBLIC_API and not auth.verify_session(request.cookies.get(COOKIE)):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

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
        return {"authenticated": auth.verify_session(request.cookies.get(COOKIE)),
                "configured": auth.configured, "totp": auth.totp_enabled}

    @app.post("/api/login")
    async def login(request: Request):
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        token, error = await asyncio.to_thread(
            auth.login, str(body.get("password", "")), str(body.get("totp", "")), client_id(request))
        if not token:
            status = 429 if "15 წუთში" in error else 401
            return JSONResponse({"error": error}, status_code=status)
        resp = JSONResponse({"ok": True})
        secure = request.url.scheme == "https"
        resp.set_cookie(COOKIE, token, max_age=30 * 86400, httponly=True, samesite="strict", secure=secure, path="/")
        return resp

    @app.post("/api/logout")
    async def logout(request: Request):
        body = await _json(request)
        if body.get("everywhere"):
            auth.logout_everywhere()
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    # -- dashboard ---------------------------------------------------------------
    @app.get("/api/overview")
    async def overview():
        inv = services.inventory()
        results = await asyncio.to_thread(check_many, list(inv.devices.values()), 2.0, 0)
        devices = []
        for r in sorted(results, key=lambda r: (r.up, r.device)):
            d = inv.devices[r.device]
            devices.append({"name": r.device, "host": r.host, "type": d.device_type, "site": d.site, "role": d.role,
                            "up": r.up, "latency_ms": r.latency_ms, "reason": r.reason,
                            "muted": services.mutes.is_muted(r.device), "watched": bool(d.watch)})
        today = services.usage.day()
        return {
            "devices": devices,
            "up": sum(r.up for r in results),
            "total": len(results),
            "alerts": services.alerts.recent(30),
            "mutes": services.mutes.active(),
            "usage": {"today": round(today.get("cost", 0.0), 3), "requests": today.get("requests", 0),
                      "month": services.usage.month_cost(), "budget": services.usage.daily_budget_usd},
            "model": settings.model,
        }

    # -- commands & chat -----------------------------------------------------------
    @app.post("/api/command")
    async def command(request: Request):
        line = str((await _json(request)).get("line", "")).strip()
        result = await asyncio.to_thread(commands.run, services, line, "app")
        if result is None:
            return JSONResponse({"error": "უცნობი ბრძანება. /help"}, status_code=400)
        return result.as_dict()

    @app.post("/api/chat")
    async def chat(text: str = Form(""), files: list[UploadFile] = File(default=[])):
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
                reply = await asyncio.to_thread(services.agent.chat, SESSION_ID, content, user="app",
                                                channel="web", on_tool=on_tool)
                await queue.put(("answer", {"text": reply.text, "files": [p.name for p in reply.files]}))
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
    async def reset():
        services.agent.reset(SESSION_ID)
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
