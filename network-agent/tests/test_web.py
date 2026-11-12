from __future__ import annotations

import os
import struct
from types import SimpleNamespace as NS

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from netagent.content import UploadError, build_content
from netagent.server import plain_text
from netagent.web.auth import WebAuth, check_password, hash_password, totp_code, totp_verify
from netagent.web.push import PushSender, VapidKeys, _hmac_sha256, _public_bytes, b64url, encrypt, unb64url

# --------------------------------------------------------------------------- auth primitives


def test_password_hash_roundtrip():
    rec = hash_password("correct horse battery")
    assert check_password("correct horse battery", rec)
    assert not check_password("wrong", rec)


def test_totp_rfc6238_vector():
    # RFC 6238 Appendix B, SHA1, secret "12345678901234567890"
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp_code(secret, at=59, digits=8) == "94287082"
    assert totp_code(secret, at=1111111109, digits=8) == "07081804"
    code = totp_code(secret, at=1_000_000)
    assert totp_verify(secret, code, at=1_000_000 + 25)  # within window
    assert not totp_verify(secret, code, at=1_000_000 + 120)
    assert not totp_verify(secret, "abc")


def test_sessions_and_rate_limit(tmp_path):
    auth = WebAuth(tmp_path / "auth.json")
    assert not auth.configured
    with pytest.raises(ValueError):
        auth.set_password("short")
    auth.set_password("a-long-password")
    token, err = auth.login("a-long-password", "", "1.2.3.4")
    assert token and auth.verify_session(token)
    assert not auth.verify_session(token + "x")
    assert not auth.verify_session("garbage")
    auth.logout_everywhere()
    assert not auth.verify_session(token)  # rotated key invalidates old sessions
    for _ in range(5):
        assert auth.login("nope", "", "9.9.9.9")[0] is None
    token, err = auth.login("a-long-password", "", "9.9.9.9")
    assert token is None and "15 წუთში" in err  # locked out even with the right password
    # owner-only: mode 0600 on Linux/macOS; on Windows chmod does nothing, so the ACL is checked instead
    from netagent.osutil import is_private

    assert is_private(tmp_path / "auth.json")


def test_env_password_first_login(tmp_path):
    # No web-setup yet: password from .env, session key created during the first login.
    auth = WebAuth(tmp_path / "auth.json", env_password="env-password-123")
    assert auth.configured
    token, _ = auth.login("env-password-123", "", "c")
    assert token and auth.verify_session(token)
    assert WebAuth(tmp_path / "auth.json", env_password="env-password-123").verify_session(token)  # survives restart
    assert auth.login("wrong", "", "c")[0] is None


def test_totp_required_when_enabled(tmp_path):
    auth = WebAuth(tmp_path / "auth.json")
    auth.set_password("a-long-password")
    secret = auth.enable_totp()
    assert auth.login("a-long-password", "", "c")[0] is None  # password alone is not enough
    assert auth.login("a-long-password", "12345", "c")[0] is None
    assert auth.login("a-long-password", totp_code(secret), "c")[0]


# --------------------------------------------------------------------------- push


def test_push_encrypt_rfc8291_vector():
    sender = derive_private_key(int.from_bytes(unb64url("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"), "big"),
                                ec.SECP256R1())
    out = encrypt(b"When I grow up, I want to be a watermelon",
                  "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
                  "BTBZMqHH6r4Tts7J_aSIgg", sender_private=sender, salt=unb64url("DGv6ra1nlYgDCS1FRnbzlw"))
    assert b64url(out) == (
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqK"
        "K6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")


def test_push_encrypt_decrypt_unicode():
    ua = ec.generate_private_key(ec.SECP256R1())
    ua_pub, auth = _public_bytes(ua.public_key()), os.urandom(16)
    body = encrypt("🔴 R1 მიუწვდომელია".encode(), b64url(ua_pub), b64url(auth))
    salt, idlen = body[:16], body[20]
    assert struct.unpack(">I", body[16:20])[0] == 4096
    as_pub, ct = body[21:21 + idlen], body[21 + idlen:]
    secret = ua.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_pub))
    prk = _hmac_sha256(salt, _hmac_sha256(_hmac_sha256(auth, secret), b"WebPush: info\x00" + ua_pub + as_pub + b"\x01"))
    cek = _hmac_sha256(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]
    nonce = _hmac_sha256(prk, b"Content-Encoding: nonce\x00\x01")[:12]
    assert AESGCM(cek).decrypt(nonce, ct, None) == "🔴 R1 მიუწვდომელია".encode() + b"\x02"


def test_vapid_jwt_and_subscriptions(tmp_path):
    from netagent.state import StateStore

    keys = VapidKeys(tmp_path / "vapid.pem")
    assert len(unb64url(keys.public_b64)) == 65
    assert VapidKeys(tmp_path / "vapid.pem").public_b64 == keys.public_b64  # persisted
    assert len(keys.jwt("https://fcm.googleapis.com/fcm/send/abc").split(".")) == 3
    sender = PushSender(StateStore(tmp_path / "s.json"), keys)
    with pytest.raises(ValueError):
        sender.subscribe({"endpoint": "http://insecure", "keys": {"p256dh": "a", "auth": "b"}})
    sub = {"endpoint": "https://push.example/1", "keys": {"p256dh": "x", "auth": "y"}, "extra": 1}
    sender.subscribe(sub)
    sender.subscribe(sub)
    assert sender.subscriptions() == [{"endpoint": "https://push.example/1", "keys": {"p256dh": "x", "auth": "y"}}]
    sender.unsubscribe("https://push.example/1")
    assert sender.subscriptions() == []


def test_plain_text_for_notifications():
    assert plain_text("🔴 **R1** down\n```\n- a\n+ b\n```") == "🔴 R1 down\n- a\n+ b"


# --------------------------------------------------------------------------- content


def test_build_content():
    assert build_content("hi", []) == "hi"
    c = build_content("", [("a.png", "image/png", b"\x89PNG..."), ("r1.cfg", "text/plain", b"interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n")])
    assert c[0]["type"] == "image" and c[1]["type"] == "text" and "uploaded_file" in c[2]["text"]
    with pytest.raises(UploadError):
        build_content("", [("bin", "application/octet-stream", b"\x00" * 100)])
    with pytest.raises(UploadError):
        build_content("", [("big.png", "image/png", b"x" * (6 * 1024 * 1024))])


# --------------------------------------------------------------------------- HTTP API


@pytest.fixture
def client(tmp_path, monkeypatch):
    from netagent.config import settings

    inv = tmp_path / "devices.yaml"
    inv.write_text("devices:\n  R1:\n    host: 127.0.0.1\n    port: 1\n    device_type: cisco_ios\n", encoding="utf-8")
    fake = {
        "inventory_path": inv, "data_dir": tmp_path / "data", "export_dir": tmp_path / "exports",
        "backup_dir": tmp_path / "backups", "audit_log_path": tmp_path / "audit.jsonl",
    }
    saved = {k: getattr(settings, k) for k in fake}
    for k, v in fake.items():
        object.__setattr__(settings, k, v)  # Settings is frozen; restored after the test

    from netagent.monitoring import MonitoringService
    from netagent.services import Services
    from netagent.web.app import create_app

    class FakeMessages:
        def create(self, **kw):
            last = kw["messages"][-1]["content"]
            U = NS(input_tokens=10, output_tokens=5, cache_read_input_tokens=0, cache_creation_input_tokens=0)
            if isinstance(last, list) and last and last[0].get("type") == "tool_result":
                return NS(model="claude-opus-5-5", stop_reason="end_turn", usage=U, content=[NS(type="text", text="**R1** ok")])
            return NS(model="claude-opus-5-5", stop_reason="tool_use", usage=U,
                      content=[NS(type="tool_use", id="t1", name="list_devices", input={})])

    services = Services.create(client=NS(beta=NS(messages=FakeMessages())))
    auth = WebAuth(tmp_path / "data" / "web_auth.json")
    auth.set_password("a-long-password")
    push = PushSender(services.state, VapidKeys(tmp_path / "data" / "vapid.pem"))
    app = create_app(services, MonitoringService(services), auth, push)
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "report.txt").write_text("hello")
    yield TestClient(app)
    for k, v in saved.items():
        object.__setattr__(settings, k, v)


H = {"X-NetAgent": "1"}


def _login(client):
    r = client.post("/api/login", json={"password": "a-long-password"}, headers=H)
    assert r.status_code == 200


def test_api_requires_login_and_csrf_header(client):
    assert client.get("/api/overview").status_code == 401
    assert client.post("/api/login", json={"password": "a-long-password"}).status_code == 403
    assert client.post("/api/login", json={"password": "bad"}, headers=H).status_code == 401
    _login(client)
    assert client.get("/api/overview").status_code == 200
    assert client.post("/api/command", json={"line": "/status"}).status_code == 403  # header still required


def test_static_shell_and_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "NetAgent" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/sw.js").headers["service-worker-allowed"] == "/"
    assert client.get("/manifest.webmanifest").json()["display"] == "standalone"
    assert client.get("/static/..%2Fapp.py").status_code == 404


def test_overview_command_and_files(client):
    _login(client)
    data = client.get("/api/overview").json()
    assert data["total"] == 1 and data["up"] == 0 and data["devices"][0]["name"] == "R1"
    r = client.post("/api/command", json={"line": "/mute R1 2h"}, headers=H).json()
    assert "დადუმებულია" in r["text"]
    assert client.get("/api/overview").json()["devices"][0]["muted"] is True
    assert client.post("/api/command", json={"line": "/nonsense"}, headers=H).status_code == 400
    assert client.get("/api/files/report.txt").text == "hello"
    assert client.get("/api/files/..%2Fdevices.yaml").status_code == 404


def test_chat_streams_steps_and_answer(client):
    _login(client)
    with client.stream("POST", "/api/chat", data={"text": "რა მოწყობილობები მაქვს?"}, headers=H) as r:
        body = "".join(r.iter_text())
    assert "event: step" in body and "📋" in body
    assert "event: answer" in body and "**R1** ok" in body
    assert client.post("/api/chat", data={"text": ""}, headers=H).status_code == 400


def test_logout_everywhere(client):
    _login(client)
    assert client.post("/api/logout", json={"everywhere": True}, headers=H).status_code == 200
    assert client.get("/api/overview").status_code == 401


def test_doctor_offline_reports_missing_pieces(tmp_path, monkeypatch):
    from netagent import doctor
    from netagent.config import settings

    inv = tmp_path / "devices.yaml"
    inv.write_text("credentials:\n  default: {username_env: NA_TEST_U, password_env: NA_TEST_P}\n"
                   "devices:\n  R1: {host: 127.0.0.1, port: 1, device_type: cisco_ios}\n", encoding="utf-8")
    saved = {k: getattr(settings, k) for k in ("inventory_path", "data_dir")}
    object.__setattr__(settings, "inventory_path", inv)
    object.__setattr__(settings, "data_dir", tmp_path / "data")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    try:
        checks = doctor.run_checks(online=False)
    finally:
        for k, v in saved.items():
            object.__setattr__(settings, k, v)
    by_title = {c.title: c.status for c in checks}
    assert by_title["ANTHROPIC_API_KEY არ არის მითითებული"] == doctor.FAIL
    assert any("credentials 'default': ცარიელია" in t for t in by_title)
    assert any(t.startswith("SSH-ზე მიუწვდომელი") for t in by_title)
    assert by_title["ყველა ბიბლიოთეკა დაყენებულია"] == doctor.OK
