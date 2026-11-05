"""Web Push notifications (RFC 8291 message encryption + RFC 8292 VAPID), using only `cryptography`.

Android Chrome delivers these to the installed app even when it is closed.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import struct
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("netagent.push")
RECORD_SIZE = 4096


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _public_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def encrypt(payload: bytes, ua_public_b64: str, auth_secret_b64: str,
            sender_private: ec.EllipticCurvePrivateKey | None = None, salt: bytes | None = None) -> bytes:
    """aes128gcm content coding for Web Push (RFC 8291 section 3.4)."""
    ua_public = unb64url(ua_public_b64)
    auth_secret = unb64url(auth_secret_b64)
    sender_private = sender_private or ec.generate_private_key(ec.SECP256R1())
    as_public = _public_bytes(sender_private.public_key())
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    ecdh_secret = sender_private.exchange(ec.ECDH(), ua_key)

    prk_key = _hmac_sha256(auth_secret, ecdh_secret)
    ikm = _hmac_sha256(prk_key, b"WebPush: info\x00" + ua_public + as_public + b"\x01")
    salt = salt or os.urandom(16)
    prk = _hmac_sha256(salt, ikm)
    cek = _hmac_sha256(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]
    nonce = _hmac_sha256(prk, b"Content-Encoding: nonce\x00\x01")[:12]

    if len(payload) > RECORD_SIZE - 17 - 86:
        raise ValueError("push payload too large")
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)  # 0x02 = last-record delimiter
    header = salt + struct.pack(">I", RECORD_SIZE) + bytes([len(as_public)]) + as_public
    return header + ciphertext


class VapidKeys:
    def __init__(self, path: Path) -> None:
        self.path = path
        if path.exists():
            self.private = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            self.private = ec.generate_private_key(ec.SECP256R1())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()))
            os.chmod(path, 0o600)

    @property
    def public_b64(self) -> str:
        return b64url(_public_bytes(self.private.public_key()))

    def jwt(self, endpoint: str, subject: str = "mailto:netagent@localhost", ttl: int = 12 * 3600) -> str:
        u = urlparse(endpoint)
        header = b64url(json.dumps({"typ": "JWT", "alg": "ES256"}).encode())
        claims = b64url(json.dumps({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + ttl,
                                    "sub": subject}).encode())
        der = self.private.sign(f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return f"{header}.{claims}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class PushSender:
    """Stores subscriptions in the state file and sends notifications to all of them."""

    KEY = "push_subscriptions"

    def __init__(self, state, keys: VapidKeys) -> None:
        self.state = state
        self.keys = keys

    def subscriptions(self) -> list[dict]:
        return self.state.get(self.KEY, []) or []

    def subscribe(self, sub: dict) -> None:
        if not (isinstance(sub, dict) and str(sub.get("endpoint", "")).startswith("https://")
                and isinstance(sub.get("keys"), dict) and {"p256dh", "auth"} <= set(sub["keys"])):
            raise ValueError("invalid subscription")
        clean = {"endpoint": sub["endpoint"], "keys": {"p256dh": sub["keys"]["p256dh"], "auth": sub["keys"]["auth"]}}
        self.state.update(self.KEY, lambda subs: [s for s in (subs or []) if s["endpoint"] != clean["endpoint"]] + [clean])

    def unsubscribe(self, endpoint: str) -> None:
        self.state.update(self.KEY, lambda subs: [s for s in (subs or []) if s["endpoint"] != endpoint])

    async def send(self, title: str, body: str, tag: str = "netagent", url: str = "/") -> int:
        payload = json.dumps({"title": title, "body": body[:600], "tag": tag, "url": url}, ensure_ascii=False).encode()
        sent = 0
        gone: list[str] = []
        async with httpx.AsyncClient(timeout=15) as client:
            for sub in self.subscriptions():
                try:
                    body_bytes = encrypt(payload, sub["keys"]["p256dh"], sub["keys"]["auth"])
                    resp = await client.post(sub["endpoint"], content=body_bytes, headers={
                        "Content-Encoding": "aes128gcm",
                        "Content-Type": "application/octet-stream",
                        "TTL": "86400",
                        "Urgency": "high",
                        "Authorization": f"vapid t={self.keys.jwt(sub['endpoint'])}, k={self.keys.public_b64}",
                    })
                except Exception:  # noqa: BLE001
                    log.exception("push send failed")
                    continue
                if resp.status_code in (404, 410):
                    gone.append(sub["endpoint"])
                elif resp.status_code >= 400:
                    log.warning("push rejected: %s %s", resp.status_code, resp.text[:200])
                else:
                    sent += 1
        for endpoint in gone:
            self.unsubscribe(endpoint)
        return sent
