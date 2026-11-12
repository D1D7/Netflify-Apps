"""Home Assistant integration over MQTT (auto-discovery): NetAgent's numbers become HA sensors.

  NETAGENT_MQTT=192.168.1.10        your MQTT broker (Mosquitto add-on in HA), optional :port (default 1883)
  NETAGENT_MQTT_USER / NETAGENT_MQTT_PASS   broker login (in .env only)
  NETAGENT_MQTT_PREFIX=homeassistant        discovery prefix
  /mqtt        status · /mqtt send   publish now

Every minute: internet up/down, ping, download/upload, devices online, unknown devices, Wi-Fi signal, DNS
blocks, and one "home" sensor per device you named in Live (/name). Sensors expire after 5 minutes without
updates, so when the PC is off, HA shows "unavailable" instead of old values. A tiny built-in MQTT 3.1.1
client is used (QoS 0, connect-publish-disconnect), no extra packages.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import socket
import struct
from datetime import datetime

from ..result import Button, CommandError, Result

log = logging.getLogger("netagent.mqtt")
NODE = re.sub(r"[^a-z0-9_]", "_", socket.gethostname().lower()) or "netagent"
LAST: dict = {}


def config() -> dict | None:
    raw = os.getenv("NETAGENT_MQTT", "").strip()
    if not raw or raw.lower() in {"off", "0", "no"}:
        return None
    host, _, port = raw.rpartition(":") if raw.count(":") == 1 else (raw, "", "")
    return {"host": host or raw, "port": int(port) if port.isdigit() else 1883,
            "user": os.getenv("NETAGENT_MQTT_USER", ""), "password": os.getenv("NETAGENT_MQTT_PASS", ""),
            "prefix": os.getenv("NETAGENT_MQTT_PREFIX", "homeassistant").strip("/") or "homeassistant"}


# ---- MQTT 3.1.1 wire format --------------------------------------------------------------------------
def _len(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n % 128, n // 128
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _str(s: str | bytes) -> bytes:
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("!H", len(b)) + b


def connect_packet(client_id: str, user: str = "", password: str = "", keepalive: int = 30) -> bytes:
    flags = 0x02 | (0x80 if user else 0) | (0x40 if user and password else 0)
    body = _str("MQTT") + bytes([4, flags]) + struct.pack("!H", keepalive) + _str(client_id)
    if user:
        body += _str(user)
        if password:
            body += _str(password)
    return bytes([0x10]) + _len(len(body)) + body


def publish_packet(topic: str, payload: str | bytes, retain: bool = True) -> bytes:
    body = _str(topic) + (payload.encode() if isinstance(payload, str) else payload)
    return bytes([0x30 | (0x01 if retain else 0)]) + _len(len(body)) + body


CONNACK_ERR = {1: "პროტოკოლის ვერსია არ მიიღო", 2: "client id უარყო", 3: "ბროკერი მიუწვდომელია",
               4: "მომხმარებელი/პაროლი არასწორია", 5: "ავტორიზაცია არ აქვს"}


async def publish_all(cfg: dict, messages: list[tuple[str, str]], timeout: float = 8.0) -> int:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(cfg["host"], cfg["port"]), timeout)
    try:
        writer.write(connect_packet(f"netagent-{NODE}", cfg["user"], cfg["password"]))
        await writer.drain()
        ack = await asyncio.wait_for(reader.readexactly(4), timeout)
        if ack[0] != 0x20:
            raise CommandError("MQTT: ბროკერმა გაუგებარი პასუხი დააბრუნა")
        if ack[3]:
            raise CommandError(f"MQTT: {CONNACK_ERR.get(ack[3], f'შეცდომა {ack[3]}')}")
        for topic, payload in messages:
            writer.write(publish_packet(topic, payload))
        writer.write(b"\xe0\x00")  # DISCONNECT
        await writer.drain()
        return len(messages)
    finally:
        writer.close()


# ---- what we publish ----------------------------------------------------------------------------------
SENSORS = [  # key, name, unit, device_class, icon
    ("ping_ms", "Ping", "ms", "duration", "mdi:timer-outline"),
    ("download_mbps", "Download", "Mbit/s", "data_rate", "mdi:download"),
    ("upload_mbps", "Upload", "Mbit/s", "data_rate", "mdi:upload"),
    ("devices_online", "Devices online", None, None, "mdi:devices"),
    ("unknown_devices", "Unknown devices", None, None, "mdi:shield-alert"),
    ("wifi_signal", "Wi-Fi signal", "%", None, "mdi:wifi"),
    ("dns_queries", "DNS queries today", None, None, "mdi:dns"),
    ("dns_blocked", "DNS blocked today", None, None, "mdi:shield-check"),
]


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:40] or "device"


def collect(s, live=None) -> dict:
    """Current values (None = unknown)."""
    v: dict = {"internet": None, "devices": {}}
    try:
        from .isp import monitor_for

        sm = monitor_for(s).summary(1 / 24)
        v["internet"] = not sm.get("down_now_since") if sm.get("samples") else None
        v["ping_ms"] = sm.get("latency_avg_ms")
    except Exception:  # noqa: BLE001
        pass
    tests = [t for t in (s.state.get("isp_speedtests") or []) if t.get("down_mbps") is not None]
    if tests:
        v["download_mbps"], v["upload_mbps"] = tests[-1]["down_mbps"], tests[-1]["up_mbps"]
    if live is None:
        from . import livedevices

        live = livedevices.ENGINE
    if live is not None:
        snap = live.snapshot()
        v["devices_online"] = snap["online"]
        v["unknown_devices"] = sum(1 for r in snap["devices"] if r["online"] and not r["trusted"] and not r["self"])
        for r in snap["devices"]:
            if r["label"]:
                v["devices"][slug(r["label"])] = {"name": r["label"], "home": r["online"], "ip": r["ip"]}
    try:
        from .quality import signal_history

        h = signal_history(1)
        v["wifi_signal"] = h[-1][1] if h else None
    except Exception:  # noqa: BLE001
        pass
    from .dnsfilter import RUNNING, STATS

    if RUNNING:
        d = STATS.as_dict()
        v["dns_queries"], v["dns_blocked"] = d["total"], d["blocked"]
    return v


def messages(cfg: dict, values: dict) -> list[tuple[str, str]]:
    base = f"netagent/{NODE}"
    dev = {"identifiers": [f"netagent_{NODE}"], "name": f"NetAgent ({NODE})", "manufacturer": "NetAgent",
           "model": "Home network agent"}
    state = {k: values.get(k) for k, *_ in SENSORS}
    state["internet"] = None if values.get("internet") is None else ("ON" if values["internet"] else "OFF")
    out = []
    p = cfg["prefix"]
    for key, name, unit, dclass, icon in SENSORS:
        c = {"name": name, "unique_id": f"netagent_{NODE}_{key}", "state_topic": f"{base}/state",
             "value_template": f"{{{{ value_json.{key} }}}}", "device": dev, "icon": icon, "expire_after": 300}
        if unit:
            c["unit_of_measurement"] = unit
            c["state_class"] = "measurement"
        if dclass:
            c["device_class"] = dclass
        out.append((f"{p}/sensor/netagent_{NODE}/{key}/config", json.dumps(c)))
    out.append((f"{p}/binary_sensor/netagent_{NODE}/internet/config", json.dumps(
        {"name": "Internet", "unique_id": f"netagent_{NODE}_internet", "state_topic": f"{base}/state",
         "value_template": "{{ value_json.internet }}", "device_class": "connectivity", "device": dev,
         "expire_after": 300})))
    for sl, d in values.get("devices", {}).items():
        out.append((f"{p}/binary_sensor/netagent_{NODE}/home_{sl}/config", json.dumps(
            {"name": f"{d['name']} home", "unique_id": f"netagent_{NODE}_home_{sl}", "state_topic": f"{base}/home/{sl}",
             "device_class": "presence", "device": dev, "expire_after": 300})))
        out.append((f"{base}/home/{sl}", "ON" if d["home"] else "OFF"))
    out.append((f"{base}/state", json.dumps(state)))
    return out


async def send(s) -> int:
    cfg = config()
    if cfg is None:
        raise CommandError("MQTT გამორთულია: .env-ში მიუთითე NETAGENT_MQTT=<ბროკერის IP> (და საჭიროების შემთხვევაში "
                           "NETAGENT_MQTT_USER / NETAGENT_MQTT_PASS), შემდეგ გადატვირთე NetAgent.")
    values = await asyncio.to_thread(collect, s)
    try:
        n = await publish_all(cfg, messages(cfg, values))
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        LAST.update(ok=False, ts=datetime.now().isoformat(timespec="seconds"), error=f"{type(exc).__name__}: {exc}")
        raise CommandError(f"MQTT ბროკერთან ({cfg['host']}:{cfg['port']}) დაკავშირება ვერ მოხერხდა: {exc}") from exc
    except CommandError as exc:
        LAST.update(ok=False, ts=datetime.now().isoformat(timespec="seconds"), error=str(exc))
        raise
    LAST.update(ok=True, ts=datetime.now().isoformat(timespec="seconds"), count=n, error="")
    return n


def mqtt_cmd(s, args, user) -> Result:
    cfg = config()
    if args and args[0].lower() == "send":
        n = asyncio.run(send(s))
        return Result(f"🏠 Home Assistant-ს გაეგზავნა {n} შეტყობინება.")
    if cfg is None:
        return Result("🏠 **Home Assistant (MQTT)** გამორთულია.\n\n1. HA-ში დააყენე **Mosquitto broker** add-on და "
                      "ჩართე MQTT ინტეგრაცია.\n2. NetAgent-ის `.env`-ში: `NETAGENT_MQTT=<HA-ის IP>`, "
                      "`NETAGENT_MQTT_USER=...`, `NETAGENT_MQTT_PASS=...`\n3. გადატვირთე NetAgent — HA-ში თავისით "
                      "გამოჩნდება მოწყობილობა „NetAgent“ სენსორებით (ინტერნეტი, ping, სიჩქარე, მოწყობილობები, "
                      "Wi-Fi, DNS) და „სახლშია“ სენსორით ყველა სახელდებული მოწყობილობისთვის.")
    st = ("✅ ბოლო გაგზავნა " + LAST["ts"][11:] + f" ({LAST.get('count')} შეტყობინება)" if LAST.get("ok")
          else f"⚠️ ბოლო მცდელობა {LAST['ts'][11:]}: {LAST['error']}" if LAST else "ჯერ არ გაგზავნილა")
    return Result(f"🏠 **Home Assistant (MQTT)**: {cfg['host']}:{cfg['port']}, prefix `{cfg['prefix']}`\n{st}",
                  buttons=[Button("📤 გაგზავნე ახლა", "/mqtt send")])


COMMANDS = {"mqtt": mqtt_cmd}
HELP = ["/mqtt — Home Assistant ინტეგრაცია (MQTT auto-discovery): ინტერნეტი, სიჩქარე, მოწყობილობები, „სახლშია“ "
        "სენსორები · ჩართვა: NETAGENT_MQTT=<ბროკერის IP>"]
BOT_COMMANDS = [("mqtt", "Home Assistant (MQTT)")]


def jobs(monitoring):
    if config() is None:
        return []

    async def push():
        try:
            await send(monitoring.s)
        except CommandError as exc:
            log.warning("%s", exc)

    return [("mqtt", 60, 45, push)]
