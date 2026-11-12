"""Device inventory loaded from YAML.

Credentials are never stored in the YAML itself: the file only names the
environment variables that hold them, so the inventory can be committed safely.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class InventoryError(RuntimeError):
    pass


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    device_type: str  # Netmiko device_type, e.g. cisco_ios, mikrotik_routeros, juniper_junos
    credentials: str = "default"
    port: int = 22
    site: str = ""
    role: str = ""
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    # Deep monitoring settings, see watch.py (interfaces / bgp / ospf / cpu)
    watch: dict = field(default_factory=dict, hash=False, compare=False)
    baudrate: int = 9600  # console cable only: host is the COM port, device_type ends with "_serial"

    @property
    def is_serial(self) -> bool:
        return self.device_type.endswith("_serial")

    def public_info(self) -> dict:
        """What the LLM is allowed to see about the device (no credentials)."""
        return {
            "name": self.name,
            "host": self.host,
            "device_type": self.device_type,
            "site": self.site,
            "role": self.role,
            "description": self.description,
            "tags": list(self.tags),
            **({"watch": self.watch} if self.watch else {}),
        }


@dataclass(frozen=True)
class Credential:
    username: str
    password: str
    secret: str = ""  # enable secret (Cisco), optional


class Inventory:
    def __init__(self, devices: dict[str, Device], credential_refs: dict[str, dict]):
        self.devices = devices
        self._credential_refs = credential_refs

    @classmethod
    def load(cls, path: Path) -> "Inventory":
        if not path.exists():
            raise InventoryError(
                f"inventory ფაილი ვერ მოიძებნა: {path}. "
                "დააკოპირე inventory/devices.example.yaml → inventory/devices.yaml"
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        creds = data.get("credentials", {}) or {}
        devices: dict[str, Device] = {}
        for name, raw in (data.get("devices", {}) or {}).items():
            if not isinstance(raw, dict) or "host" not in raw or "device_type" not in raw:
                raise InventoryError(f"მოწყობილობა '{name}': host და device_type სავალდებულოა")
            devices[name] = Device(
                name=name,
                host=str(raw["host"]),
                device_type=str(raw["device_type"]),
                credentials=str(raw.get("credentials", "default")),
                port=int(raw.get("port", 22)),
                site=str(raw.get("site", "")),
                role=str(raw.get("role", "")),
                description=str(raw.get("description", "")),
                tags=tuple(raw.get("tags", []) or []),
                watch=raw.get("watch") if isinstance(raw.get("watch"), dict) else {},
                baudrate=int(raw.get("baudrate", 9600)),
            )
        return cls(devices, creds)

    def get(self, name: str) -> Device:
        if name in self.devices:
            return self.devices[name]
        lowered = {k.lower(): v for k, v in self.devices.items()}
        if name.lower() in lowered:
            return lowered[name.lower()]
        raise InventoryError(
            f"მოწყობილობა '{name}' inventory-ში არ არის. ხელმისაწვდომია: {', '.join(self.devices) or '—'}"
        )

    def filter(self, query: str = "") -> list[Device]:
        q = query.strip().lower()
        if not q:
            return list(self.devices.values())
        out = []
        for d in self.devices.values():
            hay = " ".join([d.name, d.host, d.device_type, d.site, d.role, d.description, *d.tags]).lower()
            if q in hay:
                out.append(d)
        return out

    def credential_for(self, device: Device) -> Credential:
        ref = self._credential_refs.get(device.credentials)
        if ref is None:
            raise InventoryError(f"credentials '{device.credentials}' არ არის აღწერილი inventory-ში")

        def env(key: str, required: bool = True) -> str:
            var = ref.get(key)
            if not var:
                if required:
                    raise InventoryError(f"credentials '{device.credentials}': {key} არ არის მითითებული")
                return ""
            value = os.getenv(var, "")
            if required and not value:
                raise InventoryError(f"გარემოს ცვლადი {var} ცარიელია (.env ფაილი შეამოწმე)")
            return value

        return Credential(
            username=env("username_env"),
            password=env("password_env"),
            secret=env("secret_env", required=False),
        )
