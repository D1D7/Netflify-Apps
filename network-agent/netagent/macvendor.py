"""MAC address → manufacturer (OUI lookup).

The IEEE registry (official, public) is downloaded once and cached in data/oui.txt;
Wireshark's 'manuf' list is the fallback source. Without a database, lookups still
recognise randomized ("private") MACs that phones use.
"""

from __future__ import annotations

import csv
import io
import logging
import re
import threading
from pathlib import Path

log = logging.getLogger("netagent.oui")

SOURCES = [
    ("ieee", "https://standards-oui.ieee.org/oui/oui.csv"),
    ("wireshark", "https://www.wireshark.org/download/automated/data/manuf"),
]
RANDOM_LABEL = "შემთხვევითი MAC (ტელეფონის/ლეპტოპის privacy რეჟიმი)"


def normalize(mac: str) -> str:
    return re.sub(r"[^0-9a-f]", "", mac.lower())


def is_locally_administered(mac: str) -> bool:
    h = normalize(mac)
    return len(h) >= 2 and bool(int(h[1], 16) & 0x2)


def parse_ieee_csv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1].strip()):
            out[row[1].strip().lower()] = row[2].strip()
    return out


def parse_wireshark_manuf(text: str) -> dict[str, str]:
    """Lines like '00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc' and '00:1B:C5:00:00:00/36<TAB>...'."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix, _, bits = parts[0].partition("/")
        hexs = normalize(prefix)
        nbits = int(bits) if bits.isdigit() else 24
        if nbits % 4 or len(hexs) < nbits // 4:
            continue
        name = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
        out[hexs[: nbits // 4]] = name
    return out


# A few very common prefixes, so lookups are useful before the full list is downloaded.
COMMON = {
    "00000C": "Cisco Systems", "0026CB": "Cisco Systems", "00A3D1": "Cisco Systems", "00F28B": "Cisco Systems",
    "4C5E0C": "MikroTik (Routerboard)", "6C3B6B": "MikroTik (Routerboard)", "D4CA6D": "MikroTik (Routerboard)",
    "E48D8C": "MikroTik (Routerboard)", "00E0FC": "Huawei", "00090F": "Fortinet", "001B17": "Palo Alto Networks",
    "7483C2": "Ubiquiti", "245A4C": "Ubiquiti", "FCECDA": "Ubiquiti", "50C7BF": "TP-Link", "AC84C6": "TP-Link",
    "A45E60": "Apple", "001EC2": "Apple", "F8BC12": "Dell", "3CD92B": "Hewlett Packard", "001B21": "Intel",
    "00E04C": "Realtek", "0004F2": "Polycom", "001132": "Synology", "001788": "Philips Lighting (Hue)",
    "18B430": "Nest Labs", "3C5AB4": "Google", "F4F5D8": "Google", "001A11": "Google",
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Trading", "E45F01": "Raspberry Pi Trading",
    "000C29": "VMware (virtual)", "005056": "VMware (virtual)", "000569": "VMware (virtual)",
    "001C14": "VMware (virtual)", "080027": "VirtualBox (virtual)", "00155D": "Microsoft Hyper-V (virtual)",
    "001C42": "Parallels (virtual)", "525400": "QEMU/KVM (virtual)", "0050F2": "Microsoft",
}


class VendorDB:
    def __init__(self, cache: Path) -> None:
        self.cache = cache
        self._db: dict[str, str] | None = None
        self._lock = threading.Lock()

    def _load(self) -> dict[str, str]:
        if self._db is None:
            with self._lock:
                if self._db is None:
                    db: dict[str, str] = {}
                    if self.cache.exists():
                        for line in self.cache.read_text(encoding="utf-8", errors="replace").splitlines():
                            k, _, v = line.partition("\t")
                            if k and v:
                                db[k] = v
                    self._db = db
        return self._db

    @property
    def size(self) -> int:
        return len(self._load())

    def update(self, timeout: float = 60) -> tuple[int, str]:
        """Download the registry. Returns (entries, source)."""
        import httpx

        last = ""
        for name, url in SOURCES:
            try:
                r = httpx.get(url, timeout=timeout, follow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0 (NetAgent OUI update)"})
                r.raise_for_status()
                db = parse_ieee_csv(r.text) if name == "ieee" else parse_wireshark_manuf(r.text)
                if len(db) < 1000:
                    raise ValueError(f"{name}: only {len(db)} entries")
                self.cache.parent.mkdir(parents=True, exist_ok=True)
                self.cache.write_text("\n".join(f"{k}\t{v}" for k, v in sorted(db.items())), encoding="utf-8")
                with self._lock:
                    self._db = db
                return len(db), name
            except Exception as exc:  # noqa: BLE001
                last = f"{name}: {type(exc).__name__}: {exc}"
                log.warning("OUI download failed (%s)", last)
        raise RuntimeError(f"MAC ბაზა ვერ ჩამოიტვირთა ({last})")

    def lookup(self, mac: str) -> str | None:
        h = normalize(mac)
        if len(h) != 12:
            return None
        db = self._load()
        for n in (9, 7, 6):  # longest prefix first (MA-S /36, MA-M /28, MA-L /24)
            if h[:n] in db:
                return db[h[:n]]
        if h[:6].upper() in COMMON:  # works before (or without) the full download
            return COMMON[h[:6].upper()]
        if h.startswith("0242"):
            return "Docker container"
        if is_locally_administered(h):
            return RANDOM_LABEL
        return None

    def ensure(self) -> None:
        """Download once in the background if there is no cache yet."""
        if self.cache.exists() or getattr(self, "_started", False):
            return
        self._started = True
        threading.Thread(target=lambda: self._safe_update(), daemon=True).start()

    def _safe_update(self) -> None:
        try:
            n, src = self.update()
            log.info("OUI database: %s entries from %s", n, src)
        except Exception:  # noqa: BLE001
            pass


_DB: VendorDB | None = None


def default_db() -> VendorDB:
    global _DB
    if _DB is None:
        from .config import settings

        _DB = VendorDB(settings.data_dir / "oui.txt")
    return _DB
