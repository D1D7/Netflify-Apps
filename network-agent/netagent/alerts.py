"""Alert muting (persisted), e.g. during planned maintenance."""

from __future__ import annotations

import re
import time

from .state import StateStore

ALL = "*"
_DURATION_RE = re.compile(r"^(\d+)\s*([smhdწსდ]?)", re.I)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 60, "წ": 60, "ს": 3600, "დ": 86400}
MAX_MUTE = 30 * 86400


def parse_duration(text: str) -> int:
    """'30m', '2h', '1d', '90' (minutes). Georgian: '30წ', '2ს', '1დ'."""
    m = _DURATION_RE.match(text.strip())
    if not m:
        raise ValueError(f"ვერ გავიგე ხანგრძლივობა: {text!r} (მაგ. 30m, 2h, 1d)")
    seconds = int(m.group(1)) * _UNITS[m.group(2).lower()]
    if seconds <= 0:
        raise ValueError("ხანგრძლივობა უნდა იყოს 0-ზე მეტი")
    return min(seconds, MAX_MUTE)


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 3600:
        return f"{max(1, seconds // 60)} წთ"
    if seconds < 86400:
        h, m = divmod(seconds // 60, 60)
        return f"{h} სთ" + (f" {m} წთ" if m else "")
    d, rem = divmod(seconds, 86400)
    return f"{d} დღე" + (f" {rem // 3600} სთ" if rem >= 3600 else "")


class AlertMutes:
    KEY = "mutes"

    def __init__(self, state: StateStore) -> None:
        self.state = state

    def _clean(self, data: dict | None) -> dict:
        now = time.time()
        return {k: v for k, v in (data or {}).items() if v > now}

    def mute(self, target: str, seconds: int) -> float:
        until = time.time() + seconds
        self.state.update(self.KEY, lambda d: {**self._clean(d), target: until})
        return until

    def unmute(self, target: str) -> bool:
        existed = target in self.active()
        self.state.update(self.KEY, lambda d: {k: v for k, v in self._clean(d).items() if k != target})
        return existed

    def unmute_all(self) -> None:
        self.state.set(self.KEY, {})

    def active(self) -> dict[str, float]:
        return self._clean(self.state.get(self.KEY, {}))

    def is_muted(self, device: str) -> bool:
        active = self.active()
        return ALL in active or device in active

    def describe(self) -> str:
        active = self.active()
        if not active:
            return "🔔 დადუმებული ალერტები არ არის."
        now = time.time()
        lines = ["🔕 **დადუმებული:**"]
        for target, until in sorted(active.items(), key=lambda kv: kv[1]):
            name = "ყველა მოწყობილობა" if target == ALL else target
            lines.append(f"• {name} — დარჩა {format_duration(until - now)}")
        return "\n".join(lines)
