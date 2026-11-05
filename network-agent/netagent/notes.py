"""Notes about devices (ISP contacts, circuit IDs, known issues...), persisted in the state file."""

from __future__ import annotations

from datetime import datetime

from .state import StateStore

GENERAL = "_general"
MAX_NOTE_CHARS = 2000
MAX_NOTES_PER_TARGET = 100


class NoteStore:
    KEY = "notes"

    def __init__(self, state: StateStore) -> None:
        self.state = state

    @staticmethod
    def _target(device: str | None) -> str:
        return device.strip() if device and device.strip() else GENERAL

    def add(self, device: str | None, text: str, author: str = "") -> int:
        text = text.strip()
        if not text:
            raise ValueError("ცარიელი შენიშვნა")
        if len(text) > MAX_NOTE_CHARS:
            raise ValueError(f"შენიშვნა ძალიან გრძელია (მაქს. {MAX_NOTE_CHARS} სიმბოლო)")
        target = self._target(device)
        entry = {"text": text, "by": author, "ts": datetime.now().isoformat(timespec="minutes")}

        def apply(data: dict | None) -> dict:
            data = data or {}
            notes = data.setdefault(target, [])
            notes.append(entry)
            data[target] = notes[-MAX_NOTES_PER_TARGET:]
            return data

        data = self.state.update(self.KEY, apply)
        return len(data[target])

    def list(self, device: str | None = None) -> list[dict]:
        return (self.state.get(self.KEY, {}) or {}).get(self._target(device), [])

    def all(self) -> dict[str, list[dict]]:
        return self.state.get(self.KEY, {}) or {}

    def delete(self, device: str | None, number: int) -> dict:
        """Delete note by its 1-based number."""
        target = self._target(device)
        removed: dict = {}

        def apply(data: dict | None) -> dict:
            data = data or {}
            notes = data.get(target, [])
            if not 1 <= number <= len(notes):
                raise ValueError(f"შენიშვნა #{number} არ არსებობს")
            removed.update(notes.pop(number - 1))
            if notes:
                data[target] = notes
            else:
                data.pop(target, None)
            return data

        self.state.update(self.KEY, apply)
        return removed

    def format(self, device: str | None = None) -> str:
        target = self._target(device)
        notes = self.list(device)
        title = "ზოგადი" if target == GENERAL else target
        if not notes:
            return f"📝 {title}: შენიშვნები არ არის."
        lines = [f"📝 **{title}** — შენიშვნები:"]
        for i, n in enumerate(notes, 1):
            lines.append(f"{i}. {n['text']}  ({n['ts'].replace('T', ' ')})")
        return "\n".join(lines)
