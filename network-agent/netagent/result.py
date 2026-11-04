"""Command results shared by Telegram, the app and the feature modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Button:
    label: str
    command: str  # command line to run when pressed, e.g. "/mute R1 1h"


@dataclass
class Result:
    text: str = ""
    files: list[Path] = field(default_factory=list)
    image: Path | None = None
    buttons: list[Button] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "text": self.text,
            "files": [p.name for p in self.files],
            "image": self.image.name if self.image else None,
            "buttons": [{"label": b.label, "command": b.command} for b in self.buttons],
        }


class CommandError(Exception):
    """Wrong usage or a refused command; the message is shown to the user."""
