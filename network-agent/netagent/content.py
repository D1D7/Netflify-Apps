"""Turn uploaded photos/files into Claude message content (shared by Telegram and the app)."""

from __future__ import annotations

import base64
import json

from .security import mask_secrets
from .tools.extract import extract_network_data

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_FILE_CHARS_TO_MODEL = 60_000
IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}

DEFAULT_IMAGE_QUESTION = "რა ჩანს ამ სურათზე? თუ შეცდომაა ან პრობლემა — ამიხსენი და მითხარი, როგორ გავასწორო."
DEFAULT_FILE_QUESTION = (
    "გააანალიზე ეს ფაილი: ამოიღე IP მისამართები, ქსელები, VLAN-ები, ინტერფეისები და აღნიშნე პრობლემები."
)


class UploadError(ValueError):
    pass


def image_block(data: bytes, media_type: str) -> dict:
    if media_type not in IMAGE_TYPES:
        raise UploadError(f"მხარდაუჭერელი სურათის ტიპი: {media_type}")
    if len(data) > MAX_IMAGE_BYTES:
        raise UploadError("სურათი ძალიან დიდია (მაქს. 5 MB).")
    return {"type": "image", "source": {"type": "base64", "media_type": media_type,
                                        "data": base64.b64encode(data).decode("ascii")}}


def document_blocks(name: str, data: bytes) -> list[dict]:
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError("ფაილი ძალიან დიდია (მაქს. 2 MB).")
    if data.count(b"\x00") > 10:
        raise UploadError("ეს ტექსტური ფაილი არ არის (config, log, txt, csv...).")
    text = mask_secrets(data.decode("utf-8", errors="replace"))
    truncated = len(text) > MAX_FILE_CHARS_TO_MODEL
    return [
        {"type": "text", "text": (
            f"<uploaded_file name={json.dumps(name or 'file.txt')}>\n{text[:MAX_FILE_CHARS_TO_MODEL]}\n</uploaded_file>"
            + ("\n(ფაილი შემოკლებულია, სრული ამოღება იხ. ქვემოთ)" if truncated else ""))},
        {"type": "text", "text": "Automatic extraction from the full file (exact, deterministic):\n"
         + json.dumps(extract_network_data(text), ensure_ascii=False, indent=1)},
    ]


def build_content(text: str, uploads: list[tuple[str, str, bytes]]) -> str | list[dict]:
    """uploads: (filename, media_type, data). Returns a plain string when there are no uploads."""
    if not uploads:
        return text
    blocks: list[dict] = []
    has_image = has_doc = False
    for name, media_type, data in uploads:
        if (media_type or "").lower() in IMAGE_TYPES:
            blocks.append(image_block(data, media_type.lower()))
            has_image = True
        else:
            blocks.extend(document_blocks(name, data))
            has_doc = True
    question = text.strip() or (DEFAULT_IMAGE_QUESTION if has_image and not has_doc else DEFAULT_FILE_QUESTION)
    # Images first, then the question, then documents (Claude reads images best before the text).
    images = [b for b in blocks if b["type"] == "image"]
    docs = [b for b in blocks if b["type"] != "image"]
    return [*images, {"type": "text", "text": question}, *docs]
