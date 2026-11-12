"""Excel (.xlsx) export of tables the agent collected."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

MAX_ROWS = 50_000
MAX_SHEETS = 20
_SAFE = re.compile(r"[^\w.-]+", re.UNICODE)
_SHEET_BAD = re.compile(r"[\[\]:*?/\\]")
_FORMULA_START = ("=", "+", "-", "@")


def _cell(value: Any) -> Any:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    # Prevent formula injection when the file is opened in Excel.
    if text.startswith(_FORMULA_START) and not re.fullmatch(r"-?\d+(\.\d+)?", text):
        text = "'" + text
    return text[:32000]


def write_xlsx(export_dir: Path, filename: str, sheets: list[dict[str, Any]]) -> Path:
    """sheets: [{"name": str, "columns": [str], "rows": [[...]]}]"""
    if not sheets:
        raise ValueError("ცარიელი ექსპორტი: მინიმუმ ერთი sheet საჭიროა")
    if len(sheets) > MAX_SHEETS:
        raise ValueError(f"მაქსიმუმ {MAX_SHEETS} sheet")
    wb = Workbook()
    wb.remove(wb.active)
    header_fill = PatternFill("solid", fgColor="1F4E78")
    used_names: set[str] = set()
    for i, sheet in enumerate(sheets):
        name = _SHEET_BAD.sub("_", str(sheet.get("name") or f"Sheet{i + 1}"))[:31] or f"Sheet{i + 1}"
        while name in used_names:
            name = (name[:28] + f"_{i}")[:31]
        used_names.add(name)
        ws = wb.create_sheet(name)
        columns = [str(c) for c in sheet.get("columns", [])]
        rows = sheet.get("rows", [])[:MAX_ROWS]
        if not isinstance(rows, list):
            raise ValueError("rows უნდა იყოს სია")
        if columns:
            ws.append(columns)
            for cell in ws[1]:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = header_fill
                cell.alignment = Alignment(vertical="center")
            ws.freeze_panes = "A2"
        for row in rows:
            ws.append([_cell(v) for v in (row if isinstance(row, list) else [row])])
        width_count = max([len(columns)] + [len(r) for r in rows if isinstance(r, list)] + [1])
        for col in range(1, width_count + 1):
            letter = get_column_letter(col)
            longest = max((len(str(c.value)) for c in ws[letter] if c.value is not None), default=8)
            ws.column_dimensions[letter].width = min(60, max(10, longest + 2))
        if columns and rows:
            ws.auto_filter.ref = ws.dimensions

    export_dir.mkdir(parents=True, exist_ok=True)
    stem = _SAFE.sub("_", Path(filename).stem).strip("_") or "export"
    path = export_dir / f"{stem}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.xlsx"
    wb.save(path)
    return path
