"""device-info.txt for the report: each side's text as captured, and a line diff between them.

The file is shown for reading only. Nothing in it is parsed for values: no field, check, status
or exit code depends on it. Section labels are recognised from the output format of a few
common commands (date, uname -a, /proc/partitions, lsblk, blkid) to make the text easier to
scan; other lines are shown without a label.
"""
from __future__ import annotations

import difflib
import re

from .integrity import sha256_file
from .textdiff import INLINE_MIN_RATIO, MAX_INLINE_LINE

NAME = "device-info.txt"
MAX_BYTES = 1 << 20  # shown in the report; the full file is always copied to supporting/

_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_SECTIONS = (
    ("date", re.compile(rf"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({_MONTHS}) [ \d]\d "
                        r"\d\d:\d\d:\d\d \S+ \d{4}$")),
    ("uname -a", re.compile(r"^Linux \S+ \S+ #.*GNU/Linux$")),
    ("/proc/partitions", re.compile(r"^\s*major\s+minor\s+#blocks\s+name\s*$")),
    ("lsblk", re.compile(r"^NAME\s+MAJ:MIN\s")),
    ("blkid", re.compile(r'^/dev/\S+: [A-Z_]+="')),
)
# sections that end at the first line not like them; the tables run until the next label
_LINE_SECTIONS = {"date", "uname -a", "blkid"}
OTHER = "other output"


def _labels(lines):
    """{line index: section label} for the lines that start a section."""
    out, current = {}, None
    for i, line in enumerate(lines):
        label = next((name for name, rx in _SECTIONS if rx.match(line)), None)
        if label is None and current in _LINE_SECTIONS:
            label = OTHER
        if label is None or (label == current and label in ("blkid", OTHER)):
            continue  # same section: a run of blkid or unrecognised lines
        out[i] = current = label
    return out


def _spans(a: str, b: str):
    """Changed character ranges [[start, end], …] in a and in b; none for unrelated lines."""
    if len(a) > MAX_INLINE_LINE or len(b) > MAX_INLINE_LINE:
        return [], []
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if sm.ratio() < INLINE_MIN_RATIO:
        return [], []
    sa, sb = [], []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op != "equal":
            if i2 > i1:
                sa.append([i1, i2])
            if j2 > j1:
                sb.append([j1, j2])
    return sa, sb


def _diff_rows(a, b):
    la, lb = _labels(a), _labels(b)
    rows = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        for k in range(max(i2 - i1, j2 - j1)):
            gi = i1 + k if i1 + k < i2 else None
            ci = j1 + k if j1 + k < j2 else None
            row = {"op": op, "g": None if gi is None else [gi + 1, a[gi]],
                   "c": None if ci is None else [ci + 1, b[ci]]}
            label = (la.get(gi) if gi is not None else None) or \
                (lb.get(ci) if ci is not None else None)
            if label:
                row["label"] = label
            if op == "replace" and gi is not None and ci is not None:
                row["gm"], row["cm"] = _spans(a[gi], b[ci])
            rows.append(row)
    return rows


def _single_rows(lines):
    labels = _labels(lines)
    rows = []
    for i, line in enumerate(lines):
        row = {"op": "equal", "line": [i + 1, line]}
        if i in labels:
            row["label"] = labels[i]
        rows.append(row)
    return rows


def _read(path):
    size = path.stat().st_size
    with open(path, "rb") as fh:
        data = fh.read(MAX_BYTES)
    lines = data.decode("utf-8", errors="replace").splitlines()
    return {"present": True, "path": str(path), "sha256": sha256_file(path), "size": size,
            "truncated": size > MAX_BYTES, "lines": len(lines)}, lines


def build_device_info(golden_listing, current_listing) -> dict:
    """The report's ``device_info`` block.

    layout: ``diff`` (both sides, side by side), ``single`` (one side only, or both sides read
    the same file: ``shown`` names it) or ``none`` (no readable device-info.txt).
    """
    sides, lines, paths = {}, {}, {}
    for side, listing in (("golden", golden_listing), ("current", current_listing)):
        path = listing.supporting.get(NAME)
        if path is None:
            sides[side] = {"present": False}
            continue
        paths[side] = path.resolve()
        try:
            sides[side], lines[side] = _read(path)
        except OSError as exc:
            sides[side] = {"present": True, "path": str(path), "error": exc.strerror or str(exc)}
        sides[side]["copy"] = f"supporting/{side}/{NAME}"
    same = len(paths) == 2 and paths["golden"] == paths["current"]
    out = {"name": NAME, "golden": sides["golden"], "current": sides["current"],
           "same_file": same, "layout": "none", "shown": None, "differing": 0, "rows": []}
    if len(lines) == 2 and not same:
        out["layout"] = "diff"
        out["rows"] = _diff_rows(lines["golden"], lines["current"])
        out["differing"] = sum(r["op"] != "equal" for r in out["rows"])
    elif lines:
        shown = "golden" if "golden" in lines else "current"
        out.update(layout="single", shown=shown, rows=_single_rows(lines[shown]))
    return out
