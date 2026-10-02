"""Manifest model: one inventory of one filesystem on one side (golden or current).

Every per-entry attribute is an ``Assessed`` value carrying its evaluation state, so that
"could not be read" is never confused with "absent" or "unchanged".
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = "forensic-compare/manifest/1"

STATES = ("ok", "absent", "n/a", "error")


@dataclass
class Assessed:
    state: str
    value: Any = None
    reason: str | None = None
    log_id: int | None = None

    def __post_init__(self):
        if self.state not in STATES:
            raise ValueError(f"invalid assessment state: {self.state!r}")

    @classmethod
    def ok(cls, value):
        return cls("ok", value)

    @classmethod
    def absent(cls):
        return cls("absent")

    @classmethod
    def na(cls):
        return cls("n/a")

    @classmethod
    def error(cls, reason, log_id=None):
        return cls("error", reason=reason, log_id=log_id)

    @property
    def assessed(self) -> bool:
        return self.state != "error"

    def to_dict(self):
        d = {"state": self.state}
        if self.value is not None:
            d["value"] = self.value
        if self.reason is not None:
            d["reason"] = self.reason
        if self.log_id is not None:
            d["log_id"] = self.log_id
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(d["state"], d.get("value"), d.get("reason"), d.get("log_id"))


def encode_path(raw: bytes) -> tuple[str, str]:
    """Return (display, hex) for a raw path.

    The display form is unambiguous: backslashes are doubled, and invalid UTF-8 bytes and
    control characters are rendered as ``\\xNN``.
    """
    text = raw.decode("utf-8", errors="surrogateescape")
    out = []
    for ch in text:
        cp = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif 0xDC80 <= cp <= 0xDCFF:  # surrogate-escaped invalid byte
            out.append(f"\\x{cp - 0xDC00:02x}")
        elif cp < 0x20 or cp == 0x7F:
            out.append(f"\\x{cp:02x}")
        else:
            out.append(ch)
    return "".join(out), raw.hex()


@dataclass
class Entry:
    path: str
    path_hex: str
    inode: int
    path_lossy: bool = False
    type: Assessed = None
    mode: Assessed = None
    uid: Assessed = None
    gid: Assessed = None
    size: Assessed = None
    mtime: Assessed = None
    content: Assessed = None
    symlink: Assessed = None
    xattrs: Assessed = None
    capability: Assessed = None
    times: dict = field(default_factory=dict)
    fs_flags: dict = field(default_factory=dict)

    ASSESSED_FIELDS = ("type", "mode", "uid", "gid", "size", "mtime",
                       "content", "symlink", "xattrs", "capability")

    @classmethod
    def blank(cls, path, path_hex, inode):
        """An entry whose every field is 'not extracted' until filled in (conservative)."""
        e = cls(path=path, path_hex=path_hex, inode=inode)
        for name in cls.ASSESSED_FIELDS:
            setattr(e, name, Assessed.error("not extracted"))
        return e

    def to_dict(self):
        d = {"path": self.path, "path_hex": self.path_hex, "path_lossy": self.path_lossy,
             "inode": self.inode}
        for name in self.ASSESSED_FIELDS:
            d[name] = getattr(self, name).to_dict()
        d["times"] = self.times
        d["fs_flags"] = self.fs_flags
        return d

    @classmethod
    def from_dict(cls, d):
        e = cls(path=d["path"], path_hex=d["path_hex"], inode=d["inode"],
                path_lossy=d.get("path_lossy", False),
                times=d.get("times", {}), fs_flags=d.get("fs_flags", {}))
        for name in cls.ASSESSED_FIELDS:
            setattr(e, name, Assessed.from_dict(d[name]))
        return e


@dataclass
class Manifest:
    side: str
    source_id: str
    schema: str = SCHEMA
    image: dict = field(default_factory=dict)
    filesystem: dict = field(default_factory=dict)
    inventory: dict = field(default_factory=lambda: {"state": "partial", "diagnostics": []})
    entries: list = field(default_factory=list)
    tools: dict = field(default_factory=dict)
    diagnostics: list = field(default_factory=list)

    @classmethod
    def new(cls, side, source_id):
        if side not in ("golden", "current"):
            raise ValueError(f"invalid side: {side!r}")
        return cls(side=side, source_id=source_id)

    def to_dict(self):
        return {
            "schema": self.schema,
            "side": self.side,
            "source_id": self.source_id,
            "image": self.image,
            "filesystem": self.filesystem,
            "inventory": self.inventory,
            "tools": self.tools,
            "diagnostics": self.diagnostics,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, d):
        if d.get("schema") != SCHEMA:
            raise ValueError(f"unsupported manifest schema: {d.get('schema')!r}")
        return cls(side=d["side"], source_id=d["source_id"], schema=d["schema"],
                   image=d.get("image", {}), filesystem=d.get("filesystem", {}),
                   inventory=d.get("inventory", {}), tools=d.get("tools", {}),
                   diagnostics=d.get("diagnostics", []),
                   entries=[Entry.from_dict(e) for e in d.get("entries", [])])


def save_manifest(m: Manifest, path: Path):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(m.to_dict(), f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def load_manifest(path: Path) -> Manifest:
    with open(path, encoding="utf-8") as f:
        return Manifest.from_dict(json.load(f))
