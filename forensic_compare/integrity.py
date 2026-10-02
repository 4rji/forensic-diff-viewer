"""Image integrity: supplied checksum manifests and pre/post-analysis hashing.

Verdicts per image:

- ``verified``          — supplied checksum matches and pre == post;
- ``stable-unverified`` — pre == post, no supplied checksum ("stable, unverified against a
                          prior checksum");
- ``failed``            — integrity not established (mismatch, changed during analysis, hashing
                          error, conflicting checksums, or no post-analysis hash).

"Verified" describes image integrity against the supplied checksum; it does not establish that
the firmware is authentic or free of compromise.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

CHUNK = 4 << 20
DISCLAIMER = ("Verified describes image integrity against the supplied checksum; it does not "
              "establish that the firmware is authentic or free of compromise.")
_LINE = re.compile(r"^([0-9a-fA-F]{64}) ([ *])(.+)$")


def sha256_file(path: Path, on_bytes=None) -> str:
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY)
    try:
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            h.update(chunk)
            if on_bytes:
                on_bytes(len(chunk))
    finally:
        os.close(fd)
    return h.hexdigest()


def parse_checksum_file(p: Path):
    """Return (entries {basename: hex}, malformed [line], ignored [(line, reason)])."""
    entries, malformed, ignored = {}, [], []
    for raw in Path(p).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            malformed.append(line[:200])
            continue
        digest, _mode, name = m.group(1).lower(), m.group(2), m.group(3)
        if name == "-":
            ignored.append((line[:200], "stdin marker (not a file)"))
        elif "/" in name or name in (".", ".."):
            ignored.append((line[:200], "not a basename in this directory"))
        elif name in entries and entries[name] != digest:
            entries[name] = None  # conflicting within one file
        else:
            entries[name] = digest
    return entries, malformed, ignored


def expected_checksums(listing):
    """Collect supplied checksums for the listing's images.

    Returns ({image name: [(digest|None, checksum file name)]}, {checksum file: report}).
    """
    expected: dict[str, list] = {}
    report = {}
    for f in listing.checksum_files:
        entries, malformed, ignored = parse_checksum_file(f)
        used, unused = [], []
        for name, digest in entries.items():
            if name in listing.images:
                expected.setdefault(name, []).append((digest, f.name))
                used.append(name)
            else:
                unused.append(name)
        report[f.name] = {"used": sorted(used), "not_matching_an_image": sorted(unused),
                          "malformed": malformed, "ignored": [list(x) for x in ignored]}
    return expected, report


@dataclass
class Verdict:
    status: str
    reason: str | None
    expected: list
    pre: str | None
    post: str | None
    errors: list = field(default_factory=list)

    def to_dict(self):
        return {"status": self.status, "reason": self.reason,
                "expected": [{"sha256": d, "file": f} for d, f in self.expected],
                "pre": self.pre, "post": self.post, "errors": self.errors}


class IntegrityTracker:
    """items: iterable of (side, name, path, expected [(digest, file)])."""

    def __init__(self, items, progress=None):
        self.items = {f"{side}:{name}": (side, name, Path(path), list(expected))
                      for side, name, path, expected in items}
        self.pre: dict = {}
        self.post: dict = {}
        self.errors: dict = {k: [] for k in self.items}
        self.progress = progress

    def _hash_all(self, store, phase):
        total = 0
        for _, _, p, _ in self.items.values():
            try:
                total += p.stat().st_size
            except OSError:
                pass
        done = {"bytes": 0, "files": 0}

        def on_bytes(n):
            done["bytes"] += n
            if self.progress:
                self.progress.update(done["files"], len(self.items), done["bytes"], total,
                                     phase=phase)

        for key, (_, _, p, _) in self.items.items():
            try:
                store[key] = sha256_file(p, on_bytes)
            except OSError as exc:
                store[key] = None
                self.errors[key].append(f"{phase}: {exc.strerror or exc}")
            done["files"] += 1
        if self.progress:
            self.progress.update(done["files"], len(self.items), done["bytes"], total, phase=phase)

    def hash_pre(self):
        self._hash_all(self.pre, "hashing images (pre-analysis)")

    def hash_post(self):
        self._hash_all(self.post, "hashing images (post-analysis)")

    def verdicts(self) -> dict:
        out = {}
        for key, (_, _, _, expected) in self.items.items():
            pre, post = self.pre.get(key), self.post.get(key)
            digests = {d for d, _ in expected}
            errors = self.errors[key]
            if errors:
                status, reason = "failed", "hashing error: " + "; ".join(errors)
            elif key not in self.post:
                status, reason = "failed", "no post-analysis hash"
            elif pre != post:
                status, reason = "failed", "image changed during analysis (pre/post hash differ)"
            elif None in digests or len(digests) > 1:
                status, reason = "failed", "conflicting checksums supplied for this image"
            elif digests and pre not in digests:
                status, reason = "failed", "mismatch against supplied checksum"
            elif digests:
                status, reason = "verified", None
            else:
                status, reason = "stable-unverified", "stable, unverified against a prior checksum"
            out[key] = Verdict(status, reason, expected, pre, post, list(errors))
        return out

    def overall(self) -> str:
        statuses = {v.status for v in self.verdicts().values()}
        if "failed" in statuses:
            return "failed"
        if statuses == {"verified"}:
            return "verified"
        return "stable-unverified"
