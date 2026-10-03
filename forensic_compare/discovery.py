"""Capture-directory classification and exact-filename pairing."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

IMAGE_EXTENSIONS = (".dd", ".img", ".raw", ".bin")
SUPPORTING_NAMES = ("capture.yaml", "device-info.txt")
CAPTURE_FILE = "capture.yaml"
SIDECAR_SUFFIX = ".capture.yaml"  # <image>.capture.yaml: metadata for one image (single mode)


@dataclass
class DirListing:
    directory: Path
    images: dict = field(default_factory=dict)       # name -> Path
    realpaths: dict = field(default_factory=dict)    # name -> resolved path (str)
    checksum_files: list = field(default_factory=list)
    supporting: dict = field(default_factory=dict)   # name -> Path
    not_used: list = field(default_factory=list)     # (name, reason)
    capture_file: Path | None = None                 # capture metadata read for this side


@dataclass
class Pair:
    source_id: str
    golden: Path
    current: Path


@dataclass
class Unmatched:
    side: str
    name: str
    path: Path


@dataclass
class Pairing:
    mode: str  # "dir" | "single"
    pairs: list
    unmatched: list
    golden_listing: DirListing
    current_listing: DirListing


def _classify_name(name: str) -> tuple[str, str | None]:
    if name.endswith(".partial"):
        return "not_used", "incomplete capture (.partial)"
    if name.endswith(".received.sha256"):
        return "not_used", "received-stream checksum (not an image checksum manifest)"
    if name == "SHA256SUMS" or name.endswith((".sha256", ".sha256sum")):
        return "checksum", None
    if name in SUPPORTING_NAMES:
        return "supporting", None
    if name.endswith(SIDECAR_SUFFIX):
        return "not_used", "per-image capture file (used only when comparing two image files)"
    if name.endswith(IMAGE_EXTENSIONS):
        return "image", None
    return "not_used", "not a supported image or capture file"


def classify_dir(d: Path) -> DirListing:
    d = Path(d)
    lst = DirListing(directory=d)
    for name in sorted(os.listdir(d)):
        p = d / name
        if p.is_dir():
            lst.not_used.append((name, "directory"))
            continue
        kind, reason = _classify_name(name)
        if kind != "not_used" and not p.is_file():
            kind, reason = "not_used", "not a regular file"
        if kind == "image":
            lst.images[name] = p
            lst.realpaths[name] = str(p.resolve())
        elif kind == "checksum":
            lst.checksum_files.append(p)
        elif kind == "supporting":
            lst.supporting[name] = p
        else:
            lst.not_used.append((name, reason))
    lst.capture_file = lst.supporting.get(CAPTURE_FILE)
    return lst


def _single_listing(image: Path) -> DirListing:
    """One image: its own <image>.capture.yaml replaces the directory's capture.yaml, so two
    images in one folder can each carry their own capture metadata."""
    full = classify_dir(image.parent)
    supporting = dict(full.supporting)
    sidecar = image.parent / (image.name + SIDECAR_SUFFIX)
    if sidecar.is_file():
        supporting.pop(CAPTURE_FILE, None)
        supporting[sidecar.name] = sidecar
    else:
        sidecar = full.capture_file
    return DirListing(directory=image.parent, images={image.name: image},
                      realpaths={image.name: str(image.resolve())},
                      checksum_files=full.checksum_files, supporting=supporting,
                      capture_file=sidecar)


def pair_inputs(golden: Path, current: Path) -> Pairing:
    golden, current = Path(golden), Path(current)
    for p in (golden, current):
        if not p.exists():
            raise ValueError(f"input does not exist: {p}")
    if golden.is_dir() and current.is_dir():
        g, c = classify_dir(golden), classify_dir(current)
        common = sorted(set(g.images) & set(c.images))
        pairs = [Pair(n, g.images[n], c.images[n]) for n in common]
        unmatched = [Unmatched("golden", n, g.images[n]) for n in sorted(set(g.images) - set(common))]
        unmatched += [Unmatched("current", n, c.images[n])
                      for n in sorted(set(c.images) - set(common))]
        return Pairing("dir", pairs, unmatched, g, c)
    if golden.is_file() and current.is_file():
        sid = golden.name if golden.name == current.name else f"{golden.name}__vs__{current.name}"
        return Pairing("single", [Pair(sid, golden, current)], [], _single_listing(golden),
                       _single_listing(current))
    raise ValueError("GOLDEN and CURRENT must both be directories or both be image files")
