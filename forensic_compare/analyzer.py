"""Analysis of one image on one side: filesystem inventory, disk layout or image-level facts.

Tool failures never raise: they become ``error`` assessments (shown as "not assessed") or a
``partial`` inventory, so incomplete analysis is always visible.
"""
from __future__ import annotations

import hashlib
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .capabilities import decode_capability
from .ext_inode import ExtFS, ExtFSError, fast_symlink_target
from .manifest import Assessed, Entry, Manifest, encode_path
from .progress import Progress
from .signatures import detect_signature
from .tools.debugfs import XattrExtractor
from .tools.tsk import fls_inventory, fsstat_info, icat_stream, mmls_layout

SNIFF_BYTES = 4096
MAX_SYMLINK_BYTES = 1 << 16
CAP_XATTR = "security.capability"
S_IFMT = 0xF000
_ROOT_TYPES = {0x4000: "dir"}


def sniff_kind(head: bytes, total: int) -> str:
    if total == 0:
        return "empty"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"#!"):
        return "script"
    if b"\0" in head:
        return "binary"
    try:
        head.decode("utf-8")
        return "text"
    except UnicodeDecodeError as exc:
        # a multi-byte character cut by the sniff window is still text
        if len(head) == SNIFF_BYTES and exc.start >= len(head) - 3 and "end" in exc.reason:
            return "text"
        return "binary"


def tsk_render(name: bytes) -> bytes:
    """How TSK renders a name: control characters become '^'."""
    return bytes(b"^"[0] if b < 0x20 else b for b in name)


class _Hasher:
    def __init__(self, on_bytes):
        self.h = hashlib.sha256()
        self.head = bytearray()
        self.n = 0
        self.on_bytes = on_bytes

    def __call__(self, chunk: bytes):
        self.h.update(chunk)
        if len(self.head) < SNIFF_BYTES:
            self.head += chunk[:SNIFF_BYTES - len(self.head)]
        self.n += len(chunk)
        self.on_bytes(len(chunk))


def analyze_ext(runner, image: Path, *, side: str, source_id: str, offset_bytes: int = 0,
                sector_size: int = 512, jobs: int = 4, quiet: bool = True,
                progress_stream=None) -> Manifest:
    image = Path(image)
    offset_sectors = offset_bytes // sector_size if offset_bytes else None
    m = Manifest.new(side=side, source_id=source_id)
    m.image = {"name": image.name, "path": str(image)}
    progress = Progress(f"{source_id} · {side}", quiet=quiet, stream=progress_stream)

    # -- filesystem facts --------------------------------------------------------------------
    info = fsstat_info(runner, image, offset_sectors, sector_size)
    warnings = []
    fs = None
    try:
        fs = ExtFS(image, offset=offset_bytes).__enter__()
    except (ExtFSError, OSError) as exc:
        warnings.append(f"raw ext reader unavailable: {exc}")
    needs_recovery = fs.needs_recovery if fs else None
    if needs_recovery:
        warnings.append("Filesystem was not cleanly unmounted (needs_recovery): journal not "
                        "replayed; on-disk state may lag the live state")
    fsstat_problems = info.result.problems if info.result else []
    m.filesystem = {
        "kind": "ext",
        "fs_type": info.fs_type,
        "offset_bytes": offset_bytes,
        "sector_size": sector_size,
        "block_size": fs.block_size if fs else None,
        "features": info.features,
        "last_mounted": (Assessed.ok(info.last_mounted) if info.result.ok
                         else Assessed.error(info.result.describe(), info.result.log_id)
                         ).to_dict(),
        "unmounted_properly": info.unmounted_properly,
        "needs_recovery": needs_recovery,
        "warnings": warnings,
        "state": "complete" if info.result.ok and fs else "partial",
        "fsstat_log_id": info.result.log_id,
    }
    m.diagnostics += [dict(d, tool="fsstat") for d in fsstat_problems]

    try:
        # -- inventory -----------------------------------------------------------------------
        progress.message("listing files")
        inv = fls_inventory(runner, image, offset_sectors, sector_size)
        m.inventory = {
            "state": "complete" if inv.complete else "partial",
            "diagnostics": inv.result.problems,
            "exit_code": inv.result.exit_code,
            "virtual_excluded": inv.virtual_excluded,
            "bad_lines": len(inv.bad_lines),
            "bad_line_samples": inv.bad_lines[:5],
            "log_id": inv.result.log_id,
        }
        entries = [_entry_from_row(row) for row in inv.rows]
        root = _root_entry(fs)
        if root is not None:
            entries.insert(0, root)

        # -- symlinks (raw inode for fast links; icat for others; cross-checked) -----------
        for e, row in zip(entries[1 if root else 0:], inv.rows):
            if row.type == "symlink":
                _fill_symlink(e, row, fs, runner, image, offset_sectors, sector_size)
            _finalize_path(e, row.name if row.type != "symlink" else e.fs_flags.pop("_name"))

        # -- contents ------------------------------------------------------------------------
        _hash_contents(entries, runner, image, offset_sectors, sector_size, jobs, progress)

        # -- xattrs / capabilities -----------------------------------------------------------
        _fill_xattrs(entries, runner, image, offset_bytes, fs, progress)

        # -- ambiguity -----------------------------------------------------------------------
        counts = {}
        for e in entries:
            counts[e.path_hex] = counts.get(e.path_hex, 0) + 1
        for e in entries:
            if counts[e.path_hex] > 1:
                e.fs_flags["ambiguous"] = True
        m.entries = entries
    finally:
        if fs:
            fs.close()
        progress.finish()
    m.tools = dict(runner.versions)
    return m


def _entry_from_row(row) -> Entry:
    e = Entry.blank("", "", row.inode)
    e.type = Assessed.ok(row.type)
    e.mode = Assessed.ok(row.mode)
    e.uid = Assessed.ok(row.uid)
    e.gid = Assessed.ok(row.gid)
    e.size = Assessed.ok(row.size)
    e.mtime = Assessed.ok(row.mtime)
    e.times = {"atime": row.atime, "ctime": row.ctime, "crtime": row.crtime}
    e.content = Assessed.na() if row.type != "file" else Assessed.error("not extracted")
    e.symlink = Assessed.na() if row.type != "symlink" else Assessed.error("not extracted")
    e.fs_flags["_name"] = row.name
    return e


def _finalize_path(e: Entry, name: bytes):
    e.fs_flags.pop("_name", None)
    e.path, e.path_hex = encode_path(name)
    e.path_lossy = e.path_lossy or b"^" in name


def _root_entry(fs) -> Entry | None:
    """The root directory is not listed by fls; take its metadata from the raw inode."""
    if fs is None:
        return None
    try:
        raw = fs.read_inode(2).raw
    except ExtFSError:
        return None
    mode, uid_lo, size_lo = struct.unpack_from("<HHI", raw, 0)
    mtime, = struct.unpack_from("<I", raw, 16)
    gid_lo, = struct.unpack_from("<H", raw, 24)
    uid_hi, gid_hi = struct.unpack_from("<HH", raw, 120)
    e = Entry.blank("/", b"/".hex(), 2)
    e.type = Assessed.ok(_ROOT_TYPES.get(mode & S_IFMT, "unknown"))
    e.mode = Assessed.ok(mode & 0o7777)
    e.uid = Assessed.ok(uid_lo | uid_hi << 16)
    e.gid = Assessed.ok(gid_lo | gid_hi << 16)
    e.size = Assessed.ok(size_lo)
    e.mtime = Assessed.ok(mtime)
    e.content = Assessed.na()
    e.symlink = Assessed.na()
    e.fs_flags["source"] = "raw inode 2 (root directory is not listed by fls)"
    e.fs_flags["_name"] = b"/"
    _finalize_path(e, b"/")
    return e


def _fill_symlink(e, row, fs, runner, image, offset_sectors, sector_size):
    name = e.fs_flags["_name"]
    target = None
    reason = None
    fast = False
    if fs is None:
        reason = "raw ext reader unavailable; cannot validate symlink target"
    else:
        try:
            inode = fs.read_inode(row.inode)
        except ExtFSError as exc:
            inode, reason = None, f"raw inode not readable: {exc}"
        if inode is not None and not inode.is_symlink:
            reason = "fls reports a symlink but the raw inode is not one"
        elif inode is not None:
            if inode.is_fast_symlink or inode.flags & 0x10000000 and inode.size <= 60:
                target = fast_symlink_target(inode)
                fast = True
            elif inode.size > MAX_SYMLINK_BYTES:
                reason = f"symlink target too large ({inode.size} bytes)"
            else:
                buf = bytearray()
                res = icat_stream(runner, image, row.inode, buf.extend, offset_sectors,
                                  sector_size)
                if not res.ok:
                    reason = f"icat failed: {res.describe()}"
                elif len(buf) != inode.size:
                    reason = f"symlink read {len(buf)} bytes, expected {inode.size}"
                else:
                    target = bytes(buf)
            if target is not None and len(target) != row.size:
                reason, target = f"symlink size mismatch (fls {row.size}, inode {len(target)})", None
    if target is not None:
        # TSK 4.12 appends " -> target" to fast symlink names only. Fast targets read from the
        # raw inode must match it; slow targets come from icat (byte count checked above).
        suffix = b" -> " + tsk_render(target)
        shown, _ = encode_path(target)
        if name.endswith(suffix) and len(name) > len(suffix):
            e.fs_flags["_name"] = name[:-len(suffix)]
            e.fs_flags["symlink_crosscheck"] = "raw inode target matches fls listing"
            e.symlink = Assessed.ok({"target_hex": target.hex(), "target": shown})
            return
        if not fast:
            e.fs_flags["symlink_crosscheck"] = "slow symlink: target read with icat (length " \
                                               "verified); fls does not list slow targets"
            e.symlink = Assessed.ok({"target_hex": target.hex(), "target": shown})
            return
        reason = "symlink target does not match the fls listing"
    e.symlink = Assessed.error(reason)
    e.path_lossy = True  # the listing name may still carry an unverified ' -> ' suffix


def _hash_contents(entries, runner, image, offset_sectors, sector_size, jobs, progress):
    files = {}
    for e in entries:
        if e.type.value == "file":
            files.setdefault(e.inode, []).append(e)
    total_files = len(files)
    total_bytes = sum(es[0].size.value for es in files.values())
    lock = threading.Lock()
    state = {"files": 0, "bytes": 0}

    def on_bytes(n):
        with lock:
            state["bytes"] += n
            progress.update(state["files"], total_files, state["bytes"], total_bytes)

    def work(item):
        ino, es = item
        hasher = _Hasher(on_bytes)
        res = icat_stream(runner, image, ino, hasher, offset_sectors, sector_size)
        size = es[0].size.value
        if res.timed_out:
            result = Assessed.error(f"icat timeout ({res.describe()})", res.log_id)
        elif not res.ok:
            result = Assessed.error(f"icat failed: {res.describe()}", res.log_id)
        elif hasher.n != size:
            word = "short" if hasher.n < size else "long"
            result = Assessed.error(f"{word} read: {hasher.n} of {size} bytes", res.log_id)
        else:
            result = Assessed.ok({"sha256": hasher.h.hexdigest(), "bytes_read": hasher.n,
                                  "kind": sniff_kind(bytes(hasher.head), hasher.n)})
        for e in es:
            e.content = Assessed(result.state, dict(result.value) if result.value else None,
                                 result.reason, result.log_id)
        with lock:
            state["files"] += 1
            progress.update(state["files"], total_files, state["bytes"], total_bytes)

    progress.update(0, total_files, 0, total_bytes)
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        list(pool.map(work, files.items()))


def _fill_xattrs(entries, runner, image, offset_bytes, fs, progress):
    if fs is None:
        for e in entries:
            e.xattrs = e.capability = Assessed.error("raw ext reader unavailable; xattrs "
                                                     "cannot be validated")
        return
    inodes = sorted({e.inode for e in entries})

    def on_list(done, total):
        progress.update(done, total, 0, 0, phase="xattrs")

    results = XattrExtractor(runner, image, offset_bytes, fs, progress=on_list).extract(inodes)
    for e in entries:
        r = results.get(e.inode, Assessed.error("xattrs not extracted"))
        if r.state == "error":
            e.xattrs = Assessed.error(r.reason, r.log_id)
            e.capability = Assessed.error(r.reason, r.log_id)
            continue
        if r.state == "absent":
            e.xattrs = Assessed.absent()
            e.capability = Assessed.absent()
            continue
        items = dict(r.value)
        cap = items.pop(CAP_XATTR, None)
        e.xattrs = Assessed.ok(items) if items else Assessed.absent()
        if cap is None:
            e.capability = Assessed.absent()
        else:
            try:
                decoded = decode_capability(bytes.fromhex(cap["hex"]))
                e.capability = Assessed.ok({**decoded, "hex": cap["hex"]})
            except ValueError as exc:
                e.capability = Assessed.error(f"malformed security.capability: {exc}")


# --------------------------------------------------------------------------------------------
# Source-level analysis: kind detection, disks, image-level sources

ENCRYPTED_SIGNATURES = {"luks", "luks1", "luks2"}
UNSUPPORTED_SIGNATURES = {"squashfs": "squashfs: needs a read-only extractor",
                          "ubi": "UBI: needs a read-only extractor",
                          "jffs2": "JFFS2: needs a read-only extractor"}
IMAGE_LEVEL_REASON = ("Structural analysis not supported: image-level hash comparison only")


@dataclass
class KindInfo:
    kind: str  # "ext-fs" | "disk" | "image-level" | "unreadable"
    signatures: list = field(default_factory=list)
    layout: object = None
    reason: str | None = None


@dataclass
class PartitionAnalysis:
    number: int
    slot: str
    start: int
    length: int
    description: str
    sector_size: int
    offset_bytes: int
    signatures: list
    status: str  # "analyzed" | "encrypted" | "unsupported" | "unknown" | "unreadable"
    manifest: Manifest | None = None
    reason: str | None = None


@dataclass
class SourceAnalysis:
    side: str
    source_id: str
    image: str
    kind: str
    signatures: list = field(default_factory=list)
    image_size: int | None = None
    manifest: Manifest | None = None
    layout: object = None
    partitions: list = field(default_factory=list)
    reason: str | None = None


def detect_kind(runner, image: Path) -> KindInfo:
    try:
        sigs = detect_signature(Path(image))
    except OSError as exc:
        return KindInfo("unreadable", reason=f"cannot read image: {exc.strerror or exc}")
    if "ext" in sigs:
        return KindInfo("ext-fs", sigs)
    if "mbr" in sigs or "gpt" in sigs:
        layout = mmls_layout(runner, Path(image))
        if layout is not None and layout.partitions:
            return KindInfo("disk", sigs, layout)
        return KindInfo("image-level", sigs, reason="partition table signature found but mmls "
                                                    "found no partitions; " + IMAGE_LEVEL_REASON)
    reason = IMAGE_LEVEL_REASON
    for s in sigs:
        if s in UNSUPPORTED_SIGNATURES:
            reason = UNSUPPORTED_SIGNATURES[s] + "; " + IMAGE_LEVEL_REASON
        elif s in ENCRYPTED_SIGNATURES:
            reason = "encrypted volume; " + IMAGE_LEVEL_REASON
    return KindInfo("image-level", sigs, reason=reason)


def analyze_source(runner, image: Path, *, side: str, source_id: str, jobs: int = 4,
                   quiet: bool = True, progress_stream=None) -> SourceAnalysis:
    image = Path(image)
    k = detect_kind(runner, image)
    out = SourceAnalysis(side=side, source_id=source_id, image=str(image), kind=k.kind,
                         signatures=k.signatures, layout=k.layout, reason=k.reason)
    try:
        out.image_size = image.stat().st_size
    except OSError as exc:
        out.kind = "unreadable"
        out.reason = f"cannot stat image: {exc.strerror or exc}"
        return out
    if k.kind == "ext-fs":
        out.manifest = analyze_ext(runner, image, side=side, source_id=source_id, jobs=jobs,
                                   quiet=quiet, progress_stream=progress_stream)
    elif k.kind == "disk":
        out.partitions = [_analyze_partition(runner, image, side, source_id, p,
                                             k.layout.sector_size, out.image_size, jobs, quiet,
                                             progress_stream)
                          for p in k.layout.partitions]
    return out


def _analyze_partition(runner, image, side, source_id, p, sector_size, image_size, jobs, quiet,
                       progress_stream) -> PartitionAnalysis:
    offset = p.start * sector_size
    pa = PartitionAnalysis(number=p.number, slot=p.slot, start=p.start, length=p.length,
                           description=p.description, sector_size=sector_size,
                           offset_bytes=offset, signatures=[], status="unknown")
    if offset + p.length * sector_size > image_size:
        pa.status, pa.reason = "unreadable", "partition extends beyond the end of the image"
        return pa
    try:
        pa.signatures = detect_signature(Path(image), offset)
    except OSError as exc:
        pa.status, pa.reason = "unreadable", f"cannot read partition: {exc.strerror or exc}"
        return pa
    sigs = set(pa.signatures)
    if "ext" in sigs:
        pa.status = "analyzed"
        pa.manifest = analyze_ext(runner, image, side=side, source_id=f"{source_id}#p{p.number}",
                                  offset_bytes=offset, sector_size=sector_size, jobs=jobs,
                                  quiet=quiet, progress_stream=progress_stream)
    elif sigs & ENCRYPTED_SIGNATURES:
        pa.status, pa.reason = "encrypted", "encrypted volume signature; contents not readable"
    elif sigs & set(UNSUPPORTED_SIGNATURES):
        pa.status = "unsupported"
        pa.reason = next(UNSUPPORTED_SIGNATURES[s] for s in pa.signatures
                         if s in UNSUPPORTED_SIGNATURES)
    else:
        pa.status = "unknown"
        pa.reason = "no recognized signature (this does not imply the partition is unencrypted)"
    return pa
