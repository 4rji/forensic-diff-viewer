"""The Sleuth Kit wrappers (mmls, fsstat, fls, icat) and parsers for their output.

All TSK tools open images read-only. ``fls`` names are raw bytes: TSK passes non-UTF-8 bytes
through but renders control characters (e.g. newline) as ``^``. The ``-> target`` suffix that
``fls -m`` appends to symlink names is never trusted on its own (see analyzer).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TYPE_CHARS = {
    "r": "file", "d": "dir", "l": "symlink", "c": "chr", "b": "blk", "p": "fifo",
    "s": "socket", "h": "unknown", "w": "unknown", "-": "unknown", "V": "virtual",
}


def parse_mode_string(s: str) -> tuple[str, int]:
    """``"r/rrwsr-xr-x"`` -> ``("file", 0o4755)`` (type from the metadata part)."""
    if len(s) != 12 or s[1] != "/" or s[0] not in TYPE_CHARS or s[2] not in TYPE_CHARS:
        raise ValueError(f"bad mode string {s!r}")
    ftype = TYPE_CHARS[s[2]]
    perms = s[3:]
    mode = 0
    for i, (r, w, x) in enumerate((perms[0:3], perms[3:6], perms[6:9])):
        shift = 6 - 3 * i
        if r == "r":
            mode |= 4 << shift
        elif r != "-":
            raise ValueError(f"bad mode string {s!r}")
        if w == "w":
            mode |= 2 << shift
        elif w != "-":
            raise ValueError(f"bad mode string {s!r}")
        special = (0o4000, 0o2000, 0o1000)[i]
        special_chars = ("sS", "sS", "tT")[i]
        if x == "x":
            mode |= 1 << shift
        elif x == special_chars[0]:
            mode |= (1 << shift) | special
        elif x == special_chars[1]:
            mode |= special
        elif x != "-":
            raise ValueError(f"bad mode string {s!r}")
    return ftype, mode


@dataclass
class BodyRow:
    name: bytes
    inode: int
    type: str
    mode: int
    uid: int
    gid: int
    size: int
    atime: int
    mtime: int
    ctime: int
    crtime: int


def parse_body_line(line: bytes) -> BodyRow:
    """Parse one ``fls -m`` body line; ``|`` inside names is handled by splitting from the right."""
    parts = line.split(b"|", 1)
    if len(parts) != 2:
        raise ValueError("not a body line")
    fields = parts[1].rsplit(b"|", 9)
    if len(fields) != 10:
        raise ValueError("wrong number of body fields")
    name, inode, mode = fields[0], fields[1], fields[2]
    try:
        ino = int(inode.split(b"-")[0])
        ftype, perm = parse_mode_string(mode.decode("ascii"))
        nums = [int(x) for x in fields[3:]]
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"bad body field: {exc}") from exc
    if not name:
        raise ValueError("empty name")
    uid, gid, size, atime, mtime, ctime, crtime = nums
    return BodyRow(name, ino, ftype, perm, uid, gid, size, atime, mtime, ctime, crtime)


def _geometry_args(offset_sectors, sector_size):
    args = []
    if sector_size and sector_size != 512:
        args += ["-b", str(sector_size)]
    if offset_sectors:
        args += ["-o", str(offset_sectors)]
    return args


@dataclass
class Inventory:
    rows: list
    result: object  # RunResult
    virtual_excluded: int = 0
    bad_lines: list = field(default_factory=list)  # (line_number, hex) of unparseable lines

    @property
    def complete(self) -> bool:
        return self.result.ok and not self.bad_lines


def fls_inventory(runner, image: Path, offset_sectors=None, sector_size=512) -> Inventory:
    argv = ["fls", "-r", "-p", "-u", "-m", "/", *_geometry_args(offset_sectors, sector_size),
            str(image)]
    res = runner.run(argv, tool="fls")
    rows, bad, virtual = [], [], 0
    for n, line in enumerate(res.stdout.split(b"\n"), 1):
        if not line:
            continue
        try:
            row = parse_body_line(line)
        except ValueError:
            bad.append((n, line[:512].hex()))
            continue
        if row.type == "virtual" or row.name == b"/$OrphanFiles" \
                or row.name.startswith(b"/$OrphanFiles/"):
            virtual += 1
            continue
        rows.append(row)
    return Inventory(rows=rows, result=res, virtual_excluded=virtual, bad_lines=bad)


@dataclass
class Partition:
    number: int
    slot: str
    start: int
    length: int
    description: str


@dataclass
class Layout:
    table_type: str
    sector_size: int
    partitions: list
    result: object = None


_MMLS_ROW = re.compile(r"^\d+:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$")


def parse_mmls(text: str) -> Layout:
    lines = text.splitlines()
    if not lines:
        raise ValueError("empty mmls output")
    m = re.search(r"Units are in (\d+)-byte sectors", text)
    if not m:
        raise ValueError("mmls output without sector size")
    parts = []
    for line in lines:
        row = _MMLS_ROW.match(line.strip())
        if not row:
            continue
        slot, start, _end, length, desc = row.groups()
        if slot == "Meta" or set(slot) == {"-"}:
            continue
        parts.append(Partition(len(parts) + 1, slot, int(start), int(length), desc.strip()))
    return Layout(table_type=lines[0].strip(), sector_size=int(m.group(1)), partitions=parts)


def mmls_layout(runner, image: Path) -> Layout | None:
    res = runner.run(["mmls", str(image)], tool="mmls")
    if res.exit_code != 0 or not res.stdout.strip():
        return None
    layout = parse_mmls(res.stdout.decode("utf-8", errors="replace"))
    layout.result = res
    return layout


@dataclass
class FsInfo:
    fs_type: str | None
    last_mounted: str | None
    features: list
    unmounted_properly: bool | None
    result: object = None


def parse_fsstat(text: str) -> FsInfo:
    fs_type = last = None
    clean = None
    features = []
    for line in text.splitlines():
        if line.startswith("File System Type:"):
            fs_type = line.split(":", 1)[1].strip() or None
        elif line.startswith("Last Mounted at:"):
            v = line.split(":", 1)[1].strip()
            last = None if v in ("", "empty") else v
        elif line.strip() == "Unmounted properly":
            clean = True
        elif line.strip() == "Not Unmounted properly":
            clean = False
        elif re.match(r"^(Compat|InCompat|Read Only Compat) Features:", line):
            features += [f.strip() for f in line.split(":", 1)[1].split(",") if f.strip()]
    return FsInfo(fs_type, last, features, clean)


def fsstat_info(runner, image: Path, offset_sectors=None, sector_size=512) -> FsInfo:
    res = runner.run(["fsstat", *_geometry_args(offset_sectors, sector_size), str(image)],
                     tool="fsstat")
    info = parse_fsstat(res.stdout.decode("utf-8", errors="replace"))
    info.result = res
    return info


def icat_stream(runner, image: Path, inode: int, consumer, offset_sectors=None,
                sector_size=512):
    """Stream a file's logical content (sparse holes as zeros, no slack)."""
    argv = ["icat", *_geometry_args(offset_sectors, sector_size), str(image), str(inode)]
    return runner.stream(argv, consumer, tool="icat")
