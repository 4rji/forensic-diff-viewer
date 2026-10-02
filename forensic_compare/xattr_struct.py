"""Independent parser of ext4 extended-attribute structures (in-inode area and EA block).

Its result is compared with debugfs's enumeration: only when both agree is an xattr set
considered complete, and only a structurally empty inode is considered to have no xattrs.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .ext_inode import ExtFS, ExtFSError, RawInode

EA_MAGIC = 0xEA020000
ENTRY_HEADER = 16
BLOCK_HEADER = 32

PREFIXES = {
    0: b"",
    1: b"user.",
    2: b"system.posix_acl_access",
    3: b"system.posix_acl_default",
    4: b"trusted.",
    6: b"security.",
    7: b"system.",
    8: b"system.richacl",
}


@dataclass
class XattrEntry:
    name: bytes
    size: int
    inum: int
    location: str  # "inode" | "block"
    value: bytes | None = None  # None when stored in an EA inode (not read here)


@dataclass
class XattrStructure:
    state: str  # "absent" | "present" | "error"
    entries: list = field(default_factory=list)
    reason: str | None = None


class _Bad(Exception):
    pass


def _parse_entries(region: bytes, start: int, value_base: int, location: str) -> list:
    entries = []
    pos = start
    while True:
        if pos + 4 > len(region):
            raise _Bad(f"{location} xattr entry list runs past the end of its region")
        if struct.unpack_from("<I", region, pos)[0] == 0:
            return entries
        if pos + ENTRY_HEADER > len(region):
            raise _Bad(f"{location} xattr entry header truncated")
        name_len, index, voffs, inum, vsize, _hash = struct.unpack_from("<BBHIII", region, pos)
        if name_len == 0 and index not in (2, 3):
            raise _Bad(f"{location} xattr entry with empty name")
        if index not in PREFIXES:
            raise _Bad(f"{location} xattr entry with unknown name index {index}")
        name_end = pos + ENTRY_HEADER + name_len
        if name_end > len(region):
            raise _Bad(f"{location} xattr name runs past the end of its region")
        name = PREFIXES[index] + region[pos + ENTRY_HEADER:name_end]
        value = None
        if inum == 0:
            vstart = value_base + voffs
            if vstart + vsize > len(region) or vstart < value_base:
                raise _Bad(f"{location} xattr value of {name!r} out of bounds")
            value = region[vstart:vstart + vsize]
        entries.append(XattrEntry(name=name, size=vsize, inum=inum, location=location,
                                  value=value))
        pos = (name_end + 3) & ~3


def parse_xattrs(fs: ExtFS, inode: RawInode) -> XattrStructure:
    try:
        entries = []
        # in-inode area
        if fs.inode_size > 128 and inode.extra_isize:
            area_start = 128 + inode.extra_isize
            area = inode.raw[area_start:]
            if len(area) >= 4 and struct.unpack_from("<I", area, 0)[0] == EA_MAGIC:
                # entries start after the 4-byte magic; value offsets are relative to them
                body = area[4:]
                entries += _parse_entries(body, 0, 0, "inode")
            elif any(area):
                raise _Bad("in-inode xattr area has no EA magic but is not empty")
        # external EA block
        if inode.file_acl:
            try:
                block = fs.read_block(inode.file_acl)
            except ExtFSError as exc:
                raise _Bad(f"cannot read EA block {inode.file_acl}: {exc}") from exc
            magic, _refcount, nblocks = struct.unpack_from("<III", block, 0)
            if magic != EA_MAGIC:
                raise _Bad(f"EA block {inode.file_acl} has bad magic 0x{magic:08x}")
            if nblocks != 1:
                raise _Bad(f"EA block {inode.file_acl} has h_blocks={nblocks}")
            entries += _parse_entries(block, BLOCK_HEADER, 0, "block")
        names = [e.name for e in entries]
        if len(names) != len(set(names)):
            raise _Bad("duplicate xattr names")
        if not entries:
            return XattrStructure("absent")
        return XattrStructure("present", entries)
    except (_Bad, struct.error) as exc:
        return XattrStructure("error", reason=str(exc))
