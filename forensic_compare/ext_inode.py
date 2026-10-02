"""Read-only raw ext2/3/4 inode reader.

Deliberately independent of both TSK and debugfs: it is used to cross-validate their output
(fast symlink targets, which TSK 4.12.1 ``icat`` returns as NULs, and xattr structures, which
debugfs 1.47.2 can silently drop). The image is opened with ``O_RDONLY`` and read with
``pread`` at the filesystem's byte offset.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from pathlib import Path

EXT_MAGIC = 0xEF53
INCOMPAT_RECOVER = 0x4
INCOMPAT_64BIT = 0x80
EXT4_EXTENTS_FL = 0x80000
EXT4_INLINE_DATA_FL = 0x10000000
EXT4_EA_INODE_FL = 0x200000
EXT4_HUGE_FILE_FL = 0x40000
S_IFMT = 0xF000
S_IFLNK = 0xA000


class ExtFSError(Exception):
    pass


@dataclass
class RawInode:
    ino: int
    raw: bytes
    mode: int
    flags: int
    size: int
    blocks_lo: int
    i_block: bytes
    file_acl: int
    extra_isize: int
    block_size: int

    @property
    def is_symlink(self) -> bool:
        return self.mode & S_IFMT == S_IFLNK

    @property
    def is_fast_symlink(self) -> bool:
        """Mirror of the kernel's ext4_inode_is_fast_symlink()."""
        if not self.is_symlink:
            return False
        if self.flags & EXT4_EA_INODE_FL:
            return 0 < self.size < 60
        if self.flags & EXT4_INLINE_DATA_FL:
            return False
        ea_blocks = (self.block_size >> 9) if self.file_acl else 0
        return self.blocks_lo - ea_blocks == 0 and self.size < 60


def fast_symlink_target(inode: RawInode) -> bytes:
    """Target of a symlink stored inside the inode (fast symlink or small inline-data link)."""
    if inode.is_fast_symlink:
        return inode.i_block[:inode.size]
    if inode.is_symlink and inode.flags & EXT4_INLINE_DATA_FL and inode.size <= 60:
        return inode.i_block[:inode.size]
    raise ValueError(f"inode {inode.ino} is not a fast/inline symlink")


class ExtFS:
    def __init__(self, path: Path, offset: int = 0):
        self.path = Path(path)
        self.offset = offset
        self._fd = None

    def __enter__(self):
        self._fd = os.open(self.path, os.O_RDONLY)
        try:
            self._load_superblock()
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def _pread(self, length: int, pos: int) -> bytes:
        data = os.pread(self._fd, length, self.offset + pos)
        if len(data) != length:
            raise ExtFSError(f"short read at {pos} ({len(data)}/{length} bytes)")
        return data

    def _load_superblock(self):
        sb = self._pread(1024, 1024)
        magic = struct.unpack_from("<H", sb, 56)[0]
        if magic != EXT_MAGIC:
            raise ExtFSError(f"bad ext superblock magic 0x{magic:04x}")
        self.inodes_count = struct.unpack_from("<I", sb, 0)[0]
        self.first_data_block, log_bs = struct.unpack_from("<II", sb, 20)
        self.inodes_per_group = struct.unpack_from("<I", sb, 40)[0]
        rev_level = struct.unpack_from("<I", sb, 76)[0]
        self.inode_size = struct.unpack_from("<H", sb, 88)[0] if rev_level >= 1 else 128
        self.feature_compat, self.feature_incompat, self.feature_ro_compat = \
            struct.unpack_from("<III", sb, 92)
        if log_bs > 6 or self.inodes_per_group == 0 or self.inode_size < 128 \
                or self.inode_size & (self.inode_size - 1):
            raise ExtFSError("implausible ext superblock geometry")
        self.block_size = 1024 << log_bs
        if self.feature_incompat & INCOMPAT_64BIT:
            self.desc_size = struct.unpack_from("<H", sb, 254)[0]
            if self.desc_size < 32 or self.desc_size > 1024:
                raise ExtFSError(f"implausible descriptor size {self.desc_size}")
        else:
            self.desc_size = 32

    @property
    def needs_recovery(self) -> bool:
        return bool(self.feature_incompat & INCOMPAT_RECOVER)

    def read_block(self, blk: int) -> bytes:
        return self._pread(self.block_size, blk * self.block_size)

    def _inode_table(self, group: int) -> int:
        gdt = (self.first_data_block + 1) * self.block_size
        desc = self._pread(self.desc_size, gdt + group * self.desc_size)
        table = struct.unpack_from("<I", desc, 8)[0]
        if self.desc_size >= 64:
            table |= struct.unpack_from("<I", desc, 40)[0] << 32
        return table

    def read_inode(self, ino: int) -> RawInode:
        if not 1 <= ino <= self.inodes_count:
            raise ExtFSError(f"inode {ino} out of range 1..{self.inodes_count}")
        group, index = divmod(ino - 1, self.inodes_per_group)
        pos = self._inode_table(group) * self.block_size + index * self.inode_size
        raw = self._pread(self.inode_size, pos)
        mode, = struct.unpack_from("<H", raw, 0)
        size_lo, = struct.unpack_from("<I", raw, 4)
        blocks_lo, flags = struct.unpack_from("<II", raw, 28)
        i_block = raw[40:100]
        acl_lo, size_hi = struct.unpack_from("<II", raw, 104)
        acl_hi, = struct.unpack_from("<H", raw, 118)
        extra = struct.unpack_from("<H", raw, 128)[0] if self.inode_size > 128 else 0
        if extra and 128 + extra > self.inode_size:
            raise ExtFSError(f"inode {ino}: i_extra_isize {extra} exceeds inode size")
        return RawInode(ino=ino, raw=raw, mode=mode, flags=flags,
                        size=size_lo | (size_hi << 32), blocks_lo=blocks_lo, i_block=i_block,
                        file_acl=acl_lo | (acl_hi << 32), extra_isize=extra,
                        block_size=self.block_size)
