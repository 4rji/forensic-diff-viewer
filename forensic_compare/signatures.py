"""Magic-byte signature detection, read-only.

The result is an *observation*: an empty list means "none recognized", which never implies
"unencrypted" or "empty".
"""
import os
import struct
from pathlib import Path

PROBE_BYTES = 4096


def _read(path: Path, offset: int, length: int) -> bytes:
    fd = os.open(path, os.O_RDONLY)
    try:
        return os.pread(fd, length, offset)
    finally:
        os.close(fd)


def detect_signature(path: Path, offset: int = 0) -> list[str]:
    head = _read(path, offset, PROBE_BYTES)
    tags = []
    if head[:6] == b"LUKS\xba\xbe" and len(head) >= 8:
        version = struct.unpack(">H", head[6:8])[0]
        tags.append({1: "luks1", 2: "luks2"}.get(version, "luks"))
    if head[:4] == b"hsqs":
        tags.append("squashfs")
    if head[:4] == b"UBI#":
        tags.append("ubi")
    if head[:2] in (b"\x85\x19", b"\x19\x85"):
        tags.append("jffs2")
    if len(head) >= 4 and struct.unpack(">I", head[:4])[0] == 0x27051956:
        tags.append("uimage")
    if len(head) >= 4 and struct.unpack(">I", head[:4])[0] == 0xD00DFEED:
        tags.append("fdt")
    if head[1080:1082] == b"\x53\xef":
        tags.append("ext")
    if head[510:512] == b"\x55\xaa":
        tags.append("mbr")
    if head[512:520] == b"EFI PART":
        tags.append("gpt")
    return tags
