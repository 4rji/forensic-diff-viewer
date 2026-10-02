"""Deterministic synthetic fixture builder.

Builds ext4 images (with ``mke2fs -d``), partitioned disk images and capture directories used
by the test-suite. ``debugfs -w`` is used ONLY on images freshly generated here, never on
evidence.

Usage: python tests/fixtures/build.py OUTDIR
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
from pathlib import Path

T = 1700000000  # fixed timestamp
UUID = "11111111-2222-3333-4444-555555555555"
FS_KB = 4096
ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + b"fake-elf-body" * 20

CAP_V2_NET_RAW = bytes.fromhex("01000002" "00200000" "00000000" "00000000" "00000000")
CAP_V3_BIND_ROOTID_1000 = bytes.fromhex(
    "00000003" "00040000" "00000000" "00000000" "00000000" "e8030000")
XATTR_BIN = bytes(range(60))  # includes NUL
SPARSE_SIZE = 1 << 20
SPARSE_OFFSET = 500000

HOSTILE_HTML_NAME = "<img src=x onerror=alert(1)>"
HOSTILE_QUOTE_NAME = "\"'><svg onload=alert(1)>"
HOSTILE_LINK_TARGET = "</script><img src=x onerror=alert(2)>"


def _tool(name):
    for d in (None, "/usr/sbin", "/sbin"):
        p = shutil.which(name, path=d) if d else shutil.which(name)
        if p:
            return p
    raise FileNotFoundError(name)


def _env():
    return {**os.environ, "E2FSPROGS_FAKE_TIME": str(T), "LC_ALL": "C"}


def _run(argv, **kw):
    r = subprocess.run(argv, env=_env(), capture_output=True, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"{argv!r} failed: {r.stderr.decode(errors='replace')}")
    return r


def expected_sparse_bytes() -> bytes:
    b = bytearray(SPARSE_SIZE)
    b[SPARSE_OFFSET] = ord("X")
    return bytes(b)


# --------------------------------------------------------------------------------------------
# Source trees


def _w(root: Path, rel, data=b"", mode=0o644):
    p = root / os.fsdecode(rel) if isinstance(rel, bytes) else root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    p.chmod(mode)
    return p


def _sparse(root: Path, rel):
    p = root / rel
    with open(p, "wb") as f:
        f.truncate(SPARSE_SIZE)
        f.seek(SPARSE_OFFSET)
        f.write(b"X")
    p.chmod(0o644)


def _symlink(root: Path, rel, target):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, p)


def _fix_times(root: Path):
    paths = sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True)
    for p in paths + [root]:
        os.utime(p, (T, T), follow_symlinks=False)


def _main_tree(root: Path, side: str):
    g = side == "golden"
    _w(root, "etc/unchanged.conf", "a\n")
    _w(root, "etc/modified.conf", "a\n" if g else "b\n")
    if g:
        _w(root, "etc/deleted.conf", "x\n")
    else:
        _w(root, "etc/added.conf", "x\n")
    _w(root, "bin/tool", ELF, 0o755 if g else 0o4755)
    _w(root, "bin/sgid", "#!/bin/sh\necho sgid\n", 0o755 if g else 0o2755)
    _w(root, "etc/owner", "owner\n")
    _w(root, "etc/mtime_only", "same\n")
    _w(root, "etc/mode", "mode\n", 0o644 if g else 0o600)
    _w(root, "bin/capped", ELF)
    _w(root, "bin/capchg", ELF)
    _w(root, "etc/xattr_bin", "xb\n")
    _w(root, "etc/xattr_big", "xg\n")
    _w(root, "etc/sec_xattr", "sx\n")
    _symlink(root, "link_fast", "etc/unchanged.conf")
    _symlink(root, "link_retarget", "a" if g else "b")
    _symlink(root, "link_slow", "x" * 100)
    if not g:
        _symlink(root, "link_new", "etc")
    _symlink(root, "link_dangling", "nowhere")
    _symlink(root, "link_hostile", HOSTILE_LINK_TARGET)
    if g:
        _w(root, "file2link", "was a file\n")
    else:
        _symlink(root, "file2link", "etc/unchanged.conf")
    _sparse(root, "sparse.bin")
    _w(root, "hard_a", "hard\n")
    os.link(root / "hard_a", root / "hard_b")
    _w(root, b"pi|pe", "a\n")
    _w(root, b"new\nline", "a\n" if g else "b\n")
    _w(root, b"bad\xff\xfename", "a\n")
    _w(root, HOSTILE_HTML_NAME, "a\n" if g else "b\n")
    _w(root, HOSTILE_QUOTE_NAME, "a\n")
    d = root / "etc/sticky_dir"
    d.mkdir(parents=True)
    _w(root, "etc/sticky_dir/f", "s\n")
    d.chmod(0o1777 if g else 0o777)


def _simple_tree(root: Path, side: str):
    g = side == "golden"
    _w(root, "etc/app.conf", "mode=1\n" if g else "mode=2\n")
    _w(root, "etc/static.conf", "static\n")
    _w(root, "etc/perm.conf", "p\n", 0o644 if g else 0o640)
    if not g:
        _w(root, "etc/new.conf", "new\n")


def _nvram_tree(root: Path, side: str):
    g = side == "golden"
    _w(root, "log/app.log", "boot\n" if g else "boot\nrun\n")
    _w(root, "data/state.json", '{"n": 1}\n')
    if not g:
        _w(root, "log/app.log.1", "rotated\n")


def _inline_tree(root: Path, side: str):
    _w(root, "tiny", "small\n")
    _symlink(root, "tinylink", "tiny")


# --------------------------------------------------------------------------------------------
# Images


def mkfs(src: Path, img: Path, features="^metadata_csum", kb=FS_KB, inodes=None):
    _fix_times(src)
    extra = ["-N", str(inodes)] if inodes else []
    _run([_tool("mke2fs"), "-q", "-F", "-t", "ext4", "-b", "1024", "-I", "256", *extra,
          "-O", features, "-U", UUID, "-E", f"hash_seed={UUID},root_owner=0:0",
          "-d", str(src), str(img), str(kb)])
    normalize_atimes(img)


class _Geometry:
    """Minimal self-contained ext geometry (deliberately independent of the code under test).

    Requires metadata_csum to be disabled (raw edits would otherwise break checksums), which the
    builder enforces.
    """

    def __init__(self, f):
        f.seek(1024)
        sb = f.read(1024)
        self.inodes_count, = struct.unpack_from("<I", sb, 0)
        first_data_block, log_bs = struct.unpack_from("<II", sb, 20)
        self.ipg, = struct.unpack_from("<I", sb, 40)
        self.inode_size, = struct.unpack_from("<H", sb, 88)
        incompat, ro_compat = struct.unpack_from("<II", sb, 96)
        if ro_compat & 0x400:
            raise RuntimeError("fixture builder requires metadata_csum disabled")
        self.desc_size = struct.unpack_from("<H", sb, 254)[0] if incompat & 0x80 else 32
        self.bs = 1024 << log_bs
        self.gdt = (first_data_block + 1) * self.bs
        self.f = f

    def table(self, group):
        self.f.seek(self.gdt + group * self.desc_size)
        desc = self.f.read(self.desc_size)
        table = struct.unpack_from("<I", desc, 8)[0]
        if self.desc_size >= 64:
            table |= struct.unpack_from("<I", desc, 40)[0] << 32
        return table

    def inode_offset(self, ino):
        g, i = divmod(ino - 1, self.ipg)
        return self.table(g) * self.bs + i * self.inode_size


def normalize_atimes(img: Path) -> None:
    """Set i_atime and i_ctime (+extra) of every in-use inode to T.

    ``mke2fs -d`` copies source atimes/ctimes; reading the source updates atime and ctime cannot
    be set from user space, so they are not reproducible.
    """
    with open(img, "r+b") as f:
        geo = _Geometry(f)
        inode_size = geo.inode_size
        for ino in range(1, geo.inodes_count + 1):
            off = geo.inode_offset(ino)
            f.seek(off)
            raw = f.read(inode_size)
            if len(raw) < 132 or struct.unpack_from("<H", raw, 0)[0] == 0:
                continue
            f.seek(off + 8)
            f.write(struct.pack("<II", T, T))  # i_atime, i_ctime
            extra = struct.unpack_from("<H", raw, 128)[0]
            if inode_size > 128 and extra >= 16:  # i_ctime_extra@132, i_atime_extra@140
                f.seek(off + 132)
                f.write(struct.pack("<I", 0))
                f.seek(off + 140)
                f.write(struct.pack("<I", 0))


def _debugfs_stat(img: Path, path: str) -> str:
    return _run([_tool("debugfs"), "-R", f"stat {path}", str(img)]).stdout.decode()


def _patch(img: Path, offset: int, data: bytes, expect: bytes | None = None):
    with open(img, "r+b") as f:
        if expect is not None:
            f.seek(offset)
            got = f.read(len(expect))
            if got != expect:
                raise RuntimeError(f"{img.name}@{offset}: expected {expect.hex()}, got {got.hex()}")
        f.seek(offset)
        f.write(data)


def build_corruptions(out: Path) -> None:
    """Derived images with targeted corruptions (copies of ext/current.img)."""
    import re

    ext = out / "ext"
    src = ext / "current.img"
    ea_magic = struct.pack("<I", 0xEA020000)

    def copy(name):
        dst = ext / name
        shutil.copyfile(src, dst)
        return dst

    def inode_of(img, path):
        return int(re.search(r"Inode: (\d+)", _debugfs_stat(img, path)).group(1))

    # EA block magic of /etc/xattr_big zeroed (debugfs then silently lists nothing)
    img = copy("corrupt_eablock.img")
    acl = int(re.search(r"File ACL: (\d+)", _debugfs_stat(img, "/etc/xattr_big")).group(1))
    with open(img, "rb") as f:
        bs = _Geometry(f).bs
    _patch(img, acl * bs, b"\0\0\0\0", expect=ea_magic)

    # in-inode EA header magic of /etc/xattr_bin zeroed (entries remain)
    img = copy("corrupt_inode_ea.img")
    with open(img, "rb") as f:
        geo = _Geometry(f)
        off = geo.inode_offset(inode_of(img, "/etc/xattr_bin"))
        f.seek(off + 128)
        extra = struct.unpack("<H", f.read(2))[0]
    _patch(img, off + 128 + extra, b"\0\0\0\0", expect=ea_magic)

    # extent header magic (0xF30A) of /etc/modified.conf zeroed -> content unreadable
    img = copy("corrupt_extent.img")
    with open(img, "rb") as f:
        off = _Geometry(f).inode_offset(inode_of(img, "/etc/modified.conf"))
    _patch(img, off + 40, b"\0\0", expect=b"\x0a\xf3")

    # superblock incompat RECOVER (0x4): filesystem was not cleanly unmounted
    img = copy("recovery.img")
    with open(img, "rb") as f:
        f.seek(1024 + 96)
        incompat = struct.unpack("<I", f.read(4))[0]
    _patch(img, 1024 + 96, struct.pack("<I", incompat | 0x4))


def debugfs_w(img: Path, commands: list[str], tmp: Path):
    """Run write-mode debugfs commands on a FRESH FIXTURE image (never on evidence)."""
    cmdfile = tmp / f"{img.name}.cmds"
    cmdfile.write_text("\n".join(commands) + "\n")
    r = _run([_tool("debugfs"), "-w", "-f", str(cmdfile), str(img)])
    out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
    bad = [l for l in out.splitlines()
           if l.strip() and not l.startswith("debugfs") and not l.startswith("\t")]
    if bad:
        raise RuntimeError(f"debugfs -w reported problems on {img.name}: {bad}")


def _postprocess_main(img: Path, side: str, tmp: Path):
    g = side == "golden"
    blobs = tmp / f"blobs-{side}"
    blobs.mkdir(exist_ok=True)

    def blob(name, data):
        p = blobs / name
        p.write_bytes(data)
        return p

    cmds = [
        f"sif /etc/owner uid {1000 if g else 0}",
        "sif /etc/owner gid 1000",
        f"sif /etc/mtime_only mtime {T if g else T + 60}",
        f"ea_set -f {blob('bin', XATTR_BIN)} /etc/xattr_bin user.bin",
        f"ea_set -f {blob('big', (b'A' if g else b'B') * 300)} /etc/xattr_big user.big",
        f"ea_set -f {blob('capchg', CAP_V2_NET_RAW if g else CAP_V3_BIND_ROOTID_1000)} "
        f"/bin/capchg security.capability",
    ]
    if not g:
        cmds += [
            f"ea_set -f {blob('cap', CAP_V2_NET_RAW)} /bin/capped security.capability",
            "ea_set /etc/sec_xattr security.foo bar",
        ]
    debugfs_w(img, cmds, tmp)


def _fresh(tmp: Path, name: str) -> Path:
    d = tmp / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    return d


def build_ext(out: Path, tmp: Path) -> None:
    ext = out / "ext"
    ext.mkdir(parents=True, exist_ok=True)
    for side in ("golden", "current"):
        src = _fresh(tmp, f"src-main-{side}")
        _main_tree(src, side)
        img = ext / f"{side}.img"
        mkfs(src, img)
        _postprocess_main(img, side, tmp)

        src = _fresh(tmp, f"src-simple-{side}")
        _simple_tree(src, side)
        mkfs(src, ext / f"simple_{side}.img", kb=2048)

        src = _fresh(tmp, f"src-nvram-{side}")
        _nvram_tree(src, side)
        mkfs(src, ext / f"nvram_{side}.img", kb=2048)

    src = _fresh(tmp, "src-inline")
    _inline_tree(src, "golden")
    mkfs(src, ext / "inline.img", features="^metadata_csum,inline_data", kb=2048)


def write_mbr_disk(path: Path, p1_image: Path, p1_start: int) -> None:
    """MBR disk: p1 = ext image, p2 = squashfs magic, p3 = synthetic LUKS2 header, p4 = zeros."""
    sector = 512
    fs = p1_image.read_bytes()
    p1_len = len(fs) // sector
    small = 2048  # 1 MiB partitions
    starts = [p1_start, p1_start + p1_len, p1_start + p1_len + small,
              p1_start + p1_len + 2 * small]
    lengths = [p1_len, small, small, small]
    total = starts[3] + small + 2048
    img = bytearray(total * sector)
    table = b""
    for s, n in zip(starts, lengths):
        table += struct.pack("<B3sB3sII", 0, b"\0\0\0", 0x83, b"\0\0\0", s, n)
    img[446:510] = table
    img[510:512] = b"\x55\xaa"
    img[starts[0] * sector:starts[0] * sector + len(fs)] = fs
    img[starts[1] * sector:starts[1] * sector + 4] = b"hsqs"
    img[starts[2] * sector:starts[2] * sector + 8] = b"LUKS\xba\xbe\x00\x02"
    path.write_bytes(bytes(img))


def build_disks(out: Path) -> None:
    disk = out / "disk"
    disk.mkdir(parents=True, exist_ok=True)
    write_mbr_disk(disk / "golden.dd", out / "ext/golden.img", 2048)
    write_mbr_disk(disk / "current.dd", out / "ext/current.img", 4096)


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sums(d: Path, names, wrong=()):
    lines = []
    for n in names:
        digest = _sha(d / n)
        if n in wrong:
            digest = "0" * 64
        lines.append(f"{digest}  {n}")
    (d / "SHA256SUMS").write_text("\n".join(lines) + "\n")


CAPTURE_YAML = {
    "golden": """\
schema: 1
device_model: TEST-MODEL-1
device_serial: null
captured_at: 2026-10-01T10:00:00Z
captured_by: fixture-builder
firmware:
  active: "24.11.6"
  inactive: null
sources:
  config-active-crypt.dd: {role: config-active}
  nvram-crypt.dd: {role: nvram}
  mmcblk0.dd: {role: disk}
partitions:
  mmcblk0.dd:
    1: {role: boot}
    3: {role: config, encrypted: true, mapper_image: config-active-crypt.dd}
notes: "golden fixture"
""",
    "current": """\
schema: 1
device_model: TEST-MODEL-1
captured_at: 2026-10-02T10:00:00Z
captured_by: fixture-builder
firmware:
  active: "24.11.6"
  inactive: null
sources:
  config-active-crypt.dd: {role: config-active}
  nvram-crypt.dd: {role: nvram}
  mmcblk0.dd: {role: disk}
partitions:
  mmcblk0.dd:
    1: {role: boot}
    3: {role: config, encrypted: true, mapper_image: config-active-crypt.dd}
observations:
  - field: firmware.active
    value: "24.11.7"
    command: "cat /etc/version"
    reference: device-info.txt
""",
}

CLEAN_CAPTURE_YAML = """\
schema: 1
device_model: TEST-MODEL-1
captured_at: 2026-10-01T10:00:00Z
captured_by: fixture-builder
firmware:
  active: "24.11.6"
  inactive: "24.11.5"
sources:
  config-active-crypt.dd: {role: config-active}
"""


def build_captures(out: Path) -> None:
    rnd = random.Random(1234)
    mtd = bytes(rnd.getrandbits(8) for _ in range(65536))
    for side in ("golden", "current"):
        d = out / "captures" / side
        d.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / f"ext/{side}.img", d / "config-active-crypt.dd")
        shutil.copyfile(out / f"ext/nvram_{side}.img", d / "nvram-crypt.dd")
        shutil.copyfile(out / f"disk/{side}.dd", d / "mmcblk0.dd")
        (d / "mtdblock0.bin").write_bytes(mtd)
        if side == "golden":
            shutil.copyfile(out / "ext/simple_golden.img", d / "only-golden.dd")
            shutil.copyfile(out / "ext/simple_golden.img", d / "incompat.dd")
        else:
            (d / "incompat.dd").write_bytes(b"hsqs" + b"\0" * 65532)
        images = sorted(p.name for p in d.iterdir())
        _sums(d, images, wrong={"nvram-crypt.dd"} if side == "current" else set())
        digest = _sha(d / "config-active-crypt.dd")
        (d / "config-active-crypt.dd.received.sha256").write_text(f"{digest} *-\n")
        (d / "nvram-crypt.dd.partial").write_bytes(b"partial")
        (d / "acquisition.log").write_text("acquired\n")
        (d / "capture.yaml").write_text(CAPTURE_YAML[side])
        (d / "device-info.txt").write_text(
            "firmware.active=99.99.99\nmodel: SHOULD-NOT-BE-PARSED\n")

        c = out / "captures_clean" / side
        c.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / f"ext/simple_{side}.img", c / "config-active-crypt.dd")
        _sums(c, ["config-active-crypt.dd"])
        (c / "capture.yaml").write_text(CLEAN_CAPTURE_YAML)


def _features(img: Path) -> list[str]:
    r = _run([_tool("debugfs"), "-R", "features", str(img)])
    line = r.stdout.decode().strip()
    return line.split(":", 1)[1].split() if ":" in line else []


def _version(tool) -> str:
    r = subprocess.run([_tool(tool), "-V"], capture_output=True, env=_env())
    text = (r.stdout + r.stderr).decode(errors="replace").strip()
    return text.splitlines()[0] if text else "unknown"


def build_all(out: Path, *, post_ext=None) -> dict:
    """Build every fixture into ``out``. ``post_ext(out, tmp)`` may add derived images."""
    out = Path(out)
    if out.exists():
        for p in out.rglob("*"):
            if p.is_file():
                p.chmod(0o644)
        shutil.rmtree(out)
    out.mkdir(parents=True)
    tmp = out / ".work"
    tmp.mkdir()
    build_ext(out, tmp)
    build_corruptions(out)
    if post_ext:
        post_ext(out, tmp)
    build_disks(out)
    build_captures(out)
    shutil.rmtree(tmp)

    files = sorted(p for p in out.rglob("*") if p.is_file())
    sha = {str(p.relative_to(out)): _sha(p) for p in files}
    meta = {
        "tools": {"mke2fs": _version("mke2fs"), "debugfs": _version("debugfs")},
        "features": {p.name: _features(p) for p in sorted((out / "ext").glob("*.img"))},
        "fake_time": T,
        "uuid": UUID,
        "sha256": sha,
    }
    (out / "fixtures-metadata.json").write_text(json.dumps(meta, indent=1, sort_keys=True))
    for p in files:
        p.chmod(0o444)
    return meta


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: build.py OUTDIR")
    m = build_all(Path(sys.argv[1]))
    print(json.dumps(m["tools"]))
