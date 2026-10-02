import pytest

from forensic_compare.ext_inode import ExtFS, ExtFSError, fast_symlink_target
from tests.helpers import ino_of


def test_reads_fast_symlink_target(fixtures_dir):
    img = fixtures_dir / "ext/golden.img"
    with ExtFS(img) as fs:
        inode = fs.read_inode(ino_of(img, "/link_fast"))
        assert inode.is_symlink and inode.is_fast_symlink
        assert fast_symlink_target(inode) == b"etc/unchanged.conf"


def test_slow_symlink_is_not_fast(fixtures_dir):
    img = fixtures_dir / "ext/golden.img"
    with ExtFS(img) as fs:
        inode = fs.read_inode(ino_of(img, "/link_slow"))
        assert inode.is_symlink and not inode.is_fast_symlink and inode.size == 100
        with pytest.raises(ValueError):
            fast_symlink_target(inode)


def test_hostile_symlink_target_bytes(fixtures_dir):
    img = fixtures_dir / "ext/golden.img"
    with ExtFS(img) as fs:
        inode = fs.read_inode(ino_of(img, "/link_hostile"))
        assert fast_symlink_target(inode) == b"</script><img src=x onerror=alert(2)>"


def test_inline_data_fs_symlink(fixtures_dir):
    img = fixtures_dir / "ext/inline.img"
    with ExtFS(img) as fs:
        assert fast_symlink_target(fs.read_inode(ino_of(img, "/tinylink"))) == b"tiny"


def test_offset_reading_matches_standalone(fixtures_dir):
    standalone = fixtures_dir / "ext/current.img"
    disk = fixtures_dir / "disk/current.dd"
    ino = ino_of(standalone, "/link_fast")
    with ExtFS(standalone) as a, ExtFS(disk, offset=4096 * 512) as b:
        assert a.read_inode(ino).raw == b.read_inode(ino).raw
        assert a.block_size == b.block_size == 1024


def test_needs_recovery_flag(fixtures_dir):
    with ExtFS(fixtures_dir / "ext/recovery.img") as fs:
        assert fs.needs_recovery
    with ExtFS(fixtures_dir / "ext/current.img") as fs:
        assert not fs.needs_recovery


def test_bad_magic_raises(tmp_path):
    p = tmp_path / "zero.img"
    p.write_bytes(b"\0" * 8192)
    with pytest.raises(ExtFSError):
        ExtFS(p).__enter__()


def test_inode_out_of_range(fixtures_dir):
    with ExtFS(fixtures_dir / "ext/golden.img") as fs:
        with pytest.raises(ExtFSError):
            fs.read_inode(10 ** 9)
        with pytest.raises(ExtFSError):
            fs.read_inode(0)


def test_opened_read_only(fixtures_dir):
    # fixtures are 0444; opening must not require write access
    with ExtFS(fixtures_dir / "ext/golden.img") as fs:
        assert fs.inode_size == 256
