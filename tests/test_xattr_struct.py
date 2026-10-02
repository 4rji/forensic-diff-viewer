from forensic_compare.ext_inode import ExtFS
from forensic_compare.xattr_struct import parse_xattrs
from tests.fixtures.build import CAP_V2_NET_RAW, XATTR_BIN
from tests.helpers import ino_of


def _parse(img, path):
    with ExtFS(img) as fs:
        return parse_xattrs(fs, fs.read_inode(ino_of(img, path)))


def test_absent(fixtures_dir):
    s = _parse(fixtures_dir / "ext/golden.img", "/etc/unchanged.conf")
    assert s.state == "absent" and s.entries == []


def test_in_inode_binary_value(fixtures_dir):
    s = _parse(fixtures_dir / "ext/golden.img", "/etc/xattr_bin")
    assert s.state == "present"
    (e,) = s.entries
    assert e.name == b"user.bin" and e.size == 60 and e.location == "inode"
    assert e.value == XATTR_BIN


def test_block_value_larger_than_inode_space(fixtures_dir):
    s = _parse(fixtures_dir / "ext/golden.img", "/etc/xattr_big")
    (e,) = s.entries
    assert e.name == b"user.big" and e.size == 300 and e.location == "block"
    assert e.value == b"A" * 300


def test_security_capability(fixtures_dir):
    s = _parse(fixtures_dir / "ext/golden.img", "/bin/capchg")
    assert [(e.name, e.value) for e in s.entries] == [(b"security.capability", CAP_V2_NET_RAW)]


def test_corrupt_block_is_error(fixtures_dir):
    s = _parse(fixtures_dir / "ext/corrupt_eablock.img", "/etc/xattr_big")
    assert s.state == "error" and "magic" in s.reason


def test_corrupt_in_inode_header_is_error_not_absent(fixtures_dir):
    s = _parse(fixtures_dir / "ext/corrupt_inode_ea.img", "/etc/xattr_bin")
    assert s.state == "error"
