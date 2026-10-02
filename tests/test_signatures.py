import struct

import pytest

from forensic_compare.signatures import detect_signature


def _img(tmp_path, size=8192, patches=()):
    b = bytearray(size)
    for off, data in patches:
        b[off:off + len(data)] = data
    p = tmp_path / "img"
    p.write_bytes(bytes(b))
    return p


def test_luks2(tmp_path):
    assert detect_signature(_img(tmp_path, patches=[(0, b"LUKS\xba\xbe\x00\x02")])) == ["luks2"]


def test_luks1(tmp_path):
    assert detect_signature(_img(tmp_path, patches=[(0, b"LUKS\xba\xbe\x00\x01")])) == ["luks1"]


def test_ext(tmp_path):
    assert detect_signature(_img(tmp_path, patches=[(1080, b"\x53\xef")])) == ["ext"]


def test_squashfs_at_offset(tmp_path):
    p = _img(tmp_path, patches=[(4096, b"hsqs")])
    assert detect_signature(p, 4096) == ["squashfs"]
    assert detect_signature(p) == []


def test_mbr_and_gpt(tmp_path):
    p = _img(tmp_path, patches=[(510, b"\x55\xaa"), (512, b"EFI PART")])
    assert detect_signature(p) == ["mbr", "gpt"]


@pytest.mark.parametrize("magic,tag", [
    (b"UBI#", "ubi"),
    (b"\x85\x19", "jffs2"),
    (b"\x19\x85", "jffs2"),
    (struct.pack(">I", 0x27051956), "uimage"),
    (struct.pack(">I", 0xD00DFEED), "fdt"),
])
def test_flash_formats(tmp_path, magic, tag):
    assert detect_signature(_img(tmp_path, patches=[(0, magic)])) == [tag]


def test_none_recognized(tmp_path):
    assert detect_signature(_img(tmp_path)) == []


def test_short_file(tmp_path):
    p = tmp_path / "tiny"
    p.write_bytes(b"UBI")
    assert detect_signature(p) == []
