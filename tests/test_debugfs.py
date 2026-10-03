import os
import tempfile

import pytest

from forensic_compare.ext_inode import ExtFS
from forensic_compare.tools.debugfs import XattrExtractor, parse_ea_list, split_batch
from forensic_compare.tools.runner import ToolRunner
from tests.conftest import require_tools
from tests.fixtures.build import CAP_V2_NET_RAW, XATTR_BIN
from tests.helpers import ino_of

EA_LIST_OUT = """Extended attributes:
  user.big (60)
  user.small (2) = "hi"
  security.capability (20) = 01 00 00 02 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00
"""


def test_parse_ea_list():
    assert parse_ea_list(EA_LIST_OUT) == [("user.big", 60), ("user.small", 2),
                                          ("security.capability", 20)]


def test_parse_ea_list_empty():
    assert parse_ea_list("") == []


def test_parse_ea_list_rejects_unexpected_lines():
    with pytest.raises(ValueError):
        parse_ea_list("Extended attributes:\n  user.x (2)\nsomething else\n")


def test_split_batch():
    out = ("debugfs: ea_list <12>\nExtended attributes:\n  user.a (1) = \"x\"\n"
           "debugfs: ea_list <99999>\n"
           "debugfs: ea_list <13>\n")
    assert split_batch(out) == [
        ("ea_list <12>", "Extended attributes:\n  user.a (1) = \"x\"\n"),
        ("ea_list <99999>", ""),
        ("ea_list <13>", ""),
    ]


def test_split_batch_rejects_text_before_first_echo():
    with pytest.raises(ValueError):
        split_batch("stray\ndebugfs: ea_list <12>\n")


# ---- integration --------------------------------------------------------------------------


@pytest.fixture
def runner(tmp_path):
    return ToolRunner(tmp_path / "log.jsonl", timeout=60, jobs=2)


def _extract(runner, img, paths, offset=0, batch_size=500):
    inos = {p: ino_of(img, p, offset) for p in paths}
    before = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("fcx-")}
    with ExtFS(img, offset=offset) as fs:
        res = XattrExtractor(runner, img, offset, fs, batch_size=batch_size).extract(
            list(inos.values()))
    after = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("fcx-")}
    assert after == before, "temporary xattr files were not cleaned up"
    return {p: res[i] for p, i in inos.items()}


@pytest.mark.integration
def test_values_absent_and_binary(fixtures_dir, runner):
    require_tools("debugfs")
    r = _extract(runner, fixtures_dir / "ext/golden.img",
                 ["/etc/xattr_big", "/etc/xattr_bin", "/etc/unchanged.conf", "/bin/capchg"])
    assert r["/etc/xattr_big"].state == "ok"
    big = r["/etc/xattr_big"].value["user.big"]
    assert big["size"] == 300 and bytes.fromhex(big["hex"]) == b"A" * 300
    assert bytes.fromhex(r["/etc/xattr_bin"].value["user.bin"]["hex"]) == XATTR_BIN
    assert r["/etc/unchanged.conf"].state == "absent"
    assert bytes.fromhex(r["/bin/capchg"].value["security.capability"]["hex"]) == CAP_V2_NET_RAW


@pytest.mark.integration
def test_corrupt_ea_block_is_error_even_though_debugfs_is_silent(fixtures_dir, runner):
    require_tools("debugfs")
    r = _extract(runner, fixtures_dir / "ext/corrupt_eablock.img",
                 ["/etc/xattr_big", "/etc/unchanged.conf"])
    assert r["/etc/xattr_big"].state == "error"
    assert r["/etc/unchanged.conf"].state == "absent"  # other inodes unaffected


@pytest.mark.integration
def test_corrupt_in_inode_header_is_error(fixtures_dir, runner):
    require_tools("debugfs")
    r = _extract(runner, fixtures_dir / "ext/corrupt_inode_ea.img", ["/etc/xattr_bin"])
    assert r["/etc/xattr_bin"].state == "error"


@pytest.mark.integration
def test_offset_matches_standalone(fixtures_dir, runner):
    require_tools("debugfs")
    paths = ["/etc/xattr_big", "/bin/capped", "/etc/sec_xattr"]
    a = _extract(runner, fixtures_dir / "ext/current.img", paths)
    b = _extract(runner, fixtures_dir / "disk/current.dd", paths, offset=4096 * 512)
    assert {p: v.value for p, v in a.items()} == {p: v.value for p, v in b.items()}
    assert a["/etc/sec_xattr"].value["security.foo"]["hex"] == b"bar".hex()


@pytest.mark.integration
def test_small_batches_give_same_result(fixtures_dir, runner):
    require_tools("debugfs")
    paths = ["/etc/xattr_big", "/etc/xattr_bin", "/etc/unchanged.conf", "/bin/capchg"]
    a = _extract(runner, fixtures_dir / "ext/golden.img", paths)
    b = _extract(runner, fixtures_dir / "ext/golden.img", paths, batch_size=1)
    assert {p: (v.state, v.value) for p, v in a.items()} == \
           {p: (v.state, v.value) for p, v in b.items()}


@pytest.mark.integration
def test_unknown_inode_is_error_not_absent(fixtures_dir, runner):
    require_tools("debugfs")
    img = fixtures_dir / "ext/golden.img"
    with ExtFS(img) as fs:
        res = XattrExtractor(runner, img, 0, fs).extract([ino_of(img, "/etc/xattr_big"), 999999])
    assert res[999999].state == "error"
    assert res[ino_of(img, "/etc/xattr_big")].state == "ok"


@pytest.mark.integration
def test_clean_image_uses_batches_not_per_inode_fallback(fixtures_dir, tmp_path):
    require_tools("debugfs")
    import json

    log = tmp_path / "batch.jsonl"
    runner = ToolRunner(log, timeout=60, jobs=2)
    _extract(runner, fixtures_dir / "ext/golden.img",
             ["/etc/xattr_big", "/etc/xattr_bin", "/etc/unchanged.conf", "/bin/capchg"])
    runs = [json.loads(l) for l in log.read_text().splitlines()]
    work = [r for r in runs if r["tool"] == "debugfs"]
    assert len(work) == 2 and all("-f" in r["argv"] for r in work)  # one ea_list + one ea_get batch


@pytest.mark.integration
def test_bad_bitmap_checksum_does_not_block_xattrs(tmp_path, runner):
    """Live captures can carry stale bitmap checksums; debugfs must still read the xattrs."""
    import re

    from tests.fixtures.build import _run, _tool

    require_tools("debugfs")
    src = tmp_path / "src"
    src.mkdir()
    (src / "plain").write_bytes(b"x")
    img = tmp_path / "live.img"
    _run([_tool("mke2fs"), "-q", "-F", "-t", "ext4", "-b", "1024", "-O", "metadata_csum",
          "-d", str(src), str(img), "4096"])
    dump = _run([_tool("dumpe2fs"), str(img)]).stdout.decode()
    bitmap_block = int(re.search(r"Block bitmap at (\d+)", dump).group(1))
    with open(img, "r+b") as f:  # flip one bitmap bit: the stored checksum no longer matches
        f.seek(bitmap_block * 1024 + 100)
        b = f.read(1)[0]
        f.seek(bitmap_block * 1024 + 100)
        f.write(bytes([b ^ 0x01]))
    r = _extract(runner, img, ["/plain"])
    assert r["/plain"].state == "absent", r["/plain"].reason
