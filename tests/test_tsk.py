from pathlib import Path

import pytest

from forensic_compare.tools.runner import ToolRunner
from forensic_compare.tools.tsk import (
    fls_inventory,
    fsstat_info,
    icat_stream,
    mmls_layout,
    parse_body_line,
    parse_fsstat,
    parse_mmls,
    parse_mode_string,
)
from tests.conftest import require_tools

DATA = Path(__file__).parent / "data"


def test_parse_body_pipe_in_name():
    r = parse_body_line(b"0|/pi|pe|16|r/rrw-rw-r--|1000|1000|2|1|2|3|4")
    assert r.name == b"/pi|pe" and r.inode == 16 and r.mode == 0o664 and r.type == "file"
    assert (r.uid, r.gid, r.size, r.atime, r.mtime, r.ctime, r.crtime) == (1000, 1000, 2, 1, 2, 3, 4)


def test_parse_body_symlink_keeps_raw_name():
    r = parse_body_line(b"0|/link -> ../etc/a.txt|17|l/lrwxrwxrwx|0|0|12|1|2|3|4")
    assert r.type == "symlink" and r.name == b"/link -> ../etc/a.txt"


def test_parse_body_non_utf8_name():
    r = parse_body_line(b"0|/bad\xff\xfename|13|r/rrw-rw-r--|0|0|1|1|2|3|4")
    assert r.name == b"/bad\xff\xfename"


@pytest.mark.parametrize("s,expected", [
    ("d/drwxrwxrwt", ("dir", 0o1777)),
    ("d/drwxrwxrwT", ("dir", 0o1776)),
    ("r/rrwxr-sr-x", ("file", 0o2755)),
    ("r/rrwSr--r--", ("file", 0o4644)),
    ("r/rrwsr-xr-x", ("file", 0o4755)),
    ("l/lrwxrwxrwx", ("symlink", 0o777)),
    ("c/crw-------", ("chr", 0o600)),
    ("b/brw-rw----", ("blk", 0o660)),
    ("p/prw-r--r--", ("fifo", 0o644)),
    ("s/srwxr-xr-x", ("socket", 0o755)),
    ("V/V---------", ("virtual", 0)),
])
def test_mode_strings(s, expected):
    assert parse_mode_string(s) == expected


@pytest.mark.parametrize("bad", [b"garbage", b"0|/a|x|r/rrw-r--r--|0|0|1|1|2|3|4",
                                 b"0|/a|1|r/rrw-r--r--|0|0|1|1|2|3", b"0|/a|1|zz|0|0|1|1|2|3|4"])
def test_bad_line_raises(bad):
    with pytest.raises(ValueError):
        parse_body_line(bad)


def test_parse_mmls_dos():
    layout = parse_mmls((DATA / "mmls_dos.txt").read_text())
    assert layout.table_type == "DOS Partition Table" and layout.sector_size == 512
    assert [(p.number, p.slot, p.start, p.length) for p in layout.partitions] == [
        (1, "000:000", 2048, 16384), (2, "000:001", 18432, 2048)]
    assert layout.partitions[0].description == "Linux (0x83)"


def test_parse_fsstat_last_mounted_empty():
    info = parse_fsstat((DATA / "fsstat_ext4.txt").read_text())
    assert info.fs_type == "Ext4" and info.last_mounted is None
    assert "Ext Attributes" in info.features and "64bit" in info.features
    assert info.unmounted_properly is True


def test_parse_fsstat_boot_not_clean():
    info = parse_fsstat((DATA / "fsstat_boot.txt").read_text())
    assert info.last_mounted == "/boot" and info.unmounted_properly is False


# ---- integration (real TSK) ----------------------------------------------------------------


@pytest.fixture
def runner(tmp_path):
    return ToolRunner(tmp_path / "log.jsonl", timeout=60, jobs=2)


@pytest.mark.integration
def test_fls_inventory_real(fixtures_dir, runner):
    require_tools("fls")
    inv = fls_inventory(runner, fixtures_dir / "ext/golden.img")
    names = {r.name for r in inv.rows}
    assert b"/pi|pe" in names and b"/etc/unchanged.conf" in names
    assert not any(n.startswith(b"/$OrphanFiles") for n in names)
    assert inv.virtual_excluded == 1 and inv.bad_lines == [] and inv.result.ok
    assert "fls" in runner.versions


@pytest.mark.integration
def test_fls_inventory_with_offset(fixtures_dir, runner):
    require_tools("fls")
    a = fls_inventory(runner, fixtures_dir / "ext/current.img")
    b = fls_inventory(runner, fixtures_dir / "disk/current.dd", offset_sectors=4096)
    assert [(r.name, r.inode, r.mode) for r in a.rows] == [(r.name, r.inode, r.mode) for r in b.rows]


@pytest.mark.integration
def test_mmls_real(fixtures_dir, runner):
    require_tools("mmls")
    g = mmls_layout(runner, fixtures_dir / "disk/golden.dd")
    c = mmls_layout(runner, fixtures_dir / "disk/current.dd")
    assert [p.start for p in g.partitions][0] == 2048 and [p.start for p in c.partitions][0] == 4096
    assert len(g.partitions) == 4
    assert mmls_layout(runner, fixtures_dir / "ext/golden.img") is None


@pytest.mark.integration
def test_fsstat_and_icat_real(fixtures_dir, runner):
    require_tools("fsstat", "icat", "fls")
    img = fixtures_dir / "ext/golden.img"
    info = fsstat_info(runner, img)
    assert info.fs_type == "Ext4" and info.result.ok
    inv = fls_inventory(runner, img)
    ino = next(r.inode for r in inv.rows if r.name == b"/etc/unchanged.conf")
    got = []
    res = icat_stream(runner, img, ino, got.append)
    assert b"".join(got) == b"a\n" and res.ok and res.bytes_out == 2


@pytest.mark.integration
def test_icat_bad_inode_is_not_ok(fixtures_dir, runner):
    require_tools("icat")
    res = icat_stream(runner, fixtures_dir / "ext/golden.img", 10 ** 7, lambda c: None)
    assert not res.ok
