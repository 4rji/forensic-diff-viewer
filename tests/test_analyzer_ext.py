import hashlib
import io
import os
import stat
import sys

import pytest

from forensic_compare.analyzer import analyze_ext
from forensic_compare.progress import Progress
from forensic_compare.tools.runner import ToolRunner
from tests.conftest import require_tools
from tests.fixtures.build import (
    CAP_V2_NET_RAW,
    HOSTILE_LINK_TARGET,
    XATTR_BIN,
    expected_sparse_bytes,
)

pytestmark = pytest.mark.integration


def by_path(m, path):
    hits = [e for e in m.entries if e.path == path]
    assert len(hits) == 1, f"{path}: {len(hits)} entries"
    return hits[0]


@pytest.fixture(scope="module")
def analyses(fixtures_dir, tmp_path_factory):
    require_tools("fls", "icat", "fsstat", "debugfs")
    log = tmp_path_factory.mktemp("log") / "tool_log.jsonl"
    runner = ToolRunner(log, timeout=120, jobs=4)
    g = analyze_ext(runner, fixtures_dir / "ext/golden.img", side="golden", source_id="x")
    c = analyze_ext(runner, fixtures_dir / "ext/current.img", side="current", source_id="x")
    return g, c, log


def test_inventory_complete(analyses):
    g, c, _ = analyses
    assert g.inventory["state"] == "complete" and c.inventory["state"] == "complete"
    assert g.filesystem["fs_type"] == "Ext4" and g.filesystem["needs_recovery"] is False


def test_sparse_hash_matches_logical(analyses):
    e = by_path(analyses[0], "/sparse.bin")
    assert e.content.value["sha256"] == hashlib.sha256(expected_sparse_bytes()).hexdigest()
    assert e.content.value["bytes_read"] == 1 << 20


def test_kinds(analyses):
    g = analyses[0]
    assert by_path(g, "/bin/tool").content.value["kind"] == "elf"
    assert by_path(g, "/bin/sgid").content.value["kind"] == "script"
    assert by_path(g, "/etc/unchanged.conf").content.value["kind"] == "text"


def test_fast_symlink_target_not_nul(analyses):
    e = by_path(analyses[0], "/link_fast")
    assert e.symlink.state == "ok"
    assert bytes.fromhex(e.symlink.value["target_hex"]) == b"etc/unchanged.conf"
    assert e.content.state == "n/a" and e.type.value == "symlink"


def test_slow_and_hostile_symlinks(analyses):
    g = analyses[0]
    assert bytes.fromhex(by_path(g, "/link_slow").symlink.value["target_hex"]) == b"x" * 100
    assert by_path(g, "/link_hostile").symlink.value["target"] == HOSTILE_LINK_TARGET


def test_capability_decoded_and_split_from_xattrs(analyses):
    e = by_path(analyses[1], "/bin/capped")
    assert e.capability.state == "ok" and e.capability.value["text"] == "cap_net_raw+ep"
    assert e.capability.value["hex"] == CAP_V2_NET_RAW.hex()
    assert e.xattrs.state == "absent"
    assert by_path(analyses[0], "/bin/capped").capability.state == "absent"


def test_binary_xattr(analyses):
    e = by_path(analyses[0], "/etc/xattr_bin")
    assert bytes.fromhex(e.xattrs.value["user.bin"]["hex"]) == XATTR_BIN


def test_special_names(analyses):
    g = analyses[0]
    assert by_path(g, "/pi|pe").path_lossy is False
    lossy = by_path(g, "/new^line")
    assert lossy.path_lossy is True
    bad = by_path(g, "/bad\\xff\\xfename")
    assert bad.path_hex == b"/bad\xff\xfename".hex()


def test_hard_links_share_hash(analyses):
    g = analyses[0]
    a, b = by_path(g, "/hard_a"), by_path(g, "/hard_b")
    assert a.inode == b.inode and a.content.value == b.content.value


def test_modes_and_owner(analyses):
    g, c, _ = analyses
    assert by_path(c, "/bin/tool").mode.value == 0o4755
    assert by_path(c, "/etc/owner").uid.value == 0
    assert by_path(g, "/etc/sticky_dir").mode.value == 0o1777


def test_root_entry_present(analyses):
    root = by_path(analyses[0], "/")
    assert root.type.value == "dir" and root.uid.value == 0 and root.mode.state == "ok"


def test_tool_log_has_no_content(analyses):
    log = analyses[2].read_bytes()
    assert b"fake-elf-body" not in log and b"was a file" not in log


def test_offset_analysis_matches_standalone(fixtures_dir, tmp_path):
    runner = ToolRunner(tmp_path / "l.jsonl", timeout=120, jobs=4)
    a = analyze_ext(runner, fixtures_dir / "ext/current.img", side="current", source_id="a")
    b = analyze_ext(runner, fixtures_dir / "disk/current.dd", side="current", source_id="b",
                    offset_bytes=4096 * 512)
    def key(m):
        return sorted((e.path, e.content.to_dict().get("value", {}).get("sha256"),
                       e.xattrs.state, e.symlink.state) for e in m.entries)
    assert key(a) == key(b)
    assert b.filesystem["offset_bytes"] == 4096 * 512


def test_corrupt_extent_not_assessed(fixtures_dir, tmp_path):
    runner = ToolRunner(tmp_path / "l.jsonl", timeout=120, jobs=4)
    m = analyze_ext(runner, fixtures_dir / "ext/corrupt_extent.img", side="current",
                    source_id="x")
    assert by_path(m, "/etc/modified.conf").content.state == "error"
    assert by_path(m, "/etc/unchanged.conf").content.state == "ok"


def test_corrupt_ea_block_not_assessed(fixtures_dir, tmp_path):
    runner = ToolRunner(tmp_path / "l.jsonl", timeout=120, jobs=4)
    m = analyze_ext(runner, fixtures_dir / "ext/corrupt_eablock.img", side="current",
                    source_id="x")
    e = by_path(m, "/etc/xattr_big")
    assert e.xattrs.state == "error" and e.capability.state == "error"


def test_needs_recovery_warning_not_incomplete(fixtures_dir, tmp_path):
    runner = ToolRunner(tmp_path / "l.jsonl", timeout=120, jobs=4)
    m = analyze_ext(runner, fixtures_dir / "ext/recovery.img", side="current", source_id="x")
    assert m.filesystem["needs_recovery"] is True
    assert m.inventory["state"] == "complete"
    assert any("journal not replayed" in w for w in m.filesystem["warnings"])


def test_icat_timeout_marks_entry(fixtures_dir, tmp_path, monkeypatch):
    fake = tmp_path / "fakebin"
    fake.mkdir()
    icat = fake / "icat"
    icat.write_text(f"#!{sys.executable}\nimport sys, time\n"
                    "if sys.argv[1:] == ['-V']:\n    print('fake icat'); sys.exit(0)\n"
                    "time.sleep(30)\n")
    icat.chmod(icat.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(fake) + os.pathsep + os.environ["PATH"])
    runner = ToolRunner(tmp_path / "l.jsonl", timeout=1.5, jobs=4)
    m = analyze_ext(runner, fixtures_dir / "ext/nvram_golden.img", side="golden", source_id="x")
    e = by_path(m, "/log/app.log")
    assert e.content.state == "error" and "timeout" in e.content.reason
    assert e.mode.state == "ok" and e.xattrs.state in ("ok", "absent")


def test_progress_lines_non_tty(fixtures_dir, tmp_path):
    runner = ToolRunner(tmp_path / "l.jsonl", timeout=120, jobs=2)
    buf = io.StringIO()
    analyze_ext(runner, fixtures_dir / "ext/nvram_golden.img", side="golden", source_id="nv",
                quiet=False, progress_stream=buf)
    out = buf.getvalue()
    assert "[nv · golden]" in out and "hashing" in out and "files" in out


def test_progress_quiet_prints_nothing():
    buf = io.StringIO()
    p = Progress("x", quiet=True, stream=buf)
    p.update(1, 2, 10, 20)
    p.finish()
    assert buf.getvalue() == ""
