import os
import shutil

import pytest

from forensic_compare.analyzer import analyze_source, detect_kind
from forensic_compare.tools.runner import ToolRunner
from tests.conftest import require_tools

pytestmark = pytest.mark.integration


@pytest.fixture
def runner(tmp_path):
    require_tools("fls", "icat", "fsstat", "mmls", "debugfs")
    return ToolRunner(tmp_path / "log.jsonl", timeout=120, jobs=4)


def test_kinds(fixtures_dir, runner):
    assert detect_kind(runner, fixtures_dir / "ext/golden.img").kind == "ext-fs"
    assert detect_kind(runner, fixtures_dir / "disk/golden.dd").kind == "disk"
    k = detect_kind(runner, fixtures_dir / "captures/golden/mtdblock0.bin")
    assert k.kind == "image-level" and k.signatures == []
    k = detect_kind(runner, fixtures_dir / "captures/current/incompat.dd")
    assert k.kind == "image-level" and k.signatures == ["squashfs"]


def test_disk_partitions(fixtures_dir, runner):
    for side, start in (("golden", 2048), ("current", 4096)):
        a = analyze_source(runner, fixtures_dir / f"disk/{side}.dd", side=side,
                           source_id="mmcblk0.dd")
        assert a.kind == "disk" and a.layout.sector_size == 512
        p = {x.number: x for x in a.partitions}
        assert [x.number for x in a.partitions] == [1, 2, 3, 4]
        assert p[1].status == "analyzed" and p[1].offset_bytes == start * 512
        assert p[1].manifest is not None and p[1].manifest.source_id == "mmcblk0.dd#p1"
        assert p[1].manifest.inventory["state"] == "complete"
        assert p[2].status == "unsupported" and p[2].signatures == ["squashfs"]
        assert "extractor" in p[2].reason
        assert p[3].status == "encrypted" and p[3].signatures == ["luks2"]
        assert p[4].status == "unknown" and p[4].signatures == []


def test_image_level_source(fixtures_dir, runner):
    a = analyze_source(runner, fixtures_dir / "captures/golden/mtdblock0.bin", side="golden",
                       source_id="mtdblock0.bin")
    assert a.kind == "image-level" and a.manifest is None
    assert a.image_size == 65536
    assert "not supported" in a.reason


def test_ext_source(fixtures_dir, runner):
    a = analyze_source(runner, fixtures_dir / "ext/nvram_golden.img", side="golden",
                       source_id="nvram-crypt.dd")
    assert a.kind == "ext-fs" and a.manifest.inventory["state"] == "complete"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read 000 files")
def test_unreadable_image(fixtures_dir, runner, tmp_path):
    p = tmp_path / "locked.dd"
    shutil.copyfile(fixtures_dir / "ext/nvram_golden.img", p)
    p.chmod(0)
    try:
        assert detect_kind(runner, p).kind == "unreadable"
        a = analyze_source(runner, p, side="golden", source_id="locked.dd")
        assert a.kind == "unreadable" and "Permission denied" in a.reason
    finally:
        p.chmod(0o600)


def test_missing_image(runner, tmp_path):
    a = analyze_source(runner, tmp_path / "gone.dd", side="golden", source_id="gone.dd")
    assert a.kind == "unreadable"
