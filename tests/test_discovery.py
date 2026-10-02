import os

import pytest

from forensic_compare.discovery import classify_dir, pair_inputs


def _mk(d, names):
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        (d / n).write_bytes(b"x")
    return d


def test_classify_dir(tmp_path):
    d = _mk(tmp_path / "g", [
        "config-active-crypt.dd", "mmcblk0.dd", "mtdblock0.bin", "disk.img", "raw.raw",
        "nvram-crypt.dd.partial", "config-active-crypt.dd.received.sha256", "SHA256SUMS",
        "images.sha256", "x.sha256sum", "capture.yaml", "device-info.txt", "acquisition.log",
        "notes.md",
    ])
    (d / "subdir").mkdir()
    lst = classify_dir(d)
    assert sorted(lst.images) == ["config-active-crypt.dd", "disk.img", "mmcblk0.dd",
                                  "mtdblock0.bin", "raw.raw"]
    assert sorted(p.name for p in lst.checksum_files) == ["SHA256SUMS", "images.sha256",
                                                          "x.sha256sum"]
    assert sorted(lst.supporting) == ["capture.yaml", "device-info.txt"]
    not_used = dict(lst.not_used)
    assert "partial" in not_used["nvram-crypt.dd.partial"]
    assert "received" in not_used["config-active-crypt.dd.received.sha256"]
    assert set(not_used) >= {"acquisition.log", "notes.md", "subdir"}


def test_exact_name_pairing_never_substitutes(tmp_path):
    g = _mk(tmp_path / "g", ["config-active-crypt.dd", "nvram-crypt.dd"])
    c = _mk(tmp_path / "c", ["config-other-crypt.dd", "nvram-crypt.dd"])
    p = pair_inputs(g, c)
    assert p.mode == "dir"
    assert [x.source_id for x in p.pairs] == ["nvram-crypt.dd"]
    assert sorted((u.side, u.name) for u in p.unmatched) == [
        ("current", "config-other-crypt.dd"), ("golden", "config-active-crypt.dd")]


def test_case_sensitive_names(tmp_path):
    g = _mk(tmp_path / "g", ["NVRAM.dd"])
    c = _mk(tmp_path / "c", ["nvram.dd"])
    p = pair_inputs(g, c)
    assert p.pairs == [] and len(p.unmatched) == 2


def test_single_mode_different_names(tmp_path):
    g = _mk(tmp_path / "a", ["clean.dd", "SHA256SUMS", "other.dd"])
    c = _mk(tmp_path / "b", ["current.dd"])
    p = pair_inputs(g / "clean.dd", c / "current.dd")
    assert p.mode == "single"
    assert [x.source_id for x in p.pairs] == ["clean.dd__vs__current.dd"]
    assert list(p.golden_listing.images) == ["clean.dd"]
    assert [f.name for f in p.golden_listing.checksum_files] == ["SHA256SUMS"]
    assert p.unmatched == []


def test_single_mode_same_names(tmp_path):
    g = _mk(tmp_path / "a", ["x.dd"])
    c = _mk(tmp_path / "b", ["x.dd"])
    assert pair_inputs(g / "x.dd", c / "x.dd").pairs[0].source_id == "x.dd"


def test_symlinked_image_records_realpath(tmp_path):
    real = _mk(tmp_path / "store", ["real.dd"]) / "real.dd"
    g = _mk(tmp_path / "g", [])
    os.symlink(real, g / "nvram-crypt.dd")
    lst = classify_dir(g)
    assert lst.images["nvram-crypt.dd"] == g / "nvram-crypt.dd"
    assert lst.realpaths["nvram-crypt.dd"] == str(real.resolve())


def test_mixed_or_missing_inputs_rejected(tmp_path):
    g = _mk(tmp_path / "g", ["a.dd"])
    with pytest.raises(ValueError):
        pair_inputs(g, g / "a.dd")
    with pytest.raises(ValueError):
        pair_inputs(tmp_path / "nope", g)
