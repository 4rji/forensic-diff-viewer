import json
import time
import shutil

import pytest

from tests.fixtures.build import build_all


@pytest.fixture(scope="module")
def two_builds(tmp_path_factory):
    if not (shutil.which("mke2fs") and shutil.which("debugfs")):
        pytest.skip("e2fsprogs (mke2fs, debugfs) not available")
    a = tmp_path_factory.mktemp("a")
    b = tmp_path_factory.mktemp("b")
    ma = build_all(a)
    time.sleep(1.1)  # make wall-clock-derived timestamps differ between builds
    return a, ma, build_all(b)


def test_builder_is_deterministic(two_builds):
    _, ma, mb = two_builds
    diffs = {k: (v, mb["sha256"].get(k)) for k, v in ma["sha256"].items()
             if mb["sha256"].get(k) != v}
    assert not diffs, f"non-deterministic fixtures: {sorted(diffs)}"


def test_metadata_records_tools_and_features(two_builds):
    out, _, _ = two_builds
    meta = json.loads((out / "fixtures-metadata.json").read_text())
    assert meta["tools"]["mke2fs"].startswith("mke2fs 1.")
    assert meta["tools"]["debugfs"].startswith("debugfs 1.")
    assert "ext_attr" in meta["features"]["golden.img"]
    assert "inline_data" in meta["features"]["inline.img"]
    assert "metadata_csum" not in meta["features"]["golden.img"]


def test_capture_dirs_present_and_readonly(two_builds):
    out, _, _ = two_builds
    g = out / "captures/golden"
    c = out / "captures/current"
    for name in ("config-active-crypt.dd", "nvram-crypt.dd", "mmcblk0.dd", "mtdblock0.bin",
                 "SHA256SUMS", "capture.yaml", "device-info.txt",
                 "config-active-crypt.dd.received.sha256", "nvram-crypt.dd.partial"):
        assert (g / name).is_file() and (c / name).is_file(), name
    assert (g / "only-golden.dd").exists() and not (c / "only-golden.dd").exists()
    assert (g / "mmcblk0.dd").stat().st_mode & 0o222 == 0
