import json
import os
import shutil

import pytest

from forensic_compare.compare import main
from tests.conftest import require_tools

TOOLS = ("fls", "icat", "fsstat", "mmls", "debugfs")


def _copy_capture(src, dst):
    shutil.copytree(src, dst)
    for p in dst.rglob("*"):
        if p.is_file():
            p.chmod(0o644)
    return dst


def test_usage_error_exit2(capsys):
    assert main(["only-one-arg"]) == 2


def test_missing_output_arg_exit2(tmp_path):
    (tmp_path / "g").mkdir()
    (tmp_path / "c").mkdir()
    assert main([str(tmp_path / "g"), str(tmp_path / "c")]) == 2


def test_mixed_inputs_exit2(tmp_path, capsys):
    (tmp_path / "g").mkdir()
    (tmp_path / "c.dd").write_bytes(b"x")
    assert main([str(tmp_path / "g"), str(tmp_path / "c.dd"), "-o", str(tmp_path / "o")]) == 2
    assert "both be directories" in capsys.readouterr().err


def test_nonempty_output_refused(tmp_path, capsys):
    g, c, o = tmp_path / "g", tmp_path / "c", tmp_path / "o"
    for d in (g, c, o):
        d.mkdir()
    (o / "notes.txt").write_text("keep")
    assert main([str(g), str(c), "-o", str(o)]) == 2
    assert "not empty" in capsys.readouterr().err
    assert (o / "notes.txt").read_text() == "keep"


def test_output_inside_capture_refused(tmp_path, capsys):
    g, c = tmp_path / "g", tmp_path / "c"
    g.mkdir()
    c.mkdir()
    assert main([str(g), str(c), "-o", str(g / "report")]) == 2
    assert "overlaps" in capsys.readouterr().err
    assert not (g / "report").exists()


def test_capture_inside_output_refused(tmp_path):
    out = tmp_path / "out"
    g, c = out / "g", tmp_path / "c"
    g.mkdir(parents=True)
    c.mkdir()
    assert main([str(g), str(c), "-o", str(out)]) == 2


def test_output_symlink_alias_refused(tmp_path):
    g, c = tmp_path / "g", tmp_path / "c"
    g.mkdir()
    c.mkdir()
    alias = tmp_path / "alias"
    os.symlink(g, alias)
    assert main([str(g), str(c), "-o", str(alias / "sub")]) == 2
    assert main([str(g), str(c), "-o", str(alias)]) == 2


def test_output_equal_to_image_parent_in_single_mode_refused(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a/x.dd").write_bytes(b"x")
    (tmp_path / "b/x.dd").write_bytes(b"x")
    assert main([str(tmp_path / "a/x.dd"), str(tmp_path / "b/x.dd"), "-o", str(tmp_path / "a")]) == 2


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read 000 files")
def test_cli_unreadable_image_exit3(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    ga, cb = tmp_path / "a/x.dd", tmp_path / "b/x.dd"
    ga.write_bytes(b"\0" * 4096)
    cb.write_bytes(b"\0" * 4096)
    cb.chmod(0)
    try:
        code = main([str(ga), str(cb), "-o", str(tmp_path / "out"), "--quiet"])
    finally:
        cb.chmod(0o600)
    assert code == 3
    comp = json.loads((tmp_path / "out/comparison.json").read_text())
    assert comp["integrity"]["overall"] == "failed"
    assert comp["sources"][0]["kind"] == "unavailable"
    assert (tmp_path / "out/report.html").exists()


def test_bad_rules_file_exit2(tmp_path, capsys):
    g, c = tmp_path / "g", tmp_path / "c"
    g.mkdir()
    c.mkdir()
    rules = tmp_path / "r.yaml"
    rules.write_text("schema: 2\n")
    assert main([str(g), str(c), "-o", str(tmp_path / "o"), "--rules", str(rules)]) == 2
    assert "schema" in capsys.readouterr().err


@pytest.mark.integration
def test_force_removes_only_previous_outputs(fixtures_dir, tmp_path):
    require_tools(*TOOLS)
    first = _copy_capture(fixtures_dir / "captures_clean", tmp_path / "set1")
    second = _copy_capture(fixtures_dir / "captures_clean", tmp_path / "set2")
    for side in ("golden", "current"):
        os.rename(second / side / "config-active-crypt.dd", second / side / "renamed.dd")
        (second / side / "SHA256SUMS").unlink()
    out = tmp_path / "out"
    assert main([str(first / "golden"), str(first / "current"), "-o", str(out), "--quiet"]) == 0
    assert (out / "manifests/config-active-crypt.dd/golden.json").exists()
    (out / "notes.txt").write_text("analyst notes")
    assert main([str(second / "golden"), str(second / "current"), "-o", str(out), "--quiet"]) == 2
    code = main([str(second / "golden"), str(second / "current"), "-o", str(out), "--quiet",
                 "--force"])
    assert code == 3  # no checksums in the second set -> integrity unverified
    assert (out / "notes.txt").read_text() == "analyst notes"
    assert not (out / "manifests/config-active-crypt.dd").exists()
    assert (out / "manifests/renamed.dd/current.json").exists()
    listed = json.loads((out / "outputs.json").read_text())["files"]
    assert "notes.txt" not in listed and "report.html" in listed
