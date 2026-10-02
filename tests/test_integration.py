import json
import os
import shutil
import stat
import sys

import pytest

from forensic_compare.compare import main
from tests.conftest import require_tools
from tests.fixtures.build import _sha
from tests.fixtures.expected import MAIN

pytestmark = pytest.mark.integration
TOOLS = ("fls", "icat", "fsstat", "mmls", "debugfs")


def _copy(src, dst):
    shutil.copytree(src, dst)
    for p in dst.rglob("*"):
        if p.is_file():
            p.chmod(0o644)
    return dst


def _run(golden, current, out, *extra, hooks=None):
    code = main([str(golden), str(current), "-o", str(out), "--quiet", *extra], _hooks=hooks)
    comp = json.loads((out / "comparison.json").read_text()) if (out / "comparison.json").exists() else None
    return code, comp


@pytest.fixture(scope="module")
def full_run(fixtures_dir, tmp_path_factory):
    require_tools(*TOOLS)
    out = tmp_path_factory.mktemp("full") / "report"
    code, comp = _run(fixtures_dir / "captures/golden", fixtures_dir / "captures/current", out)
    return code, comp, out


def _section(comp, sid):
    return next(s for s in comp["sources"] if s["id"] == sid)


def test_exit0_clean_set_with_differences(fixtures_dir, tmp_path):
    require_tools(*TOOLS)
    out = tmp_path / "r"
    code, comp = _run(fixtures_dir / "captures_clean/golden", fixtures_dir / "captures_clean/current", out)
    assert code == 0
    assert comp["integrity"]["overall"] == "verified"
    assert comp["completeness"] == {"complete": True, "reasons": []}
    s = _section(comp, "config-active-crypt.dd")
    assert s["summary"]["modified"] >= 1 and s["summary"]["added"] == 1
    assert s["summary"]["incomplete_any"] == 0


def test_full_capture_set_exit3_and_sections(full_run):
    code, comp, out = full_run
    assert code == 3
    ids = {s["id"]: s for s in comp["sources"]}
    assert ids["config-active-crypt.dd"]["kind"] == "filesystem"
    assert ids["nvram-crypt.dd"]["kind"] == "filesystem"
    assert ids["mmcblk0.dd"]["kind"] == "disk" and ids["mmcblk0.dd"]["status"] == "limited"
    assert ids["mmcblk0.dd#p1"]["parent"] == "mmcblk0.dd"
    parts = {p["number"]: p["status"] for p in ids["mmcblk0.dd"]["partitions"]}
    assert parts == {1: "compared", 2: "unsupported", 3: "encrypted", 4: "unknown"}
    p3 = next(p for p in ids["mmcblk0.dd"]["partitions"] if p["number"] == 3)
    assert p3["declared"]["encrypted"]["value"] is True
    assert p3["mapper_section"] == "config-active-crypt.dd"
    assert any("p1 start: 2048 → 4096" in d for d in ids["mmcblk0.dd"]["layout_differences"])
    assert ids["mtdblock0.bin"]["kind"] == "image-level" and ids["mtdblock0.bin"]["identical"] is True
    assert ids["incompat.dd"]["kind"] == "unavailable" and "incompatible" in ids["incompat.dd"]["reason"]
    assert [u["name"] for u in comp["unmatched"]] == ["only-golden.dd"]
    verdicts = {i["key"]: i for i in comp["integrity"]["images"]}
    assert verdicts["current:nvram-crypt.dd"]["status"] == "failed"
    assert "mismatch" in verdicts["current:nvram-crypt.dd"]["reason"]
    assert verdicts["golden:config-active-crypt.dd"]["status"] == "verified"
    not_used = dict(map(tuple, comp["not_used"]["current"]))
    assert "config-active-crypt.dd.received.sha256" in not_used
    assert "nvram-crypt.dd.partial" in not_used
    ref = ids["config-active-crypt.dd"]["reference"]
    assert ref["status"] == "unverified"  # current observation conflicts on firmware.active
    types = [n["type"] for n in comp["notices"]]
    assert types[0] == "integrity-failed" and "reference-unverified" in types
    assert (out / "report.html").exists() and (out / "manifests/mmcblk0.dd#p1/current.json").exists()
    assert (out / "supporting/current/device-info.txt").read_bytes() == \
        b"firmware.active=99.99.99\nmodel: SHOULD-NOT-BE-PARSED\n"


@pytest.mark.parametrize("sid", ["config-active-crypt.dd", "mmcblk0.dd#p1"])
def test_expected_statuses_match_fixture_table(full_run, sid):
    _, comp, _ = full_run
    entries = {e["path"]: e for e in _section(comp, sid)["entries"]}
    for path, (status, sensitive, incomplete) in MAIN.items():
        e = entries.get(path)
        assert e is not None, f"{sid}: {path} missing"
        assert e["status"] == status, f"{sid} {path}: {e['status']} != {status}"
        got_sensitive = {d["field"] for d in e["diffs"] if d["sensitive"]}
        assert got_sensitive == sensitive, f"{sid} {path}: sensitive {got_sensitive}"
        assert e["incomplete"] is incomplete, f"{sid} {path}: incomplete {e['incomplete_reasons']}"


def test_boot_partition_elevates_changes(full_run):
    _, comp, _ = full_run
    s = _section(comp, "mmcblk0.dd#p1")
    assert s["boot"]["is_boot"] is True
    e = next(e for e in s["entries"] if e["path"] == "/etc/modified.conf")
    assert e["boot"] and e["priority"] == 1
    plain = next(e for e in _section(comp, "config-active-crypt.dd")["entries"]
                 if e["path"] == "/etc/modified.conf")
    assert plain["priority"] == 2


def test_integrity_change_during_analysis(fixtures_dir, tmp_path):
    require_tools(*TOOLS)
    cap = _copy(fixtures_dir / "captures_clean", tmp_path / "cap")
    target = cap / "current/config-active-crypt.dd"

    def mutate(_pairing):
        with open(target, "ab") as f:
            f.write(b"\0")

    code, comp = _run(cap / "golden", cap / "current", tmp_path / "r",
                      hooks={"after_analysis": mutate})
    assert code == 3
    v = next(i for i in comp["integrity"]["images"] if i["key"] == "current:config-active-crypt.dd")
    assert v["status"] == "failed" and "changed during analysis" in v["reason"]
    assert v["pre"] != v["post"]


def test_post_hash_runs_after_extraction_failure(fixtures_dir, tmp_path, monkeypatch):
    require_tools(*TOOLS)
    fake = tmp_path / "fakebin"
    fake.mkdir()
    icat = fake / "icat"
    icat.write_text(f"#!{sys.executable}\nimport sys, time\n"
                    "if sys.argv[1:] == ['-V']:\n    print('fake'); sys.exit(0)\n"
                    "time.sleep(30)\n")
    icat.chmod(icat.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(fake) + os.pathsep + os.environ["PATH"])
    cap = fixtures_dir / "captures_clean"
    code, comp = _run(cap / "golden", cap / "current", tmp_path / "r", "--timeout", "1")
    assert code == 3
    s = _section(comp, "config-active-crypt.dd")
    assert s["summary"]["incomplete_any"] > 0
    assert any("timeout" in r for e in s["entries"] for r in e["incomplete_reasons"])
    for v in comp["integrity"]["images"]:
        assert v["post"] and v["post"] == v["pre"] and v["status"] == "verified"


def test_inputs_unmodified_by_full_run(fixtures_dir, full_run):
    meta = json.loads((fixtures_dir / "fixtures-metadata.json").read_text())
    for rel, digest in meta["sha256"].items():
        if rel.startswith("captures/"):
            assert _sha(fixtures_dir / rel) == digest, rel


def test_tool_log_has_no_content(full_run):
    _, _, out = full_run
    log = (out / "tool_log.jsonl").read_bytes()
    assert b"fake-elf-body" not in log and b"was a file" not in log
    records = [json.loads(l) for l in log.splitlines()]
    assert any(r["tool"] == "icat" and r["bytes_extracted"] > 0 for r in records)


def test_tool_versions_recorded(full_run):
    _, comp, _ = full_run
    assert set(comp["tool_versions"]) >= {"fls", "icat", "fsstat", "mmls", "debugfs"}
