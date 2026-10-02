import hashlib
import os

import pytest

from forensic_compare.discovery import classify_dir
from forensic_compare.integrity import (
    IntegrityTracker,
    expected_checksums,
    parse_checksum_file,
    sha256_file,
)


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _capture(tmp_path, files, sums):
    d = tmp_path / "cap"
    d.mkdir()
    for n, data in files.items():
        (d / n).write_bytes(data)
    for n, text in sums.items():
        (d / n).write_text(text)
    return d


def _tracker(d):
    lst = classify_dir(d)
    expected, _ = expected_checksums(lst)
    return IntegrityTracker([("golden", n, p, expected.get(n, [])) for n, p in lst.images.items()])


def test_parse_checksum_file(tmp_path):
    p = tmp_path / "SHA256SUMS"
    p.write_text(f"{'a' * 64}  x.dd\n{'b' * 64} *y.dd\n{'c' * 64} *-\nnot a line\n\n"
                 f"{'d' * 64}  sub/z.dd\n")
    entries, malformed, ignored = parse_checksum_file(p)
    assert entries == {"x.dd": "a" * 64, "y.dd": "b" * 64}
    assert malformed == ["not a line"]
    assert any("stdin" in r for _, r in ignored) and any("basename" in r for _, r in ignored)


def test_verified(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"AAA"}, {"SHA256SUMS": f"{_sha(b'AAA')}  a.dd\n"})
    t = _tracker(d)
    t.hash_pre(); t.hash_post()
    v = t.verdicts()["golden:a.dd"]
    assert v.status == "verified" and v.pre == v.post == _sha(b"AAA")
    assert t.overall() == "verified"


def test_stable_unverified_without_checksum(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"AAA"}, {})
    t = _tracker(d)
    t.hash_pre(); t.hash_post()
    assert t.verdicts()["golden:a.dd"].status == "stable-unverified"
    assert t.overall() == "stable-unverified"


def test_received_sha256_is_not_a_manifest(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"AAA"},
                 {"a.dd.received.sha256": f"{_sha(b'AAA')} *-\n"})
    t = _tracker(d)
    t.hash_pre(); t.hash_post()
    assert t.verdicts()["golden:a.dd"].status == "stable-unverified"


def test_mismatch_failed(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"AAA"}, {"SHA256SUMS": f"{'0' * 64}  a.dd\n"})
    t = _tracker(d)
    t.hash_pre(); t.hash_post()
    v = t.verdicts()["golden:a.dd"]
    assert v.status == "failed" and "mismatch" in v.reason
    assert t.overall() == "failed"


def test_changed_during_analysis(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"AAA"}, {"SHA256SUMS": f"{_sha(b'AAA')}  a.dd\n"})
    t = _tracker(d)
    t.hash_pre()
    (d / "a.dd").write_bytes(b"AAAB")
    t.hash_post()
    v = t.verdicts()["golden:a.dd"]
    assert v.status == "failed" and "changed during analysis" in v.reason


def test_conflicting_checksums(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"AAA"}, {
        "SHA256SUMS": f"{_sha(b'AAA')}  a.dd\n", "a.sha256": f"{'1' * 64}  a.dd\n"})
    t = _tracker(d)
    t.hash_pre(); t.hash_post()
    v = t.verdicts()["golden:a.dd"]
    assert v.status == "failed" and "conflicting" in v.reason


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read 000 files")
def test_unreadable_image_failed_verdict(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"AAA"}, {})
    t = _tracker(d)
    (d / "a.dd").chmod(0)
    try:
        t.hash_pre(); t.hash_post()
        v = t.verdicts()["golden:a.dd"]
        assert v.status == "failed" and "hashing error" in v.reason and v.pre is None
    finally:
        (d / "a.dd").chmod(0o600)


def test_overall_failed_if_any(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"A", "b.dd": b"B"},
                 {"SHA256SUMS": f"{_sha(b'A')}  a.dd\n{'0' * 64}  b.dd\n"})
    t = _tracker(d)
    t.hash_pre(); t.hash_post()
    assert t.overall() == "failed"


def test_verdict_without_post_hash_is_not_verified(tmp_path):
    d = _capture(tmp_path, {"a.dd": b"AAA"}, {"SHA256SUMS": f"{_sha(b'AAA')}  a.dd\n"})
    t = _tracker(d)
    t.hash_pre()
    v = t.verdicts()["golden:a.dd"]
    assert v.status == "failed" and "post" in v.reason


def test_sha256_file_large_chunks(tmp_path):
    p = tmp_path / "big"
    data = os.urandom(9 * (1 << 20) + 7)
    p.write_bytes(data)
    assert sha256_file(p) == _sha(data)
