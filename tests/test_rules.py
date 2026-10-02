import pytest
import yaml

from forensic_compare.comparator import CompEntry, Diff
from forensic_compare.rules import (
    RulesError,
    apply_rules,
    field_covered,
    glob_match,
    load_rules,
    priority_for,
)


@pytest.mark.parametrize("pat,path,ok", [
    ("var/log/**", "/var/log/a", True),
    ("var/log/**", "/var/log/a/b/c", True),
    ("var/log/*", "/var/log/a/b", False),
    ("var/log/*", "/var/log/a", True),
    ("**/x.conf", "/x.conf", True),
    ("**/x.conf", "/a/b/x.conf", True),
    ("etc/?.conf", "/etc/a.conf", True),
    ("etc/?.conf", "/etc/ab.conf", False),
    ("etc/A.conf", "/etc/a.conf", False),  # case-sensitive
    ("etc/a.conf", "/etc/a.conf", True),
    ("etc/[ab].conf", "/etc/[ab].conf", True),  # brackets are literal
])
def test_glob(pat, path, ok):
    assert glob_match(pat, path) is ok


def _write(tmp_path, doc):
    p = tmp_path / "rules.yaml"
    p.write_text(yaml.safe_dump(doc))
    return p


RULE = {"id": "logs", "label": "Log rotation", "reason": "r", "sources": ["nv.dd"],
        "paths": ["log/**"], "statuses": ["modified", "added", "deleted"],
        "fields": ["existence", "content", "size", "mtime"]}


def test_load_rules_and_hash(tmp_path):
    rs = load_rules(_write(tmp_path, {"schema": 1, "rules": [RULE]}))
    assert [r.id for r in rs.rules] == ["logs"] and len(rs.sha256) == 64
    assert load_rules(None).rules == []


@pytest.mark.parametrize("bad", [
    {"schema": 2, "rules": []},
    {"schema": 1, "rules": [dict(RULE, paths=["/log/**"])]},          # leading slash
    {"schema": 1, "rules": [dict(RULE, fields=["bogus"])]},
    {"schema": 1, "rules": [dict(RULE, statuses=["incomplete"])]},
    {"schema": 1, "rules": [RULE, RULE]},                              # duplicate id
    {"schema": 1, "rules": [dict(RULE, extra=1)]},
    {"schema": 1, "rules": [{k: v for k, v in RULE.items() if k != "sources"}]},
    {"schema": 1, "bogus": []},
])
def test_invalid_rules_rejected(tmp_path, bad):
    with pytest.raises(RulesError):
        load_rules(_write(tmp_path, bad))


def test_example_file_loads_with_no_enabled_rules():
    from pathlib import Path

    example = Path(__file__).parents[1] / "forensic_compare/expected_changes.example.yaml"
    rs = load_rules(example)
    assert rs.rules == [] and rs.elevate == []
    assert "log" in example.read_text()  # illustrative content is present, commented out


@pytest.mark.parametrize("token,fld,ok", [
    ("content", "content", True),
    ("content", "existence", False),
    ("xattr:*", "xattr:user.a", True),
    ("xattr:*", "xattr:security.foo", False),
    ("xattr:security.*", "xattr:security.foo", True),
    ("xattr:user.a", "xattr:user.b", False),
    ("suid", "suid", True),
    ("mode", "suid", False),
])
def test_field_covered(token, fld, ok):
    assert field_covered(token, fld) is ok


def ce(status, diffs, *, path="/log/app.log", kind="text", incomplete=False, boot=False):
    return CompEntry(path=path, path_hex=path.encode().hex(), status=status,
                     incomplete=incomplete, diffs=diffs, kind=kind, boot=boot)


def rs_for(tmp_path, *rules, elevate=()):
    return load_rules(_write(tmp_path, {"schema": 1, "rules": list(rules),
                                        "elevate": list(elevate)}))


def test_full_coverage(tmp_path):
    e = ce("modified", [Diff("content", "a", "b"), Diff("mtime", 1, 2)])
    rs = rs_for(tmp_path, RULE)
    apply_rules("nv.dd", [e], rs)
    assert e.expectation == "full" and e.priority == 4 and e.rules == ["logs"]
    assert all(d.covered_by == "logs" for d in e.diffs)
    assert rs.matches == {"logs": 1}


def test_content_without_existence_does_not_cover_added(tmp_path):
    rule = dict(RULE, fields=["content", "size", "mtime"])
    e = ce("added", [Diff("existence", None, "present")])
    apply_rules("nv.dd", [e], rs_for(tmp_path, rule))
    assert e.expectation == "none" and e.priority == 2


def test_partial_takes_priority_from_uncovered(tmp_path):
    e = ce("modified", [Diff("content", "a", "b"), Diff("mode", "0644", "0600")])
    apply_rules("nv.dd", [e], rs_for(tmp_path, RULE))
    # content is covered; only the uncovered mode difference drives priority (metadata → 3)
    assert e.expectation == "partial" and e.priority == 3
    e2 = ce("metadata", [Diff("mtime", 1, 2), Diff("suid", False, True, sensitive=True)])
    apply_rules("nv.dd", [e2], rs_for(tmp_path, dict(RULE, statuses=["metadata"])))
    assert e2.expectation == "partial" and e2.priority == 1


def test_metadata_only_uncovered_is_priority_3(tmp_path):
    e = ce("metadata", [Diff("mode", "0644", "0600")])
    apply_rules("other.dd", [e], rs_for(tmp_path, RULE))
    assert e.priority == 3 and e.expectation == "none"


def test_all_covered_but_incomplete_is_partial(tmp_path):
    e = ce("modified", [Diff("content", "a", "b")], incomplete=True)
    apply_rules("nv.dd", [e], rs_for(tmp_path, RULE))
    assert e.expectation == "partial" and e.priority == 2


def test_security_xattr_needs_explicit_token(tmp_path):
    e = ce("metadata", [Diff("xattr:security.foo", None, "62", sensitive=True)])
    apply_rules("nv.dd", [e], rs_for(tmp_path, dict(RULE, statuses=["metadata"],
                                                    fields=["xattr:*"])))
    assert e.expectation == "none" and e.priority == 1
    e = ce("metadata", [Diff("xattr:security.foo", None, "62", sensitive=True)])
    apply_rules("nv.dd", [e], rs_for(tmp_path, dict(RULE, statuses=["metadata"],
                                                    fields=["xattr:security.*"])))
    assert e.expectation == "full" and e.diffs[0].explicit_sensitive is True


def test_status_must_match(tmp_path):
    e = ce("deleted", [Diff("existence", "present", None)])
    rs = rs_for(tmp_path, dict(RULE, statuses=["modified"]))
    apply_rules("nv.dd", [e], rs)
    assert e.expectation == "none" and rs.matches == {"logs": 0}


def test_zero_match_rule_reported(tmp_path):
    rs = rs_for(tmp_path, RULE)
    apply_rules("nv.dd", [], rs)
    assert rs.matches == {"logs": 0}


def test_elevate(tmp_path):
    e = ce("metadata", [Diff("mtime", 1, 2)], path="/boot/vmlinuz")
    rs = rs_for(tmp_path, elevate=[{"sources": ["mmc#p1"], "paths": ["**"], "reason": "boot"}])
    apply_rules("mmc#p1", [e], rs)
    assert e.priority == 1


def test_boot_partition_binary_content_is_priority_1(tmp_path):
    e = ce("modified", [Diff("content", "a", "b")], kind="binary", boot=True)
    apply_rules("mmc#p1", [e], rs_for(tmp_path))
    assert e.priority == 1


def test_elf_added_is_priority_1_text_modified_is_2(tmp_path):
    a = ce("added", [Diff("existence", None, "present")], kind="elf")
    m = ce("modified", [Diff("content", "a", "b")], kind="text")
    apply_rules("x", [a, m], rs_for(tmp_path))
    assert a.priority == 1 and m.priority == 2


def test_unchanged_and_incomplete_priorities(tmp_path):
    u = ce("unchanged", [])
    i = ce("incomplete", [], incomplete=True)
    apply_rules("x", [u, i], rs_for(tmp_path))
    assert u.priority == 5 and i.priority == 2


def test_priority_for_defaults():
    assert priority_for(ce("metadata", [Diff("uid", 1000, 0, sensitive=True)])) == 1
