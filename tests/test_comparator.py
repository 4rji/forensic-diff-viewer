import pytest

from forensic_compare.comparator import compare_manifests, summarize
from forensic_compare.manifest import Assessed, Entry, Manifest, encode_path

A = Assessed


def entry(path, *, type="file", mode=0o644, uid=1000, gid=1000, size=1, mtime=100,
          sha="aa", kind="text", target=None, xattrs=None, cap=None, inode=12, lossy=False,
          **overrides):
    disp, hx = encode_path(path.encode())
    e = Entry(path=disp, path_hex=hx, inode=inode, path_lossy=lossy)
    e.type, e.mode, e.uid, e.gid = A.ok(type), A.ok(mode), A.ok(uid), A.ok(gid)
    e.size, e.mtime = A.ok(size), A.ok(mtime)
    e.content = A.ok({"sha256": sha, "bytes_read": size, "kind": kind}) if type == "file" else A.na()
    e.symlink = A.ok({"target_hex": target.encode().hex(), "target": target}) \
        if type == "symlink" else A.na()
    e.xattrs = A.ok(xattrs) if xattrs else A.absent()
    e.capability = A.ok(cap) if cap else A.absent()
    for k, v in overrides.items():
        setattr(e, k, v)
    return e


def manifests(golden, current, g_state="complete", c_state="complete"):
    g, c = Manifest.new("golden", "s"), Manifest.new("current", "s")
    g.entries, c.entries = list(golden), list(current)
    g.inventory = {"state": g_state}
    c.inventory = {"state": c_state}
    return g, c


def one(golden, current, **kw):
    res = compare_manifests(*manifests(golden, current, **kw))
    assert len(res) == 1
    return res[0]


def fields(ce):
    return {d.field for d in ce.diffs}


def test_unchanged():
    ce = one([entry("/a")], [entry("/a")])
    assert ce.status == "unchanged" and not ce.incomplete and ce.diffs == []


def test_content_diff_is_modified():
    ce = one([entry("/a")], [entry("/a", sha="bb")])
    assert ce.status == "modified" and "content" in fields(ce)


def test_only_mode_is_metadata():
    ce = one([entry("/a")], [entry("/a", mode=0o600)])
    assert ce.status == "metadata" and fields(ce) == {"mode"}


def _xattr_error(e):
    e.xattrs = A.error("boom")
    e.capability = A.error("boom")
    return e


def test_mode_plus_xattr_error_is_metadata_with_incomplete_flag():
    ce = one([entry("/a")], [_xattr_error(entry("/a", mode=0o600))])
    assert ce.status == "metadata" and ce.incomplete
    assert any("xattrs" in r for r in ce.incomplete_reasons)


def test_all_equal_but_xattr_error_is_incomplete_status():
    ce = one([entry("/a")], [_xattr_error(entry("/a"))])
    assert ce.status == "incomplete" and ce.incomplete


def test_content_error_with_size_diff_is_modified():
    ce = one([entry("/a")], [entry("/a", size=5, content=A.error("short read"))])
    assert ce.status == "modified" and "size" in fields(ce) and ce.incomplete


def test_content_error_same_size_is_incomplete():
    ce = one([entry("/a")], [entry("/a", content=A.error("timeout"))])
    assert ce.status == "incomplete"


def test_type_change_is_modified_and_sensitive_to_symlink():
    ce = one([entry("/a")], [entry("/a", type="symlink", target="x")])
    assert ce.status == "modified"
    d = next(d for d in ce.diffs if d.field == "type")
    assert d.sensitive and d.golden == "file" and d.current == "symlink"
    assert "content" not in fields(ce)


def test_symlink_retarget_is_modified():
    ce = one([entry("/l", type="symlink", target="a")], [entry("/l", type="symlink", target="b")])
    assert ce.status == "modified" and "symlink_target" in fields(ce)


def test_added_when_golden_complete():
    ce = one([], [entry("/new")])
    assert ce.status == "added" and fields(ce) == {"existence"} and not ce.incomplete
    assert ce.golden is None and ce.current["path"] == "/new"


def test_added_when_golden_partial_is_incomplete():
    ce = one([], [entry("/new")], g_state="partial")
    assert ce.status == "incomplete" and "existence not assessed" in ce.incomplete_reasons[0]


def test_deleted_when_current_partial_is_incomplete():
    ce = one([entry("/old")], [], c_state="partial")
    assert ce.status == "incomplete"


def test_deleted():
    ce = one([entry("/old")], [])
    assert ce.status == "deleted" and fields(ce) == {"existence"}


def test_added_symlink_existence_is_sensitive():
    ce = one([], [entry("/l", type="symlink", target="etc")])
    assert ce.diffs[0].field == "existence" and ce.diffs[0].sensitive


def test_ambiguous_path_is_incomplete():
    g, c = manifests([entry("/a", inode=1), entry("/a", inode=2)], [entry("/a")])
    (ce,) = compare_manifests(g, c)
    assert ce.status == "incomplete" and "ambiguous" in ce.incomplete_reasons[0]


def test_lossy_path_flags_incomplete():
    ce = one([entry("/new^line", lossy=True)], [entry("/new^line", sha="bb", lossy=True)])
    assert ce.status == "modified" and ce.incomplete
    assert any("altered by TSK" in r for r in ce.incomplete_reasons)


@pytest.mark.parametrize("g_uid,c_uid,sensitive", [(1000, 0, True), (0, 1000, False)])
def test_uid_to_root_is_sensitive(g_uid, c_uid, sensitive):
    ce = one([entry("/a", uid=g_uid)], [entry("/a", uid=c_uid)])
    (d,) = ce.diffs
    assert d.field == "uid" and d.sensitive is sensitive


def test_suid_split_from_mode():
    ce = one([entry("/a", mode=0o755)], [entry("/a", mode=0o4755)])
    assert fields(ce) == {"suid"}
    assert ce.diffs[0].sensitive and ce.diffs[0].golden is False and ce.diffs[0].current is True


def test_sgid_and_sticky():
    ce = one([entry("/d", type="dir", mode=0o1777)], [entry("/d", type="dir", mode=0o2777)])
    assert fields(ce) == {"sgid", "mode"}
    mode = next(d for d in ce.diffs if d.field == "mode")
    assert mode.golden == "1777" and mode.current == "0777" and not mode.sensitive


def test_capability_only_as_capability_field():
    cap = {"text": "cap_net_raw+ep", "hex": "0100"}
    ce = one([entry("/b")], [entry("/b", cap=cap)])
    assert fields(ce) == {"capability"} and ce.diffs[0].sensitive
    assert ce.diffs[0].current == "cap_net_raw+ep" and ce.diffs[0].golden is None


def test_security_xattr_sensitive_user_xattr_not():
    ce = one([entry("/a", xattrs={"user.x": {"hex": "00", "size": 1}})],
             [entry("/a", xattrs={"user.x": {"hex": "01", "size": 1},
                                  "security.foo": {"hex": "62", "size": 1}})])
    by = {d.field: d for d in ce.diffs}
    assert set(by) == {"xattr:user.x", "xattr:security.foo"}
    assert by["xattr:security.foo"].sensitive and not by["xattr:user.x"].sensitive
    assert ce.status == "metadata"


def test_mtime_only_metadata():
    ce = one([entry("/a")], [entry("/a", mtime=160)])
    assert ce.status == "metadata" and fields(ce) == {"mtime"}


def test_dir_size_not_compared():
    ce = one([entry("/d", type="dir", size=1024)], [entry("/d", type="dir", size=2048)])
    assert ce.status == "unchanged"


def test_kind_and_boot_carried():
    g, c = manifests([entry("/k", kind="binary")], [entry("/k", sha="bb", kind="elf")])
    (ce,) = compare_manifests(g, c, boot=True)
    assert ce.kind == "elf" and ce.boot is True


def test_summarize_counts():
    g, c = manifests([entry("/a"), entry("/b"), entry("/d")],
                     [entry("/a"), entry("/b", sha="x"), entry("/n"),
                      ])
    s = summarize(compare_manifests(g, c))
    assert s["total"] == 4 and s["unchanged"] == 1 and s["modified"] == 1
    assert s["added"] == 1 and s["deleted"] == 1 and s["metadata"] == 0 and s["incomplete"] == 0
