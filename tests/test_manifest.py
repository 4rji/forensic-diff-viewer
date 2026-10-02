from forensic_compare.manifest import (
    SCHEMA,
    Assessed,
    Entry,
    Manifest,
    encode_path,
    load_manifest,
    save_manifest,
)


def test_encode_path_non_utf8_and_control():
    disp, hx = encode_path(b"/bad\xff\xfename\x01")
    assert hx == b"/bad\xff\xfename\x01".hex()
    assert "\\xff" in disp and "\\xfe" in disp and "\\x01" in disp
    assert disp.startswith("/bad")


def test_encode_path_plain_utf8_unchanged():
    assert encode_path("/etc/ñ.conf".encode())[0] == "/etc/ñ.conf"


def test_encode_path_escapes_backslash_to_stay_unambiguous():
    # a literal backslash must not be confusable with an escape sequence
    assert encode_path(b"/a\\x01")[0] == "/a\\\\x01"


def test_assessed_constructors():
    assert Assessed.error("timeout").assessed is False
    assert Assessed.error("timeout").reason == "timeout"
    assert Assessed.absent().assessed is True
    assert Assessed.na().state == "n/a"
    assert Assessed.ok(5).value == 5


def test_blank_entry_is_conservative():
    e = Entry.blank("/a", b"/a".hex(), 12)
    for name in Entry.ASSESSED_FIELDS:
        assert getattr(e, name).state == "error"


def test_manifest_roundtrip(tmp_path):
    e = Entry.blank("/a", b"/a".hex(), 12)
    e.type = Assessed.ok("file")
    e.mode = Assessed.ok(0o4755)
    e.xattrs = Assessed.ok({"user.x": {"hex": "00ff", "size": 2}})
    e.capability = Assessed.error("enumeration mismatch", log_id=7)
    m = Manifest.new(side="golden", source_id="x.dd")
    m.entries.append(e)
    save_manifest(m, tmp_path / "m.json")
    m2 = load_manifest(tmp_path / "m.json")
    assert m2.schema == SCHEMA == "forensic-compare/manifest/1"
    got = m2.entries[0]
    assert got.mode.value == 0o4755
    assert got.xattrs.value["user.x"]["hex"] == "00ff"
    assert got.capability.state == "error" and got.capability.log_id == 7
    assert m2.side == "golden" and m2.source_id == "x.dd"
