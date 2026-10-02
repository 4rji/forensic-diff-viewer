import pytest

from forensic_compare.capabilities import decode_capability


def test_cap_v2_net_raw_effective():
    raw = bytes.fromhex("01000002" "00200000" "00000000" "00000000" "00000000")
    d = decode_capability(raw)
    assert d["version"] == 2 and d["effective"] is True
    assert d["permitted"] == ["cap_net_raw"] and d["inheritable"] == []
    assert d["rootid"] is None
    assert d["text"] == "cap_net_raw+ep"


def test_cap_v3_rootid_not_effective():
    raw = bytes.fromhex("00000003" "00040000" "00000000" "00000000" "00000000" "e8030000")
    d = decode_capability(raw)
    assert d["version"] == 3 and d["rootid"] == 1000
    assert d["text"] == "cap_net_bind_service+p"


def test_cap_inheritable_and_multiple():
    # permitted: chown(0) + net_admin(12); inheritable: net_admin
    raw = bytes.fromhex("01000002" "01100000" "00100000" "00000000" "00000000")
    d = decode_capability(raw)
    # libcap-style grouping: capabilities sharing the same flag set are grouped
    assert d["text"] == "cap_chown+ep cap_net_admin+eip"


def test_cap_high_word_and_unknown_bit():
    # bit 40 (cap_checkpoint_restore) and bit 63 (unknown) in the high word
    raw = bytes.fromhex("00000002" "00000000" "00000000" "00010080" "00000000")
    d = decode_capability(raw)
    assert d["permitted"] == ["cap_checkpoint_restore", "cap_63"]


def test_cap_v1():
    raw = bytes.fromhex("01000001" "00200000" "00000000")
    assert decode_capability(raw)["text"] == "cap_net_raw+ep"


@pytest.mark.parametrize("raw", [
    b"\x01\x02",
    bytes.fromhex("01000002" "00200000"),           # truncated v2
    bytes.fromhex("01000009" + "00" * 16),           # bad version
    bytes.fromhex("00000003" + "00" * 16),           # v3 missing rootid
])
def test_cap_malformed(raw):
    with pytest.raises(ValueError):
        decode_capability(raw)
