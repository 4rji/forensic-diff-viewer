from forensic_compare.tools.diagnostics import classify, is_problem


def test_classify_debugfs_banner():
    assert classify("debugfs", "debugfs 1.47.2 (1-Jan-2025)") == "banner"


def test_classify_debugfs_known_errors():
    assert classify("debugfs", "<99999>: File not found by ext2_lookup ") == "error"
    assert classify(
        "debugfs",
        "ea_get: Extended attribute block has a bad header while getting extended attribute",
    ) == "error"


def test_classify_unknown_marks_incomplete():
    kind = classify("fsstat", "Something odd happened")
    assert kind == "unknown"
    assert is_problem(kind)


def test_classify_tsk_error():
    assert classify("icat", "Metadata address too large for image (2049)") == "error"


def test_banner_is_not_problem():
    assert not is_problem("banner")
    assert not is_problem("info")


def test_banner_of_one_tool_is_unknown_for_another():
    assert classify("fls", "debugfs 1.47.2 (1-Jan-2025)") == "unknown"
