import re

from forensic_compare.textdiff import eligibility, render_view_page, view_side
from forensic_compare.textdiff import render_diff_page as _render_marked


def render_diff_page(**kw):
    """The page without inline <mark> highlights, so assertions see whole strings."""
    return re.sub(r"</?mark>", "", _render_marked(**kw))


def _side(kind="text", sha="a" * 64, size=10, type_="file"):
    return {"type": {"state": "ok", "value": type_}, "inode": 12,
            "size": {"state": "ok", "value": size},
            "content": {"state": "ok", "value": {"sha256": sha, "kind": kind}}}


def _entry(g, c, status="modified"):
    return {"path": "/etc/x.conf", "status": status, "golden": g, "current": c}


def test_modified_text_file_is_eligible():
    assert eligibility(_entry(_side(), _side(sha="b" * 64)), max_file=100) is None


def test_ineligible_entries_say_why():
    same = _side()
    assert eligibility(_entry(same, same, status="metadata"), 100) == "no content change"
    assert "binary" in eligibility(_entry(_side(kind="elf"), _side(sha="b" * 64)), 100)
    assert "larger" in eligibility(_entry(_side(size=500), _side(sha="b" * 64)), 100)
    unread = dict(_side(), content={"state": "error", "reason": "icat failed"})
    assert "not read" in eligibility(_entry(unread, _side(sha="b" * 64)), 100)
    assert eligibility(_entry(None, _side(), status="added"), 100) == "no content change"
    link = _side(type_="symlink")
    assert eligibility(_entry(link, _side(sha="b" * 64)), 100) == "not a regular file on both sides"


def test_page_escapes_content_and_path():
    page = render_diff_page(path="/etc/<b>.conf", section="s", golden_text="a\n<script>x</script>\n",
                            current_text="a\nsafe\n", golden_sha="1" * 64, current_sha="2" * 64)
    assert "<script>x" not in page and "&lt;script&gt;x" in page
    assert "/etc/&lt;b&gt;.conf" in page
    assert "<script" not in page.replace("&lt;script", "")


def test_page_marks_removed_and_added_lines_and_has_strict_csp():
    page = render_diff_page(path="/p", section="s", golden_text="keep\nold\n",
                            current_text="keep\nnew\nextra\n", golden_sha="1" * 64,
                            current_sha="2" * 64)
    assert re.search(r'class="del"[^>]*>.*old', page)
    assert re.search(r'class="add"[^>]*>.*extra', page)
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert "default-src 'none'" in csp and "script-src" not in csp


def test_long_unchanged_runs_are_collapsed():
    a = "".join(f"line {i}\n" for i in range(100))
    b = a.replace("line 50\n", "LINE 50\n")
    page = render_diff_page(path="/p", section="s", golden_text=a, current_text=b,
                            golden_sha="1" * 64, current_sha="2" * 64)
    assert "<details" in page and "unchanged lines" in page
    assert "line 49" in page and "LINE 50" in page


def test_similar_lines_get_character_highlights():
    page = _render_marked(path="/p", section="s", golden_text="timeout = 30\n",
                          current_text="timeout = 90\n", golden_sha="1" * 64,
                          current_sha="2" * 64)
    assert "<mark>3</mark>" in page and "<mark>9</mark>" in page


def test_view_side_per_status():
    t = _side()
    assert view_side(_entry(None, t, status="added"), 100) == ("current", None)
    assert view_side(_entry(t, None, status="deleted"), 100) == ("golden", None)
    assert view_side(_entry(t, t, status="unchanged"), 100) == ("current", None)
    assert view_side(_entry(t, t, status="metadata"), 100) == ("current", None)
    unread = dict(_side(), content={"state": "error", "reason": "icat failed"})
    assert view_side(_entry(t, unread, status="incomplete"), 100) == ("golden", None)


def test_view_side_reasons_and_non_files():
    assert view_side(_entry(None, _side(kind="elf"), status="added"), 100)[1].startswith("binary")
    assert "larger" in view_side(_entry(None, _side(size=500), status="added"), 100)[1]
    assert view_side(_entry(None, _side(type_="dir"), status="added"), 100) is None


def test_view_page_escapes_and_numbers_lines():
    page = render_view_page(path="/etc/<x>", section="s", side="current",
                            text="one\n<script>two</script>\n", sha="3" * 64)
    assert "&lt;script&gt;two" in page and "<script>" not in page
    assert '<td class="n">2</td>' in page and "current" in page
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert "default-src 'none'" in csp and "script-src" not in csp
