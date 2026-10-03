"""Browser tests: the report must work offline from file://, render hostile data as text, and
keep filters, banners, pagination and the detail panel behaving as specified."""
import re

import pytest
import yaml

from forensic_compare.compare import main
from tests.conftest import require_tools

pytestmark = pytest.mark.browser

RULES = {"schema": 1, "rules": [
    {"id": "full-modified", "label": "expected edit", "reason": "test",
     "sources": ["config-active-crypt.dd"], "paths": ["etc/modified.conf"],
     "statuses": ["modified"], "fields": ["content", "size"]},
    {"id": "partial-file2link", "label": "type only", "reason": "test",
     "sources": ["config-active-crypt.dd"], "paths": ["file2link"],
     "statuses": ["modified"], "fields": ["type"]},
    {"id": "never-matches", "label": "none", "reason": "test",
     "sources": ["config-active-crypt.dd"], "paths": ["does/not/exist"],
     "statuses": ["modified"], "fields": ["content"]},
]}


@pytest.fixture(scope="module")
def report(fixtures_dir, tmp_path_factory):
    require_tools("fls", "icat", "fsstat", "mmls", "debugfs")
    base = tmp_path_factory.mktemp("browser")
    rules = base / "rules.yaml"
    rules.write_text(yaml.safe_dump(RULES))
    out = base / "report"
    code = main([str(fixtures_dir / "captures/golden"), str(fixtures_dir / "captures/current"),
                 "-o", str(out), "--quiet", "--rules", str(rules), "--verify-integrity",
                 "--allfiles"])
    assert code == 3
    return out / "report.html"


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # browser not installed
            pytest.skip(f"chromium not available: {exc}")
        yield b
        b.close()


@pytest.fixture
def page(browser, report):
    ctx = browser.new_context()
    attempts, console, dialogs = [], [], []
    ctx.on("request", lambda r: attempts.append(r.url))  # recorded before any blocking

    pages = (report.parent.as_uri() + "/diffs/", report.parent.as_uri() + "/files/")

    def gate(route):  # only the report and its local diff / file pages may load
        url = route.request.url
        if url == report.as_uri() or (url.startswith(pages) and url.endswith(".html")):
            route.continue_()
        else:
            route.abort()

    ctx.route("**/*", gate)
    pg = ctx.new_page()
    pg.set_default_timeout(5000)
    pg.on("console", lambda m: console.append((m.type, m.text)))
    pg.on("pageerror", lambda e: console.append(("pageerror", str(e))))
    pg.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    pg.goto(report.as_uri())
    pg.wait_for_selector(".topbar")
    pg.attempts, pg.console_log, pg.dialogs = attempts, console, dialogs
    yield pg
    ctx.close()


def open_section(pg, sid):
    pg.locator(".sidebar .nav-item", has_text=sid).first.click()
    pg.wait_for_selector("#entries")


def displaying(pg):
    m = re.match(r"Displaying (\d+) of (\d+) entries", pg.locator("#displaying").inner_text())
    return int(m.group(1)), int(m.group(2))


def rows(pg):
    return pg.locator("#entries tbody tr")


def paths(pg):
    return [t for t in pg.locator("#entries tbody td.path").all_inner_texts()]


def test_offline_no_unexpected_requests(page, report):
    open_section(page, "config-active-crypt.dd")
    page.locator("#entries tbody tr").first.click()
    unexpected = [u for u in page.attempts if u != report.as_uri()]
    assert unexpected == []
    assert page.console_log == []
    assert page.dialogs == []


def test_hostile_names_render_as_text(page):
    open_section(page, "config-active-crypt.dd")
    page.fill("#search", "onerror")
    texts = paths(page)
    assert "/<img src=x onerror=alert(1)>" in texts
    assert page.locator("#entries img").count() == 0
    assert page.locator("img, svg").count() == 0
    page.uncheck("#f-hide-unchanged")  # link_hostile is unchanged
    page.fill("#search", "link_hostile")
    page.locator("#entries tbody tr").first.click()
    assert "</script><img src=x onerror=alert(2)>" in page.locator("#detail").inner_text()
    assert page.locator("img, svg").count() == 0
    assert page.dialogs == []


def test_default_filters_hide_unchanged_and_count(page):
    open_section(page, "config-active-crypt.dd")
    shown, total = displaying(page)
    assert total == 35 and 0 < shown < total
    assert all("Unchanged" not in t for t in page.locator("#entries tbody td:nth-child(2)").all_inner_texts())
    assert page.locator("#f-hide-unchanged").is_checked()
    assert not page.locator("#f-hide-expected").is_checked()


def test_incomplete_filter_includes_badged_modified_entry(page):
    open_section(page, "config-active-crypt.dd")
    page.click("button[data-filter='incomplete']")
    texts = paths(page)
    assert "/new^line" in texts
    row = page.locator("#entries tbody tr", has=page.locator("td.path", has_text="/new^line"))
    assert "Modified" in row.inner_text() and "incomplete" in row.inner_text()


def test_hide_fully_expected_keeps_partial_and_incomplete(page):
    open_section(page, "config-active-crypt.dd")
    page.fill("#search", "")
    before = paths(page)
    assert "/etc/modified.conf" in before and "/file2link" in before
    page.check("#f-hide-expected")
    after = paths(page)
    assert "/etc/modified.conf" not in after
    assert "/file2link" in after and "/new^line" in after


def test_reset_restores_defaults(page):
    open_section(page, "config-active-crypt.dd")
    default = displaying(page)
    page.click("button[data-filter='unchanged']")
    page.fill("#search", "etc")
    assert displaying(page) != default
    page.click("#reset-filters")
    assert displaying(page) == default
    assert page.locator("#search").input_value() == ""


def test_search_updates_displaying(page):
    open_section(page, "config-active-crypt.dd")
    page.click("button[data-filter='all']")
    page.uncheck("#f-hide-unchanged")
    assert displaying(page) == (35, 35)
    page.fill("#search", "xattr_")
    assert displaying(page)[0] == 2


def test_pagination_bounds_dom_rows(page):
    open_section(page, "config-active-crypt.dd")
    page.uncheck("#f-hide-unchanged")
    page.select_option("select[aria-label='Rows per page']", "25")
    assert rows(page).count() == 25
    assert page.locator("#page-info").inner_text() == "Page 1 of 2"
    page.click("text=Next ›")
    assert rows(page).count() == 10


def test_detail_panel_golden_vs_current(page):
    open_section(page, "config-active-crypt.dd")
    page.click("button[data-filter='incomplete']")
    page.locator("#entries tbody tr", has=page.locator("td.path", has_text="/new^line")).click()
    detail = page.locator("#detail")
    text = detail.text_content()
    assert "Golden" in text and "Current" in text
    assert "name may have been altered by TSK" in text
    page.click("button[data-filter='metadata']")
    page.locator("#entries tbody tr", has=page.locator("td.path", has_text="/bin/capped")).click()
    text = page.locator("#detail").text_content()
    assert "cap_net_raw+ep" in text and "sensitive" in text and "uncovered" in text


def test_sensitive_allowance_and_rule_coverage_visible(page):
    open_section(page, "config-active-crypt.dd")
    page.locator("#entries tbody tr", has=page.locator("td.path", has_text="/file2link")).click()
    text = page.locator("#detail").inner_text()
    assert "Partially expected" in text and "partial-file2link" in text


def test_banners_visible_under_filters_and_collapsed(page):
    open_section(page, "config-active-crypt.dd")
    page.click("button[data-filter='unchanged']")
    assert page.locator(".banner[data-notice='integrity-failed']").count() >= 1
    page.click(".banner-bar button")
    summary = page.locator(".banner-summary").inner_text()
    assert "Integrity FAILED (1)" in summary
    assert "Reference unverified" in summary and "Incomplete analysis" in summary
    page.click("button[data-filter='all']")
    assert "Integrity FAILED (1)" in page.locator(".banner-summary").inner_text()


def test_disk_section_partitions(page):
    page.locator(".sidebar .nav-item", has_text="mmcblk0.dd").first.click()
    text = page.locator("#content").inner_text()
    for word in ("encrypted", "unsupported", "unknown", "compared", "squashfs", "luks2"):
        assert word in text
    assert "Open mapper image config-active-crypt.dd" in text


def test_rules_view_shows_no_matches(page):
    page.locator(".sidebar .nav-item", has_text="Expected-change rules").click()
    assert "No matches" in page.locator("#content").inner_text()


def test_theme_toggle(page):
    before = page.evaluate("document.documentElement.getAttribute('data-theme')")
    page.click("#theme-toggle")
    after = page.evaluate("document.documentElement.getAttribute('data-theme')")
    assert {before, after} == {"light", "dark"}


def test_works_without_storage(browser, report):
    ctx = browser.new_context()
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.add_init_script("Object.defineProperty(window, 'localStorage', {get() { throw new Error('denied'); }});")
    pg.goto(report.as_uri())
    pg.wait_for_selector(".topbar")
    assert errors == []
    ctx.close()


def test_opens_on_first_file_table(page):
    page.wait_for_selector("#entries")
    assert page.locator("#entries tbody tr").count() > 0


def test_line_diff_opens_in_new_tab(page):
    open_section(page, "config-active-crypt.dd")
    page.locator("#entries tbody tr", has=page.locator("td.path", has_text="/etc/modified.conf")).click()
    link = page.locator("#detail a.btn", has_text="line diff")
    assert link.get_attribute("target") == "_blank"
    with page.context.expect_page() as info:
        link.click()
    diff = info.value
    diff.wait_for_load_state()
    assert diff.locator("td.del").first.inner_text() == "a"
    assert diff.locator("td.add").first.inner_text() == "b"
    assert diff.url.startswith(page.url.rsplit("/", 1)[0] + "/diffs/")
    assert not [m for m in page.console_log if m[0] in ("error", "pageerror")]


def test_added_file_opens_in_new_tab(page):
    open_section(page, "config-active-crypt.dd")
    page.locator("#entries tbody tr", has=page.locator("td.path", has_text="/etc/added.conf")).click()
    link = page.locator("#detail a.btn", has_text="Open file")
    with page.context.expect_page() as info:
        link.click()
    view = info.value
    view.wait_for_load_state()
    assert view.locator("td.t").first.inner_text() == "x"
