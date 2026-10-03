import base64
import hashlib
import json
import re
from pathlib import Path

from forensic_compare.report import (
    RunContext,
    build_comparison,
    embed_json,
    render_html,
)

STATIC = Path(__file__).parents[1] / "forensic_compare" / "static"


def minimal_comparison():
    entry = {"path": "/<img src=x onerror=alert(1)>", "path_hex": "2f", "status": "modified",
             "incomplete": False, "incomplete_reasons": [], "diffs": [], "golden": None,
             "current": None, "kind": "text", "boot": False, "priority": 2,
             "expectation": "none", "rules": []}
    run = RunContext(
        generated_at="2026-10-02T00:00:00Z", command=["compare.py", "g", "c", "-o", "r"],
        mode="dir", inputs={"golden": "g", "current": "c"}, tool_versions={"fls": "x"},
        integrity={"overall": "verified", "disclaimer": "d", "images": [],
                   "checksum_files": {}},
        capture={"golden": {}, "current": {}}, rules={"rules": []},
        sources=[{"id": "a.dd", "kind": "filesystem", "status": "compared", "entries": [entry],
                  "summary": {"total": 1}}],
        unmatched=[], not_used={"golden": [], "current": []},
        completeness={"complete": True, "reasons": []}, notices=[])
    return build_comparison(run)


def test_build_comparison_schema():
    c = minimal_comparison()
    assert c["schema"] == "forensic-compare/comparison/1"
    assert c["sources"][0]["id"] == "a.dd"
    json.dumps(c)  # serializable


def test_embed_json_escapes():
    s = embed_json({"p": "</script><b>&  "})
    assert "</script>" not in s and "<" not in s and ">" not in s and "&" not in s
    assert "\\u003c" in s and "\\u2028" in s and "\\u2029" in s
    assert json.loads(s) == {"p": "</script><b>&  "}


def test_csp_first_in_head_and_hashes_match():
    html = render_html(minimal_comparison())
    head = html.split("<head>", 1)[1]
    assert head.lstrip().startswith('<meta http-equiv="Content-Security-Policy"')
    csp = re.search(r'content="([^"]+)"', head).group(1)
    for tag in ("script", "style"):
        bodies = re.findall(rf"<{tag}(?![^>]*application/json)[^>]*>(.*?)</{tag}>", html, re.S)
        assert len(bodies) == 1
        h = base64.b64encode(hashlib.sha256(bodies[0].encode()).digest()).decode()
        assert f"'sha256-{h}'" in csp
    for d in ("default-src 'none'", "base-uri 'none'", "form-action 'none'",
              "connect-src 'none'", "img-src 'none'"):
        assert d in csp


def test_data_block_is_inert_and_escaped():
    html = render_html(minimal_comparison())
    m = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S)
    assert "<img" not in m.group(1)
    assert json.loads(m.group(1))["sources"][0]["entries"][0]["path"].startswith("/<img")


def test_no_external_urls():
    html = render_html(minimal_comparison())
    assert not re.search(r"(src|href)\s*=\s*[\"']?(https?:|//|data:|javascript:)", html, re.I)
    assert "http://" not in html and "https://" not in html


def test_app_js_has_no_dangerous_sinks():
    js = (STATIC / "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                 "new Function", "fetch(", "XMLHttpRequest", ".href", ".src"):
        assert sink not in js, sink


def test_only_link_is_the_validated_diff_page():
    js = (STATIC / "app.js").read_text()
    assert js.count("href:") == 1 and "href: file" in js
    assert "var PAGE_FILE = /^(diffs|files)\\/\\d{4,}\\.html$/;" in js
    assert "if (!PAGE_FILE.test(file)) return null;" in js


def test_static_assets_cannot_break_out():
    assert "</script" not in (STATIC / "app.js").read_text().lower()
    assert "</style" not in (STATIC / "style.css").read_text().lower()
