"""comparison.json assembly and the self-contained, CSP-protected report.html.

Defense in depth for the HTML report:
- all CSS/JS is inlined; there are no external assets and no data-derived links;
- data is embedded as an inert ``application/json`` block with ``<``, ``>``, ``&``, U+2028 and
  U+2029 escaped, and rendered by app.js through ``textContent`` only;
- a Content-Security-Policy ``<meta>`` is the first element of ``<head>``; it allows only the
  exact inline script and style (by SHA-256) and forbids network access, base URLs and forms.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import __version__

SCHEMA = "forensic-compare/comparison/1"
HERE = Path(__file__).parent
_PLACEHOLDER = re.compile(r"\{\{(CSP|TITLE|STYLE|SCRIPT|DATA)\}\}")


@dataclass
class RunContext:
    generated_at: str
    command: list
    mode: str
    inputs: dict
    tool_versions: dict
    integrity: dict
    capture: dict
    rules: dict
    sources: list
    unmatched: list
    not_used: dict
    completeness: dict
    notices: list = field(default_factory=list)


def build_comparison(run: RunContext) -> dict:
    return {"schema": SCHEMA, "tool": {"name": "forensic_compare", "version": __version__},
            **asdict(run)}


def embed_json(obj) -> str:
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _sha256_source(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode() \
        + "'"


def render_html(comparison: dict) -> str:
    template = (HERE / "templates" / "report.html").read_text(encoding="utf-8")
    style = (HERE / "static" / "style.css").read_text(encoding="utf-8")
    script = (HERE / "static" / "app.js").read_text(encoding="utf-8")
    if "</style" in style.lower() or "</script" in script.lower():
        raise ValueError("static assets must not contain closing style/script tags")
    csp = ("default-src 'none'; "
           f"script-src {_sha256_source(script)}; "
           f"style-src {_sha256_source(style)}; "
           "img-src 'none'; font-src 'none'; connect-src 'none'; media-src 'none'; "
           "object-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'; "
           "base-uri 'none'; form-action 'none'")
    if '"' in csp or "&" in csp or "<" in csp:
        raise ValueError("CSP must be attribute-safe")
    values = {
        "CSP": csp,
        "TITLE": "Forensic comparison report",
        "STYLE": style,
        "SCRIPT": script,
        "DATA": embed_json(comparison),
    }
    return _PLACEHOLDER.sub(lambda m: values[m.group(1)], template)
