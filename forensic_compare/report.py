"""comparison.json assembly and the self-contained, CSP-protected report.html.

Defense in depth for the HTML report:
- all CSS/JS is inlined; there are no external assets and no data-derived links;
- data is embedded as an inert ``application/json`` block with ``<``, ``>``, ``&``, U+2028 and
  U+2029 escaped, and rendered by app.js through ``textContent`` only;
- a Content-Security-Policy ``<meta>`` is the first element of ``<head>``; it allows only the
  exact inline script and style (by SHA-256) and forbids network access, base URLs and forms;
- the optional logo banner is a build-time file embedded as a ``data:`` URI; only then does the
  CSP allow ``img-src data:``. It is never derived from the analysed data.
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
LOGO = HERE.parent / "logo.png"  # replace this file to brand the report; delete it for no logo
_PLACEHOLDER = re.compile(r"\{\{(CSP|TITLE|STYLE|SCRIPT|DATA|LOGO)\}\}")


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
    options: dict = field(default_factory=dict)  # e.g. {"text_diffs": bool}


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


def _image_type(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    head = data[:1024].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "image/svg+xml"
    return None


def load_logo(path: Path = LOGO) -> str | None:
    """The logo as a ``data:`` URI, or None when the file does not exist.

    The content decides the type, so a JPEG, GIF, WebP or SVG saved as logo.png still works.
    """
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    mime = _image_type(data)
    if mime is None:
        raise ValueError(f"{path} is not a PNG, JPEG, GIF, WebP or SVG image")
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


def render_html(comparison: dict, logo: str | None = None) -> str:
    template = (HERE / "templates" / "report.html").read_text(encoding="utf-8")
    style = (HERE / "static" / "style.css").read_text(encoding="utf-8")
    script = (HERE / "static" / "app.js").read_text(encoding="utf-8")
    if "</style" in style.lower() or "</script" in script.lower():
        raise ValueError("static assets must not contain closing style/script tags")
    img_src = "data:" if logo else "'none'"
    csp = ("default-src 'none'; "
           f"script-src {_sha256_source(script)}; "
           f"style-src {_sha256_source(style)}; "
           f"img-src {img_src}; font-src 'none'; connect-src 'none'; media-src 'none'; "
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
        "LOGO": f'<img id="logo" class="logo" alt="Logo" src="{logo}" hidden>' if logo else "",
    }
    return _PLACEHOLDER.sub(lambda m: values[m.group(1)], template)
