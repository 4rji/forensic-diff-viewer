"""File pages next to the report: line diffs of modified text files, and (``--allfiles``) a
view of every other text file.

- **Diffs** (default; ``--no-text-diffs`` turns them off): each Modified regular file whose
  content changed and is text on both sides gets a side-by-side page ``diffs/NNNN.html``.
- **Views** (``--allfiles``): every other regular text file (added, deleted, unchanged,
  metadata-only, incomplete) gets a page ``files/NNNN.html`` with its content. On large images
  this re-reads every text file, so it is opt-in.

Content is extracted again with ``icat`` (read-only), checked against the SHA-256 recorded
during the analysis, and rendered as escaped text in a standalone page with no script and a
strict CSP. Diffs come first in the shared size budget. Pages are a reading aid: they never
change a status, a priority or the exit code. They contain file content, so the output
directory must be handled as evidence.
"""
from __future__ import annotations

import base64
import difflib
import hashlib
import html
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .progress import Progress
from .tools.tsk import icat_stream

MAX_FILE_BYTES = 1 << 20
MAX_TOTAL_BYTES = 64 << 20
TEXT_KINDS = ("text", "script", "empty")
CONTEXT = 3
MAX_INLINE_LINE = 2000  # longer lines are not highlighted character by character
INLINE_MIN_RATIO = 0.5


def _ok(assessed):
    return assessed and assessed.get("state") == "ok"


def _is_file(side):
    return bool(side) and _ok(side.get("type")) and side["type"]["value"] == "file"


def eligibility(entry: dict, max_file: int) -> str | None:
    """None when a line diff can be made for this entry, else the reason it cannot."""
    g, c = entry.get("golden"), entry.get("current")
    if entry.get("status") != "modified" or not g or not c:
        return "no content change"
    if not (_is_file(g) and _is_file(c)):
        return "not a regular file on both sides"
    if not all(_ok(s.get("content")) for s in (g, c)):
        return "content was not read on both sides"
    if g["content"]["value"]["sha256"] == c["content"]["value"]["sha256"]:
        return "no content change"
    kinds = [s["content"]["value"].get("kind") for s in (g, c)]
    if any(k not in TEXT_KINDS for k in kinds):
        return f"binary content ({' / '.join(kinds)}); compare the hashes"
    if any(s["size"]["value"] > max_file for s in (g, c)):
        return f"larger than the {max_file} byte page limit"
    return None


def view_side(entry: dict, max_file: int):
    """(side, None) when a file view can be made, (side, reason) when it cannot, or None when
    neither side is a regular file. Added → current, deleted → golden, else current first."""
    order = {"added": ("current",), "deleted": ("golden",)}.get(entry.get("status"),
                                                               ("current", "golden"))
    files = [s for s in order if _is_file(entry.get(s))]
    if not files:
        return None
    side = next((s for s in files if _ok(entry[s].get("content"))), None)
    if side is None:
        return files[0], "content was not read"
    value = entry[side]["content"]["value"]
    if value.get("kind") not in TEXT_KINDS:
        return side, f"binary content ({value.get('kind')}); compare the hashes"
    if entry[side]["size"]["value"] > max_file:
        return side, f"larger than the {max_file} byte page limit"
    return side, None


def _extract(runner, manifest, inode: int, expected_sha: str) -> tuple[bytes | None, str | None]:
    fs = manifest.filesystem
    offset, sector = fs.get("offset_bytes") or 0, fs.get("sector_size") or 512
    buf = bytearray()
    res = icat_stream(runner, Path(manifest.image["path"]), inode, buf.extend,
                      offset // sector if offset else None, sector)
    if not res.ok:
        return None, f"icat failed: {res.describe()}"
    if hashlib.sha256(buf).hexdigest() != expected_sha:
        return None, "re-read content does not match the analysed SHA-256"
    return bytes(buf), None


@dataclass
class _Job:
    kind: str          # "diff" | "view"
    section: str
    entry: dict
    sides: dict        # side -> Manifest
    size: int
    page: str | None = None
    stats: dict = field(default_factory=dict)
    reason: str | None = None


def _plan(sections, manifests, max_file, all_files, text_diffs):
    by_key = {(sid, side): m for sid, side, m in manifests}
    diffs, views = [], []
    for s in sections:
        if s.get("kind") != "filesystem":
            continue
        ms = {side: by_key.get((s["id"], side)) for side in ("golden", "current")}
        for e in s["entries"]:
            reason = eligibility(e, max_file) if text_diffs else "no content change"
            if reason is None:
                if None in ms.values():
                    e["text_diff"] = {"reason": "manifest unavailable"}
                    continue
                size = e["golden"]["size"]["value"] + e["current"]["size"]["value"]
                diffs.append(_Job("diff", s["id"], e, ms, size))
                continue
            if reason != "no content change" and e.get("status") == "modified":
                e["text_diff"] = {"reason": reason}
                if reason != "not a regular file on both sides":
                    continue
            if not all_files:
                continue
            vs = view_side(e, max_file)
            if vs is None:
                continue
            side, why = vs
            if why is None and ms[side] is None:
                why = "manifest unavailable"
            if why is not None:
                e["text_view"] = {"side": side, "reason": why}
                continue
            views.append(_Job("view", s["id"], e, {side: ms[side]}, e[side]["size"]["value"]))
    return diffs + views  # diffs first in the size budget


def _run_job(job: _Job, runner) -> _Job:
    texts = {}
    for side, m in job.sides.items():
        data, job.reason = _extract(runner, m, job.entry[side]["inode"],
                                    job.entry[side]["content"]["value"]["sha256"])
        if job.reason:
            return job
        texts[side] = data.decode("utf-8", errors="replace")
    e = job.entry
    if job.kind == "diff":
        job.page, added, removed = _render(
            path=e["path"], section=job.section, golden_text=texts["golden"],
            current_text=texts["current"], golden_sha=e["golden"]["content"]["value"]["sha256"],
            current_sha=e["current"]["content"]["value"]["sha256"])
        job.stats = {"added": added, "removed": removed}
    else:
        (side, text), = texts.items()
        job.page, lines = _render_view(path=e["path"], section=job.section, side=side,
                                       text=text, sha=e[side]["content"]["value"]["sha256"])
        job.stats = {"side": side, "lines": lines}
    return job


def build_diffs(sections, manifests, runner, writer, *, text_diffs=True, all_files=False,
                jobs=4, quiet=True,
                progress_stream=None, max_file=MAX_FILE_BYTES, max_total=MAX_TOTAL_BYTES) -> dict:
    """Adds ``text_diff`` ({file, added, removed} or {reason}) to Modified text file entries
    and, with all_files, ``text_view`` ({file, side, lines} or {side, reason}) to every other
    regular file entry; writes the pages. Returns page counts and the elapsed time."""
    t0 = time.monotonic()
    budget, accepted = max_total, []
    for job in _plan(sections, manifests, max_file, all_files, text_diffs):
        key = "text_diff" if job.kind == "diff" else "text_view"
        if job.size > budget:
            job.entry[key] = {"reason": f"total page limit ({max_total} bytes) reached"}
            if job.kind == "view":
                job.entry[key]["side"] = next(iter(job.sides))
            continue
        budget -= job.size
        accepted.append(job)

    progress = Progress("file pages", quiet=quiet, stream=progress_stream)
    total_bytes = sum(j.size for j in accepted)
    done = {"n": 0, "bytes": 0}
    counts = {"diffs": 0, "views": 0}

    def work(job):
        return _run_job(job, runner)

    if accepted:
        progress.update(0, len(accepted), 0, total_bytes, phase="extracting")
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for job in pool.map(work, accepted):  # results in plan order: stable page numbers
            key = "text_diff" if job.kind == "diff" else "text_view"
            if job.reason:
                job.entry[key] = {"reason": job.reason}
                if job.kind == "view":
                    job.entry[key]["side"] = next(iter(job.sides))
            else:
                counts[job.kind + "s"] += 1
                rel = (f"diffs/{counts['diffs']:04d}.html" if job.kind == "diff"
                       else f"files/{counts['views']:04d}.html")
                writer.write_text(rel, job.page)
                job.entry[key] = {"file": rel, **job.stats}
                job.page = None  # release memory as pages are written
            done["n"] += 1
            done["bytes"] += job.size
            progress.update(done["n"], len(accepted), done["bytes"], total_bytes,
                            phase="extracting")
    progress.finish()
    counts["seconds"] = round(time.monotonic() - t0, 1)
    return counts


# --------------------------------------------------------------------------------------------
# Rendering

STYLE = """
:root { color-scheme: light dark; --bg: #fff; --fg: #1f2328; --muted: #656d76; --line: #d0d7de;
  --del: #ffebe9; --del-hl: #ffc1ba; --add: #dafbe1; --add-hl: #aceebb; --gap: #f6f8fa; }
@media (prefers-color-scheme: dark) { :root { --bg: #0d1117; --fg: #e6edf3; --muted: #8d96a0;
  --line: #30363d; --del: #3c1618; --del-hl: #7d2a2a; --add: #12261e; --add-hl: #1f5f33;
  --gap: #161b22; } }
body { margin: 0; padding: 16px; background: var(--bg); color: var(--fg);
  font: 14px/1.45 system-ui, sans-serif; }
h1 { font-size: 16px; margin: 0 0 4px; word-break: break-all; }
.meta { color: var(--muted); font-size: 12px; margin-bottom: 12px; }
.meta code { font-size: 11px; }
.note { color: var(--muted); font-size: 12px; margin: 0 0 12px; }
table { width: 100%; border-collapse: collapse; table-layout: fixed;
  font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
col.n { width: 4.5em; }
td { padding: 0 6px; vertical-align: top; white-space: pre-wrap; word-break: break-all;
  tab-size: 4; border-bottom: 1px solid transparent; }
td.n { color: var(--muted); text-align: right; user-select: none; border-right: 1px solid var(--line); }
td.del { background: var(--del); } td.add { background: var(--add); }
td.del mark { background: var(--del-hl); color: inherit; }
td.add mark { background: var(--add-hl); color: inherit; }
td.empty { background: var(--gap); }
details { border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
summary { cursor: pointer; padding: 2px 8px; background: var(--gap); color: var(--muted);
  font-size: 12px; }
table.head th { text-align: left; font: 600 12px system-ui, sans-serif; padding: 4px 6px;
  border-bottom: 1px solid var(--line); }
.stats .a { color: #1a7f37; } .stats .r { color: #cf222e; }
"""


def _csp_hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def _inline(a: str, b: str) -> tuple[str, str]:
    """Escaped a/b with the changed characters wrapped in <mark>."""
    if len(a) > MAX_INLINE_LINE or len(b) > MAX_INLINE_LINE:
        return _esc(a), _esc(b)
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if sm.ratio() < INLINE_MIN_RATIO:  # unrelated lines: highlighting characters is noise
        return _esc(a), _esc(b)
    out_a, out_b = [], []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        sa, sb = _esc(a[i1:i2]), _esc(b[j1:j2])
        if op == "equal":
            out_a.append(sa)
            out_b.append(sb)
        else:
            out_a.append(f"<mark>{sa}</mark>" if sa else "")
            out_b.append(f"<mark>{sb}</mark>" if sb else "")
    return "".join(out_a), "".join(out_b)


def _row(gn, gtext, gcls, cn, ctext, ccls) -> str:
    def cells(n, text, cls):
        if n is None:
            return '<td class="n empty"></td><td class="empty"></td>'
        return f'<td class="n">{n}</td><td class="{cls}">{text}</td>'
    return f"<tr>{cells(gn, gtext, gcls)}{cells(cn, ctext, ccls)}</tr>"


def _table(rows) -> str:
    return ('<table><colgroup><col class="n"><col><col class="n"><col></colgroup><tbody>'
            + "".join(rows) + "</tbody></table>")


def _lines(text: str) -> list[str]:
    return [line.rstrip("\r\n") for line in text.splitlines(keepends=True)]


def _render(*, path, section, golden_text, current_text, golden_sha, current_sha):
    a, b = _lines(golden_text), _lines(current_text)
    blocks, rows, added, removed = [], [], 0, 0

    def flush():
        if rows:
            blocks.append(_table(rows[:]))
            rows.clear()

    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == "equal":
            n = i2 - i1
            eq = [_row(i1 + k + 1, _esc(a[i1 + k]), "", j1 + k + 1, _esc(b[j1 + k]), "")
                  for k in range(n)]
            head = 0 if i1 == 0 else CONTEXT
            tail = 0 if i2 == len(a) and j2 == len(b) else CONTEXT
            if n > head + tail + 2:
                rows.extend(eq[:head])
                flush()
                hidden = n - head - tail
                blocks.append(f"<details><summary>{hidden} unchanged lines</summary>"
                              f"{_table(eq[head:n - tail])}</details>")
                rows.extend(eq[n - tail:])
            else:
                rows.extend(eq)
            continue
        removed += i2 - i1
        added += j2 - j1
        for k in range(max(i2 - i1, j2 - j1)):
            ga = a[i1 + k] if i1 + k < i2 else None
            cb = b[j1 + k] if j1 + k < j2 else None
            if ga is not None and cb is not None:
                ta, tb = _inline(ga, cb)
            else:
                ta = _esc(ga) if ga is not None else ""
                tb = _esc(cb) if cb is not None else ""
            rows.append(_row(i1 + k + 1 if ga is not None else None, ta, "del",
                             j1 + k + 1 if cb is not None else None, tb, "add"))
    flush()
    if not blocks:
        blocks.append('<p class="note">Both files are empty or differ only in line endings.</p>')

    meta = (f'{_esc(section)} · <span class="stats"><span class="a">+{added}</span>\n'
            f'<span class="r">−{removed}</span></span><br>\n'
            f'golden <code>{_esc(golden_sha)}</code><br>current <code>{_esc(current_sha)}</code>')
    body = ('<table class="head"><colgroup><col class="n"><col><col class="n"><col></colgroup>\n'
            '<thead><tr><th></th><th>Golden</th><th></th><th>Current</th></tr></thead></table>\n'
            + "".join(blocks))
    return _page(path, "diff", meta, "Golden on the left, current on the right.", body), \
        added, removed


def _page(path, kind, meta, lead, body) -> str:
    csp = f"default-src 'none'; style-src {_csp_hash(STYLE)}; base-uri 'none'; form-action 'none'"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(path)} · {kind}</title><style>{STYLE}</style></head><body>
<h1>{_esc(path)}</h1>
<div class="meta">{meta}</div>
<p class="note">{lead} Content was re-read read-only with icat and matches the analysed SHA-256.
It is shown as text only; invalid UTF-8 appears as \ufffd.</p>
{body}
</body></html>
"""


def _render_view(*, path, section, side, text, sha):
    lines = _lines(text)
    rows = "".join(f'<tr><td class="n">{i}</td><td class="t">{_esc(line)}</td></tr>'
                   for i, line in enumerate(lines, 1))
    body = ('<table><colgroup><col class="n"><col></colgroup><tbody>' + rows + "</tbody></table>"
            if lines else '<p class="note">The file is empty.</p>')
    meta = (f"{_esc(section)} · {_esc(side)} · {len(lines)} lines<br>\n"
            f"{_esc(side)} <code>{_esc(sha)}</code>")
    return _page(path, side, meta, f"Content of the {_esc(side)} file.", body), len(lines)


def render_view_page(**kw) -> str:
    return _render_view(**kw)[0]


def render_diff_page(**kw) -> str:
    return _render(**kw)[0]
