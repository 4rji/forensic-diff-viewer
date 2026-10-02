#!/usr/bin/env python3
"""forensic_compare — compare golden vs current forensic captures.

Usage:
    python forensic_compare/compare.py GOLDEN CURRENT -o OUTDIR [options]

GOLDEN and CURRENT are either two capture directories (images paired by exact filename) or two
image files (one pair). Inputs are only read; nothing is mounted or written to them.

Image hashing (integrity) is off by default: the analyst verifies the images before the run.
--verify-integrity hashes every image before and after the analysis and checks supplied
checksum manifests.

Exit codes: 0 = complete analysis (and, with --verify-integrity, every image verified); 3 = report
generated but analysis incomplete/limited or integrity not verified; 2 = usage or fatal error.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import sys
import traceback
from pathlib import Path

if __package__ in (None, ""):  # executed as a script: make the package importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from forensic_compare import __version__  # noqa: E402
from forensic_compare.capture_meta import load_capture  # noqa: E402
from forensic_compare.discovery import pair_inputs  # noqa: E402
from forensic_compare.integrity import (  # noqa: E402
    DISCLAIMER,
    NOT_CHECKED,
    NOT_CHECKED_REASON,
    IntegrityTracker,
    Verdict,
    expected_checksums,
)
from forensic_compare.manifest import save_manifest  # noqa: E402
from forensic_compare.pipeline import analyze_all  # noqa: E402
from forensic_compare.progress import Progress  # noqa: E402
from forensic_compare.report import RunContext, build_comparison, render_html  # noqa: E402
from forensic_compare.rules import RulesError, load_rules  # noqa: E402
from forensic_compare.textdiff import build_diffs  # noqa: E402
from forensic_compare.tools.runner import ToolRunner  # noqa: E402

EXIT_OK, EXIT_FATAL, EXIT_INCOMPLETE = 0, 2, 3
OUTPUTS_FILE = "outputs.json"


class OutputError(Exception):
    pass


def build_parser():
    p = argparse.ArgumentParser(
        prog="compare.py",
        description="Compare golden vs current forensic images at partition, filesystem, file "
                    "and metadata level.")
    p.add_argument("golden", help="golden capture directory or image file")
    p.add_argument("current", help="current capture directory or image file")
    p.add_argument("-o", "--output", required=True, help="report output directory")
    p.add_argument("--rules", help="expected-change rules file (YAML)")
    p.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1),
                   help="maximum concurrent tool processes (default: min(4, CPUs))")
    p.add_argument("--timeout", type=float, default=600.0,
                   help="timeout in seconds for each external command (default: 600)")
    p.add_argument("--force", action="store_true",
                   help="write into a non-empty output directory, replacing only the files "
                        "listed by a previous run's outputs.json")
    p.add_argument("--verify-integrity", action="store_true",
                   help="hash every image before and after the analysis and check supplied "
                        "checksum manifests (off by default: verify the images beforehand)")
    p.add_argument("--text-diffs", action="store_true",
                   help="write a side-by-side line diff page for each modified text file "
                        "(diffs/; puts file content in the output directory)")
    p.add_argument("--quiet", action="store_true", help="no progress output")
    p.add_argument("--version", action="version", version=f"forensic_compare {__version__}")
    return p


# --------------------------------------------------------------------------------------------
# Output protection


def _within(a: Path, b: Path) -> bool:
    return a == b or b in a.parents


def check_output_location(out: Path, pairing) -> None:
    out_r = out.resolve()
    protected = {pairing.golden_listing.directory.resolve(),
                 pairing.current_listing.directory.resolve()}
    for listing in (pairing.golden_listing, pairing.current_listing):
        for real in listing.realpaths.values():
            protected.add(Path(real).parent)
    for d in sorted(protected):
        if _within(out_r, d) or _within(d, out_r):
            raise OutputError(f"output directory {out} overlaps the capture location {d}; "
                              "choose an output directory outside the inputs")


def prepare_output(out: Path, force: bool) -> None:
    if out.exists() and not out.is_dir():
        raise OutputError(f"output path {out} exists and is not a directory")
    if out.exists() and any(out.iterdir()):
        if not force:
            raise OutputError(f"output directory {out} is not empty; use --force to replace a "
                              "previous report (unrelated files are kept)")
        _remove_previous_outputs(out)
    out.mkdir(parents=True, exist_ok=True)


def _remove_previous_outputs(out: Path) -> None:
    listing = out / OUTPUTS_FILE
    if not listing.is_file():
        return
    try:
        prev = json.loads(listing.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if prev.get("tool") != "forensic_compare":
        return
    root = out.resolve()
    for rel in prev.get("files", []) + [OUTPUTS_FILE]:
        p = (out / rel)
        try:
            if p.resolve().parent != root and root not in p.resolve().parents:
                continue
            if p.is_file() and not p.is_symlink():
                p.unlink()
        except OSError:
            continue
    for rel in sorted(prev.get("dirs", []), key=lambda r: -r.count("/")):
        d = out / rel
        try:
            if root in d.resolve().parents and d.is_dir() and not any(d.iterdir()):
                d.rmdir()
        except OSError:
            continue


class OutputWriter:
    def __init__(self, out: Path):
        self.out = out
        self.files: list[str] = []
        self.dirs: set[str] = set()

    def _track(self, rel: str):
        self.files.append(rel)
        parent = Path(rel).parent
        while str(parent) not in (".", ""):
            self.dirs.add(str(parent))
            parent = parent.parent

    def path(self, rel: str) -> Path:
        p = self.out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_text(self, rel: str, text: str):
        p = self.path(rel)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, p)
        self._track(rel)

    def copy(self, src: Path, rel: str):
        p = self.path(rel)
        tmp = p.with_name(p.name + ".tmp")
        shutil.copyfile(src, tmp)
        os.replace(tmp, p)
        self._track(rel)

    def manifest(self, rel: str, m):
        save_manifest(m, self.path(rel))
        self._track(rel)

    def adopt(self, rel: str):
        self._track(rel)

    def finish(self):
        self.write_text(OUTPUTS_FILE, json.dumps(
            {"tool": "forensic_compare", "files": sorted(set(self.files) - {OUTPUTS_FILE}),
             "dirs": sorted(self.dirs)}, indent=1))


def _safe_name(source_id: str) -> str:
    import re

    return re.sub(r"[^A-Za-z0-9._#-]", "_", source_id) or "_"


# --------------------------------------------------------------------------------------------
# Main


def main(argv=None, *, _hooks=None) -> int:
    hooks = _hooks or {}
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_FATAL if exc.code not in (0, None) else EXIT_OK
    err = sys.stderr
    try:
        pairing = pair_inputs(Path(args.golden), Path(args.current))
        out = Path(args.output)
        check_output_location(out, pairing)
        ruleset = load_rules(args.rules)
        prepare_output(out, args.force)
    except (ValueError, OutputError, RulesError, OSError) as exc:
        print(f"error: {exc}", file=err)
        return EXIT_FATAL

    try:
        command = ["compare.py"] + [str(a) for a in (sys.argv[1:] if argv is None else argv)]
        return _run(args, pairing, ruleset, out, hooks, command)
    except Exception as exc:  # fatal: report what happened
        print(f"fatal error: {exc}\n{traceback.format_exc()}", file=err)
        return EXIT_FATAL


def _run(args, pairing, ruleset, out, hooks, command) -> int:
    writer = OutputWriter(out)
    runner = ToolRunner(out / "tool_log.jsonl", timeout=args.timeout, jobs=args.jobs)
    writer.adopt("tool_log.jsonl")
    progress = Progress("integrity", quiet=args.quiet)
    # single mode: both sides' declarations are looked up under the golden image name
    as_name = pairing.pairs[0].golden.name if pairing.mode == "single" else None
    gmeta = load_capture(pairing.golden_listing, as_name=as_name)
    cmeta = load_capture(pairing.current_listing, as_name=as_name)

    items, checksum_reports = [], {}
    for side, listing in (("golden", pairing.golden_listing), ("current", pairing.current_listing)):
        expected, report = expected_checksums(listing)
        checksum_reports[side] = report
        for name, path in listing.images.items():
            items.append((side, name, path, expected.get(name, [])))
    tracker = IntegrityTracker(items, progress=progress) if args.verify_integrity else None
    if tracker:
        tracker.hash_pre()
        progress.finish()
    if "after_pre_hash" in hooks:
        hooks["after_pre_hash"](pairing)
    try:
        result = analyze_all(pairing, ruleset, gmeta, cmeta, runner, jobs=args.jobs,
                             quiet=args.quiet, pre_hashes=dict(tracker.pre) if tracker else {})
        n_diffs = build_diffs(result.sections, result.manifests, runner, writer) \
            if args.text_diffs else None
        if "after_analysis" in hooks:
            hooks["after_analysis"](pairing)
    finally:
        if tracker:
            tracker.hash_post()  # always, even after extraction failures or timeouts
            progress.finish()

    if tracker:
        verdicts, overall = tracker.verdicts(), tracker.overall()
    else:
        verdicts = {f"{side}:{name}": Verdict(NOT_CHECKED, NOT_CHECKED_REASON, expected, None, None)
                    for side, name, _, expected in items}
        overall = NOT_CHECKED
    images = []
    for key, v in verdicts.items():
        side, name = key.split(":", 1)
        images.append(dict(v.to_dict(), key=key, side=side, name=name))
        if v.status == "failed":
            result.notices.insert(0, {"type": "integrity-failed", "source": key,
                                      "message": f"{key}: {v.reason}"})
    unmatched = [{"side": u.side, "name": u.name,
                  "integrity": verdicts[f"{u.side}:{u.name}"].to_dict()}
                 for u in pairing.unmatched]

    for sid, side, manifest in result.manifests:
        writer.manifest(f"manifests/{_safe_name(sid)}/{side}.json", manifest)
    for side, listing in (("golden", pairing.golden_listing), ("current", pairing.current_listing)):
        for name, path in sorted(listing.supporting.items()):
            writer.copy(path, f"supporting/{side}/{name}")
        for path in listing.checksum_files:
            writer.copy(path, f"supporting/{side}/{path.name}")

    complete = not result.reasons
    run = RunContext(
        generated_at=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        command=command,
        mode=pairing.mode,
        inputs={"golden": str(args.golden), "current": str(args.current)},
        tool_versions=dict(runner.versions),
        integrity={"overall": overall, "disclaimer": DISCLAIMER, "images": images,
                   "checksum_files": checksum_reports},
        capture={"golden": gmeta.to_dict(), "current": cmeta.to_dict()},
        rules=ruleset.to_dict(),
        sources=result.sections,
        unmatched=unmatched,
        not_used={"golden": pairing.golden_listing.not_used,
                  "current": pairing.current_listing.not_used},
        completeness={"complete": complete, "reasons": result.reasons},
        notices=result.notices,
        options={"text_diffs": bool(args.text_diffs),
                 "verify_integrity": bool(args.verify_integrity)},
    )
    comparison = build_comparison(run)
    writer.write_text("comparison.json", json.dumps(comparison, ensure_ascii=False, indent=1))
    writer.write_text("report.html", render_html(comparison))
    writer.finish()

    code = EXIT_OK if complete and overall in ("verified", NOT_CHECKED) else EXIT_INCOMPLETE
    if not args.quiet:
        print(f"report: {out / 'report.html'}", file=sys.stderr)
        if n_diffs is not None:
            print(f"text diffs: {n_diffs} page(s) in {out / 'diffs'}", file=sys.stderr)
        print(f"analysis {'complete' if complete else 'INCOMPLETE/LIMITED'}; integrity "
              f"{overall}; exit {code}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
