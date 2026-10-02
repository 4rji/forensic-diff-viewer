"""Expected-change rules (field-scoped), coverage annotation and review priority.

Rules never change a status and never hide anything: they mark which differences an analyst
expects. Glob semantics: paths are relative to the filesystem root (no leading ``/``),
matching is case-sensitive, ``*`` stays within one segment, ``**`` crosses ``/``, ``?`` is one
non-``/`` character; everything else (including ``[``) is literal.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .comparator import CONTENT_FIELDS
from .integrity import sha256_file

PLAIN_FIELDS = {"existence", "type", "content", "size", "mode", "suid", "sgid", "uid", "gid",
                "mtime", "symlink_target", "capability"}
RULE_STATUSES = {"modified", "added", "deleted", "metadata"}
RULE_KEYS = {"id", "label", "reason", "sources", "paths", "statuses", "fields"}
ELEVATE_KEYS = {"sources", "paths", "reason"}


class RulesError(Exception):
    pass


def _compile(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out), re.DOTALL)


def glob_match(pattern: str, path: str) -> bool:
    return _compile(pattern).fullmatch(path.lstrip("/")) is not None


def field_covered(token: str, fld: str) -> bool:
    if token.startswith("xattr:") and fld.startswith("xattr:"):
        pat, name = token[6:], fld[6:]
        if name.startswith("security.") and not pat.startswith("security."):
            return False  # security.* attributes must be named explicitly
        return fnmatch.fnmatchcase(name, pat)
    return token == fld


@dataclass
class Rule:
    id: str
    label: str
    reason: str
    sources: list
    paths: list
    statuses: list
    fields: list

    def to_dict(self):
        return {k: getattr(self, k) for k in RULE_KEYS}


@dataclass
class RuleSet:
    rules: list = field(default_factory=list)
    elevate: list = field(default_factory=list)
    file: str | None = None
    sha256: str | None = None
    matches: dict = field(default_factory=dict)

    def to_dict(self):
        return {"file": self.file, "sha256": self.sha256,
                "rules": [dict(r.to_dict(), matches=self.matches.get(r.id, 0))
                          for r in self.rules],
                "elevate": self.elevate}


def _str_list(v, what):
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
        raise RulesError(f"{what} must be a non-empty list of strings")
    return v


def _check_paths(paths, what):
    for p in _str_list(paths, what):
        if p.startswith("/"):
            raise RulesError(f"{what}: paths are relative to the filesystem root; remove the "
                             f"leading '/' from {p!r}")
    return paths


def load_rules(path) -> RuleSet:
    if path is None:
        return RuleSet()
    path = Path(path)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RulesError(f"cannot read rules file {path}: {exc}") from exc
    doc = doc or {}
    if not isinstance(doc, dict):
        raise RulesError("rules file: top level must be a mapping")
    unknown = set(doc) - {"schema", "rules", "elevate"}
    if unknown:
        raise RulesError(f"rules file: unknown keys {sorted(unknown)}")
    if doc.get("schema") != 1:
        raise RulesError(f"rules file: unsupported schema {doc.get('schema')!r} (expected 1)")
    rs = RuleSet(file=str(path), sha256=sha256_file(path))
    seen = set()
    for i, r in enumerate(doc.get("rules") or []):
        where = f"rule #{i + 1}"
        if not isinstance(r, dict):
            raise RulesError(f"{where}: must be a mapping")
        if set(r) - RULE_KEYS:
            raise RulesError(f"{where}: unknown keys {sorted(set(r) - RULE_KEYS)}")
        rid = r.get("id")
        if not isinstance(rid, str) or not rid:
            raise RulesError(f"{where}: missing id")
        if rid in seen:
            raise RulesError(f"duplicate rule id {rid!r}")
        seen.add(rid)
        statuses = _str_list(r.get("statuses"), f"rule {rid}: statuses")
        if set(statuses) - RULE_STATUSES:
            raise RulesError(f"rule {rid}: statuses must be among {sorted(RULE_STATUSES)}")
        fields = _str_list(r.get("fields"), f"rule {rid}: fields")
        for t in fields:
            if t not in PLAIN_FIELDS and not (t.startswith("xattr:") and len(t) > 6):
                raise RulesError(f"rule {rid}: unknown field token {t!r}")
        rs.rules.append(Rule(id=rid, label=str(r.get("label") or rid),
                             reason=str(r.get("reason") or ""),
                             sources=_str_list(r.get("sources"), f"rule {rid}: sources"),
                             paths=_check_paths(r.get("paths"), f"rule {rid}: paths"),
                             statuses=statuses, fields=fields))
    for i, e in enumerate(doc.get("elevate") or []):
        if not isinstance(e, dict) or set(e) - ELEVATE_KEYS:
            raise RulesError(f"elevate #{i + 1}: allowed keys are {sorted(ELEVATE_KEYS)}")
        rs.elevate.append({"sources": _str_list(e.get("sources"), f"elevate #{i + 1}: sources"),
                           "paths": _check_paths(e.get("paths"), f"elevate #{i + 1}: paths"),
                           "reason": str(e.get("reason") or "")})
    rs.matches = {r.id: 0 for r in rs.rules}
    return rs


def priority_for(entry, elevated: bool = False) -> int:
    if entry.status == "unchanged" and not entry.diffs and not entry.incomplete:
        return 5
    if entry.expectation == "full":
        return 4
    uncovered = [d for d in entry.diffs if not d.covered_by]
    content = [d for d in uncovered if d.field in CONTENT_FIELDS]
    if uncovered and elevated:
        return 1
    if any(d.sensitive for d in uncovered):
        return 1
    if content and (entry.kind in ("elf", "script") or entry.boot):
        return 1
    if content or entry.incomplete or entry.status == "incomplete":
        return 2
    if uncovered:
        return 3
    return 2  # all differences covered but the entry is not fully assessed


def apply_rules(source_id: str, entries, ruleset: RuleSet) -> None:
    rules = [r for r in ruleset.rules if source_id in r.sources]
    elevations = [e for e in ruleset.elevate if source_id in e["sources"]]
    for r in ruleset.rules:
        ruleset.matches.setdefault(r.id, 0)
    for entry in entries:
        matching = [r for r in rules if entry.status in r.statuses
                    and any(glob_match(p, entry.path) for p in r.paths)]
        entry.rules = [r.id for r in matching]
        for r in matching:
            ruleset.matches[r.id] += 1
        for d in entry.diffs:
            for r in matching:
                if any(field_covered(t, d.field) for t in r.fields):
                    d.covered_by = r.id
                    d.explicit_sensitive = d.sensitive
                    break
        covered = [d for d in entry.diffs if d.covered_by]
        if entry.diffs and len(covered) == len(entry.diffs) and not entry.incomplete:
            entry.expectation = "full"
        elif covered:
            entry.expectation = "partial"
        else:
            entry.expectation = "none"
        elevated = any(glob_match(p, entry.path) for e in elevations for p in e["paths"])
        entry.priority = priority_for(entry, elevated)
