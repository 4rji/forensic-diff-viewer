"""Entry-by-entry comparison of two manifests.

Status (exactly one): modified, added, deleted, metadata, unchanged, incomplete. The
``incomplete`` flag is orthogonal: any entry with a not-assessed field carries it. Differences
are kept per field, with a ``sensitive`` marker; rules (rules.py) annotate them afterwards.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .manifest import Entry, Manifest

PERM_MASK = 0o7777 & ~0o6000  # rwx + sticky; SUID/SGID are separate fields
CONTENT_FIELDS = {"existence", "type", "content", "symlink_target", "size"}
STATUSES = ("modified", "added", "deleted", "metadata", "unchanged", "incomplete")


@dataclass
class Diff:
    field: str
    golden: object
    current: object
    sensitive: bool = False
    covered_by: str | None = None
    explicit_sensitive: bool = False

    def to_dict(self):
        return {"field": self.field, "golden": self.golden, "current": self.current,
                "sensitive": self.sensitive, "covered_by": self.covered_by,
                "explicit_sensitive": self.explicit_sensitive}


@dataclass
class CompEntry:
    path: str
    path_hex: str
    status: str
    incomplete: bool = False
    incomplete_reasons: list = field(default_factory=list)
    diffs: list = field(default_factory=list)
    golden: dict | None = None
    current: dict | None = None
    kind: str | None = None
    boot: bool = False
    priority: int | None = None
    expectation: str = "none"  # "none" | "partial" | "full"
    rules: list = field(default_factory=list)

    def to_dict(self):
        return {"path": self.path, "path_hex": self.path_hex, "status": self.status,
                "incomplete": self.incomplete, "incomplete_reasons": self.incomplete_reasons,
                "diffs": [d.to_dict() for d in self.diffs], "golden": self.golden,
                "current": self.current, "kind": self.kind, "boot": self.boot,
                "priority": self.priority, "expectation": self.expectation,
                "rules": self.rules}


def _kind(e: Entry | None):
    if e is not None and e.content.state == "ok":
        return e.content.value.get("kind")
    return None


class _Cmp:
    def __init__(self, g: Entry, c: Entry):
        self.g, self.c = g, c
        self.diffs: list[Diff] = []
        self.reasons: list[str] = []

    def assessed(self, name) -> bool:
        ga, ca = getattr(self.g, name), getattr(self.c, name)
        ok = True
        for side, a in (("golden", ga), ("current", ca)):
            if not a.assessed:
                self.reasons.append(f"{name} not assessed ({side}): {a.reason}")
                ok = False
        return ok

    def add(self, fld, gv, cv, sensitive=False):
        if gv != cv:
            self.diffs.append(Diff(fld, gv, cv, sensitive))
            return True
        return False


def _compare_pair(g: Entry, c: Entry):
    k = _Cmp(g, c)
    modified = False
    types_equal = True
    if k.assessed("type"):
        gt, ct = g.type.value, c.type.value
        if k.add("type", gt, ct, sensitive=ct == "symlink"):
            modified, types_equal = True, False
    else:
        types_equal = False

    ftype = c.type.value if types_equal else None
    if ftype == "file":
        content_ok = k.assessed("content")
        size_ok = k.assessed("size")
        if content_ok:
            if k.add("content", g.content.value["sha256"], c.content.value["sha256"]):
                modified = True
                if size_ok:
                    k.add("size", g.size.value, c.size.value)
        elif size_ok and k.add("size", g.size.value, c.size.value):
            modified = True  # different size proves different content
    elif ftype == "symlink":
        if k.assessed("symlink") and \
                g.symlink.value["target_hex"] != c.symlink.value["target_hex"]:
            k.diffs.append(Diff("symlink_target", g.symlink.value["target"],
                                c.symlink.value["target"]))
            modified = True

    if k.assessed("mode"):
        gm, cm = g.mode.value, c.mode.value
        k.add("mode", f"{gm & PERM_MASK:04o}", f"{cm & PERM_MASK:04o}")
        k.add("suid", bool(gm & 0o4000), bool(cm & 0o4000), sensitive=True)
        k.add("sgid", bool(gm & 0o2000), bool(cm & 0o2000), sensitive=True)
    for idf in ("uid", "gid"):
        if k.assessed(idf):
            gv, cv = getattr(g, idf).value, getattr(c, idf).value
            k.add(idf, gv, cv, sensitive=cv == 0 and gv != 0)
    if k.assessed("mtime"):
        k.add("mtime", g.mtime.value, c.mtime.value)
    if k.assessed("xattrs"):
        gx = g.xattrs.value or {}
        cx = c.xattrs.value or {}
        for name in sorted(set(gx) | set(cx)):
            gv = gx.get(name, {}).get("hex")
            cv = cx.get(name, {}).get("hex")
            k.add(f"xattr:{name}", gv, cv, sensitive=name.startswith("security."))
    if k.assessed("capability"):
        gc = g.capability.value if g.capability.state == "ok" else None
        cc = c.capability.value if c.capability.state == "ok" else None
        if (gc or {}).get("hex") != (cc or {}).get("hex"):
            k.diffs.append(Diff("capability", gc and gc.get("text"), cc and cc.get("text"),
                                sensitive=True))
    for e in (g, c):
        if e.path_lossy:
            k.reasons.append("name may have been altered by TSK; exact bytes not verified")
            break

    if modified:
        status = "modified"
    elif k.diffs:
        status = "metadata"
    elif k.reasons:
        status = "incomplete"
    else:
        status = "unchanged"
    return status, k.diffs, k.reasons


def _entry_reasons(e: Entry) -> list[str]:
    reasons = [f"{n} not assessed: {getattr(e, n).reason}" for n in Entry.ASSESSED_FIELDS
               if not getattr(e, n).assessed]
    if e.path_lossy:
        reasons.append("name may have been altered by TSK; exact bytes not verified")
    return reasons


def compare_manifests(g: Manifest, c: Manifest, *, boot: bool = False) -> list[CompEntry]:
    gi, ci = {}, {}
    for e in g.entries:
        gi.setdefault(e.path_hex, []).append(e)
    for e in c.entries:
        ci.setdefault(e.path_hex, []).append(e)
    g_complete = g.inventory.get("state") == "complete"
    c_complete = c.inventory.get("state") == "complete"
    out = []
    for key in sorted(set(gi) | set(ci), key=lambda h: bytes.fromhex(h)):
        gs, cs = gi.get(key, []), ci.get(key, [])
        ge = gs[0] if len(gs) == 1 else None
        ce = cs[0] if len(cs) == 1 else None
        any_e = (gs or cs)[0]
        ent = CompEntry(path=any_e.path, path_hex=key, status="incomplete",
                        golden=ge.to_dict() if ge else None,
                        current=ce.to_dict() if ce else None, boot=boot,
                        kind=_kind(ce) or _kind(ge))
        if len(gs) > 1 or len(cs) > 1:
            ent.incomplete_reasons = ["ambiguous path: listed more than once in one inventory"]
            ent.golden = gs[0].to_dict() if gs else None
            ent.current = cs[0].to_dict() if cs else None
        elif ge and ce:
            ent.status, ent.diffs, ent.incomplete_reasons = _compare_pair(ge, ce)
        elif ce:  # only in current
            if g_complete:
                ent.status = "added"
                ent.diffs = [Diff("existence", None, "present",
                                  sensitive=ce.type.state == "ok" and ce.type.value == "symlink")]
                ent.incomplete_reasons = _entry_reasons(ce)
            else:
                ent.incomplete_reasons = ["existence not assessed: golden inventory is partial"]
        else:  # only in golden
            if c_complete:
                ent.status = "deleted"
                ent.diffs = [Diff("existence", "present", None)]
                ent.incomplete_reasons = _entry_reasons(ge)
            else:
                ent.incomplete_reasons = ["existence not assessed: current inventory is partial"]
        ent.incomplete = bool(ent.incomplete_reasons)
        out.append(ent)
    return out


def summarize(entries) -> dict:
    s = {k: 0 for k in STATUSES}
    s.update(total=len(entries), incomplete_any=0, sensitive=0, expected_full=0,
             expected_partial=0)
    for e in entries:
        s[e.status] += 1
        s["incomplete_any"] += bool(e.incomplete or e.status == "incomplete")
        s["sensitive"] += any(d.sensitive for d in e.diffs)
        s["expected_full"] += e.expectation == "full"
        s["expected_partial"] += e.expectation == "partial"
    return s
