"""Per-source orchestration: analyze both sides, compare, apply rules, and build the report
sections, completeness reasons and notices.

An unexpected exception while handling one pair never aborts the run: that pair becomes an
"unavailable" section with the error, and the analysis is marked incomplete.
"""
from __future__ import annotations

import traceback
from dataclasses import dataclass, field

from .analyzer import analyze_source
from .capture_meta import Resolved, Valued, reference_check
from .comparator import compare_manifests, summarize
from .rules import apply_rules


@dataclass
class PipelineResult:
    sections: list = field(default_factory=list)
    manifests: list = field(default_factory=list)  # (source_id, side, Manifest)
    reasons: list = field(default_factory=list)    # completeness reasons
    notices: list = field(default_factory=list)


def _ref_notices(section_id, ref):
    out = []
    for item in ref.items:
        if item["state"] == "mismatch":
            out.append({"type": "reference-mismatch", "source": section_id,
                        "message": f"{item['field']} differs between golden and current"})
        elif item["state"] == "unverified":
            out.append({"type": "reference-unverified", "source": section_id,
                        "message": f"{item['field']} is not recorded or is in conflict "
                                   f"(golden: {item['golden']['state']}, "
                                   f"current: {item['current']['state']})"})
    return out


def _merged(gmeta, cmeta, field_name) -> Resolved:
    values = []
    for side, meta in (("golden", gmeta), ("current", cmeta)):
        for v in meta.fields.get(field_name, []):
            values.append(Valued(v.value, v.provenance,
                                 f"{side} {v.detail}" if v.detail else side))
    if not values:
        return Resolved(None, "not-recorded", [])
    if len({repr(v.value) for v in values}) == 1:
        return Resolved(values[0].value, "recorded", values)
    return Resolved(None, "conflict", values)


def _fs_side(m):
    return m.filesystem if m else None


def _filesystem_section(sid, title, image, gm, cm, ruleset, ref, *, parent=None, boot=None):
    boot = boot or {"is_boot": False, "sources": []}
    entries = compare_manifests(gm, cm, boot=boot["is_boot"])
    apply_rules(sid, entries, ruleset)
    summary = summarize(entries)
    reasons, warnings = [], []
    for side, m in (("golden", gm), ("current", cm)):
        if m.inventory.get("state") != "complete":
            reasons.append(f"{side} inventory is partial ({m.inventory.get('bad_lines', 0)} "
                           f"unparseable lines, exit code {m.inventory.get('exit_code')})")
        if m.filesystem.get("state") != "complete":
            reasons.append(f"{side} filesystem facts are incomplete (fsstat diagnostics or raw "
                           f"reader unavailable)")
        for w in m.filesystem.get("warnings", []):
            warnings.append(f"{side}: {w}")
        for d in m.diagnostics:
            warnings.append(f"{side}: {d.get('tool')}: {d['line']} ({d['kind']})")
    if summary["incomplete_any"]:
        reasons.append(f"{summary['incomplete_any']} entries not fully assessed")
    return {
        "id": sid, "title": title, "kind": "filesystem", "parent": parent, "image": image,
        "role": ref.role, "status": "incomplete" if reasons else "compared",
        "incomplete_reasons": reasons, "warnings": warnings, "reference": ref.to_dict(),
        "boot": boot,
        "filesystem": {"golden": _fs_side(gm), "current": _fs_side(cm)},
        "inventory": {"golden": gm.inventory, "current": cm.inventory},
        "summary": summary, "entries": [e.to_dict() for e in entries],
    }


def _side_desc(a):
    return {"kind": a.kind, "signatures": a.signatures, "reason": a.reason,
            "size": a.image_size}


def _part_desc(p):
    if p is None:
        return None
    return {"start": p.start, "length": p.length, "sector_size": p.sector_size,
            "offset_bytes": p.offset_bytes, "signatures": p.signatures, "status": p.status,
            "reason": p.reason, "slot": p.slot, "description": p.description}


def _layout_desc(layout):
    if layout is None:
        return None
    return {"table_type": layout.table_type, "sector_size": layout.sector_size,
            "partitions": [{"number": p.number, "slot": p.slot, "start": p.start,
                            "length": p.length, "description": p.description}
                           for p in layout.partitions]}


def _layout_differences(gl, cl):
    diffs = []
    if gl.table_type != cl.table_type:
        diffs.append(f"partition table type: {gl.table_type} → {cl.table_type}")
    if gl.sector_size != cl.sector_size:
        diffs.append(f"sector size: {gl.sector_size} → {cl.sector_size}")
    gp = {p.number: p for p in gl.partitions}
    cp = {p.number: p for p in cl.partitions}
    for n in sorted(set(gp) | set(cp)):
        a, b = gp.get(n), cp.get(n)
        if a is None or b is None:
            diffs.append(f"p{n}: present only in {'golden' if b is None else 'current'}")
            continue
        for attr in ("start", "length", "description"):
            if getattr(a, attr) != getattr(b, attr):
                diffs.append(f"p{n} {attr}: {getattr(a, attr)} → {getattr(b, attr)}")
    return diffs


def _disk_sections(sid, image, ga, ca, ruleset, ref, gmeta, cmeta, all_ids, result):
    gparts = {p.number: p for p in ga.partitions}
    cparts = {p.number: p for p in ca.partitions}
    parts, children, reasons = [], [], []
    for n in sorted(set(gparts) | set(cparts)):
        gp, cp = gparts.get(n), cparts.get(n)
        declared = {k: _merged(gmeta, cmeta, f"partitions.{image}.{n}.{k}").to_dict()
                    for k in ("role", "encrypted", "mapper_image")}
        mapper = declared["mapper_image"]["value"]
        entry = {"number": n, "golden": _part_desc(gp), "current": _part_desc(cp),
                 "declared": declared, "section_id": None,
                 "mapper_section": mapper if mapper in all_ids else None}
        statuses = {p.status for p in (gp, cp) if p}
        if gp and cp and gp.status == cp.status == "analyzed":
            child_id = f"{sid}#p{n}"
            boot_sources = []
            if declared["role"]["value"] == "boot":
                boot_sources.append("declared role: boot (capture.yaml)")
            for side, p in (("golden", gp), ("current", cp)):
                lm = p.manifest.filesystem.get("last_mounted", {})
                if lm.get("state") == "ok" and lm.get("value") == "/boot":
                    boot_sources.append(f"{side} fsstat: last mounted at /boot")
            child = _filesystem_section(child_id, f"{sid} · p{n}", image, gp.manifest,
                                        cp.manifest, ruleset, ref, parent=sid,
                                        boot={"is_boot": bool(boot_sources),
                                              "sources": boot_sources})
            children.append(child)
            result.manifests += [(child_id, "golden", gp.manifest),
                                 (child_id, "current", cp.manifest)]
            entry["status"] = "compared"
            entry["section_id"] = child_id
            if child["status"] != "compared":
                reasons.append(f"p{n}: comparison incomplete")
        else:
            if not (gp and cp):
                entry["status"] = "missing on one side"
            elif "encrypted" in statuses:
                entry["status"] = "encrypted"
            elif "unsupported" in statuses:
                entry["status"] = "unsupported"
            elif "unreadable" in statuses:
                entry["status"] = "unreadable"
            elif len(statuses) > 1:
                entry["status"] = "incompatible"
            else:
                entry["status"] = "unknown"
            why = "; ".join(sorted({p.reason for p in (gp, cp) if p and p.reason}))
            reasons.append(f"p{n}: {entry['status']}" + (f" ({why})" if why else ""))
        parts.append(entry)
    layout_diffs = _layout_differences(ga.layout, ca.layout)
    limited = any(p["status"] in ("encrypted", "unsupported", "unknown") for p in parts)
    disk = {
        "id": sid, "title": sid, "kind": "disk", "parent": None, "image": image,
        "role": ref.role,
        "status": "compared" if not reasons else ("limited" if limited else "incomplete"),
        "incomplete_reasons": reasons, "warnings": [], "reference": ref.to_dict(),
        "layout": {"golden": _layout_desc(ga.layout), "current": _layout_desc(ca.layout)},
        "layout_differences": layout_diffs, "partitions": parts,
    }
    return [disk] + children, [f"{sid} {r}" for r in reasons]


def analyze_all(pairing, ruleset, gmeta, cmeta, runner, *, jobs=4, quiet=True,
                progress_stream=None, pre_hashes=None) -> PipelineResult:
    result = PipelineResult()
    pre_hashes = pre_hashes or {}
    all_ids = {p.source_id for p in pairing.pairs}
    for pair in pairing.pairs:
        sid = pair.source_id
        ref = reference_check(pair.golden.name, gmeta, cmeta)
        result.notices += _ref_notices(sid, ref)
        try:
            ga = analyze_source(runner, pair.golden, side="golden", source_id=sid, jobs=jobs,
                                quiet=quiet, progress_stream=progress_stream)
            ca = analyze_source(runner, pair.current, side="current", source_id=sid, jobs=jobs,
                                quiet=quiet, progress_stream=progress_stream)
            sections, reasons = _pair_sections(pair, sid, ga, ca, ruleset, ref, gmeta, cmeta,
                                               all_ids, result, pre_hashes)
        except Exception as exc:  # keep the run alive; make the failure visible
            sections = [{"id": sid, "title": sid, "kind": "unavailable", "parent": None,
                         "image": pair.golden.name, "role": ref.role, "status": "incomplete",
                         "reason": f"internal error while analyzing this pair: {exc!r}",
                         "traceback": traceback.format_exc(limit=8),
                         "incomplete_reasons": ["internal error"], "warnings": [],
                         "reference": ref.to_dict(), "golden": None, "current": None}]
            reasons = [f"{sid}: internal error ({exc!r})"]
        result.sections += sections
        result.reasons += reasons
    for u in pairing.unmatched:
        result.reasons.append(f"unmatched source: {u.name} ({u.side} only)")
    if not pairing.pairs and not pairing.unmatched:
        result.reasons.append("no supported images found in the inputs "
                              "(.dd, .img, .raw, .bin)")
    for r in result.reasons:
        result.notices.append({"type": "incomplete", "source": None, "message": r})
    return result


def _pair_sections(pair, sid, ga, ca, ruleset, ref, gmeta, cmeta, all_ids, result, pre_hashes):
    image = pair.golden.name
    if "unreadable" in (ga.kind, ca.kind) or ga.kind != ca.kind:
        if "unreadable" in (ga.kind, ca.kind):
            reason = "image unreadable: " + "; ".join(
                f"{a.side}: {a.reason}" for a in (ga, ca) if a.kind == "unreadable")
        else:
            reason = f"incompatible formats: golden is {ga.kind}, current is {ca.kind}"
        return [{"id": sid, "title": sid, "kind": "unavailable", "parent": None, "image": image,
                 "role": ref.role, "status": "incomplete", "reason": reason,
                 "incomplete_reasons": [reason], "warnings": [], "reference": ref.to_dict(),
                 "golden": _side_desc(ga), "current": _side_desc(ca)}], [f"{sid}: {reason}"]
    if ga.kind == "ext-fs":
        section = _filesystem_section(sid, sid, image, ga.manifest, ca.manifest, ruleset, ref,
                                      boot=_standalone_boot(gmeta, cmeta, image))
        result.manifests += [(sid, "golden", ga.manifest), (sid, "current", ca.manifest)]
        reasons = [f"{sid}: {r}" for r in section["incomplete_reasons"]]
        return [section], reasons
    if ga.kind == "disk":
        return _disk_sections(sid, image, ga, ca, ruleset, ref, gmeta, cmeta, all_ids, result)
    # image-level
    gh = pre_hashes.get(f"golden:{pair.golden.name}")
    ch = pre_hashes.get(f"current:{pair.current.name}")
    reason = ga.reason or ca.reason
    section = {"id": sid, "title": sid, "kind": "image-level", "parent": None, "image": image,
               "role": ref.role, "status": "limited", "reason": reason,
               "incomplete_reasons": [reason], "warnings": [], "reference": ref.to_dict(),
               "golden": dict(_side_desc(ga), sha256=gh),
               "current": dict(_side_desc(ca), sha256=ch),
               "identical": (gh == ch) if gh and ch else None}
    return [section], [f"{sid}: {reason}"]


def _standalone_boot(gmeta, cmeta, image):
    roles = {m.role(image) for m in (gmeta, cmeta)}
    if "boot" in roles:
        return {"is_boot": True, "sources": ["declared role: boot (capture.yaml)"]}
    return {"is_boot": False, "sources": []}
