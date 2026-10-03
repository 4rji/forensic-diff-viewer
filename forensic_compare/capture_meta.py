"""Capture metadata (capture.yaml) with per-value provenance, and reference checks.

When two image files are compared, each image may carry its own ``<image>.capture.yaml`` next to
it (it replaces the directory's capture.yaml). That file may declare the image's ``role`` at the
top level. If both sides read the same capture file, its values cannot confirm that the two
captures match, so the reference stays unverified.

Provenance values:
- ``analyst``          — a field written by the analyst in capture.yaml;
- ``capture-command``  — a structured ``observations`` entry (capture-time command output);
- ``image-file``       — read from a file inside an image (reserved; no MVP producer);
- ``analyst-role``     — derived from a declared source role (e.g. config-active → active fw).

Unknown values are never guessed. ``device-info.txt`` is preserved verbatim and never parsed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from .discovery import SIDECAR_SUFFIX
from .integrity import sha256_file

TOP_FIELDS = ("device_model", "device_serial", "captured_at", "captured_by", "notes")
SOURCE_KEYS = ("role", "firmware", "notes")
PARTITION_KEYS = ("role", "encrypted", "mapper_image")
KNOWN_TOP = {"schema", "firmware", "sources", "partitions", "observations", "role",
             *TOP_FIELDS}
NULLS = {"", "~", "null", "Null", "NULL"}


@dataclass
class Valued:
    value: object
    provenance: str
    detail: str | None = None

    def to_dict(self):
        return {"value": self.value, "provenance": self.provenance, "detail": self.detail}


@dataclass
class Resolved:
    value: object
    state: str  # "recorded" | "not-recorded" | "conflict"
    values: list

    def to_dict(self):
        return {"value": self.value, "state": self.state,
                "values": [v.to_dict() for v in self.values]}


def _scalar(v):
    """BaseLoader keeps every scalar as text (so 24.10 stays "24.10"); map nulls to None."""
    if isinstance(v, str):
        return None if v in NULLS else v
    return v


def _bool(v):
    v = _scalar(v)
    if v is None:
        return None
    if str(v).lower() in ("true", "yes", "on"):
        return True
    if str(v).lower() in ("false", "no", "off"):
        return False
    return v


@dataclass
class CaptureMeta:
    present: bool = False
    fields: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    supporting: list = field(default_factory=list)
    raw_notes: list = field(default_factory=list)
    path: str | None = None  # resolved capture file read for this side

    def add(self, name, value, provenance, detail=None):
        if value is None:
            return
        self.fields.setdefault(name, []).append(Valued(value, provenance, detail))

    def get(self, name) -> Resolved:
        values = self.fields.get(name, [])
        if not values:
            return Resolved(None, "not-recorded", [])
        distinct = {repr(v.value) for v in values}
        if len(distinct) == 1:
            return Resolved(values[0].value, "recorded", values)
        return Resolved(None, "conflict", values)

    def role(self, image_name) -> str | None:
        r = self.get(f"sources.{image_name}.role")
        return r.value if r.state == "recorded" else None

    def rename_image(self, own: str, as_name: str):
        """Look up this side's image under as_name (single mode, differing file names). Applies
        only when the file declares the image under its own name."""
        prefixes = [(f"{kind}.{own}.", f"{kind}.{as_name}.") for kind in ("sources", "partitions")]
        if own == as_name or not any(k.startswith(o) for k in self.fields for o, _ in prefixes):
            return
        for _, new in prefixes:
            for k in [k for k in self.fields if k.startswith(new)]:
                del self.fields[k]
        for old, new in prefixes:
            for k in [k for k in self.fields if k.startswith(old)]:
                self.fields[new + k[len(old):]] = self.fields.pop(k)

    def to_dict(self):
        return {"present": self.present, "path": self.path, "errors": self.errors,
                "supporting": self.supporting,
                "fields": {k: self.get(k).to_dict() for k in sorted(self.fields)}}


def load_capture(listing, as_name: str | None = None) -> CaptureMeta:
    """as_name: in single mode, the name this side's image is looked up under (the pair's id)."""
    m = CaptureMeta()
    for name, path in sorted(listing.supporting.items()):
        try:
            m.supporting.append({"name": name, "path": str(path), "sha256": sha256_file(path),
                                 "size": path.stat().st_size})
        except OSError as exc:
            m.errors.append(f"{name}: {exc.strerror or exc}")
    path = listing.capture_file
    if path is None:
        return m
    m.present = True
    m.path = str(path.resolve())
    label = path.name
    try:
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        m.errors.append(f"{label} could not be read: {exc}")
        return m
    if not isinstance(doc, dict):
        m.errors.append(f"{label}: top level must be a mapping")
        return m
    if _scalar(doc.get("schema")) != "1":
        m.errors.append(f"{label}: unsupported or missing schema {doc.get('schema')!r}")
    for key in doc:
        if key not in KNOWN_TOP:
            m.errors.append(f"{label}: unknown key {key!r} (ignored)")
    for f in TOP_FIELDS:
        m.add(f, _scalar(doc.get(f)), "analyst", label)
    fw = doc.get("firmware") or {}
    if isinstance(fw, dict):
        for slot in ("active", "inactive"):
            m.add(f"firmware.{slot}", _scalar(fw.get(slot)), "analyst", label)
    if "role" in doc:
        if label.endswith(SIDECAR_SUFFIX):
            own = label[:-len(SIDECAR_SUFFIX)]
            m.add(f"sources.{own}.role", _scalar(doc["role"]), "analyst", label)
        else:
            m.errors.append(f"{label}: 'role' is only valid in a per-image <image>"
                            f"{SIDECAR_SUFFIX} (ignored; use sources:)")
    for img, attrs in (doc.get("sources") or {}).items():
        if isinstance(attrs, dict):
            for k in SOURCE_KEYS:
                m.add(f"sources.{img}.{k}", _scalar(attrs.get(k)), "analyst", label)
    for img, parts in (doc.get("partitions") or {}).items():
        if not isinstance(parts, dict):
            continue
        for num, attrs in parts.items():
            if not isinstance(attrs, dict):
                continue
            for k in PARTITION_KEYS:
                v = _bool(attrs.get(k)) if k == "encrypted" else _scalar(attrs.get(k))
                m.add(f"partitions.{img}.{num}.{k}", v, "analyst", label)
    for i, obs in enumerate(doc.get("observations") or []):
        if not isinstance(obs, dict) or not obs.get("field"):
            m.errors.append(f"{label}: observation #{i + 1} has no field")
            continue
        detail = f"command: {_scalar(obs.get('command'))}"
        if obs.get("reference"):
            detail += f"; reference: {_scalar(obs.get('reference'))}"
        m.add(_scalar(obs["field"]), _scalar(obs.get("value")), "capture-command", detail)
    if as_name and len(listing.images) == 1:
        m.rename_image(next(iter(listing.images)), as_name)
    return m


# --------------------------------------------------------------------------------------------
# Reference checks

ROLE_FIRMWARE = {"config-active": "firmware.active", "config-inactive": "firmware.inactive"}


def _source_firmware(meta: CaptureMeta, image: str, role: str | None) -> Resolved:
    explicit = meta.get(f"sources.{image}.firmware")
    if explicit.state != "not-recorded" or role not in ROLE_FIRMWARE:
        return explicit
    derived = meta.get(ROLE_FIRMWARE[role])
    values = [Valued(v.value, "analyst-role" if v.provenance == "analyst" else v.provenance,
                     f"derived from declared role {role} ({ROLE_FIRMWARE[role]})"
                     + (f"; {v.detail}" if v.detail else ""))
              for v in derived.values]
    return Resolved(derived.value, derived.state, values)


@dataclass
class RefCheck:
    status: str  # "ok" | "mismatch" | "unverified"
    role: str | None
    items: list = field(default_factory=list)
    context: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def notices(self):
        out = []
        if any(i["state"] == "mismatch" for i in self.items):
            out.append("Reference mismatch")
        if any(i["state"] == "unverified" for i in self.items):
            out.append("Reference unverified")
        return out

    def to_dict(self):
        return {"status": self.status, "role": self.role, "items": self.items,
                "context": self.context, "notes": self.notes, "notices": self.notices}


def _compare(field_name, g: Resolved, c: Resolved):
    if g.state == "recorded" and c.state == "recorded":
        state = "ok" if g.value == c.value else "mismatch"
    else:
        state = "unverified"
    return {"field": field_name, "golden": g.to_dict(), "current": c.to_dict(), "state": state}


def reference_check(image: str, golden: CaptureMeta, current: CaptureMeta) -> RefCheck:
    roles = {r for r in (golden.role(image), current.role(image)) if r}
    notes = []
    if len(roles) > 1:
        notes.append(f"declared roles differ between sides: {sorted(roles)}")
        role = None
    else:
        role = next(iter(roles), None)
    if role is None and not notes:
        notes.append("role not declared")
    items = [_compare("device_model", golden.get("device_model"), current.get("device_model"))]
    context = []
    if role in ROLE_FIRMWARE:
        items.append(_compare("source firmware", _source_firmware(golden, image, role),
                              _source_firmware(current, image, role)))
    else:
        slots = ("firmware.active",) if role == "nvram" else ("firmware.active",
                                                               "firmware.inactive")
        for f in slots:
            context.append({"field": f, "golden": golden.get(f).to_dict(),
                            "current": current.get(f).to_dict()})
        if role == "nvram":
            notes.append("NVRAM is shared persistent storage; active firmware at capture time "
                         "is shown as context only")
    if len(roles) > 1:
        items.append({"field": "role", "golden": golden.get(f"sources.{image}.role").to_dict(),
                      "current": current.get(f"sources.{image}.role").to_dict(),
                      "state": "unverified"})
    if golden.path and golden.path == current.path:
        notes.append(f"golden and current read the same capture file ({golden.path}): it cannot "
                     f"confirm that the two captures match; put an <image>{SIDECAR_SUFFIX} next "
                     "to each image")
        for i in items:
            if i["state"] == "ok":
                i["state"] = "unverified"
    states = {i["state"] for i in items}
    status = "mismatch" if "mismatch" in states else "unverified" if "unverified" in states \
        else "ok"
    return RefCheck(status, role, items, context, notes)
