from forensic_compare.capture_meta import load_capture, reference_check
from forensic_compare.discovery import classify_dir


def _meta(tmp_path, name, yaml_text, device_info=None):
    d = tmp_path / name
    d.mkdir()
    if yaml_text is not None:
        (d / "capture.yaml").write_text(yaml_text)
    if device_info is not None:
        (d / "device-info.txt").write_text(device_info)
    return load_capture(classify_dir(d))


BASE = """\
schema: 1
device_model: M1
firmware:
  active: "24.11.6"
  inactive: null
sources:
  config-active-crypt.dd: {role: config-active}
  config-other-crypt.dd: {role: config-inactive}
  nvram-crypt.dd: {role: nvram}
"""


def test_provenance_and_not_recorded(tmp_path):
    m = _meta(tmp_path, "g", BASE)
    r = m.get("device_model")
    assert r.state == "recorded" and r.value == "M1"
    assert r.values[0].provenance == "analyst"
    assert m.get("firmware.inactive").state == "not-recorded"
    assert m.get("device_serial").state == "not-recorded"


def test_inactive_unknown_makes_config_other_unverified(tmp_path):
    g, c = _meta(tmp_path, "g", BASE), _meta(tmp_path, "c", BASE)
    rc = reference_check("config-other-crypt.dd", g, c)
    assert rc.status == "unverified"
    assert reference_check("config-active-crypt.dd", g, c).status == "ok"


def test_active_firmware_derived_from_role(tmp_path):
    g, c = _meta(tmp_path, "g", BASE), _meta(tmp_path, "c", BASE)
    rc = reference_check("config-active-crypt.dd", g, c)
    item = next(i for i in rc.items if i["field"] == "source firmware")
    assert item["golden"]["value"] == "24.11.6"
    assert item["golden"]["values"][0]["provenance"] == "analyst-role"


def test_model_difference_is_mismatch(tmp_path):
    g = _meta(tmp_path, "g", BASE)
    c = _meta(tmp_path, "c", BASE.replace("M1", "M2"))
    assert reference_check("nvram-crypt.dd", g, c).status == "mismatch"


def test_firmware_difference_is_mismatch(tmp_path):
    g = _meta(tmp_path, "g", BASE)
    c = _meta(tmp_path, "c", BASE.replace('"24.11.6"', '"24.11.7"'))
    assert reference_check("config-active-crypt.dd", g, c).status == "mismatch"


def test_observation_conflict_makes_unverified(tmp_path):
    g = _meta(tmp_path, "g", BASE)
    c = _meta(tmp_path, "c", BASE + """\
observations:
  - field: firmware.active
    value: "24.11.7"
    command: "cat /etc/version"
    reference: device-info.txt
""")
    r = c.get("firmware.active")
    assert r.state == "conflict" and r.value is None
    assert {v.provenance for v in r.values} == {"analyst", "capture-command"}
    assert reference_check("config-active-crypt.dd", g, c).status == "unverified"


def test_nvram_firmware_is_context_only(tmp_path):
    g = _meta(tmp_path, "g", BASE)
    c = _meta(tmp_path, "c", BASE.replace('"24.11.6"', '"24.11.7"'))
    rc = reference_check("nvram-crypt.dd", g, c)
    assert rc.status == "ok"
    assert any(x["field"] == "firmware.active" for x in rc.context)


def test_undeclared_role(tmp_path):
    g, c = _meta(tmp_path, "g", BASE), _meta(tmp_path, "c", BASE)
    rc = reference_check("mystery.dd", g, c)
    assert rc.role is None and rc.status == "ok"
    assert any("role not declared" in n for n in rc.notes)


def test_missing_capture_yaml_is_unverified(tmp_path):
    g, c = _meta(tmp_path, "g", None), _meta(tmp_path, "c", BASE)
    assert g.present is False
    assert reference_check("nvram-crypt.dd", g, c).status == "unverified"


def test_device_info_is_never_parsed(tmp_path):
    m = _meta(tmp_path, "g", BASE, device_info="firmware.active=99.9.9\ndevice_model: X\n")
    assert m.get("firmware.active").value == "24.11.6"
    assert [s["name"] for s in m.supporting] == ["capture.yaml", "device-info.txt"]
    assert all(len(s["sha256"]) == 64 for s in m.supporting)


def test_yaml_errors_recorded_not_raised(tmp_path):
    m = _meta(tmp_path, "g", "schema: 1\ndevice_model: [unclosed\n")
    assert m.errors and m.get("device_model").state == "not-recorded"


def test_partitions_declared(tmp_path):
    m = _meta(tmp_path, "g", BASE + """\
partitions:
  mmcblk0.dd:
    1: {role: boot}
    3: {role: config, encrypted: true, mapper_image: config-active-crypt.dd}
""")
    assert m.get("partitions.mmcblk0.dd.1.role").value == "boot"
    assert m.get("partitions.mmcblk0.dd.3.encrypted").value is True
    assert m.get("partitions.mmcblk0.dd.3.mapper_image").value == "config-active-crypt.dd"


def test_unquoted_version_kept_as_text(tmp_path):
    m = _meta(tmp_path, "g", "schema: 1\nfirmware:\n  active: 24.10\n")
    assert m.get("firmware.active").value == "24.10"


def _single(tmp_path, gname, cname, files):
    from forensic_compare.discovery import pair_inputs

    d = tmp_path / "s"
    d.mkdir()
    for n in (gname, cname):
        (d / n).write_bytes(b"\0" * 4096)
    for n, text in files.items():
        (d / n).write_text(text)
    p = pair_inputs(d / gname, d / cname)
    return (load_capture(p.golden_listing, as_name=gname),
            load_capture(p.current_listing, as_name=gname))


SIDECAR = """\
schema: 1
device_model: M1
role: config-active
firmware: {{active: "{fw}"}}
"""


def test_per_image_sidecars_verify_reference_in_one_folder(tmp_path):
    g, c = _single(tmp_path, "cfg1.dd", "cfg2.dd", {
        "cfg1.dd.capture.yaml": SIDECAR.format(fw="24.11.6"),
        "cfg2.dd.capture.yaml": SIDECAR.format(fw="24.11.6")})
    assert g.errors == [] and c.errors == []
    rc = reference_check("cfg1.dd", g, c)
    assert rc.role == "config-active" and rc.status == "ok", rc.to_dict()


def test_per_image_sidecars_report_firmware_mismatch(tmp_path):
    g, c = _single(tmp_path, "cfg1.dd", "cfg2.dd", {
        "cfg1.dd.capture.yaml": SIDECAR.format(fw="24.11.6"),
        "cfg2.dd.capture.yaml": SIDECAR.format(fw="24.12.0")})
    assert reference_check("cfg1.dd", g, c).status == "mismatch"


def test_current_sources_keyed_by_its_own_name(tmp_path):
    text = "schema: 1\ndevice_model: M1\nsources:\n  {n}: {{role: nvram}}\n"
    g, c = _single(tmp_path, "nv1.dd", "nv2.dd", {
        "nv1.dd.capture.yaml": text.format(n="nv1.dd"),
        "nv2.dd.capture.yaml": text.format(n="nv2.dd")})
    rc = reference_check("nv1.dd", g, c)
    assert rc.role == "nvram" and rc.status == "ok"


def test_shared_capture_file_cannot_verify_reference(tmp_path):
    g, c = _single(tmp_path, "cfg1.dd", "cfg2.dd", {"capture.yaml": BASE})
    rc = reference_check("cfg1.dd", g, c)
    assert rc.status == "unverified"
    assert any("same capture file" in n for n in rc.notes)


def test_role_key_is_rejected_in_directory_capture_yaml(tmp_path):
    m = _meta(tmp_path, "g", "schema: 1\nrole: nvram\n")
    assert any("role" in e for e in m.errors)
