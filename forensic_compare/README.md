# forensic_compare

Compares a **golden** (baseline) capture with a **current** capture of the same Linux device
and produces a self-contained HTML report. The comparison runs at the partition, filesystem,
file and metadata level. A byte-by-byte diff of whole images is only used as a last resort,
for sources the tool cannot analyse structurally, and the report labels it as such.

Principles:

- **Differences are facts, not verdicts.** Configuration, logs and device-specific keys are
  expected to differ, so nothing is classified as compromise automatically. "Expected" is an
  analyst annotation; it does not mean a file is safe.
- **Incomplete is never unchanged.** Anything that could not be read or validated is shown as
  *not assessed*, and the analysis is marked incomplete.
- **Inputs are read-only.** Images are opened `O_RDONLY` and never mounted. `debugfs` runs
  without `-w`. Images are hashed before and after the analysis.
- **Provenance is explicit.** Every metadata value records where it came from. Unknown values
  stay unknown.
- **Integrity ≠ authenticity.** "Verified" means the image matches a supplied checksum and did
  not change during analysis. It does not establish that the firmware is authentic or free of
  compromise.

## Install

```bash
sudo apt install sleuthkit e2fsprogs           # mmls, fsstat, fls, icat, debugfs (>= TSK 4.12)
python3 -m pip install -r forensic_compare/requirements.txt   # PyYAML
```

## Usage

```bash
# two capture directories: images are paired by exact filename
python forensic_compare/compare.py golden/ current/ -o report/

# a single pair of images (the names may differ)
python forensic_compare/compare.py clean.dd current.dd -o report/

# options
  --rules FILE      expected-change rules (see expected_changes.example.yaml)
  --jobs N          concurrent tool processes (default min(4, CPUs))
  --timeout SEC     per-command timeout (default 600)
  --force           write into a non-empty output dir (removes only the previous run's files)
  --quiet           no progress output
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Report generated, analysis complete, and every image's integrity `verified` |
| 3 | Report generated, but the analysis is incomplete or limited, or some integrity is not `verified` |
| 2 | Usage error or fatal error |

Differences, however many, never change the exit code. Reference notices (mismatch or
unverified) do not change it either.

### Output

```
report/
├── report.html               # open directly from disk; no server, no network
├── comparison.json           # everything the report shows
├── manifests/<source>/{golden,current}.json
├── supporting/{golden,current}/   # capture.yaml, device-info.txt, checksum files (verbatim)
├── tool_log.jsonl            # every external command: argv, status, diagnostics, timing, bytes
└── outputs.json              # the files written by this run (used by --force)
```

The output directory must not overlap the capture directories, in either direction and
including through symlinks. The tool refuses to write into a non-empty directory unless
`--force` is given. Even then it removes only the files listed in the previous run's
`outputs.json`.

## Capture directory

```
golden/
├── config-active-crypt.dd      # images: .dd .img .raw .bin
├── config-other-crypt.dd
├── nvram-crypt.dd
├── mmcblk0.dd
├── mtdblock0.bin
├── SHA256SUMS                  # sha256sum format; *.sha256 / *.sha256sum also accepted
├── capture.yaml                # optional, written by the analyst
└── device-info.txt             # optional; copied verbatim, never parsed
```

The following files are listed as "not used":

- `*.partial`;
- `*.received.sha256`, which is a stream checksum, not an image manifest;
- logs and anything else.

In checksum manifests, entries named `-` (stdin) are ignored, and only entries that name an
image in the same directory are used.

How each image is handled:

| Detected | Handling |
|---|---|
| ext2/3/4 filesystem image | Full file and metadata comparison |
| Partitioned disk (MBR/GPT) | Layout comparison. ext partitions are fully compared as their own sections. LUKS partitions are reported as *encrypted*; squashfs, UBI and JFFS2 as *unsupported (needs extractor)*; anything else as *unknown*. The absence of a signature never means "unencrypted". |
| Anything else (e.g. raw flash `.bin`) | *Image-level only*: signature detection and an identical/different image hash. This is not a file-level comparison. |
| Present on one side only | *Unmatched source*. Its integrity is still checked. Its contents are never reported as added or deleted. |

### capture.yaml

```yaml
schema: 1
device_model: XYZ-100
device_serial: null              # unknown: leave null, never guess
captured_at: 2026-10-01T14:20:00Z
captured_by: analyst
firmware:
  active: "24.11.6"
  inactive: null                 # unknown
sources:
  config-active-crypt.dd: { role: config-active }      # source firmware = firmware.active
  config-other-crypt.dd:  { role: config-inactive }    # source firmware = firmware.inactive
  nvram-crypt.dd:         { role: nvram }              # active firmware shown as context only
  mmcblk0.dd:             { role: disk }
partitions:
  mmcblk0.dd:
    1: { role: boot }
    3: { role: config, encrypted: true, mapper_image: config-active-crypt.dd }
observations:                    # structured capture-time command output
  - field: firmware.active
    value: "24.11.6"
    command: "cat /etc/version"
    reference: device-info.txt
```

Every value carries its provenance:

- `analyst`;
- `analyst-role` (derived from a declared role);
- `capture-command` (from `observations`).

If two provenances disagree, the value is shown as **Conflict**.

**Reference notices.** The required fields are `device_model` plus the source firmware for
configuration roles.

- **Reference mismatch:** a required value is known on both sides and differs.
- **Reference unverified:** a required value is missing on either side, or is in Conflict.

The comparison always continues, with a persistent notice.

## What is compared per file

| Field | Notes |
|---|---|
| path | Matched by raw bytes. TSK renders control characters as `^`, so paths containing `^` are flagged *name may have been altered*. |
| SHA-256 | Logical content via `icat`: sparse holes are hashed as zeros, slack is excluded, and the byte count is verified against the size. |
| size | Files and symlinks only; directory sizes are not compared. |
| permissions | Permission bits plus sticky, with SUID and SGID reported as separate fields. |
| uid / gid | — |
| mtime | Seconds precision (from `fls -m`). atime, ctime and crtime are shown as context only. |
| symlink target | **Fast symlinks:** read from the raw inode, because TSK 4.12.1 `icat` returns NULs for them; cross-checked against the `fls` listing. **Slow symlinks:** read with `icat`. Links are never followed. |
| xattrs | Enumerated with `debugfs ea_list`, fetched with `ea_get -f` by inode, and cross-validated against an independent parse of the on-disk xattr structures. debugfs 1.47.2 can silently return an empty list for a corrupt EA block, so a disagreement means *not assessed*. |
| capabilities | `security.capability` decoded (v1/v2/v3, including rootid); the raw hex is kept. |

The root directory `/` is included, taken from raw inode 2, because `fls` does not list it.

### Statuses

Every entry gets exactly one status:

| Status | Meaning |
|---|---|
| **Modified** (red) | The type, content or symlink target changed. |
| **Added** (yellow) | Present only in current. Requires a complete inventory on the other side. |
| **Deleted** (gray) | Present only in golden. Requires a complete inventory on the other side. |
| **Metadata changed** (orange) | Only metadata changed. |
| **Unchanged** (green) | Every field was assessed and is equal. |
| **Incomplete** (purple) | No difference among the assessed fields, but something was not assessed. |

A Modified, Metadata changed, Added or Deleted entry with a not-assessed field also carries an
*incomplete* badge.

### Review priority

Priority is computed on the differences that rules do not cover. It is a review order, not a
compromise verdict.

| Priority | Conditions |
|---|---|
| P1 | Any sensitive change: SUID/SGID, capabilities, `security.*` xattrs, ownership changed to root, a new symlink, a type change to symlink. Also any content, existence or type change on an ELF binary or script, on any file in a boot-role partition, or on a path matched by `elevate`. |
| P2 | Other content, existence or type changes, and incomplete entries. |
| P3 | Metadata-only changes. |
| P4 | Fully expected entries. |
| P5 | Unchanged entries. |

No signature validity is checked.

## Expected-change rules

See `expected_changes.example.yaml`. The example is illustrative only and contains no enabled
rules.

Rule semantics:

- **Matching.** A rule matches by exact source id (an image name, or `mmcblk0.dd#p1` for a
  partition), by path glob and by status.
- **Coverage.** A rule covers only the listed fields:
  - added and deleted entries need `existence`;
  - `suid`, `sgid`, `capability` and `xattr:security.*` must be named explicitly.
- **Expectation levels.**
  - **Fully expected:** every difference is covered and the entry was fully assessed.
  - **Partially expected:** some differences are covered; the uncovered ones keep their
    priority.
- **Globs.**
  - Paths are relative to the filesystem root and matching is case-sensitive.
  - `*` matches within one directory level, `**` crosses directories, and `?` matches one
    character.
- **Reporting.** The report lists every rule with its match count, shows "No matches" for
  rules that matched nothing, and records the rules file's SHA-256.
- **Filtering.** *Hide fully expected* is off by default. It never hides partially expected
  or incomplete entries, and it never hides notices.

## The report

- **Banners:** persistent banners for Integrity FAILED, Reference mismatch/unverified and
  Incomplete analysis. They can be collapsed but never dismissed.
- **Sidebar:** per-source sections, plus disk partitions, image-level and unmatched sources,
  integrity, capture metadata, rules, files not used, and tools.
- **Summary cards:** computed before filters are applied.
- **Filters:** status filters (All, Modified, Added, Deleted, Metadata Changed, Unchanged,
  Incomplete), *Hide unchanged* (on by default), *Hide fully expected*, *Sensitive only*,
  search by path, name or hash (`/` to focus), "Displaying X of Y entries", and Reset filters.
- **Table:** sortable columns and pagination; only the visible page is in the DOM.
- **Detail panel:** golden vs current with every field and its assessment state, the
  differences highlighted, and rule coverage per difference.
- **Theme:** light and dark.
- **Security:** a CSP with exact hashes of the inline script and style, no network access, and
  data rendered as text only. This is defense in depth, not a guarantee.

Phase 2, decided but not yet implemented:

- column chooser;
- font controls and monospace option;
- zoom, Fit to Page and Full Screen;
- vertical/horizontal layout;
- card view on narrow screens;
- virtualized rendering;
- opt-in text diffs, with per-file and total limits.

## Limitations

- **Squashfs** (the firmware root filesystems) is not analysed yet; it needs a read-only
  extractor. Firmware binary changes are therefore **not** covered by the MVP.
- **Timestamps:** mtime is compared at one-second precision.
- **Lossy names:** names containing control characters are rendered lossily by TSK and flagged
  as such.
- **Live captures:** the filesystem may need journal recovery. `needs_recovery` is reported,
  and the journal is not replayed.
- **Performance:** one `icat` process runs per regular file. 20,000 files per side took about
  4.5 minutes with `--jobs 4` on the test machine.

## Development and tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/playwright install chromium

.venv/bin/python -m pytest                       # integration/browser tests skip if tools are missing
.venv/bin/python -m pytest --strict-validation   # skips of required tests count as failures
.venv/bin/python -m pytest -m "not slow"         # without the ~5 min large-inventory test
```

`FC_TSK_BIN_DIR` and `FC_TSK_LIB_DIR` can point the tests at a non-system sleuthkit build.

Fixtures are synthetic ext4 images built by `tests/fixtures/build.py` with `mke2fs -d`.
`debugfs -w` is used **only** on those freshly generated images. Determinism is verified by
building twice and comparing hashes, and the tool versions and filesystem features are recorded
in `fixtures-metadata.json`.

## Real-image validation (separate acceptance step)

Synthetic fixtures establish how the implementation behaves. They do not establish
compatibility with the real device images. Before relying on the tool, run it on the real
captures and confirm:

- [ ] Whether `/etc/version` exists in any standalone image or in `/boot`. The tool does not
      assume it does.
- [ ] The real log, data and key paths, to write `--rules` (none are assumed).
- [ ] The encryption format observed on mmcblk0 p3/p5/p6, and that the declared `partitions:`
      entries match.
- [ ] The real `fls`, `fsstat` and `debugfs` diagnostics. Extend
      `tools/diagnostics.py` only with understood messages.
- [ ] No unexpected *not assessed* xattr results on real kernel-written inodes. The
      structural check treats a non-empty in-inode EA area without the EA magic as an error.
- [ ] Runtime and report size on the real NVRAM image.
- [ ] The `.bin` sources (`mtdblock0.bin`, `mmcblk0boot0/1.bin`) are detected and labelled as
      expected.
