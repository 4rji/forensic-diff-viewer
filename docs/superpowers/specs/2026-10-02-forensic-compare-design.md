# forensic_compare — Design Spec

- **Date:** 2026-10-02
- **Status:** Approved in conversation (sections 1–5 and refinements); MVP implementation authorized
- **Scope of this spec:** MVP (phase 1) plus the phase-2 UI items that are already decided

## 1. Purpose and context

An analyst captures read-only images from a Linux-based embedded device and needs to compare them
against a **golden reference** captured from the same device model and firmware version, with its
configuration documented. The tool detects differences at the partition, filesystem, file and
metadata level (never a plain byte-by-byte image diff as the main method) and produces a
self-contained HTML report that is fast to review.

Key principles:

1. **Differences are facts, not verdicts.** Configuration, logs and device-specific keys are expected
   to differ. Nothing is automatically classified as compromise. "Expected" is an analyst
   annotation, never a statement that a file is safe.
2. **Incomplete is never unchanged.** Live captures may contain filesystem inconsistencies.
   Anything that could not be read or validated is reported as *not assessed* and keeps the analysis
   from being complete.
3. **Inputs are read-only.** Images are never mounted or written. Every tool is invoked read-only.
4. **Provenance is explicit.** Every metadata value records where it came from. Unknown values stay
   unknown and are never inferred or guessed.
5. **Image integrity ≠ firmware authenticity.** "Verified" means the image matches a supplied
   checksum and did not change during analysis. It says nothing about firmware authenticity or the
   absence of compromise.

### 1.1 Capture set (current device)

| Image | Content | MVP treatment |
|---|---|---|
| `config-active-crypt.dd` | ext4 filesystem image (decrypted dm volume), active configuration | Full comparison — priority 1 |
| `nvram-crypt.dd` | ext4 filesystem image (decrypted dm volume), persistent data/logs | Full comparison — priority 2 |
| `config-other-crypt.dd` | ext4 filesystem image (decrypted dm volume), inactive configuration | Full comparison against its own reference |
| `mmcblk0.dd` | Full eMMC: p1 ext4 `/boot`; p2/p4 squashfs roots; p3/p5 encrypted config; p6 encrypted NVRAM | Layout detection; p1 fully compared; other partitions explicitly reported as encrypted/unsupported |
| `mtdblock0.bin`, `mmcblk0boot0.bin`, `mmcblk0boot1.bin` | Raw flash / eMMC boot areas | Paired + integrity + signature detection; image-level hash comparison only, limitation shown explicitly |

The standalone ext4 images have no partition table and are inspected directly. Encrypted
partitions inside `mmcblk0.dd` are never treated as readable ext4; their decrypted contents are the
mapper images. Squashfs comparison is out of the MVP (needs a read-only extraction tool) but the
architecture must allow plugging it in.

## 2. Usage

```
python compare.py GOLDEN CURRENT -o OUTDIR [--rules FILE] [--jobs N] [--timeout SECONDS]
                  [--force] [--quiet]
# phase 2: [--text-diffs] [--text-diff-max BYTES] [--text-diff-total BYTES]
```

- **Directory mode:** `GOLDEN` and `CURRENT` are capture directories. Candidate images are paired by
  **exact filename** (never fuzzy: `config-active` is never substituted for `config-other`).
- **Single-pair mode:** `GOLDEN` and `CURRENT` are image files. They form one pair even when the
  names differ. `capture.yaml` and checksum manifests are read from each image's own directory when
  present, and only entries naming that image are used.

### 2.1 Exit codes

| Code | Meaning |
|---|---|
| 0 | Report generated, analysis **complete** and integrity **verified** for every image |
| 3 | Report generated, but analysis is incomplete/limited, or any image integrity is not `verified` |
| 2 | Usage error or fatal error (no report, or partial output clearly marked) |

Differences, even many, do not change the exit code. Reference notices (mismatch/unverified) do not
change the exit code either: they are persistent report notices. Analysis is **incomplete** when
any of the following hold:

- an unmatched source exists;
- a pair is incompatible or unreadable;
- an inventory is partial;
- any entry is not fully assessed;
- any partition or source is encrypted, unsupported or image-level-only;
- any unknown diagnostic was raised.

### 2.2 Output

```
OUTDIR/
├── report.html                  # standalone; works via file:// with no server and no network
├── comparison.json              # everything the report shows
├── manifests/<source-id>/golden.json
├── manifests/<source-id>/current.json
├── supporting/golden/…          # capture.yaml, device-info.txt, checksum files — copied verbatim
├── supporting/current/…
├── tool_log.jsonl               # every external command (no file contents)
└── outputs.json                 # list of files written by this run (used by --force)
```

`<source-id>` is the image filename for standalone images, `<image>#p<N>` for partitions (directory
name sanitized), and `<golden-name>__vs__<current-name>` in single-pair mode when the names differ.

**Output protection:**

- If OUTDIR exists and is non-empty, the tool refuses to run unless `--force` is given.
- With `--force`, the tool deletes only the files listed in a previous run's `outputs.json`, then
  writes its own files. Unrelated files are preserved.
- OUTDIR must not be equal to, inside, or contain any capture directory or the directory of any
  input image. The check uses fully resolved real paths, so symlink aliases are caught too.
- Files are written to a temporary name and renamed into place.

## 3. Architecture

```
forensic_compare/
├── compare.py          # CLI: args, output protection, orchestration, progress, exit codes
├── discovery.py        # list capture dirs, classify files, pair by exact name, unmatched
├── integrity.py        # sha256sum manifest parsing, pre/post image hashing, verdicts
├── capture_meta.py     # capture.yaml + observations, provenance, conflicts, reference checks
├── tools/
│   ├── runner.py       # subprocess wrapper: capture & stream modes, timeouts, logging, versions
│   ├── diagnostics.py  # known-benign diagnostic patterns; classifier
│   ├── tsk.py          # mmls / fsstat / fls / icat wrappers + parsers
│   └── debugfs.py      # read-only debugfs: ea_list / ea_get / inode_dump / block_dump by inode
├── signatures.py       # magic-byte detection (ext, LUKS, squashfs, UBI, JFFS2, uImage, FDT/FIT)
├── ext_inode.py        # read-only raw ext superblock/group-desc/inode reader (independent of TSK/debugfs)
├── xattr_struct.py     # independent parser of ext4 in-inode and block xattr structures
├── capabilities.py     # vfs_cap_data v1/v2/v3 decoder
├── analyzer.py         # per image: detect kind → disk layout / filesystem inventory / image-level
├── manifest.py         # dataclasses, Assessed[T], JSON schema (versioned), load/save
├── comparator.py       # entry diff → status, per-field diffs, completeness
├── rules.py            # expected-change rules, globs, coverage, elevation, priority
├── report.py           # comparison.json + self-contained report.html (inlines static assets, CSP)
├── templates/report.html
├── static/app.js, static/style.css
├── expected_changes.example.yaml
├── requirements.txt    # PyYAML only
└── README.md
tests/                  # pytest; fixture builder; unit, runner, integration, browser, slow
requirements-dev.txt    # pytest, playwright
```

Data flow:

```
golden/  ─┐                         ┌─ analyzer(golden)  ─┐
          ├─ discovery → pairs ─────┤                     ├─ comparator → rules → report
current/ ─┘  integrity(pre)         └─ analyzer(current) ─┘      integrity(post)
             capture_meta
```

Module boundaries:

- `analyzer` produces a `Manifest` and knows nothing about comparison.
- `comparator` takes two `Manifest`s and knows nothing about tools.
- `rules` only annotates existing differences.
- Analysis kinds (`ext-fs`, `disk`, `image-level`) implement one interface:
  `analyze(image, side, ctx) -> SourceAnalysis`.
- A future `squashfs` analyzer (or NVRAM-specific source) plugs in by producing the same `Manifest`.

## 4. Discovery and pairing

### 4.1 Classifying files in a capture directory

- **Candidate image:** a regular file with extension `.dd`, `.img`, `.raw` or `.bin`, not ending in
  `.partial`.
- **Checksum manifest:** `*.sha256`, `*.sha256sum` or `SHA256SUMS`, **excluding** `*.received.sha256`.
- **Supporting:** `capture.yaml` and `device-info.txt`. They are copied verbatim with their SHA-256.
  `device-info.txt` is never parsed.
- **Other:** `*.received.sha256`, `*.partial`, logs and anything else are listed in the report as
  "not used" with the reason.

### 4.2 Pairing

- Directory mode pairs by exact filename. An image present on one side only becomes an **unmatched
  source**: its integrity is still assessed and it is shown in its own section. It is never
  reported as added or deleted filesystem content.
- The kind of each image is detected on both sides. If the kinds differ (e.g. ext4 vs squashfs),
  the pair is **incomplete — incompatible formats**.
- If an image is unreadable, the pair is **incomplete — unreadable**.
- Each pair, and each partition of a disk pair, is its own section in the report.

## 5. Integrity

- **Manifest parsing:** `sha256sum` format, one `<64 hex><space><space|*><name>` per line.
  - An entry is used only if `<name>` is a basename equal to a candidate image in the same
    directory.
  - Entries named `-` (stdin marker, e.g. `*-`) are always ignored.
  - Malformed lines are reported.
  - If two manifests disagree about the same image, the result is FAILED with the reason
    "conflicting checksums".
- **Hashing:** every candidate image is hashed (SHA-256, 4 MiB `O_RDONLY` reads) **before** analysis
  and **after** analysis. The post-analysis hash always runs, even after extraction failures or
  timeouts (`try/finally`).
- **Verdicts (per image):**
  - `verified` — the supplied checksum matches, and the pre and post hashes are equal.
  - `stable-unverified` — the pre and post hashes are equal, but there is no supplied checksum
    ("stable, unverified against a prior checksum").
  - `failed` — "integrity not established". Reasons:
    - mismatch against the supplied checksum;
    - pre and post hashes differ (changed during analysis);
    - hashing error;
    - conflicting checksums.
- **Overall verdict:** `verified` only if every image is `verified`. Any `failed` image produces a
  permanent **Integrity FAILED** banner.
- The report always states: *"Verified describes image integrity against the supplied checksum; it
  does not establish that the firmware is authentic or free of compromise."*

## 6. Capture metadata and reference checks

### 6.1 `capture.yaml` (one per side, optional)

```yaml
schema: 1
device_model: XYZ-100
device_serial: null            # unknown → leave null or omit; never guess
captured_at: 2026-10-01T14:20:00Z
captured_by: analyst-name
firmware:
  active: "24.11.6"
  inactive: null               # unknown
sources:
  config-active-crypt.dd: { role: config-active }
  config-other-crypt.dd:  { role: config-inactive, firmware: null }
  nvram-crypt.dd:         { role: nvram }
  mmcblk0.dd:             { role: disk }
partitions:
  mmcblk0.dd:
    1: { role: boot }
    3: { role: config, encrypted: true, mapper_image: config-active-crypt.dd }
observations:                  # structured capture-time command output
  - field: firmware.active
    value: "24.11.6"
    command: "cat /etc/version"
    reference: device-info.txt
notes: "Golden configured per doc ref CFG-017"
```

### 6.2 Provenance

Every value is stored as `{value, provenance, detail}`. `provenance` is one of:

- `analyst` — a top-level field of `capture.yaml`;
- `capture-command` — an entry in `observations`;
- `image-file` — a file read from an image (reserved; no MVP producer);
- `analyst-role` — derived from a declared role, see 6.3.

If two provenances give different values for the same field, the field is shown as **Conflict**
with all values. Missing fields are displayed as *not recorded*, never filled in.

### 6.3 Reference checks per source

| Source role | Required on both sides | Notes |
|---|---|---|
| `config-active` | `device_model`, source firmware | source firmware = `sources.<name>.firmware`, else `firmware.active` (provenance `analyst-role`) |
| `config-inactive` | `device_model`, source firmware | source firmware = `sources.<name>.firmware`, else `firmware.inactive` |
| `nvram` | `device_model` | `firmware.active` shown as context ("active firmware at capture time"); NVRAM is shared storage and not bound to a slot |
| `disk`, `other`, undeclared | `device_model` | `firmware.active` and `firmware.inactive` shown as context; undeclared role shown as "role not declared" |

- **Reference mismatch:** a required value is known on both sides and differs, including model
  differences.
- **Reference unverified:** a required value is missing on either side, or is in Conflict.

Both notices are persistent. Comparison always continues.

### 6.4 Partitions

The **observed signature** (from magic bytes and tools) is stored separately from **declared
attributes** (`capture.yaml` `partitions:` with provenance).

- The display reads, for example, `Encrypted (declared: analyst) · signature: LUKS2 header` or
  `signature: none recognized`.
- A missing signature is never displayed as "unencrypted".
- `mapper_image` declarations become links to that source's section.

## 7. Analysis

### 7.1 Tool runner (`tools/runner.py`)

- Uses `subprocess.Popen` with an argument list, never `shell=True`.
- Environment: `LC_ALL=C`. Each process runs in its own session (process group).
- **Capture mode:** stdout is collected in memory. Used only for small textual output (`mmls`,
  `fsstat`, `fls`, debugfs batches).
- **Stream mode:** stdout is delivered in chunks to a consumer (SHA-256 + kind sniffing). Used for
  `icat`. Contents are never buffered in full and never logged.
- **Timeout:** the process group gets SIGTERM, then SIGKILL after a grace period. The worker
  semaphore slot is released and partial results are preserved. The affected entries become
  *not assessed (timeout)*.
- **`tool_log.jsonl`:** one record per invocation with `id`, `argv`, `exit_code`, `timed_out`,
  `duration_s`, `stdout_bytes`, classified `diagnostics`, and `bytes_extracted` (stream mode).
  Errors in manifests reference this `id`.
- **Tool versions:** recorded only for tools actually used, by the first invocation of each tool
  (`fls -V`, `debugfs -V`, …).

### 7.2 Diagnostics (`tools/diagnostics.py`)

- Every stderr line, and every unexpected stdout line in batch modes, is classified as:
  - `banner` — a known version banner, e.g. `^debugfs \d+\.\d+(\.\d+)? \(.*\)$`;
  - `info` — a known informational message;
  - `error` — a known error pattern;
  - `unknown`.
- The patterns are a versioned table in code.
- `error` and `unknown` diagnostics remain visible in the report and conservatively mark the
  affected scope (an inode, an inventory, or a source) as not assessed or incomplete.

### 7.3 Image kind detection (`signatures.py`, `analyzer.py`)

1. Read magic bytes with `O_RDONLY`:
   - ext2/3/4 — `0xEF53` at byte 1080;
   - LUKS1/2 — `LUKS\xba\xbe` at 0;
   - squashfs — `hsqs` at 0;
   - UBI — `UBI#`;
   - JFFS2 — `0x1985` (either endianness);
   - uImage — `0x27051956`;
   - FDT/FIT — `0xd00dfeed`;
   - MBR — `0x55AA` at 510;
   - GPT — `EFI PART` at 512.
2. Confirm with tools:
   - a partition table → `mmls` (sector size, start, length, description);
   - ext → `fsstat`.
3. Resulting kinds:
   - `ext-fs` — full analysis;
   - `disk` — layout plus per-partition sub-analysis;
   - `image-level` — `.bin` and other unsupported content: signature detection plus image hash
     comparison, labeled *"Structural analysis not supported — image-level hash comparison only"*.
     The image-level result says only that the image hashes are identical or different; it is
     never presented as a file-level comparison.
   - `unreadable`.

### 7.4 Disk images

- `mmls` runs on each side independently. The tool records the sector size, start sector, length
  and byte offset per partition. The layout is never hardcoded.
- Partition numbering: the allocated `mmls` entries (not `Meta` or unallocated `-------`) are taken
  in table order as p1..pN. The `mmls` slot text is recorded alongside.
- Layouts are compared (the partition count and each partition's start, length and description);
  differences are shown in the disk section.
- For each partition, signature detection runs at its byte offset:
  - ext → a full `ext-fs` analysis with the offset passed to every TSK call
    (`-o <start sector>`, sector size honored via `-b` when not 512) and to debugfs as
    `image?offset=<bytes>`;
  - LUKS → *encrypted*;
  - squashfs → *unsupported — needs extractor*;
  - anything else → *unknown*, combined with declared attributes when present.
- Successfully comparing p1 does **not** make the disk comparison complete. Encrypted and
  unsupported partitions keep the disk section incomplete and remain visible.
- **Boot role:** a partition has the boot role if it is declared `role: boot`, or if `fsstat`
  reports `Last Mounted at: /boot` (recorded as an observation). Either way, the source of the role
  is shown.

### 7.5 ext filesystem analysis

**Filesystem facts**

- From `fsstat`: features, block size, `Last mounted at`.
- From the superblock: `needs_recovery` (incompat `0x4`). When set, the source shows the warning
  *"journal not replayed; on-disk state may lag the live state"*.
- `fsstat` diagnostics are classified as in 7.2.

**Inventory**

- One call: `fls -r -p -u -m / [-o N] image`. Only allocated entries are listed; recovered deleted
  entries are never mixed in.
- Parsing:
  - The body format is `MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`. The name is
    obtained by splitting off the first field and **right-splitting the last 9 fields**, so `|`
    inside names is safe.
  - The trailing ` -> target` text is never trusted. Symlink targets come from `icat`.
  - TSK virtual entries (`$OrphanFiles` and below) are excluded and counted.
  - A line that does not parse (e.g. a filename containing a newline) is reported as a diagnostic,
    and the inventory becomes `partial`.
  - Mode string: `<name type>/<meta type><rwx×3>`, where `s/S/t/T` decode to the SUID, SGID and
    sticky bits.
- A non-zero exit code or any `error`/`unknown` diagnostic makes the inventory `partial`.
- **Paths are byte strings.**
  - *Verified behavior:* TSK passes non-UTF-8 bytes through raw, but replaces control characters
    (e.g. a newline) with `^`.
  - Paths are kept as raw bytes (`path_hex`) and as a display string (surrogate-escaped, with
    control characters escaped).
  - A path containing `^` may have been rendered lossily, so it is flagged `path_lossy`. Such
    entries are compared, but they carry an incomplete flag with the reason "name may have been
    altered by TSK; exact bytes not verified".
  - Duplicate paths within one inventory are **ambiguous**.

**Content (regular files)**

- `icat [-o N] image <inode>`, streamed into SHA-256. Defaults are used: sparse holes are emitted
  as zeros and slack is excluded (no `-s`, no `-h`).
- `bytes_read` must equal the inventory size; otherwise the result is *not assessed (short/long
  read)*.
- `kind` is sniffed from the first 4 KiB:
  - `elf` — ELF magic;
  - `script` — `#!`;
  - `text` — valid UTF-8 with no NUL;
  - `binary` — otherwise.
- Hard links: content is extracted once per inode and shared.
- Concurrency: a bounded thread pool (`--jobs`, default `min(4, cpu_count)`). Progress is printed to
  stderr:
  `[nvram-crypt.dd · current] hashing 1234/5678 files · 120/2300 MiB`
  It uses a TTY-aware single line, or periodic lines when stderr is not a TTY. `--quiet` disables
  it.

**Symlinks**

*Verified behavior:* TSK 4.12.1 `icat` on an ext4 **fast** symlink returns `size` NUL bytes
instead of the target. The byte count still matches, so a length check cannot detect it.

- **Fast symlinks** (`i_size < 60`, no `EXTENTS_FL`, no `INLINE_DATA_FL`): the target is read from
  `i_block` by the independent raw inode reader (`ext_inode.py`).
- **Slow symlinks** (extent-mapped): the target is read with `icat` on the link's own inode.
- **Inline-data symlinks:** read from `i_block` by the raw reader.
- The result is cross-checked against the `fls -m` ` -> target` suffix, after applying TSK's
  control-character rendering to the target. Disagreement → *not assessed*.
- Links are never followed.
- Stored as `target_hex` plus a display string with escapes for non-printable or invalid UTF-8.

**Raw inode reader (`ext_inode.py`)**

- A read-only (`O_RDONLY`) Python parser of the ext2/3/4 superblock, the group descriptors (32-bit
  and 64-bit descriptor sizes) and the inode table, at the filesystem's byte offset.
- Returns the raw inode bytes, `i_flags`, `i_size`, `i_block`, `i_file_acl` and `i_extra_isize`.
- Used for fast symlink targets and for the independent xattr structure validation. It is
  deliberately independent of both TSK and debugfs.

**Extended attributes (by inode, debugfs read-only, never `-w`)**

1. Enumerate with `ea_list <ino>` in batches (`debugfs -f cmdfile 'image?offset=N'`). The
   per-command output is split on the `debugfs: <cmd>` echo lines.
2. Run an **independent structural validation** (`xattr_struct.py` on top of `ext_inode.py`, which
   reads the image directly and read-only, independent of debugfs):
   - check the in-inode EA header magic `0xEA020000` at `128 + i_extra_isize`;
   - read `i_file_acl`; if it is non-zero, read that EA block and check the block magic
     `0xEA020000`;
   - parse both regions into a list of entries `(name_index+name, value_size, value_inum)`.

   *Verified behavior:* with a corrupted EA block, debugfs 1.47.2 `ea_list` prints nothing (it even
   drops the in-inode attributes) and exits 0. `ea_get -f` prints an error, exits 0 and leaves a
   0-byte output file.
3. Decide:
   - `absent` only if there is no in-inode EA header, `i_file_acl == 0`, and `ea_list` reported
     nothing with no diagnostics;
   - `complete` only if the structural enumeration and `ea_list` agree on names and sizes;
   - any disagreement, unparseable structure, bad magic or diagnostic → `error`, shown as
     *not assessed*.
   - An empty `ea_list` with exit 0 is **never** sufficient on its own: debugfs 1.47.2 can suppress
     internal xattr read errors.
4. Get values with `ea_get -f <tmpfile> <ino> <name>` per attribute. The value is accepted only if
   there are no `error`/`unknown` diagnostics **and** the written file length equals the enumerated
   size. The existence of the temp file alone proves nothing.
5. Temp files live in a private `mkdtemp` directory (`0700`; files `0600`) and are removed in
   `finally`, on success, failure and timeout.
6. **Batch fallback:** if a batch produces any `error`/`unknown` diagnostic or a parse anomaly
   (stderr and stdout can interleave out of order), every inode in the batch is retried one at a
   time so that each failure is attributed to the right inode.
7. `security.capability` is decoded (`capabilities.py`, vfs_cap_data v1/v2/v3 including `rootid`)
   into text such as `cap_net_admin,cap_net_raw+ep`. The raw hex is kept.

### 7.6 Manifest schema (`manifest.py`)

Every per-entry field is `Assessed`: `{"state": "ok"|"absent"|"n/a"|"error", "value": …,
"reason": …, "log_id": …}`.

```json
{
  "schema": "forensic-compare/manifest/1",
  "side": "golden",
  "source_id": "config-active-crypt.dd",
  "image": {"name": "...", "path": "...", "size": 0, "sha256_pre": "..."},
  "filesystem": {"kind": "ext4", "offset_bytes": 0, "sector_size": 512,
                 "features": ["..."], "last_mounted": {"state": "ok", "value": "/boot"},
                 "needs_recovery": false},
  "inventory": {"state": "complete|partial", "diagnostics": [], "virtual_excluded": 0},
  "entries": [{
    "path": "/etc/app/conf.json", "path_lossy": false, "inode": 1234,
    "type":   {"state": "ok", "value": "file"},
    "mode":   {"state": "ok", "value": 420},
    "uid":    {"state": "ok", "value": 0},
    "gid":    {"state": "ok", "value": 0},
    "size":   {"state": "ok", "value": 812},
    "mtime":  {"state": "ok", "value": 1727790000},
    "times":  {"atime": 0, "ctime": 0, "crtime": 0},
    "content":    {"state": "ok", "value": {"sha256": "...", "bytes_read": 812, "kind": "text"}},
    "symlink":    {"state": "n/a"},
    "xattrs":     {"state": "ok", "value": {"user.x": {"hex": "...", "size": 41}}},
    "capability": {"state": "absent"}
  }],
  "tools": {"fls": "The Sleuth Kit ver 4.12.1"}
}
```

- `type` is one of `file`, `dir`, `symlink`, `chr`, `blk`, `fifo`, `socket`, `unknown`.
- `mode` holds the permission bits including SUID/SGID/sticky (`0o7777`). The file type is kept
  separately.
- `times` are context only. Only `mtime` is compared, with seconds precision (`fls -m`).
- `content` is `n/a` for anything that is not a regular file.
- `capability` is derived from the `security.capability` xattr. That xattr is shown under
  `capability` and is not duplicated as a generic xattr difference.

## 8. Comparison (`comparator.py`)

### 8.1 Status (exactly one per entry)

| Status | Color/icon | Condition |
|---|---|---|
| Modified | red ✎ | `type` differs; or content sha256 differs; or symlink target differs; or content is not assessed but `size` is assessed and differs |
| Added | yellow ＋ | present only in Current, **and** the Golden inventory is `complete` and the path is unambiguous |
| Deleted | gray − | present only in Golden, **and** the Current inventory is `complete` and the path is unambiguous |
| Metadata changed | orange ◑ | no Modified condition holds, and at least one of mode/SUID/SGID/uid/gid/mtime/xattrs/capability differs |
| Unchanged | green ✓ | every field assessed on both sides and equal |
| Incomplete | purple ? | no difference found among the assessed fields, but some field is not assessed. This also covers a path missing on one side when that side's inventory is `partial` or the path is ambiguous ("existence not assessed") |

`incomplete` is also an orthogonal **flag**. A Modified, Metadata changed, Added or Deleted entry
with any not-assessed field carries an "incomplete" badge. The **Incomplete filter matches every
entry where the flag or the status is set.**

### 8.2 Per-field differences

Each difference is `{field, golden, current, assessed, sensitive, covered_by}`. Field tokens:

- `existence`, `type`, `content`, `size`, `mode` (permission bits other than SUID/SGID, sticky
  included);
- `suid`, `sgid`, `uid`, `gid`, `mtime`, `symlink_target`;
- `xattr:<name>`, `capability`.

**Sensitive differences:**

- any change to `suid`, `sgid` or `capability`;
- any change to an `xattr:security.*` attribute;
- a `uid`/`gid` change whose new value is 0;
- `existence` of an added symlink;
- a `type` change to symlink.

## 9. Expected-change rules and review priority (`rules.py`)

### 9.1 Rule file (`--rules`, YAML, optional)

```yaml
schema: 1
rules:
  - id: example-logs
    label: "Log rotation"
    reason: "Logs are written continuously on a live device"
    sources: [nvram-crypt.dd]              # exact source ids
    paths: ["var/log/**"]                  # illustrative only
    statuses: [modified, added, deleted]
    fields: [existence, content, size, mtime]
elevate:                                   # optional: always priority 1 when changed
  - sources: ["mmcblk0.dd#p1"]
    paths: ["**"]
    reason: "Boot chain"
```

**Glob semantics:**

- Paths are relative to the filesystem root, with no leading `/`.
- Matching is case-sensitive.
- `*` matches within one path segment; `**` matches zero or more segments, crossing `/`; `?`
  matches one character other than `/`.

**Field tokens:**

- The tokens of 8.2. `xattr:<pattern>` allows `*` in the name, but a pattern only covers
  `security.*` attributes when it literally starts with `xattr:security.`.
- `suid`, `sgid`, `capability` and `xattr:security.*` must be named explicitly; a generic pattern
  never covers them.
- An Added or Deleted entry is covered only if the rule lists `existence` (plus the relevant
  attributes). Allowing `content`, `size` or `mtime` alone never authorizes creation or deletion.

### 9.2 Coverage

- **Matching:** a rule matches an entry when its source id is listed, its path matches a glob and
  its status is in `statuses`. A difference is covered by a matching rule that lists its field.
- **Fully expected:** every difference is covered **and** the entry is fully assessed. Rules can
  never turn incomplete analysis into a fully expected result.
- **Partially expected:** some differences are covered, but not all, or all are covered but the
  entry is incomplete. The uncovered differences drive the priority.
- **None:** no difference is covered.
- Expected and Partially expected are overlapping **annotations**, not statuses. Every difference
  and the original status are always preserved.
- A sensitive difference covered by an explicit allowance is shown with ⚠ "sensitive field
  explicitly allowed by rule <id>" in the detail panel.
- The report lists the rules loaded, the rule file's SHA-256 and each rule's match count. Zero
  matches are shown as **"No matches"** (which may be legitimate).
- The example file ships with illustrative, commented, non-enabled rules only. No device paths are
  assumed: `/log/**` and similar paths are not confirmed.

### 9.3 Review priority (review order, not a compromise verdict)

| Priority | Condition (computed on the **uncovered** differences) |
|---|---|
| 1 Critical | any sensitive difference; or a content/existence/type difference on `kind` elf/script; or any content/existence/type difference inside a boot-role partition (regardless of `kind`); or a path matched by `elevate` |
| 2 High | a Modified/Added/Deleted difference; or the entry is incomplete |
| 3 Medium | metadata-only differences |
| 4 Expected | fully expected |
| 5 None | unchanged |

Partially expected entries land in 1–3 according to what remains uncovered. Signature files are
compared like any other file. The report states that **no signature validity is verified**.

## 10. Report

### 10.1 Embedding and security (defense in depth)

- **Self-contained:** `templates/report.html` with `static/style.css` and `static/app.js` inlined.
  There are no external assets, and no links are derived from data.
- **Data:** comparison data is embedded as `<script type="application/json" id="data">`. `<`, `>`,
  `&`, U+2028 and U+2029 are escaped as `<`, `>`, `&`, ` ` and ` `.
- **Rendering:** data is rendered only through `textContent` and attribute setters. `innerHTML` is
  never used with data.
- **CSP:** the CSP `<meta http-equiv="Content-Security-Policy">` is the **first element of
  `<head>`**, before any protected content:
  `default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…'; img-src 'none';
  connect-src 'none'; base-uri 'none'; form-action 'none'`.
  The hashes are computed at build time from the exact inline bytes.
- **Preferences:** theme, font, columns and page size are stored in `localStorage`, wrapped in
  `try/catch`, and fall back to defaults.
- This is documented as defense in depth, not a guarantee.

### 10.2 MVP (phase 1)

- **Top bar:**
  - title and case data (model, capture times, with provenance indicators);
  - the integrity badge;
  - the light/dark toggle (defaults to `prefers-color-scheme`).
- **Persistent banners:**
  - Integrity FAILED;
  - Reference mismatch;
  - Reference unverified;
  - Incomplete analysis;
  - "This report contains file contents" (phase 2).

  They are visible regardless of filters. They can be collapsed, never dismissed. Collapsed, they
  keep each type and count, e.g. `⛔ Integrity FAILED (1) · ⚠ Reference unverified (2) ·
  ◐ Incomplete (14)`, so that Integrity FAILED remains explicitly identifiable.
- **Collapsible sidebar:**
  - source sections with status chips and counts;
  - disk partitions: p1 compared; squashfs unsupported; encrypted (declared) with signature and
    mapper link;
  - image-level sources;
  - unmatched sources;
  - files not used;
  - capture metadata;
  - rules;
  - integrity;
  - tool-log summary and tool versions.
- **Summary cards** for the selected source, computed before table filters:
  - Total, Unchanged, Modified, Added, Deleted, Metadata, Incomplete;
  - Expected and Partially expected, shown as annotations.

  Clicking a card applies that filter.
- **Filters:**
  - status: All · Modified · Added · Deleted · Metadata Changed · Unchanged · Incomplete;
  - toggles: Hide unchanged (**on** by default), Hide fully expected (**off** by default; never
    hides partially expected, incomplete entries or banners), Sensitive only;
  - search over path, name and hash: substring, case-insensitive, focused with `/`;
  - a **"Displaying X of Y entries"** count and a **Reset filters** action.
- **Table:**
  - columns: Priority | Status | Path | Golden Hash | Current Hash | Size | Permissions | Owner |
    Change | Expected;
  - sortable by clicking a header; the default sort is priority, then path;
  - status shown as color + icon + text;
  - truncated hashes with the full value on hover/copy;
  - **pagination**: 200 rows per page by default with a selector; only the visible page exists in
    the DOM.
- **Detail panel:**
  - Golden vs Current, every field shown with its assessment state;
  - differences highlighted;
  - *not assessed* shown with the reason and log id;
  - an xattr table with hex and the decoded capability;
  - per-difference coverage (covered by rule X / uncovered / ⚠ sensitive explicit allowance);
  - the symlink target in hex and display form;
  - `kind`.
- **Disk section:** a layout table (golden vs current) with the start, length, sector size, byte
  offset, observed signature, declared attributes with provenance, and analysis status per
  partition.
- **Image-level section:** size, signature and image hashes, with the limitation stated explicitly.

### 10.3 Phase 2 (decided, not in MVP)

- column chooser;
- font size +/−, monospace toggle and font family;
- zoom +/−, Fit to Page and Full Screen;
- vertical/horizontal layout (detail panel below or to the right);
- a responsive table that becomes cards on narrow screens;
- virtualized rendering;
- **text diffs** (opt-in `--text-diffs`):
  - applies to `kind` text or script with valid UTF-8 on both sides;
  - a per-file limit (`--text-diff-max`, default 256 KiB) and an aggregate report-content limit
    (`--text-diff-total`, default 8 MiB);
  - computed in Python with `difflib`;
  - every skipped or truncated diff states its reason;
  - a persistent "This report contains file contents" banner.

## 11. Testing

### 11.1 Fixture builder (`tests/fixtures/build.py`)

**Generation**

- Deterministic, built without root:
  - `/sbin/mke2fs -t ext4 -d <src>` with a fixed `-U` UUID, `-E hash_seed=…` and
    `E2FSPROGS_FAKE_TIME`;
  - source mtimes fixed with `os.utime`.
- `debugfs -w` is used **only on freshly generated fixture images**, for:
  - uid/gid changes;
  - `ea_set` of binary and large xattrs and of `security.capability`;
  - corruptions.
- **Determinism is verified, not assumed:** the builder runs twice and the image SHA-256s are
  compared. The tool versions and the filesystem features used (`debugfs -R features`) are
  recorded in `fixtures-metadata.json`.
- Built images are made `0444`, and their hashes are checked before and after each test.

**Content coverage**

- **Permissions and ownership:**
  - SUID, SGID and sticky;
  - an ownership change to root;
  - a mode change;
  - an mtime-only change.
- **Entry types:**
  - fast and slow symlinks: one new, one retargeted, one dangling;
  - a file becoming a symlink.
- **Content:**
  - a sparse file (holes hashed as zeros, compared against Python's logical hash);
  - an `inline_data` fixture;
  - hard links.
- **Xattrs and capabilities:**
  - binary xattrs containing NUL;
  - xattrs larger than 40 bytes in an external EA block;
  - capability added and changed (v2, and v3 with rootid).
- **Hostile names:** names containing `|`, ` -> `, a newline, non-UTF-8 bytes, and HTML/JS
  (`<img src=x onerror=alert(1)>`, `"'</script>`).

**Failure cases**

- corrupted extents (`icat` failure);
- a corrupted EA block (exercises the empty-and-exit-0 behavior of debugfs);
- a corrupted in-inode EA header;
- `needs_recovery` set.

**Partitioned disk:** an MBR written in Python with:

- p1 ext4 at **different offsets** in Golden and Current;
- p2 with `hsqs`;
- p3 with a synthetic LUKS header;
- p4 with no signature.

This validates `-o` and `image?offset=` with debugfs read-only.

**Capture directories**

- `capture.yaml` with a missing field and with a provenance conflict, expressed through
  **structured `observations`** (`device-info.txt` stays unparsed);
- `SHA256SUMS` with one mismatching entry;
- `*.received.sha256` containing `*-`;
- a `.partial` file;
- an unsigned `.bin`;
- an unmatched image;
- an incompatible pair.

### 11.2 Levels

1. **Unit tests (no TSK):**
   - parsers on recorded outputs of `fls`, `mmls`, `fsstat` and `debugfs`;
   - the diagnostics classifier;
   - the capability decoder;
   - the xattr structure parser;
   - glob semantics;
   - rule coverage (full, partial, incomplete, existence, sensitive, `xattr:security.`);
   - the comparator state matrix;
   - checksum parsing;
   - provenance and conflicts;
   - pairing;
   - JSON/HTML escaping;
   - CSP hash computation.
2. **Runner tests:** fake tools on a temporary `PATH` that time out, print unknown diagnostics, or
   produce short output. They assert that the process is killed, the worker slot is released,
   partial results are preserved, temp files are cleaned up, and file contents never reach
   `tool_log.jsonl`.
3. **Integration tests** (require sleuthkit and e2fsprogs): the full pipeline on the fixtures, with
   assertions on `comparison.json` (status, fields, completeness, priority and coverage per path),
   on the integrity verdicts and on the exit codes. They cover:
   - **Exit 0:** a fully assessed ext4 pair with valid checksums **that contains differences**.
   - **Exit 3:** incomplete and unverified runs.
   - **Exit 2:** usage errors.
   - **Integrity changing during analysis:** a test hook mutates a copy of the image between the
     pre and post hashes and expects `failed`.
   - **Post-hash after failures:** the post-analysis hash still runs after extraction failures and
     timeouts.
   - **Output protection:**
     - a non-empty directory is refused;
     - `--force` deletes only the previous run's listed outputs and preserves unrelated files;
     - OUTDIR equal to, inside, or containing a capture dir is refused, including via symlink
       aliases.
4. **Browser tests** (Playwright for Python, dev-only):
   - `report.html` is opened via `file://`;
   - **every request attempt is recorded before being blocked**, and the test asserts that there
     are **no unexpected attempts** (only the report's own `file://` URL);
   - no CSP violations or console errors;
   - hostile names are rendered as text;
   - filters, the Incomplete filter (including badged Modified/Metadata entries), Reset,
     "Displaying X of Y", pagination, the detail panel, and banners staying visible under filters.
5. **Slow tests:** about 20k files, for concurrency, progress and pagination.

### 11.3 Validation gates

- The MVP is **validated** only after the integration and browser tests have **actually run and
  passed**. Skips (missing sleuthkit or browser) are fine during development but do not count as
  validation.
- **Real-image validation** is a separate acceptance step after the MVP. Synthetic fixtures
  establish implementation behavior, not compatibility with the captured device images. Checklist:
  - whether `/etc/version` exists in any image;
  - the real log paths, to write rules;
  - the encryption format observed on p3/p5/p6;
  - the real `fls`/`debugfs` diagnostics;
  - performance on NVRAM.

## 12. Out of scope (MVP)

- Squashfs extraction (future analyzer using a read-only extractor such as `unsquashfs`).
- Parsing `device-info.txt` (only structured `observations` are used).
- Automatic firmware version detection from image files (`image-file` provenance is reserved).
- Recovery or listing of deleted entries.
- Signature validity verification.
- Byte-range diffing of image-level sources.

## 13. Environment

- Python ≥ 3.11.
- Runtime dependency: `PyYAML`.
- System tools: `sleuthkit` (≥ 4.12) and `e2fsprogs` (`debugfs`, `mke2fs` for tests). On Debian:
  `sudo apt install sleuthkit e2fsprogs`, run on the machine where the tool is developed and run.
- Dev: `pytest`, `playwright` (plus `playwright install chromium`).
