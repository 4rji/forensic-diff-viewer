# Reading the report

This guide walks through everything `report.html` shows, view by view. For installation and
command-line options, see the [README](../README.md). For a step-by-step tour with screenshots,
see the [report walkthrough](report-walkthrough.md).

The report compares a **golden** capture (the clean reference) with a **current** capture (the
device under investigation). Which is which is decided only by the order of the arguments: the
first is golden, the second is current. Every result reads from golden to current: *Added*
means present in current only, *Deleted* means present in golden only.

## What gets examined

On a typical capture set (the CM8148 layout below), almost everything is compared file by
file. Encrypted partitions are covered through their decrypted images; the only part that is
not examined at all is the squashfs root filesystem.

| Image / partition | What it is | Examined? |
|---|---|---|
| `config-active-crypt.dd` | Partition p5, **already decrypted** | ✅ File by file |
| `config-other-crypt.dd` | Partition p3, **already decrypted** | ✅ File by file |
| `nvram-crypt.dd` | Partition p6, **already decrypted** | ✅ File by file |
| `mmcblk0.dd` p1 | `/boot` (ext4) | ✅ File by file |
| `mmcblk0.dd` p2 | `rootfs-0` (ext4) | ✅ File by file |
| `mmcblk0.dd` p3, p5, p6 | The same partitions, **encrypted** | ⚪ Not needed: their decrypted content is in the three `-crypt.dd` images above |
| `mmcblk0.dd` **p4** | `rootfs-1`, **squashfs**: the running `/` | ❌ **Not examined**: neither files nor hash |
| `mtdblock0.bin` | Raw flash | 🟡 Whole-image hash only: identical or different |
| `mmcblk0boot0.bin`, `mmcblk0boot1.bin` | eMMC boot partitions | 🟡 Whole-image hash only: identical or different |

Inside `mmcblk0.dd`, the encrypted partitions show *no signature*: plain dm-crypt has no
header. Their content is still compared, because each one is also captured decrypted from
`/dev/mapper/…`. `lsblk` in `device-info.txt` shows which mapper sits on which partition.

> **Firmware note.** p4 holds the firmware that was running, and it is not compared. Compare
> its hash by hand in both images, using the start and length shown in the `mmcblk0.dd`
> section (in 512-byte sectors):
>
> ```bash
> dd if=golden/mmcblk0.dd bs=512 skip=<start> count=<length> 2>/dev/null | shasum -a 256
> dd if=current/mmcblk0.dd bs=512 skip=<start> count=<length> 2>/dev/null | shasum -a 256
> ```
>
> Equal hashes mean the running firmware is identical. If they differ, extract the squashfs
> from a copy (for example with `unsquashfs`) to see which files changed.

## Contents

- [Opening the report](#opening-the-report)
- [Top bar](#top-bar)
- [Banners](#banners)
- [Sidebar](#sidebar)
- [Overview](#overview)
- [Filesystem sections](#filesystem-sections)
- [Entry details](#entry-details)
- [Line diffs and file views](#line-diffs-and-file-views)
- [Disk sections](#disk-sections)
- [Raw image sections](#raw-image-sections)
- [Integrity](#integrity)
- [Device info](#device-info)
- [Expected-change rules](#expected-change-rules)
- [Files not used](#files-not-used)
- [Tools & run](#tools--run)
- [Other files in the output folder](#other-files-in-the-output-folder)
- [What the report does not tell you](#what-the-report-does-not-tell-you)

## Opening the report

Open `report.html` straight from disk in any browser. It needs no server and makes no network
requests. The line diff and file view pages (`diffs/`, `files/`) open from links inside it and
must stay next to it.

The output folder contains file contents and metadata from the evidence. Handle it as
evidence, and do not commit or publish it.

## Top bar

| Element | What it shows |
|---|---|
| ☰ | Shows or hides the sidebar. Hiding it gives the tables and the detail panel more width. |
| **Golden** / **Current** | The two inputs exactly as they were given on the command line. |
| Integrity badge | The overall image integrity of the run (see [Integrity](#integrity)): **Integrity verified**, **Integrity: stable, unverified**, **Integrity: not checked by this run** or **Integrity FAILED**. Hovering shows the disclaimer: *verified* is not proof of authenticity. |
| **Light / dark** | Switches the theme. The browser remembers the choice; by default the report follows the system setting. |

## Banners

Banners sit under the top bar on every view. They can be collapsed but not dismissed.

- **⛔ Integrity FAILED**: an image did not match its supplied checksum, changed during the
  analysis, could not be hashed, or had conflicting checksums.
- **? Incomplete analysis**: something could not be read or compared: an unreadable image, an
  image present on one side only, a partial file inventory, entries that were not fully
  assessed, or an internal error.

Format limits are **not** banners. Encrypted or unsupported partitions and raw flash images are
the same on every run of a device, so they are listed in the [Overview](#overview) and in their
own sections instead. With no problems, there are no banners at all.

## Sidebar

**Overview** is at the top.

**Sources** lists one entry per compared image, in name order:

- a filesystem image, with a chip **N changes** (entries that are not unchanged), or
  **incomplete**;
- a partitioned disk, with its compared partitions indented below it (`mmcblk0.dd · p1`);
- a raw image that can only be compared by hash, with a **limited** chip;
- an image present on one side only, with an **unmatched** chip.

**Case** holds the views about the run as a whole: Integrity, Device info, Expected-change
rules, Files not used, and Tools & run.

## Overview

The summary of the whole comparison. Everything on it is clickable where it makes sense.

**Headline tiles**

| Tile | Meaning | Click |
|---|---|---|
| **Changed entries** | All entries that are not unchanged, across every filesystem, and in how many filesystems they are. | Opens the first filesystem with changes. |
| **Sensitive changes** | Entries with a sensitive difference: SUID/SGID, capabilities, `security.*` xattrs, ownership changed to root, new symlinks. | Opens the first filesystem that has them, with *Sensitive only* on. |
| **Image integrity** | The integrity verdict and how many images match their checksum. | Opens [Integrity](#integrity). |
| **Analysis** | *Complete*, *Limited by format* (some parts cannot be analysed file by file) or *Incomplete* (something could not be read). | — |

**Changed entries per filesystem**: one row per filesystem section. The bar length is the
number of changed entries, on one scale for all rows, so the sections can be compared at a
glance. Next to it, the count per status (✎ Modified, ＋ Added, − Deleted, ≈ Metadata changed,
? incomplete) and ⚑ sensitive. Each of those is a link: **81 Added** opens that section's file
table already filtered to Added. Sections without changes say *no changes · N entries
compared*.

**Partitioned disks**: one tile per partition, with its size and detected signature.

- A solid tile is a partition that was compared file by file. It shows *no changes* or
  *N changes*, and a click opens it.
- A dashed tile is a partition the tool cannot open: *no signature* (often an encrypted
  partition; the absence of a signature never means "unencrypted"), *unsupported format* (for
  example squashfs) or *encrypted*. Hover it for the exact reason.

**Raw images**: images without a filesystem the tool can read (raw flash dumps such as
`mtdblock0.bin`). Only the hash of the whole image is compared: **✓ identical** or
**≠ different**, with the short hash and the size.

**Format limits**: a collapsible list of everything that was not analysed file by file, with
the reason for each.

If something could not be read or compared, an alert panel at the top of the overview lists it.

## Filesystem sections

A filesystem section compares one ext2/3/4 filesystem: a standalone image (for example a
decrypted `config-active-crypt.dd`) or a partition of a disk.

**Header**: the section name, its kind, the number of changes and, for a boot partition, a
*boot* chip with the reason (fsstat reports it was last mounted at `/boot`). Below it:

- **Incomplete**: why parts of this section were not fully assessed.
- **Warnings**: for example *Filesystem was not cleanly unmounted (needs_recovery): journal not
  replayed*. This means the capture was taken while the filesystem was mounted. Changes that
  were still only in the journal are not applied, because that would mean writing to the
  evidence, so the on-disk state can lag the live state by the last few seconds of writes.

**Filesystem facts**, one line per side: filesystem type, offset, sector size, last mount
point and time, inventory state, and `needs_recovery` when set.

**Summary cards**: counts for the whole section, computed before any filter. Clicking a
status card (Total, Unchanged, Modified, Added, Deleted, Metadata changed, Incomplete) filters
the table. *Expected*, *Partially expected* and *Sensitive changes* are annotations: they show
counts only.

**Filters**

- Status buttons: All, Modified, Added, Deleted, Metadata Changed, Unchanged, Incomplete.
- **Hide unchanged** (on by default). With it on, *Displaying 165 of 291 entries* means 126
  unchanged entries are hidden. Untick it to see every entry.
- **Hide fully expected**: hides entries whose every difference is covered by a rule. It never
  hides partially expected or incomplete entries.
- **Sensitive only**: only entries with a sensitive difference.
- **Search**: by path, name or hash. Press `/` to jump to it.
- **Reset filters** puts everything back to the defaults.

Pagination counts the rows left after filtering; the page size (25 to 1000) is remembered.

**Table columns**

| Column | Content |
|---|---|
| Priority | Review order, P1 first (see below). Sortable. |
| Status | The entry's status, plus an *incomplete* chip when a field could not be assessed. |
| Path | The full path inside the filesystem. |
| Golden Hash / Current Hash | The first 12 characters of the SHA-256 of the content; hover for the full hash. |
| Size, Permissions, Owner | Shown as `golden → current` when they differ. |
| Change | The fields that differ (`content`, `size`, `mtime`, `mode`, `xattr:…`, `existence`…). |
| Expected | *Expected* or *Partially expected* when a rule covers the differences. |
| Open | **diff ↗** or **view ↗** when the entry has a content page (see below). |

Click a row, or press Enter on it, to open its details.

**Statuses**

| Status | Meaning |
|---|---|
| **Modified** | The type, the content or the symlink target changed. |
| **Added** | Present only in current. |
| **Deleted** | Present only in golden. |
| **Metadata changed** | Same content; only metadata changed (permissions, owner, mtime, xattrs…). |
| **Unchanged** | Every field was assessed and is equal. |
| **Incomplete** | No difference among the fields that were assessed, but something could not be assessed. Never read it as unchanged. |

**Priorities**

| Priority | When |
|---|---|
| **P1 Critical** | A sensitive change (SUID/SGID, capabilities, `security.*` xattrs, owner changed to root, new symlink, type changed to symlink), or any content, existence or type change on an ELF binary, a script, a file in a boot partition, or a path a rule elevates. |
| **P2 High** | Other content, existence or type changes, and incomplete entries. |
| **P3 Medium** | Metadata-only changes. |
| **P4 Expected** | Entries fully covered by expected-change rules. |
| **P5 None** | Unchanged entries. |

A priority is a review order, not a verdict.

## Entry details

The detail panel opens **below the table**, as a full-width drawer docked at the bottom of the
window, so full SHA-256 hashes fit on one line. **⇥ Beside** moves it next to the table and
**⇩ Below** brings it back; the browser remembers the choice. ✕ closes it.

What it shows:

- the path, and chips for the status, priority, file kind (text, script, ELF…), *boot partition*
  and *Expected*;
- links to the line diff or file view, or the reason there is none;
- **Not fully assessed**: why a field could not be read, when that happened;
- the field table, golden against current, with the fields that differ highlighted:

| Field | Notes |
|---|---|
| Type | file, dir, symlink, chr, blk, fifo, socket, or *absent* on the side where the entry does not exist. |
| Mode | Octal and `rwx` form, including SUID, SGID and sticky. |
| UID / GID | Numeric owner and group. |
| Size | Human-readable and in bytes. |
| mtime | UTC time and the raw value (one-second precision). |
| Content (SHA-256) | The full hash, the detected kind and the number of bytes read. |
| Symlink target | The target, and its bytes in hex. Links are never followed. |
| Capabilities | Decoded `security.capability`, with version, rootid and the raw hex. |
| Extended attributes | Each attribute's name, size and value in hex. |
| Inode | The inode number on each side. |
| atime / ctime / crtime | Context only; never compared. |

A value that could not be read shows **not assessed: reason**, with the number of the
command in `tool_log.jsonl` that failed.

Below the table, **Path bytes (hex)** gives the exact bytes of the name, and **Differences**
lists every difference with golden and current values, a *sensitive* chip where it applies,
and its rule coverage: *expected by rule X*, *uncovered*, or a warning when a rule explicitly
allows a sensitive field.

## Line diffs and file views

Text files get a page with their content, opened in a new tab from the **Open** column or the
detail panel:

| Entry | Page |
|---|---|
| Modified text file | **diff ↗**: side-by-side line diff (`diffs/NNNN.html`), golden on the left, current on the right, changed characters highlighted, long unchanged runs collapsed. |
| Added, Deleted or Metadata changed text file | **view ↗**: the file content (`files/NNNN.html`); golden for deleted files, current otherwise. |
| Unchanged or Incomplete text file | A view only when the run used `--allfiles`. |

Every page is extracted again read-only and written only if it matches the SHA-256 recorded
during the analysis. Binary files, files over 1 MiB and anything beyond the 64 MiB total get a
reason instead of a page. `--no-text-diffs` turns all pages off. Directories and symlinks have
no page; a symlink's target is in the detail panel.

## Disk sections

For a partitioned disk image (MBR or GPT):

- the partition table type and sector size on each side, and **Layout differences** when the
  partitions moved, changed size or changed type;
- the **Partitions** table: number, analysis state, start, length, offset and signature on each
  side, and **Open comparison** for every partition that was compared file by file.

Partitions with an ext filesystem become their own filesystem sections. The others are
reported as *encrypted*, *unsupported (needs extractor)* or *unknown*, with the reason.

## Raw image sections

For images without a filesystem the tool can read (for example raw flash `.bin` dumps): the
size and detected signature on each side, the SHA-256 of each whole image, and whether they
are **identical** or **different**. This is not a file-level comparison.

## Integrity

- **Verdict per image**, golden and current: *verified*, *stable, unverified*, *not checked*
  or *FAILED — integrity not established*, with the reason, the supplied checksum and the
  hashes taken before and after the analysis.
- **Checksum manifests**: every checksum file found, which images it was used for, and how many
  lines were malformed or ignored. A per-image file with a single `-` line (as written by
  `dd … | sha256sum`) shows *stdin entry "-", matched by the file name*.

| Verdict | Meaning |
|---|---|
| verified | The image matches its supplied checksum and did not change during the analysis. |
| stable, unverified | Hashed before and after the analysis with the same result, but no checksum was supplied to compare against. |
| not checked | The run did not use `--verify-integrity`, so the images were not hashed. |
| FAILED | Mismatch, changed during the analysis, hashing error or conflicting checksums. |

*Verified* says the image is the one that was captured. It does not say the firmware is
authentic or free of compromise.

## Device info

Each side's `device-info.txt`, as captured, side by side with line numbers.

- Lines that differ are highlighted, and the changed characters are marked.
- **Only differing lines** hides the identical ones.
- Section labels (DATE, UNAME -A, /PROC/PARTITIONS, LSBLK, BLKID, OTHER OUTPUT) are recognised
  from the output format of those commands, only to make the text easier to read.
- The file's path, SHA-256 and size are shown for each side. The full files are copied to
  `supporting/golden/` and `supporting/current/`.

Nothing in `device-info.txt` is used by any check, status or verdict.

## Expected-change rules

The rules file passed with `--rules`, with its SHA-256, and every rule: id, label, sources,
path patterns, statuses, fields and how many entries it matched (*No matches* when none).
Rules only annotate: they never change a status and never hide an entry by default.

## Files not used

Everything in each capture folder that the tool did not use, with the reason: logs, `.partial`
files, `*.received.sha256`, directories and any other file.

## Tools & run

When and how the report was made: generation time, the exact command line, the mode
(directories or two image files), both inputs, the forensic_compare version, and the version
of every external tool used (`mmls`, `fsstat`, `fls`, `icat`, `debugfs`). Every external
command is recorded in `tool_log.jsonl` next to the report.

## Other files in the output folder

| File | Content |
|---|---|
| `comparison.json` | Everything the report shows, machine-readable. |
| `manifests/<source>/{golden,current}.json` | The full inventory of each side of each filesystem. |
| `supporting/{golden,current}/` | `device-info.txt` and the checksum files, copied verbatim. |
| `diffs/`, `files/` | The line diff and file view pages. |
| `tool_log.jsonl` | Every external command: arguments, exit status, diagnostics, timing and bytes. |
| `outputs.json` | The files this run wrote; `--force` removes only these. |

## What the report does not tell you

- **Whether the device is compromised.** Differences are facts. Configuration, logs and
  device-specific keys are expected to differ; deciding what a difference means is the
  analyst's job.
- **What it could not read.** *Not assessed*, *incomplete* and the format limits are gaps,
  never "unchanged".
- **Squashfs contents.** Firmware root filesystems in squashfs are not analysed, so changes to
  the running firmware's files are not covered. Compare such a partition by hash by hand.
- **The last writes of a live capture.** With `needs_recovery`, changes still in the journal
  are not included.
- **Authenticity.** *Verified* integrity only proves the image is the one that was captured.
