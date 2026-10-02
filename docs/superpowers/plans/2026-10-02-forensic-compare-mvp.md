# forensic_compare MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the phase-1 (MVP) `forensic_compare` tool: compare golden vs current capture sets at
partition/filesystem/file/metadata level and emit `comparison.json`, manifests and a standalone,
CSP-protected `report.html`.

**Architecture:**

- Pure-Python orchestration around read-only external tools: TSK (`mmls`, `fsstat`, `fls`, `icat`)
  and `debugfs`.
- Independent read-only Python parsers (`ext_inode.py`, `xattr_struct.py`) cross-validate the tools.
- Analyzers produce versioned `Manifest`s. A tool-agnostic comparator and a rules layer annotate
  them, and the report module inlines all assets and data into one HTML file.

**Tech Stack:**

- Runtime: Python ≥ 3.11 with PyYAML only; sleuthkit 4.12.1 and e2fsprogs 1.47.2.
- Dev: pytest, Playwright (Python) with Chromium.
- Report: vanilla JS + CSS.

**Spec:** `docs/superpowers/specs/2026-10-02-forensic-compare-design.md`. Section references below
use the form §N.

## Global Constraints

- Python ≥ 3.11; runtime dependency `PyYAML` only (`forensic_compare/requirements.txt`).
- Inputs are opened only with `O_RDONLY`. `debugfs` is never given `-w` except in
  `tests/fixtures/build.py` on freshly generated fixture images. Nothing is mounted.
- External commands: an argument list, never `shell=True`, with `LC_ALL=C`, each in its own process
  group, always through `tools/runner.py`.
- File contents never go into `tool_log.jsonl`, `comparison.json` or `report.html` in the MVP
  (text diffs are phase 2).
- Exit codes: `0` = complete analysis and every image `verified`; `3` = report generated but
  incomplete/limited or integrity not `verified`; `2` = usage/fatal. Differences and reference
  notices do not change the exit code.
- Statuses: `modified`, `added`, `deleted`, `metadata`, `unchanged`, `incomplete`. The incomplete
  flag is orthogonal. Expected and partially expected are annotations, not statuses.
- Integrity verdicts: `verified`, `stable-unverified`, `failed`.
- Missing metadata is never guessed. Unknown stays `null` and is displayed as "not recorded".
- All code, comments, docs and UI text are in English.
- Run from the repo root as `python forensic_compare/compare.py …` or
  `python -m forensic_compare.compare …`.
- The MVP is validated only when `pytest --strict-validation` passes, i.e. the integration and
  browser tests ran and were not skipped.

## Review Focus

1. **Very large NVRAM inventories (100k+ entries):**
   - `comparison.json` and `report.html` must still build within memory;
   - pagination must keep the DOM bounded;
   - progress must update.

   Test: Task 19 `test_slow_large_inventory` (20k files) asserts the build time, that the page DOM
   row count is ≤ the page size, and that progress lines appear.
2. **Image files that are not readable by the user (permission denied) or that vanish mid-run:**
   - expect a pair status of `incomplete — unreadable` and integrity `failed (hashing error)`,
     never a crash.

   Test: Task 11 `test_unreadable_image_failed_verdict` and Task 16
   `test_cli_unreadable_image_exit3`.
3. **Two partitions or images whose tools emit warnings without failing** (e.g. the `fsstat`
   journal-recovery note):
   - known-benign text must not mark them incomplete;
   - unknown text must.

   Test: Task 2 `test_classify_unknown_marks_incomplete` and Task 8
   `test_needs_recovery_warning_not_incomplete`.
4. **Paths that differ only by TSK's `^` rendering or contain `|`:**
   - must not merge or break rows.

   Test: Task 5 `test_parse_body_pipe_in_name` and Task 13 `test_lossy_path_flags_incomplete`.
5. **Re-running into the same output directory with `--force` after the source set changed:**
   - stale manifests from the previous run must be removed and unrelated files kept.

   Test: Task 16 `test_force_removes_only_previous_outputs`.

---

## File map

```
forensic_compare/__init__.py            package marker, __version__
forensic_compare/compare.py             CLI, output protection, orchestration, exit codes
forensic_compare/discovery.py           capture dir classification, pairing
forensic_compare/integrity.py           checksum manifests, pre/post hashing, verdicts
forensic_compare/capture_meta.py        capture.yaml, provenance, reference checks
forensic_compare/signatures.py          magic-byte detection
forensic_compare/ext_inode.py           raw ext superblock/GDT/inode reader
forensic_compare/xattr_struct.py        ext4 xattr structure parser
forensic_compare/capabilities.py        vfs_cap_data decoder
forensic_compare/manifest.py            Assessed/Entry/Manifest + JSON
forensic_compare/analyzer.py            ext-fs / disk / image-level analysis
forensic_compare/comparator.py          per-entry diff, statuses
forensic_compare/rules.py               rules, globs, coverage, priority
forensic_compare/report.py              comparison.json + report.html builder
forensic_compare/progress.py            stderr progress reporter
forensic_compare/tools/__init__.py
forensic_compare/tools/runner.py        subprocess wrapper
forensic_compare/tools/diagnostics.py   diagnostic classifier
forensic_compare/tools/tsk.py           TSK wrappers + parsers
forensic_compare/tools/debugfs.py       debugfs wrappers + parsers
forensic_compare/templates/report.html
forensic_compare/static/app.js
forensic_compare/static/style.css
forensic_compare/expected_changes.example.yaml
forensic_compare/requirements.txt
forensic_compare/README.md
requirements-dev.txt
pyproject.toml                          pytest config only (markers, testpaths)
tests/conftest.py                       markers, --strict-validation, tool discovery, fixture session
tests/fixtures/build.py                 deterministic fixture builder (CLI + importable)
tests/data/                             recorded tool outputs for unit tests
tests/test_*.py                         one test module per source module + integration/browser
```

---

### Task 0: Scaffold, test harness and the validation gate

**Files:**

- Create: `pyproject.toml`, `requirements-dev.txt`, `forensic_compare/__init__.py`,
  `forensic_compare/requirements.txt`, `forensic_compare/tools/__init__.py`, `tests/conftest.py`,
  `tests/test_harness.py`, `.gitignore`

**Interfaces:**

- Produces:
  - pytest markers `integration`, `browser`, `slow`;
  - the `--strict-validation` option;
  - the `tools_available() -> dict[str, str|None]` fixture helper;
  - the `TSK_BIN`/`DEBUGFS` resolution in conftest: env `FC_TSK_BIN_DIR` is prepended to `PATH`
    if set.

- [ ] **Step 1: Write the harness test**

```python
# tests/test_harness.py
import subprocess, sys

def test_strict_validation_turns_skips_into_failures(tmp_path):
    t = tmp_path / "test_x.py"
    t.write_text("import pytest\n@pytest.mark.integration\ndef test_a():\n    pytest.skip('no tools')\n")
    conftest = (__import__("pathlib").Path(__file__).parent / "conftest.py").read_text()
    (tmp_path / "conftest.py").write_text(conftest)
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "--strict-validation", str(t)],
                       cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode != 0
    assert "strict validation" in (r.stdout + r.stderr).lower()
```

- [ ] **Step 2: Run it and confirm it fails** (no conftest yet): `python -m pytest tests/test_harness.py -q`
- [ ] **Step 3: Implement `conftest.py`.**
  - Register the markers.
  - `pytest_addoption("--strict-validation")`.
  - `pytest_runtest_makereport` hook: when strict and `report.skipped` and the item has the
    `integration`/`browser` marker → set `report.outcome = "failed"` with
    `longrepr = "strict validation: skipped required test: <reason>"`.
  - If `FC_TSK_BIN_DIR` is set, prepend it to `PATH` (and `FC_TSK_LIB_DIR` to `LD_LIBRARY_PATH`).
- [ ] **Step 4: Create the venv and install dev deps:**
  `python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt`. Run the harness test →
  PASS.
- [ ] **Step 5: Commit** (`chore: scaffold package and test harness with strict validation gate`).

---

### Task 1: Manifest model (`manifest.py`)

**Files:** Create `forensic_compare/manifest.py`, `tests/test_manifest.py`

**Interfaces:**

- Produces:
  - `Assessed` dataclass: `state: Literal["ok","absent","n/a","error"]`, `value: Any = None`,
    `reason: str|None = None`, `log_id: int|None = None`; classmethods `ok(v)`, `absent()`, `na()`,
    `error(reason, log_id=None)`; property `assessed -> bool` (`state != "error"`).
  - `Entry` dataclass:
    - `path: str` (display), `path_hex: str`, `path_lossy: bool`, `inode: int`;
    - `type`, `mode`, `uid`, `gid`, `size`, `mtime`, `content`, `symlink`, `xattrs`, `capability`
      (all `Assessed`);
    - `times: dict`; `fs_flags: dict` (e.g. `{"fls_link_suffix": "..."}`).
  - `Manifest` dataclass: `schema`, `side`, `source_id`, `image: dict`, `filesystem: dict`,
    `inventory: dict`, `entries: list[Entry]`, `tools: dict`, `diagnostics: list`.
  - `encode_path(raw: bytes) -> tuple[str, str]` (display, hex). The display form uses
    `surrogateescape` and replaces control characters with `\xNN`.
  - `save_manifest(m, path)` / `load_manifest(path) -> Manifest`.
  - `SCHEMA = "forensic-compare/manifest/1"`.

- [ ] **Step 1: Failing tests**

```python
from forensic_compare.manifest import Assessed, Entry, Manifest, encode_path, save_manifest, load_manifest

def test_encode_path_non_utf8_and_control():
    disp, hx = encode_path(b"/bad\xff\xfename\x01")
    assert hx == b"/bad\xff\xfename\x01".hex()
    assert "\\xff" in disp and "\\x01" in disp

def test_assessed_constructors():
    assert Assessed.error("timeout").assessed is False
    assert Assessed.absent().assessed is True

def test_manifest_roundtrip(tmp_path):
    e = Entry.blank("/a", b"/a".hex(), 12)
    e.type = Assessed.ok("file"); e.mode = Assessed.ok(0o4755)
    m = Manifest.new(side="golden", source_id="x.dd")
    m.entries.append(e)
    save_manifest(m, tmp_path / "m.json")
    m2 = load_manifest(tmp_path / "m.json")
    assert m2.entries[0].mode.value == 0o4755 and m2.schema == "forensic-compare/manifest/1"
```

- [ ] **Step 2: Run** `pytest tests/test_manifest.py -q` → FAIL (import error)
- [ ] **Step 3: Implement** the dataclasses with `to_dict`/`from_dict`. `Entry.blank()` sets every
  `Assessed` field to `error("not extracted")` so that forgetting to fill a field is conservative.
- [ ] **Step 4: Run** → PASS
- [ ] **Step 5: Commit** (`feat: manifest model with per-field assessment states`)

---

### Task 2: Diagnostics classifier and tool runner

**Files:** Create `forensic_compare/tools/diagnostics.py`, `forensic_compare/tools/runner.py`,
`tests/test_runner.py`, `tests/test_diagnostics.py`

**Interfaces:**

- Produces (`diagnostics.py`):
  - `classify(tool: str, line: str) -> Literal["banner","info","error","unknown"]`;
  - `PATTERNS: dict[str, list[tuple[str, regex]]]`;
  - `is_problem(kind) -> bool` (true for `error`/`unknown`).
- Produces (`runner.py`):
  - `class ToolRunner(log_path: Path, timeout: float, jobs: int)` with:
    - `run(argv, *, tool: str, timeout=None) -> RunResult` (capture mode);
    - `stream(argv, consumer: Callable[[bytes], None], *, tool, timeout=None) -> RunResult`;
    - `version(tool) -> str|None` (lazily runs `<tool> -V` once; recorded only if the tool was used);
    - `.versions: dict`;
    - `.semaphore` (`threading.BoundedSemaphore(jobs)`).
  - `RunResult` dataclass: `log_id`, `argv`, `exit_code: int|None`, `timed_out: bool`,
    `stdout: bytes` (empty in stream mode), `diagnostics: list[dict(line, kind)]`, `duration_s`,
    `bytes_out: int`; property `problems -> list` (the error/unknown diagnostics); property
    `ok -> bool` (`exit_code == 0 and not timed_out and not problems`).
- Logging: one JSON line per call:
  `{id, tool, argv, exit_code, timed_out, duration_s, stdout_bytes, bytes_extracted, diagnostics}`.

- [ ] **Step 1: Failing tests.** Fake tools are written into `tmp_path/bin` and put on `PATH`.

```python
def test_classify_debugfs_banner():
    assert classify("debugfs", "debugfs 1.47.2 (1-Jan-2025)") == "banner"
def test_classify_unknown_marks_incomplete():
    assert classify("fsstat", "Something odd happened") == "unknown"
def test_stream_does_not_log_content(fake_tool, tmp_path):
    # fake tool prints b"SECRET"*1000 to stdout
    chunks = []
    r = runner.stream([fake_tool("cat_secret")], chunks.append, tool="icat")
    assert b"".join(chunks) == b"SECRET"*1000 and r.bytes_out == 6000
    assert b"SECRET" not in (tmp_path/"tool_log.jsonl").read_bytes()
def test_timeout_kills_group_and_releases_slot(fake_tool):
    # fake tool: sleeps 30s, spawns child sleeping 30s
    r = runner.run([fake_tool("sleeper")], tool="x", timeout=0.5)
    assert r.timed_out and r.exit_code is None
    assert runner.semaphore.acquire(blocking=False)  # slot released
    # assert child pid (written to a file by the fake tool) is gone
def test_partial_stream_preserved_on_timeout(fake_tool):
    # fake tool writes 10 bytes then sleeps
    ...; assert r.timed_out and r.bytes_out == 10
def test_unknown_stderr_is_problem(fake_tool):
    r = runner.run([fake_tool("weird_stderr")], tool="fls")
    assert r.exit_code == 0 and r.problems and not r.ok
```

- [ ] **Step 2: Run** → FAIL
- [ ] **Step 3: Implement.**
  - Use `Popen(start_new_session=True, env={**os.environ, "LC_ALL": "C"})`.
  - A stderr reader thread collects lines. In stream mode the stdout is read in 1 MiB chunks into
    the consumer.
  - On timeout: `os.killpg(SIGTERM)`, wait 2 s, then `SIGKILL`.
  - The semaphore is acquired and released in `try/finally` around each call.
  - `diagnostics.PATTERNS`:
    - `debugfs`: banner `^debugfs \d+\.\d+(\.\d+)? \(.*\)$`; errors `^\S+: .* while `,
      `File not found by ext2_lookup`, `Extended attribute .* bad header`;
    - `fsstat`: info lines are none for now;
    - `icat`/`fls`/`mmls`: errors `^Metadata address too large`, `^Error`, `^Invalid`.

    Everything else is `unknown`.
- [ ] **Step 4: Run** → PASS
- [ ] **Step 5: Commit** (`feat: tool runner with streaming, timeouts, diagnostics classification`)

---

### Task 3: Signatures and capabilities

**Files:** Create `forensic_compare/signatures.py`, `forensic_compare/capabilities.py`,
`tests/test_signatures.py`, `tests/test_capabilities.py`

**Interfaces:**

- `detect_signature(path: Path, offset: int = 0) -> list[str]` returns tags from `ext`, `luks1`,
  `luks2`, `squashfs`, `ubi`, `jffs2`, `uimage`, `fdt`, `mbr`, `gpt`. Empty means "none recognized".
  It reads with `os.open(O_RDONLY)` + `os.pread`.
- `decode_capability(raw: bytes) -> dict` →
  `{"version": 2, "effective": bool, "permitted": [names], "inheritable": [names], "rootid": int|None, "text": "cap_net_raw+ep"}`.
  Raises `ValueError` on malformed input (the caller turns it into `Assessed.error`).

- [ ] **Step 1: Failing tests**

```python
def test_luks2_and_ext(tmp_path):
    p = tmp_path/"x"; b = bytearray(4096); b[0:6]=b"LUKS\xba\xbe"; b[6:8]=b"\x00\x02"; p.write_bytes(b)
    assert "luks2" in detect_signature(p)
    b = bytearray(4096); b[1080:1082]=b"\x53\xef"; p.write_bytes(b)
    assert detect_signature(p) == ["ext"]
def test_offset_detection(tmp_path):
    p = tmp_path/"x"; b = bytearray(8192); b[4096:4100]=b"hsqs"; p.write_bytes(b)
    assert detect_signature(p, 4096) == ["squashfs"]
def test_cap_v2_net_raw():
    raw = bytes.fromhex("01000002" "00200000" "00000000" "00000000" "00000000")
    assert decode_capability(raw)["text"] == "cap_net_raw+ep"
def test_cap_v3_rootid():
    raw = bytes.fromhex("00000003" "00100000" "00000000" "00000000" "00000000" "e8030000")
    d = decode_capability(raw); assert d["rootid"] == 1000 and d["text"] == "cap_net_bind_service+p"
def test_cap_malformed():
    with pytest.raises(ValueError): decode_capability(b"\x01\x02")
```

- [ ] **Steps 2–4:** run → FAIL. Implement. Capability names come from a 0–40 name table
  (`cap_chown`…`cap_checkpoint_restore`), with unknown bits shown as `cap_<n>`. The magic is
  `0x01000000|0x02000000|0x03000000`, and the effective flag is `0x000001`. Run → PASS.
- [ ] **Step 5: Commit** (`feat: magic signature detection and vfs_cap_data decoder`)

---

### Task 4: Fixture builder (synthetic ext4, disks, capture dirs)

**Files:** Create `tests/fixtures/build.py`, `tests/test_fixtures.py`; modify `tests/conftest.py`
(session fixture `fixtures_dir`)

**Interfaces:**

- `build_all(out: Path) -> dict` writes:
  - `ext/golden.img`, `ext/current.img`;
  - `ext/corrupt_eablock.img`, `ext/corrupt_inode_ea.img`, `ext/corrupt_extent.img`,
    `ext/recovery.img`;
  - `disk/golden.dd`, `disk/current.dd`;
  - `captures/golden/…`, `captures/current/…` (§11.1);
  - `fixtures-metadata.json` with `mke2fs`/`debugfs` versions, `features` and per-image sha256.
- `expected.py`, a dict of `path → expected status/fields`, is used by the integration tests.
- CLI: `python tests/fixtures/build.py OUT`.

**Content (golden → current):**

| path | golden | current | expect |
|---|---|---|---|
| `etc/unchanged.conf` | "a" | "a" | unchanged |
| `etc/modified.conf` | "a" | "b" | modified |
| `etc/deleted.conf` | x | — | deleted |
| `etc/added.conf` | — | x | added |
| `bin/tool` | ELF magic, 0755 | same content, 4755 | metadata, sensitive suid, prio 1 |
| `bin/sgid` | 0755 | 2755 | metadata, sensitive sgid |
| `etc/owner` | uid 1000 | uid 0 | metadata, sensitive uid→0 |
| `etc/mtime_only` | mtime T | mtime T+60 | metadata |
| `etc/mode` | 0644 | 0600 | metadata (mode) |
| `bin/capped` | no cap | cap v2 `cap_net_raw+ep` | metadata, sensitive capability |
| `bin/capchg` | cap v2 net_raw | cap v3 net_bind rootid 1000 | metadata, sensitive |
| `etc/xattr_bin` | `user.bin` = 60 bytes with NUL | same | unchanged (xattrs ok) |
| `etc/xattr_big` | `user.big` = 300 B ('A') | 300 B ('B') | metadata xattr:user.big |
| `etc/sec_xattr` | none | `security.foo` | metadata, sensitive |
| `link_fast` | → `etc/unchanged.conf` | same | unchanged (fast symlink target read via raw inode) |
| `link_retarget` | → `a` | → `b` | modified symlink_target |
| `link_slow` | → `"x"*100` | same | unchanged |
| `link_new` | — | → `etc` | added, sensitive (new symlink) |
| `link_dangling` | → `nowhere` | same | unchanged |
| `file2link` | file | symlink | modified (type) |
| `sparse.bin` | 1 MiB with 1 byte at 500000 | same | unchanged; sha = python logical hash |
| `hard_a`, `hard_b` | same inode | same | unchanged ×2 |
| `pi\|pe` | "a" | "a" | unchanged |
| `new\nline` | "a" | "b" | modified + lossy flag (incomplete) |
| `bad\xff\xfename` | "a" | "a" | unchanged, path_hex preserved |
| `<img src=x onerror=alert(1)>` | "a" | "b" | modified (browser escaping test) |
| `"'</script>` | "a" | "a" | unchanged |
| `etc/sticky_dir/` | 1777 | 0777 | metadata (mode) |

- **Corruption fixtures** (copies of current):
  - `corrupt_eablock` zeroes the magic of `etc/xattr_big`'s EA block;
  - `corrupt_inode_ea` zeroes the in-inode EA magic of `etc/xattr_bin`;
  - `corrupt_extent` zeroes the extent header magic (`i_block[0:2]`) of `etc/modified.conf`;
  - `recovery` sets the superblock incompat `0x4` (`needs_recovery`).

  For checksum-enabled filesystems the builder uses `-O ^metadata_csum`, so that raw edits do not
  trip checksum verification in unrelated tools and the tests stay targeted.
- **Disk:**
  - an MBR with p1 = the golden ext image at sector 2048 (golden) / 4096 (current);
  - p2 starting with `hsqs`;
  - p3 starting with a synthetic LUKS2 header (`LUKS\xba\xbe\x00\x02`);
  - p4 zeros.
- **Captures** (golden and current):
  - images `config-active-crypt.dd` (ext pair), `nvram-crypt.dd` (smaller ext pair),
    `mtdblock0.bin` (random bytes, identical on both sides), `mmcblk0.dd` (the disk pair),
    `only-golden.dd` (unmatched), and `incompat.dd` (ext in golden, squashfs magic in current);
  - `SHA256SUMS` (correct for all images, except a deliberately wrong entry for `nvram-crypt.dd`
    in current);
  - `config-active-crypt.dd.received.sha256` containing `<hash> *-`;
  - `nvram-crypt.dd.partial`;
  - `capture.yaml` (golden: model + firmware.active; current: the same model plus an observation
    conflicting on `firmware.active`, with `firmware.inactive` null);
  - `device-info.txt` (free text, unparsed).
- A second capture set, `captures_clean/`, holds one ext pair with valid checksums and complete
  metadata → exit 0 despite differences.

- [ ] **Step 1: Failing test**

```python
def test_builder_is_deterministic(tmp_path):
    a = build_all(tmp_path/"a"); b = build_all(tmp_path/"b")
    assert a["sha256"] == b["sha256"]  # every image identical across builds
    meta = json.loads((tmp_path/"a"/"fixtures-metadata.json").read_text())
    assert meta["tools"]["mke2fs"].startswith("mke2fs 1.") and "ext_attr" in meta["features"]["golden.img"]
```

- [ ] **Step 2: Run** → FAIL
- [ ] **Step 3: Implement.**
  - Use `/sbin/mke2fs -q -t ext4 -b 1024 -I 256 -O ^metadata_csum,inline_data?` (one separate
    inline_data fixture: `ext/inline.img`).
  - Pass `-U <fixed> -E hash_seed=<fixed>,root_owner=0:0 -d src img 4M` with
    `E2FSPROGS_FAKE_TIME=1700000000` and `os.utime(…, (T, T))` on every source path
    (`follow_symlinks=False`).
  - Post-process with `debugfs -w -f cmds`: `sif <path> uid 0`, `ea_set -f file <path> name`,
    `ea_rm`.
  - Apply corruptions by locating inodes/EA blocks with `ext_inode.py`. If Task 5 is not available
    yet, write the corruption step after Task 5 and keep this step to clean images.
  - Run `chmod 0444` on outputs.
- [ ] **Step 4: Run** → PASS (determinism verified). If timestamps leak (dirs, lost+found), fix by
  setting `E2FSPROGS_FAKE_TIME` and utime on directories bottom-up.
- [ ] **Step 5: Commit** (`test: deterministic synthetic fixture builder`)

---

### Task 5: Raw inode reader and xattr structure parser

**Files:** Create `forensic_compare/ext_inode.py`, `forensic_compare/xattr_struct.py`,
`tests/test_ext_inode.py`, `tests/test_xattr_struct.py`; modify `tests/fixtures/build.py` (add the
corruption fixtures)

**Interfaces:**

- `class ExtFS(path: Path, offset: int = 0)`, a read-only context manager:
  - `.block_size`, `.inode_size`, `.inodes_per_group`, `.desc_size`, `.feature_incompat`, …;
  - `.needs_recovery: bool`;
  - `read_inode(ino: int) -> RawInode`;
  - `read_block(blk: int) -> bytes`.

  Raises `ExtFSError` on a bad magic or out-of-range values.
- `RawInode` dataclass: `ino`, `raw: bytes`, `mode`, `flags`, `size`, `i_block: bytes` (60),
  `file_acl: int`, `extra_isize: int`; property `is_fast_symlink`.
- `fast_symlink_target(inode: RawInode) -> bytes` raises `ValueError` if the inode is not a fast
  symlink.
- `parse_xattrs(fs: ExtFS, inode: RawInode) -> XattrStructure` with fields `state`
  (`"absent"|"present"|"error"`), `entries: list[XattrEntry(name: bytes, size: int, inum: int, location: "inode"|"block")]`
  and `reason`.
  - Name prefixes by index: 1 `user.`, 2 `system.posix_acl_access`, 3
    `system.posix_acl_default`, 4 `trusted.`, 6 `security.`, 7 `system.`, 8 `system.richacl`.
    An unknown index → `error`.

- [ ] **Step 1: Failing tests** (built on fixtures, using only mke2fs/debugfs)

```python
def test_reads_fast_symlink_target(fixtures_dir):
    with ExtFS(fixtures_dir/"ext/golden.img") as fs:
        ino = lookup_inode_via_debugfs(fixtures_dir/"ext/golden.img", "/link_fast")
        assert fast_symlink_target(fs.read_inode(ino)) == b"etc/unchanged.conf"
def test_xattr_absent_vs_present(fixtures_dir): ...  # etc/unchanged.conf absent; etc/xattr_big present, 300 bytes in block
def test_corrupt_block_is_error(fixtures_dir):
    with ExtFS(fixtures_dir/"ext/corrupt_eablock.img") as fs:
        s = parse_xattrs(fs, fs.read_inode(ino_of("etc/xattr_big")))
        assert s.state == "error" and "magic" in s.reason
def test_offset_reading(fixtures_dir):  # disk/current.dd at 4096*512 reads same root inode as ext/golden.img
def test_needs_recovery_flag(fixtures_dir): assert ExtFS(fixtures_dir/"ext/recovery.img").needs_recovery
```

- [ ] **Steps 2–4:** run → FAIL; implement; run → PASS.
  - Superblock at `offset+1024`: `s_inodes_count`@0, `s_log_block_size`@24, `s_inodes_per_group`@40,
    `s_magic`@56, `s_inode_size`@88, `s_feature_incompat`@96, `s_desc_size`@254 (used if the
    `64bit` incompat bit `0x80` is set).
  - The GDT starts at block `first_data_block + 1`. `bg_inode_table` is lo@8 plus hi@40 when 64-bit.
  - Inode fields: mode@0, size_lo@4, flags@32, i_block@40 (60 B), file_acl_lo@104,
    size_high@108, file_acl_high@118 (u16), extra_isize@128.
  - In-inode EA: magic u32 at `128+extra_isize`, entries follow, values offset from the first
    entry.
  - EA block: header magic@0 (`0xEA020000`); entries start at 32.
  - Entry: name_len u8, name_index u8, value_offs u16, value_inum u32, value_size u32, hash u32,
    name, padded to 4 bytes; the list ends at 4 zero bytes.
  - Bounds-check everything: any out-of-range value → `error`.
- [ ] **Step 5: Commit** (`feat: independent raw ext inode and xattr structure readers`)

---

### Task 6: TSK wrappers and parsers

**Files:** Create `forensic_compare/tools/tsk.py`, `tests/test_tsk.py`, and
`tests/data/fls_body_*.txt`, `mmls_*.txt`, `fsstat_*.txt` (recorded from the probes in this
session)

**Interfaces:**

- `parse_mode_string(s: str) -> tuple[str, int]`: `"r/rrwsr-xr-x"` → `("file", 0o4755)`. Types:
  `r→file d→dir l→symlink c→chr b→blk p→fifo s→socket h→shadow(unknown) V→virtual`.
- `parse_body_line(line: bytes) -> BodyRow` with fields `name: bytes`, `inode: int`, `type`,
  `mode`, `uid`, `gid`, `size`, `atime`, `mtime`, `ctime`, `crtime`, `link_suffix: bytes|None`.
  Raises `ValueError`. The name is obtained with `line.split(b"|", 1)[1].rsplit(b"|", 9)`.
- `fls_inventory(runner, image, offset_sectors=None, sector_size=512) -> tuple[list[BodyRow], RunResult, int]`.
  The int is the count of virtual entries excluded.
- `mmls_layout(runner, image) -> Layout|None` with fields `sector_size`, `table_type`,
  `partitions: list[Partition(number, slot, start, length, description)]`. Returns `None` when
  `mmls` exits non-zero with no table.
- `fsstat_info(runner, image, offset_sectors) -> FsInfo(fs_type, last_mounted: str|None, features: list[str], raw_ok: bool)`
- `icat_stream(runner, image, inode, consumer, offset_sectors) -> RunResult`

- [ ] **Step 1: Failing tests**

```python
def test_parse_body_pipe_in_name():
    r = parse_body_line(b"0|/pi|pe|16|r/rrw-rw-r--|1000|1000|2|1|2|3|4")
    assert r.name == b"/pi|pe" and r.inode == 16 and r.mode == 0o664
def test_parse_body_symlink_suffix():
    r = parse_body_line(b"0|/link -> ../etc/a.txt|17|l/lrwxrwxrwx|0|0|12|1|2|3|4")
    assert r.type == "symlink" and r.name == b"/link -> ../etc/a.txt"  # suffix resolved later, not trusted
def test_mode_sticky_sgid():
    assert parse_mode_string("d/drwxrwxrwt") == ("dir", 0o1777)
    assert parse_mode_string("r/rrwxr-sr-x") == ("file", 0o2755)
    assert parse_mode_string("r/rrwSr--r--") == ("file", 0o4644)
def test_mmls_dos(): # tests/data/mmls_dos.txt → 2 partitions, p1 start 2048 length 16384, sector 512
def test_fsstat_last_mounted_empty(): # "Last Mounted at: empty" → None
def test_bad_line_raises():
    with pytest.raises(ValueError): parse_body_line(b"garbage")
```

- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Integration check** (marker `integration`): `fls_inventory` on `ext/golden.img`
  returns `/pi|pe` and `$OrphanFiles` is excluded (virtual count 1).
- [ ] **Step 6: Commit** (`feat: TSK wrappers and robust body/mmls/fsstat parsers`)

---

### Task 7: debugfs xattr extraction

**Files:** Create `forensic_compare/tools/debugfs.py`, `tests/test_debugfs.py`,
`tests/data/debugfs_*.txt`

**Interfaces:**

- `parse_ea_list(out: str) -> list[tuple[str, int]]`: lines `  <name> (<size>)[ = …]` under
  `Extended attributes:`. Parsing uses the regex `^  (.+?) \((\d+)\)(?: = .*)?$`.
- `split_batch(stdout: str) -> list[tuple[str, str]]`: splits on lines starting with
  `debugfs: `, returning `(command, output)`.
- `class XattrExtractor(runner, image, offset_bytes, fs: ExtFS)`:
  `extract(inodes: list[int], progress=None) -> dict[int, Assessed]`, where each value is
  `{name: {"hex", "size"}}`, `absent` or `error`.
  1. Batch `ea_list <ino>` (500 per batch) with
     `runner.run(["debugfs", "-f", cmdfile, f"{image}?offset={off}"])`.
  2. If a batch has `problems` or a parse anomaly → re-run each inode alone.
  3. For each inode, compare with `parse_xattrs(fs, fs.read_inode(ino))`:
     - both empty → `absent`;
     - names and sizes equal → fetch values;
     - otherwise → `error("xattr enumeration mismatch: debugfs=… structure=…")`.
  4. Values: `ea_get -f <tmpdir>/<n> <ino> <name>` (batched per inode). Accept a value only if the
     file length equals the size and there are no problems for that command; otherwise `error`.
  5. The tmpdir is created with `tempfile.mkdtemp()` (mode 0700), files are `os.chmod 0600` before
     reading, and `shutil.rmtree` runs in `finally`.
- `security.capability` is not handled here (the analyzer decodes it).

- [ ] **Step 1: Failing tests**
  - Unit: `parse_ea_list` on the recorded output; `split_batch` with an error line between echoes.
  - Integration:
    - `etc/xattr_big` → `ok`, size 300, and the hex decodes to `b"A"*300`;
    - `etc/xattr_bin` → NUL bytes preserved;
    - `corrupt_eablock` → `error` (even though debugfs prints nothing with exit 0);
    - `corrupt_inode_ea` → `error`;
    - `etc/unchanged.conf` → `absent`;
    - disk p1 via `?offset=` matches the standalone result;
    - after any run, no temp dir remains (assert the `tempfile.gettempdir()` listing difference
      is empty for `fcx-*`).
- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: debugfs xattr extraction validated against raw structures`)

---

### Task 8: ext filesystem analyzer + progress

**Files:** Create `forensic_compare/analyzer.py` (the ext part), `forensic_compare/progress.py`,
`tests/test_analyzer_ext.py`

**Interfaces:**

- `class Progress(label: str, quiet: bool, stream=sys.stderr)` with
  `update(done_files, total_files, done_bytes, total_bytes)` and `finish()`.
  - On a TTY it rewrites one line with `\r`; otherwise it prints at most every 2 s.
- `analyze_ext(runner, image: Path, *, side, source_id, offset_bytes=0, sector_size=512, jobs, quiet) -> Manifest`.
  It never raises for a tool failure; it records `error` states instead.
- Algorithm:
  1. Get `fsstat` info and open `ExtFS`. Record `needs_recovery` and the `fsstat` warnings into
     `manifest.diagnostics` and `manifest.filesystem`.
  2. Build the inventory with `fls_inventory`. The inventory `state` is `partial` if the run
     result is not `ok` or any line failed to parse.
  3. For each row, fill:
     - `type`, `mode`, `uid`, `gid`, `size` and `mtime` from the body;
     - `path_lossy = b"^" in name`;
     - duplicates → mark both entries `fs_flags["ambiguous"]=True`.
  4. Regular files go through a thread pool (`jobs`):
     - `icat_stream` with a consumer that hashes and sniffs `kind`;
     - hard links are cached by inode;
     - `bytes_read != size` → `error`.
  5. Symlinks:
     - fast → `ext_inode`; slow → `icat`;
     - then validate against the `fls` suffix: the name must end with
       `b" -> " + tsk_render(target)`, where `tsk_render` replaces bytes < 0x20 with `^`;
     - the path is the name with the suffix stripped;
     - a mismatch → `symlink=error`, and the path keeps the raw name with `path_lossy=True`.
  6. Xattrs via `XattrExtractor` for all inodes:
     - `security.capability` is moved into `capability` via `decode_capability`;
     - absent xattrs → `capability=absent`;
     - an xattrs `error` → `capability=error`.
  7. `content`/`symlink` are `n/a` where they do not apply.

- [ ] **Step 1: Failing tests** (integration)

```python
def test_sparse_hash_matches_logical(an_golden):  # manifest of ext/golden.img
    e = by_path(an_golden, "/sparse.bin")
    assert e.content.value["sha256"] == hashlib.sha256(expected_sparse_bytes()).hexdigest()
def test_fast_symlink_target_not_nul(an_golden):
    assert bytes.fromhex(by_path(an_golden, "/link_fast").symlink.value["target_hex"]) == b"etc/unchanged.conf"
def test_capability_decoded(an_current): assert by_path(an_current, "/bin/capped").capability.value["text"] == "cap_net_raw+ep"
def test_corrupt_extent_not_assessed(tmp_runner, fixtures_dir):
    m = analyze_ext(..., fixtures_dir/"ext/corrupt_extent.img", ...)
    e = by_path(m, "/etc/modified.conf"); assert e.content.state == "error"
def test_needs_recovery_warning_not_incomplete(...):
    m = analyze_ext(... recovery.img ...); assert m.filesystem["needs_recovery"] is True and m.inventory["state"] == "complete"
def test_icat_timeout_marks_entry(...):  # runner timeout=0.0001 for icat via a fake icat → content error "timeout"; other fields still ok
def test_progress_lines_non_tty(capsys): ...
```

- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: ext filesystem analyzer with streamed hashing and validated symlinks/xattrs`)

---

### Task 9: Disk and image-level analysis, kind detection

**Files:** Modify `forensic_compare/analyzer.py`; create `tests/test_analyzer_disk.py`

**Interfaces:**

- `detect_kind(runner, image) -> KindInfo(kind: "ext-fs"|"disk"|"image-level"|"unreadable", signatures: list[str], layout: Layout|None, reason: str|None)`
- `analyze_source(runner, image, *, side, source_id, jobs, quiet) -> SourceAnalysis` with:
  - `kind`;
  - `manifest: Manifest|None` (for `ext-fs`);
  - `partitions: list[PartitionAnalysis(number, slot, start, length, sector_size, offset_bytes, signatures, status, manifest: Manifest|None, reason)]`
    for `disk`;
  - `image_size`;
  - `diagnostics`.
- Partition `status` is one of:
  - `compared` (ext);
  - `encrypted` (LUKS signature);
  - `unsupported` (squashfs/ubi/jffs2: "needs extractor");
  - `unknown` (none recognized);
  - `unreadable`.

- [ ] **Step 1: Failing tests**
  - disk/golden.dd → 4 partitions:
    - p1 `compared` with offset 2048×512 (golden) and 4096×512 (current);
    - p2 `unsupported`;
    - p3 `encrypted`;
    - p4 `unknown`.
  - mtdblock0.bin → `image-level`.
  - A permission-denied file → `unreadable`.
- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: disk layout and image-level source analysis`)

---

### Task 10: Discovery and pairing

**Files:** Create `forensic_compare/discovery.py`, `tests/test_discovery.py`

**Interfaces:**

- `classify_dir(d: Path) -> DirListing(images: dict[str, Path], checksum_files: list[Path], supporting: dict[str, Path], not_used: list[tuple[str, str]])`
  - `not_used` holds `(name, reason)` pairs.
- `pair_inputs(golden: Path, current: Path) -> Pairing(mode: "dir"|"single", pairs: list[Pair(source_id, golden: Path, current: Path)], unmatched: list[Unmatched(side, name, path)], golden_listing, current_listing)`
  - Single mode: `source_id = name` if the names are equal, else `f"{g}__vs__{c}"`. The listings
    are of the parent directories, restricted to that image.

- [ ] **Step 1: Failing tests**
  - Exact-name pairing; `config-active` is never paired with `config-other`.
  - `.partial`, `*.received.sha256`, logs and `capture.yaml` are classified correctly.
  - An unmatched image appears in `unmatched`, never in `pairs`.
  - Single mode with different names.
  - Symlinked images are included and recorded with their realpath.
- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: capture directory discovery and exact-name pairing`)

---

### Task 11: Integrity

**Files:** Create `forensic_compare/integrity.py`, `tests/test_integrity.py`

**Interfaces:**

- `parse_checksum_file(p: Path) -> tuple[dict[str, str], list[str]]` returns `(entries, malformed)`.
  Entries named `-` are skipped.
- `class IntegrityTracker(images: dict[str, Path], checksum_files: list[Path], progress)`, where
  `images` is keyed by `"golden:<name>"` / `"current:<name>"`:
  - `hash_pre()`;
  - `hash_post()`;
  - `verdicts() -> dict[key, Verdict(status, reason, expected, pre, post)]`;
  - `overall() -> "verified"|"stable-unverified"|"failed"`.
- `sha256_file(path) -> str` reads 4 MiB chunks via `os.open(O_RDONLY)`.

- [ ] **Step 1: Failing tests**
  - A matching checksum → `verified`.
  - No checksum → `stable-unverified`.
  - A wrong checksum → `failed` (reason "mismatch").
  - A file mutated between `hash_pre` and `hash_post` → `failed` ("changed during analysis").
  - `test_unreadable_image_failed_verdict` (chmod 000) → `failed` ("hashing error").
  - Conflicting checksum files → `failed`.
  - The `*-` stdin line is ignored.
  - `overall()` is `failed` if any image failed.
- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: image integrity tracking with pre/post hashing and verdicts`)

---

### Task 12: Capture metadata and reference checks

**Files:** Create `forensic_compare/capture_meta.py`, `tests/test_capture_meta.py`

**Interfaces:**

- `load_capture(listing: DirListing) -> CaptureMeta` with:
  - `fields: dict[str, list[Valued(value, provenance, detail)]]`, keyed by dotted field names
    (`device_model`, `firmware.active`, `firmware.inactive`, `sources.<img>.firmware`,
    `sources.<img>.role`, `partitions.<img>.<n>.role` / `.encrypted` / `.mapper_image`);
  - `errors: list[str]` (YAML errors are recorded, not raised);
  - `supporting: list[{name, sha256}]`.
- `CaptureMeta.get(field) -> Resolved(value|None, state: "recorded"|"not-recorded"|"conflict", values)`
- `reference_check(source_id, role, golden: CaptureMeta, current: CaptureMeta) -> RefCheck(status: "ok"|"mismatch"|"unverified", items: list[{field, golden, current, state}], context: list)`
  - Implements the §6.3 table, with `analyst-role` provenance for derived source firmware.

- [ ] **Step 1: Failing tests**
  - The `inactive` null field → not-recorded → `config-inactive` is unverified.
  - A model difference → mismatch.
  - An observation conflicting with the analyst value → conflict → unverified.
  - NVRAM shows `firmware.active` as context only.
  - `device-info.txt` content is never parsed (assert that `fields` has no key from it even when it
    contains `firmware.active=…`).
- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: capture metadata with provenance, conflicts and reference checks`)

---

### Task 13: Comparator

**Files:** Create `forensic_compare/comparator.py`, `tests/test_comparator.py`

**Interfaces:**

- `compare_manifests(g: Manifest, c: Manifest, *, boot_role: bool=False) -> list[CompEntry]`
- `CompEntry` dataclass:
  - `path`, `path_hex`, `status`, `incomplete: bool`;
  - `incomplete_reasons: list[str]`;
  - `diffs: list[Diff(field, golden, current, assessed: bool, sensitive: bool, covered_by: str|None=None)]`;
  - `golden: dict|None`, `current: dict|None` (the entry dicts);
  - `kind: str|None`, `boot: bool`;
  - `priority: int|None` (set by rules), `expectation: "none"|"partial"|"full"` (set by rules).
- Matching key: `path_hex`.
- Statuses and sensitivity exactly as §8.1–8.2. The inventory `state` and the `ambiguous`/
  `path_lossy` flags drive existence assessment and incompleteness.
- `summarize(entries) -> dict` counts per status plus `incomplete_any`.

- [ ] **Step 1: Failing tests:** a table-driven state matrix over synthetic `Entry` pairs:
  - content diff → modified;
  - only mode → metadata;
  - mode + xattr error → metadata + incomplete;
  - all ok, xattr error → incomplete status;
  - content error and size differs → modified;
  - type change → modified;
  - added when golden complete → added + `existence` diff;
  - added when golden partial → incomplete "existence not assessed";
  - ambiguous → incomplete;
  - `test_lossy_path_flags_incomplete`;
  - uid 1000 → 0 is sensitive; uid 0 → 1000 is not;
  - an added symlink has a sensitive `existence`;
  - suid/sgid split out of mode (a 0o4755 vs 0o0755 diff yields only `suid`, no `mode` diff);
  - `security.capability` only appears as `capability`;
  - a `security.foo` change is sensitive.
- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: comparator with statuses, per-field diffs and completeness`)

---

### Task 14: Rules, coverage and priority

**Files:** Create `forensic_compare/rules.py`, `forensic_compare/expected_changes.example.yaml`,
`tests/test_rules.py`

**Interfaces:**

- `glob_match(pattern: str, path: str) -> bool` implements the §9.1 semantics (compiled to a regex;
  the path has its leading `/` stripped).
- `load_rules(path|None) -> RuleSet(rules, elevate, sha256, errors)`. A schema error is fatal:
  exit 2 with the message.
- `field_covered(token: str, field: str) -> bool` honors the `security.` and explicit-sensitive
  constraints.
- `apply_rules(source_id, entries: list[CompEntry], ruleset) -> None`:
  - sets `covered_by` per diff, `expectation`, `priority`;
  - records `ruleset.matches[id] += 1`.
- `priority_for(entry) -> int` follows the §9.3 table.

- [ ] **Step 1: Failing tests**
  - `**` crosses directories; `*` does not; matching is case-sensitive; there is no leading `/`.
  - `content` + `size` + `mtime` without `existence` does not cover an added entry.
  - A rule covering content but not mode → `partial`, with priority taken from mode (3) or from
    suid (1).
  - All covered + incomplete → `partial`.
  - `xattr:*` does not cover `xattr:security.foo`; `xattr:security.*` does.
  - `suid` only when named.
  - An explicit sensitive allowance → `covered_by` set and `explicit_sensitive=True`.
  - A zero-match rule is reported as 0.
  - `elevate` → priority 1.
  - A boot partition content change on a binary kind → 1.
  - ELF added → 1.
  - A plain text modified → 2.
- [ ] **Steps 2–4:** FAIL → implement → PASS. The example file is entirely commented-out
  illustrative rules plus `rules: []`.
- [ ] **Step 5: Commit** (`feat: field-scoped expected-change rules and review priority`)

---

### Task 15: Report builder and MVP UI

**Files:** Create `forensic_compare/report.py`, `forensic_compare/templates/report.html`,
`forensic_compare/static/app.js`, `forensic_compare/static/style.css`, `tests/test_report.py`

**Interfaces:**

- `build_comparison(run: RunContext) -> dict` assembles the `comparison.json` structure:
  - `schema: "forensic-compare/comparison/1"`;
  - `generated_at`, `tool_versions`, `command`;
  - `integrity: {overall, images: {...}, disclaimer}`;
  - `capture: {golden, current}`;
  - `rules: {file, sha256, rules: [{id, label, matches}]}`;
  - `sources: [...]` (each with `id`, `kind`, `status`, `role`, `reference`, `warnings`, `summary`,
    `entries`, `partitions`, `layout_diff`);
  - `unmatched`, `not_used`, `completeness: {complete: bool, reasons: [..]}`.
- `embed_json(obj) -> str` replaces `<`, `>`, `&`, U+2028 and U+2029 with `\u` escapes.
- `render_html(comparison: dict) -> str`:
  - reads the template;
  - inlines the CSS/JS;
  - computes `sha256-<b64>` of the exact inline script/style text;
  - fills the CSP `<meta>` as the **first child of `<head>`**.
- UI (`app.js`, vanilla, `textContent` only), §10.2 MVP:
  - persistent banners with a collapsed summary;
  - sidebar sections;
  - summary cards (pre-filter);
  - status filters + toggles (Hide unchanged on, Hide fully expected off, Sensitive only);
  - search;
  - "Displaying X of Y entries";
  - Reset filters;
  - sortable columns;
  - pagination (200, with a selector);
  - detail panel (Golden vs Current, diffs, coverage, not-assessed reasons, xattr hex, capability);
  - disk layout table;
  - image-level and unmatched sections;
  - light/dark mode (`localStorage` in `try/catch`).

- [ ] **Step 1: Failing tests (unit)**

```python
def test_embed_json_escapes():
    s = embed_json({"p": "</script><b>& "})
    assert "</script>" not in s and "\\u003c" in s and "\\u2028" in s
def test_csp_first_in_head_and_hashes_match():
    html = render_html(minimal_comparison())
    head = html.split("<head>",1)[1]
    assert head.lstrip().startswith('<meta http-equiv="Content-Security-Policy"')
    csp = re.search(r'content="([^"]+)"', head).group(1)
    for tag in ("script", "style"):
        body = re.search(rf"<{tag}(?![^>]*application/json)[^>]*>(.*?)</{tag}>", html, re.S).group(1)
        h = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
        assert f"'sha256-{h}'" in csp
    for d in ("default-src 'none'", "base-uri 'none'", "form-action 'none'", "connect-src 'none'", "img-src 'none'"):
        assert d in csp
def test_no_external_urls():
    html = render_html(minimal_comparison()); assert not re.search(r'(src|href)=["\']?(https?:|//)', html)
def test_app_js_has_no_innerhtml(): assert "innerHTML" not in (STATIC/"app.js").read_text()
```

- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: self-contained CSP-protected HTML report (MVP UI)`)

---

### Task 16: CLI orchestration, output protection, exit codes

**Files:** Create `forensic_compare/compare.py`, `tests/test_cli.py`

**Interfaces:**

- `main(argv: list[str]|None = None, *, _hooks: dict|None = None) -> int`. Test hook keys:
  `after_pre_hash`, `after_analysis` (a callable receiving the context).
- Flow:
  1. Parse args.
  2. Check output protection (realpath: `out` ≠/⊂/⊃ any capture dir or image parent).
  3. Prepare the output: refuse non-empty without `--force`; with `--force`, delete the files listed
     in the existing `outputs.json` (realpath-confined to `out`).
  4. Discover and pair.
  5. Load the rules (exit 2 on error).
  6. `hash_pre`.
  7. Inside `try`, analyze each pair, then compare and apply the rules; `finally` → `hash_post`
     (always).
  8. Build the comparison and write `manifests/`, `supporting/`, `comparison.json`, `report.html`,
     `tool_log.jsonl` and `outputs.json` (tmp + rename).
  9. Exit `0` if `completeness.complete` and `integrity.overall == "verified"`, else `3`.

  Fatal exceptions → message to stderr, exit 2.
- Args: `golden`, `current`, `-o/--output` (required), `--rules`, `--jobs`, `--timeout` (default
  600 s per command), `--force`, `--quiet`.

- [ ] **Step 1: Failing tests**
  - `test_usage_error_exit2` (missing `-o`);
  - `test_nonempty_output_refused`;
  - `test_force_removes_only_previous_outputs` (run twice with different capture sets; an unrelated
    `notes.txt` survives; stale `manifests/<old>` is removed);
  - `test_output_inside_capture_refused`;
  - `test_output_symlink_alias_refused` (a symlink to the golden dir as `-o`);
  - `test_capture_inside_output_refused`;
  - `test_cli_unreadable_image_exit3`.
- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** (`feat: CLI orchestration with output protection and exit codes`)

---

### Task 17: End-to-end integration tests

**Files:** Create `tests/test_integration.py` (marker `integration`)

- [ ] **Step 1: Write the tests** (they should pass if Tasks 0–16 are correct; any failure is a bug
  to fix in the owning module).
  - `test_exit0_clean_set_with_differences`:
    - `captures_clean` → exit 0;
    - `comparison.json` has ≥1 modified entry;
    - `integrity.overall == "verified"`;
    - `completeness.complete`.
  - `test_full_capture_set_exit3_and_sections`:
    - exit 3;
    - sources include `config-active-crypt.dd`, `nvram-crypt.dd`, `mmcblk0.dd` (with partitions)
      and `mtdblock0.bin` (`image-level`);
    - unmatched includes `only-golden.dd`;
    - `incompat.dd` is incomplete;
    - nvram integrity is `failed` with a mismatch;
    - `config-active-crypt.dd.received.sha256` is in `not_used`;
    - the reference is unverified (conflict).
  - `test_expected_statuses_match_fixture_table`: for each path in `fixtures/expected.py`, assert
    the status, the sensitive fields and the incomplete flag.
  - `test_integrity_change_during_analysis`: `_hooks["after_analysis"]` appends a byte to a
    *writable copy* of an image in a tmp capture dir → that image is `failed` ("changed during
    analysis") and the exit code is 3.
  - `test_post_hash_runs_after_extraction_failure`: a capture dir with `corrupt_extent` + a fake
    `icat` that times out → the verdicts still contain `post` hashes.
  - `test_inputs_unmodified`: every fixture's sha256 is equal before and after the whole suite
    (session finalizer).
  - `test_tool_log_has_no_content`: grep `tool_log.jsonl` for known file contents → absent.
- [ ] **Step 2: Run** `pytest -m integration -q` → PASS (fix the owning modules on failure, with a
  test added there).
- [ ] **Step 3: Commit** (`test: end-to-end integration coverage`)

---

### Task 18: Browser tests (Playwright)

**Files:** Create `tests/test_browser.py` (marker `browser`)

- Setup: `.venv/bin/playwright install chromium`. If the system libraries are missing, report the
  `playwright install-deps` command for the user to run with sudo.
- Fixture: generate the report from the full capture set into `tmp_path`.

```python
def test_offline_no_unexpected_requests(page, report):
    attempts = []
    page.context.route("**/*", lambda route: (attempts.append(route.request.url), route.abort() if not route.request.url.startswith("file://") else route.continue_()))
    errors = []; page.on("console", lambda m: m.type in ("error","warning") and errors.append(m.text))
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(report.as_uri())
    assert [u for u in attempts if u != report.as_uri()] == []
    assert not [e for e in errors if "Content Security Policy" in e or "Refused" in e]
```

- Further tests:
  - hostile names are rendered as text (`page.get_by_text("<img src=x onerror=alert(1)>")` is
    visible and no `img` element exists in the table);
  - the Incomplete filter includes a modified entry with the incomplete badge (the `new^line`
    path);
  - Hide fully expected leaves partial/incomplete entries visible;
  - Reset restores the defaults;
  - "Displaying X of Y entries" updates;
  - pagination keeps the `tbody tr` count ≤ the page size;
  - the detail panel shows Golden vs Current and a `not assessed` reason;
  - banners stay visible after filtering to Unchanged, and when collapsed they show
    "Integrity FAILED (1)".
- [ ] **Steps:** write the tests → run `pytest -m browser` → fix the UI → PASS → commit
  (`test: browser tests for offline behavior, escaping and filters`).

---

### Task 19: Slow test, README, final validation

**Files:** Create `tests/test_slow.py`, `forensic_compare/README.md`

- `test_slow_large_inventory` (markers `slow`, `integration`):
  - a 20k-file ext image (mke2fs `-d`, `-N 25000`), golden vs current with 200 modified files;
  - assert completion, that progress lines were printed, and a page DOM row count ≤ 200 (via the
    browser if available).
- README:
  - purpose and principles;
  - install (`sudo apt install sleuthkit e2fsprogs`, `pip install -r requirements.txt`);
  - usage, capture dir layout, the `capture.yaml` and rules schemas, exit codes;
  - outputs, limitations (squashfs, TSK `^` names, fast symlinks, mtime seconds);
  - the integrity disclaimer;
  - running the tests: `pytest`, `pytest --strict-validation -m "integration or browser"`;
  - the real-image validation checklist (§11.3).
- [ ] **Final:** `pytest --strict-validation` → all pass, with no skips among the integration and
  browser tests. Record the output in the PR/commit message.
- [ ] **Commit** (`docs: README; test: large inventory`).
