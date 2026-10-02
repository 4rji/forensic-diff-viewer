"""Extended-attribute extraction with debugfs (read-only: never ``-w``), validated by inode.

debugfs always runs with ``-c`` (catastrophic mode): it does not read the allocation bitmaps,
which xattr lookups do not need, and it forces a read-only open. Live captures often carry
bitmaps whose checksums no longer match, and without ``-c`` debugfs refuses to open them.

debugfs is queried by inode number. Its enumeration (``ea_list``) is accepted only when it
agrees with the independent structural parse (``xattr_struct``), because debugfs 1.47.2 can
silently drop attributes (e.g. a corrupt EA block yields empty output and exit 0). Values are
fetched with ``ea_get -f`` into a private temporary directory and accepted only when no
problem diagnostic was raised and the byte count equals the enumerated size; values stored
inline are also compared byte-for-byte with the structural parse.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path

from ..ext_inode import ExtFSError
from ..manifest import Assessed
from ..xattr_struct import parse_xattrs

_ENTRY = re.compile(r"^  (.+?) \((\d+)\)(?: = .*)?$")
_ECHO = "debugfs: "
_SAFE_NAME = re.compile(r"^[\x21-\x7e]+$")


def parse_ea_list(out: str) -> list[tuple[str, int]]:
    lines = [l for l in out.splitlines() if l.strip()]
    if not lines:
        return []
    if lines[0] != "Extended attributes:":
        raise ValueError(f"unexpected ea_list output: {lines[0][:100]!r}")
    result = []
    for line in lines[1:]:
        m = _ENTRY.match(line.rstrip())
        if not m:
            raise ValueError(f"unexpected ea_list line: {line[:100]!r}")
        result.append((m.group(1), int(m.group(2))))
    return result


def split_batch(stdout: str) -> list[tuple[str, str]]:
    """Split ``debugfs -f`` output on its ``debugfs: <command>`` echo lines."""
    chunks: list[tuple[str, list[str]]] = []
    for line in stdout.splitlines(keepends=True):
        if line.startswith(_ECHO):
            chunks.append((line[len(_ECHO):].rstrip("\n"), []))
        elif chunks:
            chunks[-1][1].append(line)
        elif line.strip():
            raise ValueError(f"debugfs output before first command echo: {line[:100]!r}")
    return [(cmd, "".join(body)) for cmd, body in chunks]


class XattrExtractor:
    def __init__(self, runner, image: Path, offset_bytes: int, fs, batch_size: int = 500,
                 progress=None):
        self.runner = runner
        self.image = Path(image)
        self.offset = offset_bytes
        self.fs = fs
        self.batch_size = max(1, batch_size)
        self.progress = progress

    # -- public ----------------------------------------------------------------------------

    def extract(self, inodes: list[int]) -> dict[int, Assessed]:
        tmp = Path(tempfile.mkdtemp(prefix="fcx-"))
        try:
            os.chmod(tmp, 0o700)
            target = self._target(tmp)
            listed = self._list_all(inodes, tmp, target)
            results: dict[int, Assessed] = {}
            wanted: dict[int, list] = {}
            for ino in inodes:
                verdict = self._validate_enumeration(ino, listed[ino])
                if isinstance(verdict, Assessed):
                    results[ino] = verdict
                else:
                    wanted[ino] = verdict
            results.update(self._get_values(wanted, tmp, target))
            return results
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # -- enumeration -----------------------------------------------------------------------

    def _target(self, tmp: Path) -> str:
        path = self.image
        if "?" in str(path):  # libext2fs would parse it as an io option
            link = tmp / "image"
            os.symlink(os.path.abspath(path), link)
            path = link
        return f"{path}?offset={self.offset}" if self.offset else str(path)

    def _run_batch(self, commands: list[str], tmp: Path, target: str):
        cmdfile = tmp / "cmds"
        cmdfile.write_text("\n".join(commands) + "\n")
        res = self.runner.run(["debugfs", "-c", "-f", str(cmdfile), target], tool="debugfs")
        if not res.ok:
            return res, None
        try:
            parts = split_batch(res.stdout.decode("utf-8", errors="surrogateescape"))
        except ValueError:
            return res, None
        if [c for c, _ in parts] != commands:
            return res, None
        return res, [out for _, out in parts]

    def _run_one(self, command: str, target: str):
        return self.runner.run(["debugfs", "-c", "-R", command, target], tool="debugfs")

    def _list_all(self, inodes, tmp, target) -> dict:
        """ino -> list[(name, size)] or Assessed.error."""
        listed = {}
        for i in range(0, len(inodes), self.batch_size):
            batch = inodes[i:i + self.batch_size]
            cmds = [f"ea_list <{ino}>" for ino in batch]
            res, outs = self._run_batch(cmds, tmp, target)
            parsed = None
            if outs is not None:
                try:
                    parsed = [parse_ea_list(o) for o in outs]
                except ValueError:
                    parsed = None
            if parsed is not None:
                listed.update(zip(batch, parsed))
            else:  # attribute failures to individual inodes
                for ino in batch:
                    listed[ino] = self._list_one(ino, target)
            if self.progress:
                self.progress(min(i + self.batch_size, len(inodes)), len(inodes))
        return listed

    def _list_one(self, ino, target):
        res = self._run_one(f"ea_list <{ino}>", target)
        if not res.ok:
            return Assessed.error(f"debugfs ea_list failed: {res.describe()}", res.log_id)
        try:
            return parse_ea_list(res.stdout.decode("utf-8", errors="surrogateescape"))
        except ValueError as exc:
            return Assessed.error(f"debugfs ea_list output not understood: {exc}", res.log_id)

    def _validate_enumeration(self, ino, listed):
        if isinstance(listed, Assessed):
            return listed
        try:
            structure = parse_xattrs(self.fs, self.fs.read_inode(ino))
        except ExtFSError as exc:
            return Assessed.error(f"raw inode not readable: {exc}")
        if structure.state == "error":
            return Assessed.error(f"xattr structure invalid: {structure.reason}")
        expected = sorted((e.name.decode("utf-8", errors="surrogateescape"), e.size)
                          for e in structure.entries)
        if sorted(listed) != expected:
            return Assessed.error(
                f"xattr enumeration mismatch: debugfs={sorted(listed)} structure={expected}")
        if not expected:
            return Assessed.absent()
        by_name = {e.name.decode("utf-8", errors="surrogateescape"): e for e in structure.entries}
        return [(name, size, by_name[name].value) for name, size in sorted(listed)]

    # -- values ----------------------------------------------------------------------------

    def _get_values(self, wanted: dict, tmp: Path, target: str) -> dict:
        results = {}
        jobs = []  # (ino, name, size, structural_value, outfile)
        for ino, attrs in wanted.items():
            if any(not _SAFE_NAME.match(name) for name, _, _ in attrs):
                results[ino] = Assessed.error("xattr name cannot be passed to debugfs safely")
                continue
            for k, (name, size, value) in enumerate(attrs):
                jobs.append((ino, name, size, value, tmp / f"v{ino}_{k}"))
        for i in range(0, len(jobs), self.batch_size):
            batch = jobs[i:i + self.batch_size]
            cmds = [f"ea_get -f {out} <{ino}> {name}" for ino, name, _, _, out in batch]
            res, outs = self._run_batch(cmds, tmp, target)
            if outs is None or any(o.strip() for o in outs):
                for job, cmd in zip(batch, cmds):
                    _unlink(job[4])
                    one = self._run_one(cmd, target)
                    self._collect(job, one, results)
            else:
                for job in batch:
                    self._collect(job, res, results)
        return results

    def _collect(self, job, res, results):
        ino, name, size, structural, out = job
        if ino in results and results[ino].state == "error":
            return
        if not res.ok:
            results[ino] = Assessed.error(f"debugfs ea_get {name} failed: {res.describe()}",
                                          res.log_id)
            return
        try:
            os.chmod(out, 0o600)
            data = out.read_bytes()
        except OSError as exc:
            results[ino] = Assessed.error(f"ea_get {name} produced no output: {exc}", res.log_id)
            return
        if len(data) != size:
            results[ino] = Assessed.error(
                f"ea_get {name} returned {len(data)} bytes, expected {size}", res.log_id)
            return
        if structural is not None and data != structural:
            results[ino] = Assessed.error(f"ea_get {name} value differs from on-disk structure",
                                          res.log_id)
            return
        current = results.setdefault(ino, Assessed.ok({}))
        current.value[name] = {"hex": data.hex(), "size": size}


def _unlink(path: Path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass
