"""Single entry point for running external tools.

- Argument lists only (never a shell), ``LC_ALL=C``, each process in its own session so a
  timeout can kill the whole process group.
- *Capture* mode keeps stdout in memory (small textual outputs only).
- *Stream* mode hands stdout chunks to a consumer and never keeps or logs file contents.
- Every invocation is appended to ``tool_log.jsonl`` (argv, status, classified diagnostics,
  duration, byte counts). Results reference the log record id.
- Concurrency is bounded by a semaphore shared by all callers.
"""
from __future__ import annotations

import itertools
import json
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .diagnostics import classify, is_problem

CHUNK = 1 << 20
KILL_GRACE_S = 2.0

# tool name -> args that print its version. Only tools listed here get a version record.
VERSION_ARGS = {
    "mmls": ["-V"],
    "fsstat": ["-V"],
    "fls": ["-V"],
    "icat": ["-V"],
    "debugfs": ["-V"],
}


@dataclass
class RunResult:
    log_id: int
    argv: list
    exit_code: int | None
    timed_out: bool
    stdout: bytes = b""
    diagnostics: list = field(default_factory=list)
    duration_s: float = 0.0
    bytes_out: int = 0

    @property
    def problems(self):
        return [d for d in self.diagnostics if is_problem(d["kind"])]

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.problems

    def describe(self) -> str:
        """Short human-readable failure description for 'not assessed' reasons."""
        if self.timed_out:
            return f"timeout (log {self.log_id})"
        parts = []
        if self.exit_code != 0:
            parts.append(f"exit code {self.exit_code}")
        if self.problems:
            parts.append(self.problems[0]["line"][:200])
        return "; ".join(parts or ["ok"]) + f" (log {self.log_id})"


class ToolRunner:
    def __init__(self, log_path: Path, timeout: float = 600.0, jobs: int = 4):
        self.log_path = Path(log_path)
        self.timeout = timeout
        self.semaphore = threading.BoundedSemaphore(max(1, jobs))
        self.versions: dict[str, str] = {}
        self._ids = itertools.count(1)
        self._log_lock = threading.Lock()
        self._version_lock = threading.Lock()

    # -- public API -------------------------------------------------------------------------

    def run(self, argv, *, tool: str, timeout: float | None = None) -> RunResult:
        buf = bytearray()
        res = self._execute(argv, tool, timeout, buf.extend, capture=True)
        res.stdout = bytes(buf)
        self._record_version(argv, tool)
        return res

    def stream(self, argv, consumer: Callable[[bytes], None], *, tool: str,
               timeout: float | None = None) -> RunResult:
        res = self._execute(argv, tool, timeout, consumer, capture=False)
        self._record_version(argv, tool)
        return res

    # -- internals --------------------------------------------------------------------------

    def _execute(self, argv, tool, timeout, sink, capture) -> RunResult:
        argv = [str(a) for a in argv]
        timeout = self.timeout if timeout is None else timeout
        log_id = next(self._ids)
        diagnostics: list[dict] = []
        start = time.monotonic()
        bytes_out = 0
        timed_out = threading.Event()
        exit_code = None

        with self.semaphore:
            try:
                proc = subprocess.Popen(
                    argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, start_new_session=True,
                    env={**os.environ, "LC_ALL": "C"},
                )
            except OSError as exc:
                diagnostics.append({"line": f"tool not found or not executable: {exc}",
                                    "kind": "error"})
                return self._finish(log_id, tool, argv, None, False, diagnostics, start, 0, capture)

            def read_stderr():
                for raw in proc.stderr:
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    if line:
                        diagnostics.append({"line": line, "kind": classify(tool, line)})

            err_thread = threading.Thread(target=read_stderr, daemon=True)
            err_thread.start()

            def on_timeout():
                timed_out.set()
                _kill_group(proc)

            timer = threading.Timer(timeout, on_timeout)
            timer.daemon = True
            timer.start()
            try:
                while True:
                    chunk = proc.stdout.read1(CHUNK)
                    if not chunk:
                        break
                    bytes_out += len(chunk)
                    try:
                        sink(chunk)
                    except Exception as exc:  # consumer failure: stop the tool, report it
                        diagnostics.append({"line": f"consumer error: {exc}", "kind": "error"})
                        _kill_group(proc)
                        break
                exit_code = proc.wait()
            finally:
                timer.cancel()
                if proc.poll() is None:
                    _kill_group(proc)
                    proc.wait()
                err_thread.join(timeout=5)
                proc.stdout.close()
                proc.stderr.close()

        if timed_out.is_set():
            exit_code = None
        return self._finish(log_id, tool, argv, exit_code, timed_out.is_set(), diagnostics,
                            start, bytes_out, capture)

    def _finish(self, log_id, tool, argv, exit_code, timed_out, diagnostics, start, bytes_out,
                capture) -> RunResult:
        duration = round(time.monotonic() - start, 4)
        record = {
            "id": log_id, "tool": tool, "argv": argv, "exit_code": exit_code,
            "timed_out": timed_out, "duration_s": duration,
            "stdout_bytes": bytes_out if capture else 0,
            "bytes_extracted": 0 if capture else bytes_out,
            "diagnostics": diagnostics,
        }
        with self._log_lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return RunResult(log_id=log_id, argv=argv, exit_code=exit_code, timed_out=timed_out,
                         diagnostics=diagnostics, duration_s=duration, bytes_out=bytes_out)

    def _record_version(self, argv, tool):
        args = VERSION_ARGS.get(tool)
        if not args or tool in self.versions or os.path.basename(str(argv[0])) != tool:
            return
        with self._version_lock:
            if tool in self.versions:
                return
            self.versions[tool] = None  # reserve (avoid duplicate probes)
            res = self.run([argv[0], *args], tool=f"{tool}-version", timeout=30)
            text = res.stdout.decode("utf-8", errors="replace").strip()
            if not text:
                text = "\n".join(d["line"] for d in res.diagnostics).strip()
            self.versions[tool] = text.splitlines()[0] if text else "unknown"


def _kill_group(proc):
    pgid = proc.pid  # start_new_session=True: the child leads its own process group
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + KILL_GRACE_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    try:
        os.killpg(pgid, signal.SIGKILL)  # also reaps children that ignored SIGTERM
    except ProcessLookupError:
        pass
