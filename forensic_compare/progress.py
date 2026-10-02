"""Progress reporting on stderr (single rewritten line on a TTY, periodic lines otherwise)."""
import sys
import threading
import time

NON_TTY_INTERVAL_S = 2.0


def _mib(n):
    return n / (1 << 20)


class Progress:
    def __init__(self, label: str, quiet: bool = False, stream=None):
        self.label = label
        self.quiet = quiet
        self.stream = stream if stream is not None else sys.stderr
        self.tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._last = 0.0
        self._lock = threading.Lock()
        self._line = ""

    def message(self, text: str):
        if self.quiet:
            return
        with self._lock:
            self._emit(f"[{self.label}] {text}", force=True)

    def update(self, done_files, total_files, done_bytes, total_bytes, phase="hashing"):
        if self.quiet:
            return
        line = f"[{self.label}] {phase} {done_files}/{total_files} files"
        if total_bytes:
            line += f" · {_mib(done_bytes):.0f}/{_mib(total_bytes):.0f} MiB"
        with self._lock:
            self._emit(line, force=done_files == total_files)

    def _emit(self, line, force):
        now = time.monotonic()
        self._line = line
        if self.tty:
            self.stream.write("\r\x1b[K" + line)
            self.stream.flush()
        elif force or now - self._last >= NON_TTY_INTERVAL_S:
            self.stream.write(line + "\n")
            self.stream.flush()
            self._last = now

    def finish(self):
        if self.quiet:
            return
        with self._lock:
            if self.tty and self._line:
                self.stream.write("\n")
                self.stream.flush()
