"""Classification of diagnostic lines emitted by external tools.

Every stderr line (and every unexpected stdout line in batch modes) is classified as:

- ``banner``  — a known version banner (harmless);
- ``info``    — a known informational message (harmless);
- ``error``   — a known error message;
- ``unknown`` — anything else.

``error`` and ``unknown`` are *problems*: they stay visible in the report and conservatively
mark the affected scope as not assessed / incomplete. The table is versioned with the code;
extend it only with messages that have been observed and understood.
"""
import re

PATTERNS_VERSION = 1

_TSK_ERRORS = [
    r"^Metadata address too large",
    r"^Error ",
    r"^Invalid ",
    r"^Cannot determine file system type",
    r"^Possible encryption detected",
    r"^Unable to ",
    r"^Sector offset",
    r"^Encryption detected",
    r"^Error reading",
    r"^Partition table",
    r"^Unsupported",
]

PATTERNS = {
    "debugfs": [
        ("banner", re.compile(r"^debugfs \d+\.\d+(\.\d+)? \(.*\)$")),
        ("info", re.compile(r"^\s*Using EXT2FS Library version \S+$")),
        ("error", re.compile(r"File not found by ext2_lookup")),
        ("error", re.compile(r"^\S+: .* while ")),
        ("error", re.compile(r"^\S+: Usage: ")),
        ("error", re.compile(r"^\S+: Bad inode")),
    ],
}
for _tool in ("mmls", "fsstat", "fls", "icat"):
    PATTERNS[_tool] = [("error", re.compile(p)) for p in _TSK_ERRORS]


def classify(tool: str, line: str) -> str:
    line = line.rstrip()
    for kind, rx in PATTERNS.get(tool, []):
        if rx.search(line):
            return kind
    return "unknown"


def is_problem(kind: str) -> bool:
    return kind in ("error", "unknown")
