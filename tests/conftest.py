"""Shared pytest configuration.

- Markers: ``integration`` (needs sleuthkit + e2fsprogs), ``browser`` (needs Playwright +
  Chromium), ``slow``.
- ``--strict-validation``: a skipped ``integration`` or ``browser`` test is reported as a
  failure. Skips are fine during development but never count as validation.
- ``FC_TSK_BIN_DIR`` / ``FC_TSK_LIB_DIR``: optional directories prepended to ``PATH`` /
  ``LD_LIBRARY_PATH`` so a non-system sleuthkit build can be used.
"""
import os
import shutil

import pytest

REQUIRED_MARKERS = ("integration", "browser")


def _prepend_env(var, value):
    if value:
        os.environ[var] = value + (os.pathsep + os.environ[var] if os.environ.get(var) else "")


_prepend_env("PATH", os.environ.get("FC_TSK_BIN_DIR"))
_prepend_env("LD_LIBRARY_PATH", os.environ.get("FC_TSK_LIB_DIR"))
# debugfs / mke2fs live in /sbin on Debian, which is often not on a normal user's PATH.
for _sbin in ("/usr/sbin", "/sbin"):
    if _sbin not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + _sbin


def pytest_addoption(parser):
    parser.addoption(
        "--strict-validation",
        action="store_true",
        default=False,
        help="Fail instead of skipping required integration/browser tests.",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: needs sleuthkit and e2fsprogs")
    config.addinivalue_line("markers", "browser: needs Playwright with Chromium")
    config.addinivalue_line("markers", "slow: long-running test")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if not item.config.getoption("--strict-validation") or not report.skipped:
        return
    if any(item.get_closest_marker(m) for m in REQUIRED_MARKERS):
        reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else str(report.longrepr)
        report.outcome = "failed"
        report.longrepr = f"strict validation: skipped required test: {reason}"


@pytest.fixture(scope="session")
def fixtures_dir(tmp_path_factory):
    """All synthetic fixtures, built once per session (needs mke2fs + debugfs)."""
    if not (shutil.which("mke2fs") and shutil.which("debugfs")):
        pytest.skip("e2fsprogs (mke2fs, debugfs) not available")
    from tests.fixtures.build import build_all

    out = tmp_path_factory.mktemp("fixtures")
    meta = build_all(out)
    yield out
    # inputs must never be modified by the code under test
    from tests.fixtures.build import _sha

    changed = [rel for rel, digest in meta["sha256"].items() if _sha(out / rel) != digest]
    assert not changed, f"fixture inputs were modified: {changed}"


def tools_available():
    """Return {tool: path or None} for every external tool the suite may use."""
    return {t: shutil.which(t) for t in ("mmls", "fsstat", "fls", "icat", "debugfs", "mke2fs")}


def require_tools(*names):
    missing = [n for n in names if not shutil.which(n)]
    if missing:
        pytest.skip("missing tools: " + ", ".join(missing))
