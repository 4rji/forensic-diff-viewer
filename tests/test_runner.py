import json
import os
import stat
import sys
import textwrap
import time

import pytest

from forensic_compare.tools.runner import ToolRunner


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("PATH", str(d) + os.pathsep + os.environ["PATH"])

    def make(name, body):
        p = d / name
        p.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        return name

    return make


@pytest.fixture
def runner(tmp_path):
    return ToolRunner(tmp_path / "tool_log.jsonl", timeout=10, jobs=2)


def _log(tmp_path):
    return [json.loads(line) for line in (tmp_path / "tool_log.jsonl").read_text().splitlines()]


def test_capture_mode_collects_stdout_and_logs(fake_bin, runner, tmp_path):
    fake_bin("hello", "import sys; sys.stdout.write('hi\\n')\n")
    r = runner.run(["hello"], tool="hello")
    assert r.stdout == b"hi\n" and r.exit_code == 0 and r.ok
    rec = _log(tmp_path)[0]
    assert rec["id"] == r.log_id and rec["argv"] == ["hello"] and rec["exit_code"] == 0
    assert rec["stdout_bytes"] == 3


def test_stream_does_not_log_content(fake_bin, runner, tmp_path):
    fake_bin("secret", "import sys; sys.stdout.buffer.write(b'SECRET'*1000)\n")
    chunks = []
    r = runner.stream(["secret"], chunks.append, tool="icat")
    assert b"".join(chunks) == b"SECRET" * 1000
    assert r.bytes_out == 6000 and r.stdout == b""
    log = (tmp_path / "tool_log.jsonl").read_bytes()
    assert b"SECRET" not in log
    assert _log(tmp_path)[0]["bytes_extracted"] == 6000


def test_timeout_kills_group_and_releases_slot(fake_bin, runner, tmp_path):
    pidfile = tmp_path / "child.pid"
    fake_bin("sleeper", f"""
        import subprocess, sys, time
        c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        open({str(pidfile)!r}, 'w').write(str(c.pid))
        time.sleep(30)
    """)
    t0 = time.monotonic()
    r = runner.run(["sleeper"], tool="sleeper", timeout=1.0)
    assert time.monotonic() - t0 < 8
    assert r.timed_out and r.exit_code is None and not r.ok
    # both slots are free again
    assert runner.semaphore.acquire(blocking=False)
    assert runner.semaphore.acquire(blocking=False)
    child = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("child process of timed-out tool survived")


def test_partial_stream_preserved_on_timeout(fake_bin, runner):
    fake_bin("partial", """
        import sys, time
        sys.stdout.buffer.write(b'0123456789'); sys.stdout.flush()
        time.sleep(30)
    """)
    got = []
    r = runner.stream(["partial"], got.append, tool="icat", timeout=1.0)
    assert r.timed_out and r.bytes_out == 10 and b"".join(got) == b"0123456789"


def test_unknown_stderr_is_problem(fake_bin, runner, tmp_path):
    fake_bin("weird", "import sys; sys.stderr.write('Something odd happened\\n')\n")
    r = runner.run(["weird"], tool="fls")
    assert r.exit_code == 0 and r.problems and not r.ok
    assert _log(tmp_path)[0]["diagnostics"] == [{"line": "Something odd happened", "kind": "unknown"}]


def test_banner_stderr_is_not_problem(fake_bin, runner):
    fake_bin("debugfs", "import sys; sys.stderr.write('debugfs 1.47.2 (1-Jan-2025)\\n')\n")
    r = runner.run(["debugfs"], tool="debugfs")
    assert r.ok and r.diagnostics[0]["kind"] == "banner"


def test_missing_tool_is_reported_not_raised(runner):
    r = runner.run(["definitely-not-a-tool-xyz"], tool="xyz")
    assert not r.ok and r.exit_code is None
    assert any("not found" in d["line"] for d in r.diagnostics)


def test_consumer_exception_kills_process_and_is_reported(fake_bin, runner):
    fake_bin("big", "import sys\nfor _ in range(1000): sys.stdout.buffer.write(b'x'*65536)\n")

    def boom(_chunk):
        raise RuntimeError("consumer failed")

    r = runner.stream(["big"], boom, tool="icat", timeout=5)
    assert not r.ok
    assert any("consumer failed" in d["line"] for d in r.diagnostics)


def test_version_recorded_only_when_used(fake_bin, runner):
    fake_bin("fls", """
        import sys
        if sys.argv[1:] == ['-V']:
            print('The Sleuth Kit ver 4.12.1')
    """)
    assert runner.versions == {}
    runner.run(["fls", "x"], tool="fls")
    assert runner.versions == {"fls": "The Sleuth Kit ver 4.12.1"}


def test_lc_all_is_c(fake_bin, runner):
    fake_bin("envtool", "import os; print(os.environ.get('LC_ALL'))\n")
    assert runner.run(["envtool"], tool="envtool").stdout.strip() == b"C"


def test_tool_outside_path_is_found_in_sbin(tmp_path, monkeypatch):
    from forensic_compare.tools import runner as runner_mod

    sbin = tmp_path / "sbin"
    sbin.mkdir()
    tool = sbin / "fake-sbin-tool"
    tool.write_text(f"#!{sys.executable}\nprint('from sbin')\n")
    tool.chmod(0o755)
    monkeypatch.setattr(runner_mod, "SBIN_DIRS", (str(sbin),))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    r = ToolRunner(tmp_path / "tool_log.jsonl", timeout=10).run(["fake-sbin-tool"], tool="x")
    assert r.ok and r.stdout == b"from sbin\n"
    assert _log(tmp_path)[0]["argv"] == [str(tool)]
