import subprocess
import sys
from pathlib import Path


def test_strict_validation_turns_skips_into_failures(tmp_path):
    t = tmp_path / "test_x.py"
    t.write_text(
        "import pytest\n"
        "@pytest.mark.integration\n"
        "def test_a():\n"
        "    pytest.skip('no tools')\n"
    )
    conftest = (Path(__file__).parent / "conftest.py").read_text()
    (tmp_path / "conftest.py").write_text(conftest)
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "--strict-validation", str(t)],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "strict validation" in (r.stdout + r.stderr).lower()


def test_without_strict_validation_skip_is_ok(tmp_path):
    t = tmp_path / "test_x.py"
    t.write_text(
        "import pytest\n"
        "@pytest.mark.integration\n"
        "def test_a():\n"
        "    pytest.skip('no tools')\n"
    )
    conftest = (Path(__file__).parent / "conftest.py").read_text()
    (tmp_path / "conftest.py").write_text(conftest)
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(t)],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
