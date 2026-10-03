"""Large-inventory test (~20k files): concurrency, progress output, report size/pagination."""
import json
import time

import pytest

from forensic_compare.compare import main
from tests.conftest import require_tools
from tests.fixtures.build import _sums, mkfs

pytestmark = [pytest.mark.slow, pytest.mark.integration]
N_FILES = 20000
N_MODIFIED = 200


@pytest.fixture(scope="module")
def big_capture(tmp_path_factory):
    require_tools("fls", "icat", "fsstat", "mmls", "debugfs", "mke2fs")
    base = tmp_path_factory.mktemp("big")
    for side in ("golden", "current"):
        src = base / f"src-{side}"
        for i in range(N_FILES):
            d = src / f"d{i // 500:03d}"
            d.mkdir(parents=True, exist_ok=True)
            changed = side == "current" and i % (N_FILES // N_MODIFIED) == 0
            (d / f"f{i:05d}.conf").write_text(f"value={i}{'-changed' if changed else ''}\n")
        cap = base / "cap" / side
        cap.mkdir(parents=True)
        img = cap / "nvram-crypt.dd"
        mkfs(src, img, kb=65536, inodes=N_FILES + 1000)
        _sums(cap, ["nvram-crypt.dd"])
        img.chmod(0o444)
    return base / "cap"


def test_slow_large_inventory(big_capture, tmp_path, capsys):
    out = tmp_path / "report"
    t0 = time.monotonic()
    code = main([str(big_capture / "golden"), str(big_capture / "current"), "-o", str(out),
                 "--jobs", "4", "--verify-integrity"])
    elapsed = time.monotonic() - t0
    err = capsys.readouterr().err
    assert code == 0, err[-2000:]
    assert "hashing" in err and f"{N_FILES}/{N_FILES} files" in err
    comp = json.loads((out / "comparison.json").read_text())
    s = comp["sources"][0]
    assert s["summary"]["modified"] == N_MODIFIED
    assert s["summary"]["total"] >= N_FILES
    assert elapsed < 1800
    print(f"\nlarge inventory: {N_FILES} files per side analyzed in {elapsed:.0f}s; "
          f"report.html {(out / 'report.html').stat().st_size / 1e6:.1f} MB")

    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page()
        pg.goto((out / "report.html").as_uri())
        pg.locator(".sidebar .nav-item", has_text="nvram-crypt.dd").first.click()
        pg.wait_for_selector("#entries")
        pg.uncheck("#f-hide-unchanged")
        assert pg.locator("#entries tbody tr").count() == 200  # default page size
        assert pg.locator("#displaying").inner_text().startswith(f"Displaying {s['summary']['total']} of")
        b.close()
