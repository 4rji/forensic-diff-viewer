import io

from forensic_compare.progress import Progress


def test_progress_omits_bytes_when_unknown():
    buf = io.StringIO()
    p = Progress("x · golden", stream=buf)
    p.update(3, 3, 0, 0, phase="xattrs")
    assert buf.getvalue().strip() == "[x · golden] xattrs 3/3 files"


def test_progress_includes_bytes():
    buf = io.StringIO()
    Progress("x", stream=buf).update(2, 2, 3 << 20, 4 << 20)
    assert buf.getvalue().strip() == "[x] hashing 2/2 files · 3/4 MiB"
