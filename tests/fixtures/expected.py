"""Expected comparison results for ext/golden.img vs ext/current.img (see build.py).

path -> (status, sensitive diff fields, incomplete flag)
"""
from tests.fixtures.build import HOSTILE_HTML_NAME, HOSTILE_QUOTE_NAME

MAIN = {
    "/etc/unchanged.conf": ("unchanged", set(), False),
    "/etc/modified.conf": ("modified", set(), False),
    "/etc/deleted.conf": ("deleted", set(), False),
    "/etc/added.conf": ("added", set(), False),
    "/bin/tool": ("metadata", {"suid"}, False),
    "/bin/sgid": ("metadata", {"sgid"}, False),
    "/etc/owner": ("metadata", {"uid"}, False),
    "/etc/mtime_only": ("metadata", set(), False),
    "/etc/mode": ("metadata", set(), False),
    "/bin/capped": ("metadata", {"capability"}, False),
    "/bin/capchg": ("metadata", {"capability"}, False),
    "/etc/xattr_bin": ("unchanged", set(), False),
    "/etc/xattr_big": ("metadata", set(), False),
    "/etc/sec_xattr": ("metadata", {"xattr:security.foo"}, False),
    "/link_fast": ("unchanged", set(), False),
    "/link_retarget": ("modified", set(), False),
    "/link_slow": ("unchanged", set(), False),
    "/link_new": ("added", {"existence"}, False),
    "/link_dangling": ("unchanged", set(), False),
    "/link_hostile": ("unchanged", set(), False),
    "/file2link": ("modified", {"type"}, False),
    "/sparse.bin": ("unchanged", set(), False),
    "/hard_a": ("unchanged", set(), False),
    "/hard_b": ("unchanged", set(), False),
    "/pi|pe": ("unchanged", set(), False),
    # TSK renders the newline as '^' -> lossy path -> incomplete flag
    "/new^line": ("modified", set(), True),
    "/bad\\xff\\xfename": ("unchanged", set(), False),
    "/" + HOSTILE_HTML_NAME: ("modified", set(), False),
    "/" + HOSTILE_QUOTE_NAME: ("unchanged", set(), False),
    "/etc/sticky_dir": ("metadata", set(), False),
}
