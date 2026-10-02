"""Small test helpers (read-only debugfs lookups on fixture images)."""
import re
import shutil
import subprocess


def debugfs_bin():
    return shutil.which("debugfs") or "/sbin/debugfs"


def ino_of(img, path, offset=0):
    target = f"{img}?offset={offset}" if offset else str(img)
    out = subprocess.run([debugfs_bin(), "-R", f"stat {path}", target],
                         capture_output=True, text=True).stdout
    m = re.search(r"Inode: (\d+)", out)
    assert m, f"inode of {path} not found in {img}"
    return int(m.group(1))


def file_acl_of(img, path):
    out = subprocess.run([debugfs_bin(), "-R", f"stat {path}", str(img)],
                         capture_output=True, text=True).stdout
    return int(re.search(r"File ACL: (\d+)", out).group(1))
