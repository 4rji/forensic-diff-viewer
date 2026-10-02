"""Decoder for the ``security.capability`` xattr (struct vfs_cap_data, v1/v2/v3)."""
import struct

CAP_NAMES = [
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_fsetid",
    "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_linux_immutable",
    "cap_net_bind_service", "cap_net_broadcast", "cap_net_admin", "cap_net_raw",
    "cap_ipc_lock", "cap_ipc_owner", "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot",
    "cap_sys_ptrace", "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
    "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod", "cap_lease",
    "cap_audit_write", "cap_audit_control", "cap_setfcap", "cap_mac_override",
    "cap_mac_admin", "cap_syslog", "cap_wake_alarm", "cap_block_suspend", "cap_audit_read",
    "cap_perfmon", "cap_bpf", "cap_checkpoint_restore",
]

_REVISION_MASK = 0xFF000000
_FLAGS_EFFECTIVE = 0x000001
# version -> (number of 32-bit words per set, total struct size)
_LAYOUT = {1: (1, 12), 2: (2, 20), 3: (2, 24)}


def _name(bit):
    return CAP_NAMES[bit] if bit < len(CAP_NAMES) else f"cap_{bit}"


def _bits(words):
    value = 0
    for i, w in enumerate(words):
        value |= w << (32 * i)
    return [b for b in range(32 * len(words)) if value >> b & 1]


def decode_capability(raw: bytes) -> dict:
    if len(raw) < 4:
        raise ValueError("capability xattr too short")
    magic = struct.unpack("<I", raw[:4])[0]
    version = (magic & _REVISION_MASK) >> 24
    if version not in _LAYOUT:
        raise ValueError(f"unknown vfs_cap_data revision 0x{magic & _REVISION_MASK:08x}")
    words, size = _LAYOUT[version]
    if len(raw) != size:
        raise ValueError(f"vfs_cap_data v{version} must be {size} bytes, got {len(raw)}")
    effective = bool(magic & _FLAGS_EFFECTIVE)
    perm_words, inh_words = [], []
    for i in range(words):
        p, inh = struct.unpack("<II", raw[4 + 8 * i:12 + 8 * i])
        perm_words.append(p)
        inh_words.append(inh)
    permitted = _bits(perm_words)
    inheritable = _bits(inh_words)
    rootid = struct.unpack("<I", raw[20:24])[0] if version == 3 else None

    groups: dict[str, list[str]] = {}
    for bit in sorted(set(permitted) | set(inheritable)):
        flags = ("e" if effective else "") + ("i" if bit in inheritable else "") + \
                ("p" if bit in permitted else "")
        groups.setdefault(flags, []).append(_name(bit))
    text = " ".join(f"{','.join(names)}+{flags}" for flags, names in groups.items())
    return {
        "version": version,
        "effective": effective,
        "permitted": [_name(b) for b in permitted],
        "inheritable": [_name(b) for b in inheritable],
        "rootid": rootid,
        "text": text,
    }
