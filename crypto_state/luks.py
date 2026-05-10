from crypto_state.base import UnlockPlan, VolumeProbe


LUKS_MAGIC = b"LUKS\xba\xbe"


def probe_luks(data: bytes):
    if len(data) < 0xA8 + 40 or data[:6] != LUKS_MAGIC:
        return None

    version = int.from_bytes(data[6:8], "big")
    if version not in (1, 2):
        return None

    cipher_name = data[8:40].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    cipher_mode = data[40:72].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    hash_spec = data[72:104].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    payload_offset = int.from_bytes(data[104:108], "big")
    key_bytes = int.from_bytes(data[108:112], "big")
    uuid = data[168:208].split(b"\x00", 1)[0].decode("ascii", errors="replace")

    name = f"luks{version}"
    return VolumeProbe(
        kind=name,
        display_name=name.upper(),
        is_encrypted=True,
        details={
            "version": version,
            "cipher_name": cipher_name,
            "cipher_mode": cipher_mode,
            "hash_spec": hash_spec,
            "payload_offset_sectors": payload_offset,
            "key_bytes": key_bytes,
            "uuid": uuid,
        },
    )


def build_unlock_plan(image_path: str, key_file: str | None = None, mapping_name: str | None = None):
    mapping_name = mapping_name or "luks_volume"
    args = ["cryptsetup", "luksOpen"]

    if key_file:
        args.extend(["--key-file", key_file])

    args.extend([image_path, mapping_name])
    return UnlockPlan(
        kind="luks",
        command=" ".join(f'"{arg}"' if " " in arg else arg for arg in args),
        details={
            "image_path": image_path,
            "key_file": key_file,
            "mapping_name": mapping_name,
        },
    )
