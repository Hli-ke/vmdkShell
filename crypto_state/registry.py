from crypto_state.luks import build_unlock_plan as build_luks_unlock_plan
from crypto_state.luks import probe_luks
from crypto_state.lvm import build_unlock_plan as build_lvm_unlock_plan
from crypto_state.lvm import probe_lvm2_pv


def probe_container(data: bytes):
    for fn in (probe_luks, probe_lvm2_pv):
        result = fn(data)
        if result is not None:
            return result
    return None


def build_unlock_plan(kind: str, image_path: str, key_file: str | None = None, mapping_name: str | None = None):
    if kind in ("luks1", "luks2"):
        return build_luks_unlock_plan(image_path, key_file=key_file, mapping_name=mapping_name)

    if kind == "lvm2-pv":
        return build_lvm_unlock_plan(image_path, key_file=key_file, mapping_name=mapping_name)

    return None
