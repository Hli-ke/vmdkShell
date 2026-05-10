from crypto_state.base import UnlockPlan, VolumeProbe
import re


def _parse_text_metadata(text: str):
    marker = 'contents = "Text Format Volume Group"'
    start = text.find(marker)
    if start == -1:
        return {}

    chunk = text[start:]
    vg_match = re.search(r"([A-Za-z0-9_+\-\.]+)\s*\{\s*[\r\n]+\s*id = \"([^\"]+)\"", chunk)
    if not vg_match:
        return {}

    vg_name = vg_match.group(1)
    vg_id = vg_match.group(2)

    extent_match = re.search(r"\nextent_size = (\d+)", chunk)
    extent_size = int(extent_match.group(1)) if extent_match else None

    pvs = {}
    pv_block = ""
    pv_start = chunk.find("physical_volumes {")
    lv_start = chunk.find("logical_volumes {")
    if pv_start != -1 and lv_start != -1 and lv_start > pv_start:
        pv_block = chunk[pv_start:lv_start]

    for pv_match in re.finditer(
        r"([A-Za-z0-9_+\-\.]+)\s*\{\s*[\r\n]+\s*id = \"([^\"]+)\".*?\npe_start = (\d+).*?\npe_count = (\d+)",
        pv_block,
        re.DOTALL,
    ):
        pvs[pv_match.group(1)] = {
            "name": pv_match.group(1),
            "id": pv_match.group(2),
            "pe_start": int(pv_match.group(3)),
            "pe_count": int(pv_match.group(4)),
        }

    lvs = []
    lv_block = chunk[lv_start:] if lv_start != -1 else ""
    for lv_match in re.finditer(
        r"([A-Za-z0-9_+\-\.]+)\s*\{\s*[\r\n]+\s*id = \"([^\"]+)\".*?\nsegment_count = (\d+).*?\nsegment1\s*\{.*?\nstart_extent = (\d+).*?\nextent_count = (\d+).*?\ntype = \"([^\"]+)\".*?\nstripe_count = (\d+).*?\nstripes = \[\s*[\r\n]+\s*\"([^\"]+)\",\s*(\d+)",
        lv_block,
        re.DOTALL,
    ):
        lvs.append({
            "name": lv_match.group(1),
            "id": lv_match.group(2),
            "segment_count": int(lv_match.group(3)),
            "start_extent": int(lv_match.group(4)),
            "extent_count": int(lv_match.group(5)),
            "segment_type": lv_match.group(6),
            "stripe_count": int(lv_match.group(7)),
            "pv_name": lv_match.group(8),
            "pv_extent_start": int(lv_match.group(9)),
        })

    return {
        "vg_name": vg_name,
        "vg_id": vg_id,
        "extent_size": extent_size,
        "physical_volumes": pvs,
        "logical_volumes": lvs,
    }


def probe_lvm2_pv(data: bytes):
    for sector_start in range(0, min(len(data), 4 * 512), 512):
        sector = data[sector_start:sector_start + 512]
        if len(sector) < 0x20 or sector[:8] != b"LABELONE":
            continue

        label = sector[0x18:0x20].decode("ascii", errors="replace").strip("\x00 ").strip()
        if not label.startswith("LVM2"):
            continue

        return VolumeProbe(
            kind="lvm2-pv",
            display_name="LVM2 PV",
            is_encrypted=False,
            details={
                "label": label,
                "label_sector": sector_start // 512,
                **_parse_text_metadata(data.decode("latin-1", errors="ignore")),
            },
        )

    return None


def build_unlock_plan(image_path: str, key_file: str | None = None, mapping_name: str | None = None):
    return UnlockPlan(
        kind="lvm2-pv",
        command=None,
        details={
            "image_path": image_path,
            "note": "LVM2 PV is a volume-management container, not an encryption format.",
            "key_file": key_file,
            "mapping_name": mapping_name,
        },
    )
