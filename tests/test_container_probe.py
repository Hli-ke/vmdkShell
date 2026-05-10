import io
import json
import os
import tempfile
import unittest

from crypto_state import build_unlock_plan, probe_container
from partitions.mbrpartition import MBRPartition
from vmdk_shell_ops import VMDKShellOps


def _mbr_entry(partition_type: int, rel_lba: int, sectors: int):
    entry = bytearray(16)
    entry[4] = partition_type
    entry[8:12] = rel_lba.to_bytes(4, "little")
    entry[12:16] = sectors.to_bytes(4, "little")
    return bytes(entry)


class FakeContainerOps(VMDKShellOps):
    def __init__(self, items, raw_bytes):
        self._items = items
        self.want_partition = None
        self.raw_f = io.BytesIO(raw_bytes)
        self.sector_size = 512
        self.unlock_write_records = {}
        self.fileName = "sample.vmdk"

    def list_filesystems(self):
        return self._items

    def set_partition(self, partition):
        self.want_partition = partition


class ContainerProbeTests(unittest.TestCase):
    def test_probe_luks_header(self):
        data = bytearray(4096)
        data[:6] = b"LUKS\xba\xbe"
        data[6:8] = (1).to_bytes(2, "big")
        data[8:8 + len(b"aes")] = b"aes"
        data[40:40 + len(b"xts-plain64")] = b"xts-plain64"
        data[72:72 + len(b"sha256")] = b"sha256"
        data[104:108] = (4096).to_bytes(4, "big")
        data[108:112] = (64).to_bytes(4, "big")
        data[168:168 + len(b"11111111-2222-3333-4444-555555555555")] = b"11111111-2222-3333-4444-555555555555"

        probe = probe_container(bytes(data))
        self.assertIsNotNone(probe)
        self.assertEqual(probe.kind, "luks1")
        self.assertTrue(probe.is_encrypted)
        self.assertEqual(probe.details["cipher_name"], "aes")

    def test_probe_lvm2_label(self):
        data = bytearray(512)
        data[:8] = b"LABELONE"
        data[0x18:0x20] = b"LVM2 001"

        probe = probe_container(bytes(data))
        self.assertIsNotNone(probe)
        self.assertEqual(probe.kind, "lvm2-pv")
        self.assertFalse(probe.is_encrypted)

    def test_build_unlock_plan_for_luks(self):
        plan = build_unlock_plan("luks2", "disk.raw", key_file="key.bin", mapping_name="home")
        self.assertIsNotNone(plan)
        self.assertIn("cryptsetup", plan.command)
        self.assertIn("key.bin", plan.command)
        self.assertIn("home", plan.command)

    def test_extended_partition_chain_is_parsed(self):
        disk = bytearray(512 * 200)
        disk[446 + 16 * 3:446 + 16 * 4] = _mbr_entry(0x85, 100, 100)
        disk[510:512] = b"\x55\xaa"

        ebr1 = 100 * 512
        disk[ebr1 + 446:ebr1 + 462] = _mbr_entry(0x83, 1, 20)
        disk[ebr1 + 462:ebr1 + 478] = _mbr_entry(0x85, 30, 50)
        disk[ebr1 + 510:ebr1 + 512] = b"\x55\xaa"

        ebr2 = 130 * 512
        disk[ebr2 + 446:ebr2 + 462] = _mbr_entry(0x83, 1, 20)
        disk[ebr2 + 510:ebr2 + 512] = b"\x55\xaa"

        part = MBRPartition(file=io.BytesIO(bytes(disk)), sector_size=512)
        part.parse_mbr_partition()

        names = [p["name"] for p in part.partitions]
        self.assertIn("MBR_LogicalPartition5", names)
        self.assertIn("MBR_LogicalPartition6", names)
        logical = [p for p in part.partitions if p.get("is_logical")]
        self.assertEqual([p["first_lba"] for p in logical], [101, 131])

    def test_prepare_unlock_exports_partition_and_plan(self):
        item = {
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "crypt1",
            "partition": {"first_lba": 0, "start_byte": 0, "size_bytes": 16},
            "fs_kind": None,
            "fs": None,
            "container_kind": "luks1",
            "container_detail": {"cipher_name": "aes"},
            "container_display": "LUKS1",
            "is_encrypted": True,
        }
        ops = FakeContainerOps([item], b"0123456789abcdef")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "crypt1.raw")
            ops.prepare_unlock(out_file, key_file="key.bin", mapping_name="home")

            with open(out_file, "rb") as f:
                self.assertEqual(f.read(), b"0123456789abcdef")

            with open(out_file + ".unlock.json", "r", encoding="utf-8") as f:
                payload = json.load(f)

            self.assertEqual(payload["container_kind"], "luks1")
            self.assertIn("cryptsetup", payload["unlock"]["command"])

    def test_unlock_write_record_is_created_once(self):
        class RecordOps(FakeContainerOps):
            def __init__(self, items, raw_bytes):
                super().__init__(items, raw_bytes)
                self.record_calls = []

            def record_vmdk(self, out_file=None):
                self.record_calls.append(out_file)

        item = {
            "name": "groupZ_home_clear",
            "unlock_source": {"kind": "luks1"},
        }
        ops = RecordOps([], b"")

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                ops._ensure_unlock_write_record(item)
                ops._ensure_unlock_write_record(item)
            finally:
                os.chdir(old_cwd)

        self.assertEqual(len(ops.record_calls), 1)
        self.assertIn("groupZ_home_clear", ops.unlock_write_records)

    def test_rename_view_updates_selected_view_and_record(self):
        ops = FakeContainerOps([], b"")
        ops.unlocked_items = [{
            "name": "groupZ_home_clear",
            "partition": {"name": "groupZ_home_clear"},
        }]
        ops.unlock_write_records["groupZ_home_clear"] = "snapshot.vmdk"
        ops.want_partition = "groupZ_home_clear"

        ops.rename_view("groupZ_home_clear", "home_rw")

        self.assertEqual(ops.unlocked_items[0]["name"], "home_rw")
        self.assertEqual(ops.unlocked_items[0]["partition"]["name"], "home_rw")
        self.assertEqual(ops.want_partition, "home_rw")
        self.assertEqual(ops.unlock_write_records["home_rw"], "snapshot.vmdk")


if __name__ == "__main__":
    unittest.main()
