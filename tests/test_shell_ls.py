import io
import gzip
import os
import stat
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
try:
    import lz4.frame as lz4_frame
except ImportError:  # pragma: no cover - optional dependency
    lz4_frame = None
try:
    import zstandard
except ImportError:  # pragma: no cover - optional dependency
    zstandard = None

from base_analyze import VMDK
from vmdk_shell import VMDKShell
from vmdk_shell_ops import VMDKShellOps


class FakeFS:
    def __init__(self, nodes):
        self.nodes = nodes

    def find_file(self, path):
        return self.nodes.get(path)

    def list_dir(self, path="/"):
        inode = self.find_file(path)
        if inode is None or not stat.S_ISDIR(inode["i_mode"]):
            return []
        return inode.get("entries", [])

    def read_file_by_inode(self, inode):
        return inode.get("data", b"")


class FakeOps(VMDKShellOps):
    def __init__(self, items, raw_bytes=b""):
        self._items = items
        self.want_partition = None
        self.gpt = object()
        self.mbr = None
        self.raw_f = io.BytesIO(raw_bytes)
        self.sector_size = 512
        self.fileName = "sample.vmdk"

    def list_filesystems(self):
        return self._items


class FakeRecordTarget:
    def __init__(self):
        self.calls = []

    def record_vmdk(self, out_file=None):
        self.calls.append(out_file)


class ShellBehaviorTests(unittest.TestCase):
    def _build_elf64(self):
        ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
        header = struct.pack(
            "<HHIQQQIHHHHHH",
            2,
            62,
            1,
            0x401000,
            0,
            0,
            0,
            64,
            0,
            0,
            0,
            0,
            0,
        )
        return ident + header

    def _build_bzimage(self):
        data = bytearray(0x400)
        data[0x1F1] = 0x0E
        data[0x1FE:0x200] = b"\x55\xaa"
        data[0x202:0x206] = b"HdrS"
        data[0x206:0x208] = (0x020B).to_bytes(2, "little")
        data[0x211] = 0x01
        return bytes(data)

    def _build_cpio_newc(self, entries=None, crc=False):
        if entries is None:
            entries = [("TRAILER!!!", b"")]

        magic = b"070702" if crc else b"070701"
        chunks = []
        ino = 1

        for name, payload in entries:
            namesize = len(name.encode("latin-1")) + 1
            header = (
                magic
                + f"{ino:08x}".encode()
                + b"000081A4"
                + b"00000000"
                + b"00000000"
                + b"00000001"
                + b"00000000"
                + f"{len(payload):08x}".encode()
                + b"00000000"
                + b"00000000"
                + b"00000000"
                + b"00000000"
                + f"{namesize:08x}".encode()
                + b"00000000"
            )
            name_bytes = name.encode("latin-1") + b"\x00"
            chunk = header + name_bytes
            while len(chunk) % 4:
                chunk += b"\x00"
            chunk += payload
            while len(chunk) % 4:
                chunk += b"\x00"
            chunks.append(chunk)
            ino += 1

        return b"".join(chunks)

    def _build_uimage(self):
        data = bytearray(64)
        data[0:4] = (0x27051956).to_bytes(4, "big")
        data[8:12] = (1710000000).to_bytes(4, "big")
        data[12:16] = (0x123456).to_bytes(4, "big")
        data[16:20] = (0x8000).to_bytes(4, "big")
        data[20:24] = (0x8000).to_bytes(4, "big")
        data[28] = 5
        data[29] = 2
        data[30] = 2
        data[31] = 1
        data[32:32 + len(b"Linux-ARM")] = b"Linux-ARM"
        return bytes(data)

    def _build_fit(self):
        strings = b"description\x00default\x00compatible\x00"
        off_description = 0
        off_default = len(b"description\x00")
        off_compatible = off_default + len(b"default\x00")

        def be32(v): return v.to_bytes(4, "big")

        struct_parts = []
        struct_parts.extend([be32(1), b"\x00\x00\x00\x00"])  # root
        struct_parts.extend([be32(3), be32(len(b"Test FIT\x00")), be32(off_description), b"Test FIT\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.extend([be32(3), be32(len(b"u-boot,fit\x00")), be32(off_compatible), b"u-boot,fit\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.extend([be32(1), b"images\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.extend([be32(1), b"kernel-1\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.append(be32(2))
        struct_parts.extend([be32(1), b"fdt-1\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.append(be32(2))
        struct_parts.append(be32(2))
        struct_parts.extend([be32(1), b"configurations\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.extend([be32(3), be32(len(b"conf-1\x00")), be32(off_default), b"conf-1\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.extend([be32(1), b"conf-1\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.append(be32(2))
        struct_parts.append(be32(2))
        struct_parts.append(be32(9))
        struct_block = b"".join(struct_parts)

        off_struct = 0x38
        off_strings = off_struct + len(struct_block)
        total_size = off_strings + len(strings)
        data = bytearray(total_size)
        data[0:4] = b"\xd0\x0d\xfe\xed"
        data[4:8] = be32(total_size)
        data[8:12] = be32(off_struct)
        data[12:16] = be32(off_strings)
        data[16:20] = be32(0)
        data[20:24] = be32(17)
        data[24:28] = be32(16)
        data[28:32] = be32(0)
        data[32:36] = be32(len(strings))
        data[36:40] = be32(len(struct_block))
        data[off_struct:off_struct + len(struct_block)] = struct_block
        data[off_strings:off_strings + len(strings)] = strings
        return bytes(data)

    def _build_dtb(self):
        strings = b"model\x00compatible\x00"
        off_model = 0
        off_compatible = len(b"model\x00")

        def be32(v): return v.to_bytes(4, "big")

        struct_parts = []
        struct_parts.extend([be32(1), b"\x00\x00\x00\x00"])  # root
        struct_parts.extend([be32(3), be32(len(b"DemoBoard\x00")), be32(off_model), b"DemoBoard\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.extend([be32(3), be32(len(b"demo,board\x00")), be32(off_compatible), b"demo,board\x00"])
        while len(struct_parts[-1]) % 4:
            struct_parts[-1] += b"\x00"
        struct_parts.append(be32(2))
        struct_parts.append(be32(9))
        struct_block = b"".join(struct_parts)

        off_struct = 0x38
        off_strings = off_struct + len(struct_block)
        total_size = off_strings + len(strings)
        data = bytearray(total_size)
        data[0:4] = b"\xd0\x0d\xfe\xed"
        data[4:8] = be32(total_size)
        data[8:12] = be32(off_struct)
        data[12:16] = be32(off_strings)
        data[16:20] = be32(0)
        data[20:24] = be32(17)
        data[24:28] = be32(16)
        data[28:32] = be32(0)
        data[32:36] = be32(len(strings))
        data[36:40] = be32(len(struct_block))
        data[off_struct:off_struct + len(struct_block)] = struct_block
        data[off_strings:off_strings + len(strings)] = strings
        return bytes(data)

    def _build_efi_pe(self):
        data = bytearray(512)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        data[0x80:0x84] = b"PE\x00\x00"
        data[0x84:0x86] = (0x8664).to_bytes(2, "little")
        data[0x98:0x9A] = (0x20B).to_bytes(2, "little")
        data[0x98 + 68:0x98 + 70] = (10).to_bytes(2, "little")
        return bytes(data)

    def _build_squashfs(self):
        data = bytearray(96)
        data[0:4] = b"hsqs"
        data[4:8] = (123).to_bytes(4, "little")
        data[12:16] = (131072).to_bytes(4, "little")
        data[28:30] = (4).to_bytes(2, "little")
        data[30:32] = (0).to_bytes(2, "little")
        return bytes(data)

    def _build_extfs(self, compat=0, incompat=0, ro_compat=0):
        data = bytearray(4096)
        data[1024 + 0x18:1024 + 0x1C] = (1).to_bytes(4, "little")
        data[1024 + 0x38:1024 + 0x3A] = b"\x53\xef"
        data[1024 + 0x4C:1024 + 0x50] = (1).to_bytes(4, "little")
        data[1024 + 0x5C:1024 + 0x60] = compat.to_bytes(4, "little")
        data[1024 + 0x60:1024 + 0x64] = incompat.to_bytes(4, "little")
        data[1024 + 0x64:1024 + 0x68] = ro_compat.to_bytes(4, "little")
        data[1024 + 0x78:1024 + 0x78 + len(b"rootfs")] = b"rootfs"
        return bytes(data)

    def _build_ufs2(self):
        data = bytearray(0x12000)
        base = 0x10000 + 0x55C
        data[base:base + 4] = (0x19540119).to_bytes(4, "little")
        return bytes(data)

    def test_partition_number_prefers_source_partition_index(self):
        ops = FakeOps([
            {
                "index": 1,
                "display_index": 1,
                "source_index": 1,
                "name": "p1",
                "partition": {"first_lba": 0, "size_bytes": 0},
                "fs_kind": "ufs2",
                "fs": FakeFS({}),
            },
            {
                "index": 2,
                "display_index": 2,
                "source_index": 2,
                "name": "p2/a",
                "partition": {"first_lba": 0, "size_bytes": 0},
                "fs_kind": "ufs2",
                "fs": FakeFS({}),
            },
            {
                "index": 3,
                "display_index": 3,
                "source_index": 2,
                "name": "p2/d",
                "partition": {"first_lba": 0, "size_bytes": 0},
                "fs_kind": "ufs2",
                "fs": FakeFS({}),
            },
        ])

        ops.want_partition = 2
        names = [item["name"] for item in ops._iter_filesystems()]
        self.assertEqual(names, ["p2/a", "p2/d"])

    def test_ls_empty_directory_is_not_reported_as_not_found(self):
        empty_dir = {
            "i_mode": stat.S_IFDIR | 0o755,
            "i_size": 0,
            "entries": [],
        }
        fs = FakeFS({"/empty": empty_dir})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ufs2",
            "fs": fs,
        }])

        output = io.StringIO()
        with redirect_stdout(output):
            ops.ls("/empty", long=True)

        rendered = output.getvalue()
        self.assertIn("=== p1:/empty ===", rendered)
        self.assertIn("(empty)", rendered)
        self.assertNotIn("not found: /empty", rendered)

    def test_cmd_ls_accepts_command_string(self):
        class Recorder:
            def __init__(self):
                self.calls = []

            def ls(self, path, long=False):
                self.calls.append((path, long))

        recorder = Recorder()
        shell = VMDKShell(recorder)
        shell.cmd_ls("ls -l /")

        self.assertEqual(recorder.calls, [("/", True)])

    def test_cmd_record_routes_optional_output_path(self):
        target = FakeRecordTarget()
        shell = VMDKShell(target)

        shell.cmd_record([])
        shell.cmd_record(["snapshot.vmdk"])

        self.assertEqual(target.calls, [None, "snapshot.vmdk"])

    def test_tool_list_shows_builtin_tools(self):
        shell = VMDKShell(FakeRecordTarget())
        output = io.StringIO()
        with redirect_stdout(output):
            shell.cmd_tool([])

        rendered = output.getvalue()
        self.assertIn("dd", rendered)
        self.assertIn("file", rendered)
        self.assertIn("hexdump", rendered)
        self.assertIn("readelf", rendered)

    def test_view_command_switches_tool_view(self):
        shell = VMDKShell(FakeRecordTarget())
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("view", ["host"])

        self.assertEqual(shell.tool_view, "host")
        self.assertIn("tool view -> host", output.getvalue())

    def test_execute_command_file_reports_elf_binary(self):
        elf_inode = {
            "i_mode": stat.S_IFREG | 0o755,
            "i_size": 64,
            "data": self._build_elf64(),
        }
        fs = FakeFS({"/bin/app": elf_inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/bin/app"])

        rendered = output.getvalue()
        self.assertIn("/bin/app: ELF 64-bit LSB executable", rendered)
        self.assertIn("X86-64", rendered)

    def test_execute_command_file_reports_linux_bzimage(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 0x400,
            "data": self._build_bzimage(),
        }
        fs = FakeFS({"/boot/flatkc": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/flatkc"])

        rendered = output.getvalue()
        self.assertIn("/boot/flatkc: Linux kernel", rendered)
        self.assertIn("bzImage", rendered)
        self.assertIn("version=0x020b", rendered)

    def test_execute_command_file_reports_cpio_archive(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 128,
            "data": self._build_cpio_newc(),
        }
        fs = FakeFS({"/boot/initramfs.cpio": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/initramfs.cpio"])

        rendered = output.getvalue()
        self.assertIn("ASCII cpio archive (SVR4 with no CRC)", rendered)
        self.assertIn("likely initramfs", rendered)

    def test_execute_command_file_reports_gzip_wrapped_initramfs(self):
        payload = gzip.compress(self._build_cpio_newc())
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": len(payload),
            "data": payload,
        }
        fs = FakeFS({"/boot/initramfs.img": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/initramfs.img"])

        rendered = output.getvalue()
        self.assertIn("gzip compressed data", rendered)
        self.assertIn("embedded ASCII cpio archive", rendered)

    def test_execute_command_file_reports_cpio_generator_hint(self):
        data = self._build_cpio_newc([
            ("init", b""),
            ("usr/lib/initcpio/init", b""),
            ("usr/lib/modules/6.6.0/kernel/fs/ext4/ext4.ko", b""),
            ("usr/lib/firmware/amdgpu/sample.bin", b""),
            ("TRAILER!!!", b""),
        ])
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": len(data),
            "data": data,
        }
        fs = FakeFS({"/boot/initramfs-mkinitcpio.img": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/initramfs-mkinitcpio.img"])

        rendered = output.getvalue()
        self.assertIn("entries=5", rendered)
        self.assertIn("modules=1", rendered)
        self.assertIn("firmware=1", rendered)
        self.assertIn("generator=mkinitcpio", rendered)
        self.assertIn("likely initramfs", rendered)

    def test_execute_command_file_reports_cpio_microcode_hint(self):
        data = self._build_cpio_newc([
            ("kernel/x86/microcode/GenuineIntel.bin", b""),
            ("TRAILER!!!", b""),
        ])
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": len(data),
            "data": data,
        }
        fs = FakeFS({"/boot/early.cpio": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/early.cpio"])

        rendered = output.getvalue()
        self.assertIn("early-microcode", rendered)

    def test_execute_command_file_reports_uboot_uimage(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 64,
            "data": self._build_uimage(),
        }
        fs = FakeFS({"/boot/uImage": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/uImage"])

        rendered = output.getvalue()
        self.assertIn("U-Boot legacy uImage", rendered)
        self.assertIn("Linux/ARM", rendered)
        self.assertIn("kernel", rendered)

    def test_execute_command_file_reports_fit_image(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 256,
            "data": self._build_fit(),
        }
        fs = FakeFS({"/boot/fit.itb": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/fit.itb"])

        rendered = output.getvalue()
        self.assertIn("U-Boot FIT image", rendered)
        self.assertIn("version=17", rendered)
        self.assertIn("description=\"Test FIT\"", rendered)
        self.assertIn("default=\"conf-1\"", rendered)
        self.assertIn("images=kernel-1,fdt-1", rendered)
        self.assertIn("configs=conf-1", rendered)

    def test_execute_command_file_reports_device_tree_blob(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": len(self._build_dtb()),
            "data": self._build_dtb(),
        }
        fs = FakeFS({"/boot/devicetree.dtb": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/devicetree.dtb"])

        rendered = output.getvalue()
        self.assertIn("Device Tree Blob", rendered)
        self.assertIn("model=\"DemoBoard\"", rendered)
        self.assertIn("compatible=\"demo,board\"", rendered)

    def test_execute_command_file_reports_efi_pe(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 512,
            "data": self._build_efi_pe(),
        }
        fs = FakeFS({"/EFI/BOOT/BOOTX64.EFI": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/EFI/BOOT/BOOTX64.EFI"])

        rendered = output.getvalue()
        self.assertIn("PE32+ executable (EFI application) x86-64", rendered)

    def test_execute_command_file_reports_zstd(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 16,
            "data": b"\x28\xb5\x2f\xfd" + b"\x00" * 12,
        }
        fs = FakeFS({"/boot/initramfs.zst": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/initramfs.zst"])

        self.assertIn("Zstandard compressed data", output.getvalue())

    def test_execute_command_file_reports_lz4_frame(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 16,
            "data": b"\x04\x22\x4d\x18" + b"\x00" * 12,
        }
        fs = FakeFS({"/boot/initramfs.lz4": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/initramfs.lz4"])

        self.assertIn("LZ4 compressed data (frame)", output.getvalue())

    @unittest.skipIf(zstandard is None, "zstandard module not available")
    def test_execute_command_file_reports_zstd_wrapped_initramfs(self):
        payload = zstandard.ZstdCompressor().compress(self._build_cpio_newc())
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": len(payload),
            "data": payload,
        }
        fs = FakeFS({"/boot/initramfs.zst": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/initramfs.zst"])

        rendered = output.getvalue()
        self.assertIn("Zstandard compressed data", rendered)
        self.assertIn("embedded ASCII cpio archive", rendered)

    @unittest.skipIf(lz4_frame is None, "lz4.frame module not available")
    def test_execute_command_file_reports_lz4_wrapped_initramfs(self):
        payload = lz4_frame.compress(self._build_cpio_newc())
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": len(payload),
            "data": payload,
        }
        fs = FakeFS({"/boot/initramfs.lz4": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/boot/initramfs.lz4"])

        rendered = output.getvalue()
        self.assertIn("LZ4 compressed data (frame)", rendered)
        self.assertIn("embedded ASCII cpio archive", rendered)

    def test_execute_command_file_reports_squashfs(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 96,
            "data": self._build_squashfs(),
        }
        fs = FakeFS({"/images/root.sqsh": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/images/root.sqsh"])

        rendered = output.getvalue()
        self.assertIn("Squashfs filesystem", rendered)
        self.assertIn("version 4.0", rendered)

    def test_execute_command_file_reports_ext2_filesystem_image(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 4096,
            "data": self._build_extfs(),
        }
        fs = FakeFS({"/images/root.ext": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/images/root.ext"])

        rendered = output.getvalue()
        self.assertIn("ext2 filesystem", rendered)
        self.assertIn("volume=\"rootfs\"", rendered)

    def test_execute_command_file_reports_ext3_filesystem_image(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 4096,
            "data": self._build_extfs(compat=0x0004),
        }
        fs = FakeFS({"/images/root.ext3": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/images/root.ext3"])

        self.assertIn("ext3 filesystem", output.getvalue())

    def test_execute_command_file_reports_ext4_filesystem_image(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 4096,
            "data": self._build_extfs(compat=0x0004, incompat=0x0040),
        }
        fs = FakeFS({"/images/root.ext4": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/images/root.ext4"])

        self.assertIn("ext4 filesystem", output.getvalue())

    def test_execute_command_file_reports_ufs2_filesystem_image(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 0x12000,
            "data": self._build_ufs2(),
        }
        fs = FakeFS({"/images/root.ufs": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["/images/root.ufs"])

        rendered = output.getvalue()
        self.assertIn("UFS2 filesystem", rendered)

    def test_execute_command_file_prefers_external_file_backend_when_available(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 4,
            "data": b"ABCD",
        }
        fs = FakeFS({"/boot/flatkc": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()

        class Result:
            returncode = 0
            stdout = "Linux kernel x86 boot executable bzImage\n"

        with patch("vmdkshell_tools.file_tool.shutil.which", return_value="file"), patch("vmdkshell_tools.file_tool.subprocess.run", return_value=Result()):
            with redirect_stdout(output):
                shell.execute_command("file", ["/boot/flatkc"])

        rendered = output.getvalue()
        self.assertIn("/boot/flatkc: Linux kernel x86 boot executable bzImage", rendered)

    def test_execute_command_readelf_header_renders_elf_header(self):
        elf_inode = {
            "i_mode": stat.S_IFREG | 0o755,
            "i_size": 64,
            "data": self._build_elf64(),
        }
        fs = FakeFS({"/bin/app": elf_inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("readelf", ["-h", "/bin/app"])

        rendered = output.getvalue()
        self.assertIn("ELF Header:", rendered)
        self.assertIn("Class:                             ELF64", rendered)
        self.assertIn("Machine:                           Advanced Micro Devices X86-64", rendered)

    def test_execute_command_hexdump_renders_canonical_output(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 17,
            "data": b"hello\x00world\n12345",
        }
        fs = FakeFS({"/data.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("hexdump", ["-s", "1", "-n", "8", "/data.bin"])

        rendered = output.getvalue()
        self.assertIn("00000001", rendered)
        self.assertIn("|ello.wor        |", rendered)
        self.assertTrue(rendered.rstrip().endswith("00000009"))

    def test_execute_command_dd_writes_requested_slice(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 16,
            "data": b"0123456789abcdef",
        }
        fs = FakeFS({"/data.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "chunk.bin")
            output = io.StringIO()
            with redirect_stdout(output):
                shell.execute_command("dd", ["/data.bin", out_file, "bs=4", "skip=1", "count=2"])

            with open(out_file, "rb") as fp:
                self.assertEqual(fp.read(), b"456789ab")

            rendered = output.getvalue()
            self.assertIn("8 bytes copied", rendered)
            self.assertIn("2 block(s) written, bs=4", rendered)

    def test_execute_command_hexdump_reads_selected_raw_region(self):
        item = {
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "start_byte": 4, "size_bytes": 8},
            "fs_kind": None,
            "fs": None,
        }
        ops = FakeOps([item], raw_bytes=b"0123456789abcdef")
        ops.want_partition = "p1"
        shell = VMDKShell(ops)
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("hexdump", ["-n", "4", "@selected"])

        rendered = output.getvalue()
        self.assertIn("00000000", rendered)
        self.assertIn("|4567", rendered)
        self.assertTrue(rendered.rstrip().endswith("00000004"))

    def test_execute_command_dd_reads_named_raw_item_and_seeks_output(self):
        item = {
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "start_byte": 4, "size_bytes": 8},
            "fs_kind": None,
            "fs": None,
        }
        ops = FakeOps([item], raw_bytes=b"0123456789abcdef")
        shell = VMDKShell(ops)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "chunk.bin")
            with open(out_file, "wb") as fp:
                fp.write(b"ZZZZZZ")

            output = io.StringIO()
            with redirect_stdout(output):
                shell.execute_command(
                    "dd",
                    ["if=@item:p1", f"of={out_file}", "skip_bytes=2", "count_bytes=3", "seek_bytes=1"],
                )

            with open(out_file, "rb") as fp:
                self.assertEqual(fp.read(), b"Z678ZZ")

            rendered = output.getvalue()
            self.assertIn("source: item:p1", rendered)
            self.assertIn("input offset: 2 bytes", rendered)
            self.assertIn("output offset: 1 bytes", rendered)

    def test_execute_command_dd_conv_notrunc_preserves_tail(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 8,
            "data": b"01234567",
        }
        fs = FakeFS({"/data.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "out.bin")
            with open(out_file, "wb") as fp:
                fp.write(b"ABCDEFGH")

            shell.execute_command("dd", ["/data.bin", out_file, "count_bytes=3", "conv=notrunc"])

            with open(out_file, "rb") as fp:
                self.assertEqual(fp.read(), b"012DEFGH")

    def test_execute_command_dd_conv_sync_pads_short_block(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 3,
            "data": b"abc",
        }
        fs = FakeFS({"/tiny.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "sync.bin")
            shell.execute_command("dd", ["/tiny.bin", out_file, "bs=4", "count=1", "conv=sync"])

            with open(out_file, "rb") as fp:
                self.assertEqual(fp.read(), b"abc\x00")

    def test_execute_command_dd_iflag_skip_and_count_bytes(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 10,
            "data": b"0123456789",
        }
        fs = FakeFS({"/data.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "bytes.bin")
            shell.execute_command(
                "dd",
                ["/data.bin", out_file, "bs=4", "skip=2", "count=3", "iflag=skip_bytes,count_bytes"],
            )

            with open(out_file, "rb") as fp:
                self.assertEqual(fp.read(), b"234")

    def test_execute_command_dd_oflag_append_appends_output(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 6,
            "data": b"012345",
        }
        fs = FakeFS({"/data.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "append.bin")
            with open(out_file, "wb") as fp:
                fp.write(b"AA")

            shell.execute_command("dd", ["/data.bin", out_file, "count_bytes=2", "oflag=append"])

            with open(out_file, "rb") as fp:
                self.assertEqual(fp.read(), b"AA01")

    def test_execute_command_dd_status_none_suppresses_summary(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 4,
            "data": b"data",
        }
        fs = FakeFS({"/data.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "quiet.bin")
            output = io.StringIO()
            with redirect_stdout(output):
                shell.execute_command("dd", ["/data.bin", out_file, "status=none"])

            self.assertEqual(output.getvalue(), "")

    def test_execute_command_dd_status_progress_prints_progress(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 4,
            "data": b"data",
        }
        fs = FakeFS({"/data.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "progress.bin")
            output = io.StringIO()
            with redirect_stdout(output):
                shell.execute_command("dd", ["/data.bin", out_file, "bs=2", "status=progress"])

            rendered = output.getvalue()
            self.assertIn("progress:", rendered)
            self.assertIn("4 bytes copied", rendered)

    def test_execute_command_dd_reads_host_file(self):
        shell = VMDKShell(FakeOps([]))

        with tempfile.TemporaryDirectory() as tmpdir:
            host_in = os.path.join(tmpdir, "host.bin")
            host_out = os.path.join(tmpdir, "copy.bin")
            with open(host_in, "wb") as fp:
                fp.write(b"host-data")

            shell.execute_command("dd", [f"if=@host:{host_in}", f"of={host_out}", "count_bytes=4"])

            with open(host_out, "rb") as fp:
                self.assertEqual(fp.read(), b"host")

    def test_execute_command_hexdump_reads_host_file(self):
        shell = VMDKShell(FakeOps([]))

        with tempfile.TemporaryDirectory() as tmpdir:
            host_in = os.path.join(tmpdir, "host.bin")
            with open(host_in, "wb") as fp:
                fp.write(b"ABCD")

            output = io.StringIO()
            with redirect_stdout(output):
                shell.execute_command("hexdump", [f"@host:{host_in}"])

            rendered = output.getvalue()
            self.assertIn("00000000", rendered)
            self.assertIn("|ABCD", rendered)

    def test_execute_command_file_falls_back_to_host_file(self):
        shell = VMDKShell(FakeOps([]))

        with tempfile.TemporaryDirectory() as tmpdir:
            host_in = os.path.join(tmpdir, "note.txt")
            with open(host_in, "wb") as fp:
                fp.write(b"hello host\n")

            output = io.StringIO()
            with redirect_stdout(output):
                shell.execute_command("file", [host_in])

            rendered = output.getvalue()
            self.assertIn(host_in, rendered)
            self.assertIn("ASCII text", rendered)

    def test_execute_command_dd_uses_host_view_for_plain_path(self):
        shell = VMDKShell(FakeOps([]))
        shell.tool_view = "host"

        with tempfile.TemporaryDirectory() as tmpdir:
            host_in = os.path.join(tmpdir, "host.bin")
            host_out = os.path.join(tmpdir, "copy.bin")
            with open(host_in, "wb") as fp:
                fp.write(b"host-data")

            shell.execute_command("dd", [f"if={host_in}", f"of={host_out}", "count_bytes=4"])

            with open(host_out, "rb") as fp:
                self.assertEqual(fp.read(), b"host")

    def test_execute_command_file_uses_image_prefix_in_host_view(self):
        inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 4,
            "data": b"ABCD",
        }
        fs = FakeFS({"/data.bin": inode})
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "p1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])
        shell = VMDKShell(ops)
        shell.tool_view = "host"
        output = io.StringIO()
        with redirect_stdout(output):
            shell.execute_command("file", ["@image:/data.bin"])

        rendered = output.getvalue()
        self.assertIn("/data.bin: ASCII text", rendered)

    def test_execute_command_readelf_reads_host_file(self):
        shell = VMDKShell(FakeOps([]))

        with tempfile.TemporaryDirectory() as tmpdir:
            host_in = os.path.join(tmpdir, "app.elf")
            with open(host_in, "wb") as fp:
                fp.write(self._build_elf64())

            output = io.StringIO()
            with redirect_stdout(output):
                shell.execute_command("readelf", ["-h", f"@host:{host_in}"])

            rendered = output.getvalue()
            self.assertIn("ELF Header:", rendered)
            self.assertIn("Class:                             ELF64", rendered)

    def test_record_vmdk_copies_current_file(self):
        class RecordOps(VMDKShellOps):
            def __init__(self, file_name):
                self.fileName = file_name
                self.file = None

        with tempfile.TemporaryDirectory() as tmpdir:
            source = os.path.join(tmpdir, "disk.vmdk")
            target = os.path.join(tmpdir, "snapshot.vmdk")

            with open(source, "wb") as f:
                f.write(b"current-state")

            ops = RecordOps(source)
            output = io.StringIO()
            with redirect_stdout(output):
                ops.record_vmdk(target)

            with open(target, "rb") as f:
                self.assertEqual(f.read(), b"current-state")

            self.assertIn("record success:", output.getvalue())
            if ops.file and not ops.file.closed:
                ops.file.close()

    def test_extract_filesystem_exports_tree(self):
        file_inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 5,
            "i_mtime": 1700000000,
            "data": b"hello",
        }
        child_dir = {
            "i_mode": stat.S_IFDIR | 0o755,
            "i_size": 0,
            "i_mtime": 1700000000,
            "entries": [
                {"name": "file.txt", "inode_obj": file_inode, "i_mode": file_inode["i_mode"], "i_size": file_inode["i_size"], "is_dir": False},
            ],
        }
        root_dir = {
            "i_mode": stat.S_IFDIR | 0o755,
            "i_size": 0,
            "i_mtime": 1700000000,
            "entries": [
                {"name": "child", "inode_obj": child_dir, "i_mode": child_dir["i_mode"], "i_size": child_dir["i_size"], "is_dir": True},
            ],
        }
        fs = FakeFS({
            "/": root_dir,
            "/child": child_dir,
            "/child/file.txt": file_inode,
        })
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "partition_1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])

        with tempfile.TemporaryDirectory() as tmpdir:
            output = io.StringIO()
            with redirect_stdout(output):
                ops.extract_filesystem(tmpdir)

            with open(os.path.join(tmpdir, "child", "file.txt"), "rb") as f:
                self.assertEqual(f.read(), b"hello")

            self.assertIn("extract success:", output.getvalue())

    def test_extract_filesystem_exports_subtree(self):
        file_inode = {
            "i_mode": stat.S_IFREG | 0o644,
            "i_size": 5,
            "i_mtime": 1700000000,
            "data": b"hello",
        }
        child_dir = {
            "i_mode": stat.S_IFDIR | 0o755,
            "i_size": 0,
            "i_mtime": 1700000000,
            "entries": [
                {"name": "file.txt", "inode_obj": file_inode, "i_mode": file_inode["i_mode"], "i_size": file_inode["i_size"], "is_dir": False},
            ],
        }
        root_dir = {
            "i_mode": stat.S_IFDIR | 0o755,
            "i_size": 0,
            "i_mtime": 1700000000,
            "entries": [
                {"name": "child", "inode_obj": child_dir, "i_mode": child_dir["i_mode"], "i_size": child_dir["i_size"], "is_dir": True},
            ],
        }
        fs = FakeFS({
            "/": root_dir,
            "/child": child_dir,
            "/child/file.txt": file_inode,
        })
        ops = FakeOps([{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": "partition_1",
            "partition": {"first_lba": 0, "size_bytes": 0},
            "fs_kind": "ext",
            "fs": fs,
        }])

        with tempfile.TemporaryDirectory() as tmpdir:
            ops.extract_filesystem(tmpdir, "/child")

            with open(os.path.join(tmpdir, "child", "file.txt"), "rb") as f:
                self.assertEqual(f.read(), b"hello")

    def test_open_image_uses_raw_path_for_non_vmdk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = os.path.join(tmpdir, "initramfs")
            with open(image_path, "wb") as f:
                f.write(b"UFS2")

            with patch.object(VMDK, "analyze_raw") as analyze_raw, patch.object(VMDK, "analyze_virtual_disk") as analyze_virtual:
                obj = VMDK.open_image(image_path)

            analyze_raw.assert_called_once_with(image_path)
            analyze_virtual.assert_not_called()
            self.assertEqual(obj.fileName, image_path)

    def test_open_image_forwards_runtime_configuration(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = os.path.join(tmpdir, "initramfs")
            with open(image_path, "wb") as f:
                f.write(b"UFS2")

            with patch.object(VMDK, "analyze_raw"), patch.object(VMDK, "analyze_virtual_disk"), patch.object(VMDK, "prepare_runtime") as prepare_runtime:
                VMDK.open_image(
                    image_path,
                    partition="groupZ/home",
                    unlock_key_file="lvmkey",
                )

            prepare_runtime.assert_called_once_with(
                partition="groupZ/home",
                unlock_key_file="lvmkey",
                auto_unlock=True,
            )

    def test_prepare_runtime_auto_unlock_does_not_select_unlocked_view(self):
        obj = VMDK.__new__(VMDK)
        obj.want_partition = None

        with patch.object(VMDK, "set_partition") as set_partition, patch.object(VMDK, "try_unlock_with_key") as try_unlock:
            VMDK.prepare_runtime(
                obj,
                partition="groupZ/home",
                unlock_key_file="lvmkey",
                auto_unlock=True,
            )

        set_partition.assert_called_once_with("groupZ/home")
        try_unlock.assert_called_once_with(
            "lvmkey",
            stop_after_first=True,
            select_result=False,
        )


if __name__ == "__main__":
    unittest.main()
