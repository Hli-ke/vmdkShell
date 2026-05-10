import bz2
import gzip
import io
import os
import re
import stat
import struct
import shutil
import subprocess
import tempfile
import lzma
try:
    import lz4.frame as lz4_frame
except ImportError:  # pragma: no cover - optional dependency
    lz4_frame = None
try:
    import zstandard
except ImportError:  # pragma: no cover - optional dependency
    zstandard = None

from filesystems.ufs import detect_ufs
from .base import ShellTool
from .elf import describe_elf
from .magic_engine import VendoredMagicEngine
from .source_utils import resolve_host_path, resolve_source


class FileTool(ShellTool):
    name = "file"
    description = "identify file type"
    usage = "file <path|@host:path>"
    _vendored_engine = None

    def run(self, shell, argv):
        if len(argv) != 1:
            print(f"usage: {self.usage}")
            return

        if argv[0].startswith("@host:") or argv[0].startswith("host:"):
            self._run_host(argv[0], shell)
            return

        path = shell.resolve_path(argv[0])
        _, fs, inode = shell.vmdk.get_path_entry(path)
        if fs is not None and inode is not None:
            mode = inode["i_mode"]
            if stat.S_ISDIR(mode):
                print(f"{path}: directory")
                return

            if stat.S_ISLNK(mode):
                target = shell.vmdk.read_path_bytes(path, max_size=4096).decode("latin-1", errors="replace")
                print(f"{path}: symbolic link to {target}")
                return

        source = resolve_source(shell, argv[0])
        external = self._describe_with_external_backend(source)
        if external:
            print(f"{source.label}: {external}")
            return

        data = source.read(0, 8 * 1024 * 1024)
        heuristic = self._describe_bytes(data)
        if heuristic != "data":
            print(f"{source.label}: {heuristic}")
            return

        vendored = self._describe_with_vendored_magic_from_data(data)
        if vendored:
            print(f"{source.label}: {self._normalize_description(vendored)}")
            return

        print(f"{source.label}: {heuristic}")

    def _run_host(self, spec: str, shell):
        host_path = resolve_host_path(shell, spec)
        if os.path.isdir(host_path):
            print(f"{host_path}: directory")
            return
        if os.path.islink(host_path):
            print(f"{host_path}: symbolic link to {os.readlink(host_path)}")
            return

        source = resolve_source(shell, spec)
        external = self._describe_with_external_backend(source)
        if external:
            print(f"{host_path}: {external}")
            return

        data = source.read(0, 8 * 1024 * 1024)
        heuristic = self._describe_bytes(data)
        if heuristic != "data":
            print(f"{host_path}: {heuristic}")
            return

        vendored = self._describe_with_vendored_magic_from_data(data)
        if vendored:
            print(f"{host_path}: {self._normalize_description(vendored)}")
            return

        print(f"{host_path}: {heuristic}")

    def _describe_with_vendored_magic_from_data(self, data: bytes):
        if self.__class__._vendored_engine is None:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "third_party", "file_magic"))
            self.__class__._vendored_engine = VendoredMagicEngine(base_dir)

        return self.__class__._vendored_engine.describe(data)

    def _normalize_description(self, text: str):
        text = re.sub(r"\s+([,.:])", r"\1", text)
        text = re.sub(r"([,(])\s+", r"\1 ", text)
        text = re.sub(r"\s{2,}", " ", text)
        return text.strip()

    def _describe_with_external_backend(self, source):
        file_cmd = self._find_external_file_command()
        if not file_cmd:
            return None

        if source.source_type == "host" and source.host_path:
            return self._run_external_file(file_cmd, source.host_path)

        data = source.read(0, 8 * 1024 * 1024)
        suffix = ""
        if source.label:
            _, suffix = os.path.splitext(source.label)

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            return self._run_external_file(file_cmd, tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _find_external_file_command(self):
        configured = os.environ.get("VMDK_FILE_COMMAND", "").strip()
        if configured:
            return configured
        return shutil.which("file")

    def _run_external_file(self, file_cmd: str, target_path: str):
        try:
            proc = subprocess.run(
                [file_cmd, "-b", target_path],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            return None

        if proc.returncode != 0:
            return None

        result = proc.stdout.strip()
        return result or None

    def _describe_bytes(self, data: bytes):
        if data.startswith(b"\x7fELF"):
            return describe_elf(data)

        kernel_desc = self._describe_linux_kernel(data)
        if kernel_desc:
            return kernel_desc

        pe_desc = self._describe_pe_efi(data)
        if pe_desc:
            return pe_desc

        uboot_desc = self._describe_uboot_image(data)
        if uboot_desc:
            return uboot_desc

        dtb_desc = self._describe_dtb_or_fit(data)
        if dtb_desc:
            return dtb_desc

        cpio_desc = self._describe_cpio(data)
        if cpio_desc:
            return cpio_desc

        filesystem_desc = self._describe_filesystem_image(data)
        if filesystem_desc:
            return filesystem_desc

        for magic, label in (
            (b"\x1f\x8b\x08", "gzip compressed data"),
            (b"\xfd7zXZ\x00", "XZ compressed data"),
            (b"\x28\xb5\x2f\xfd", "Zstandard compressed data"),
            (b"\x04\x22\x4d\x18", "LZ4 compressed data (frame)"),
            (b"\x02\x21\x4c\x18", "LZ4 compressed data (legacy)"),
            (b"BZh", "bzip2 compressed data"),
            (b"PK\x03\x04", "ZIP archive data"),
            (b"\x89PNG\r\n\x1a\n", "PNG image data"),
            (b"\xff\xd8\xff", "JPEG image data"),
            (b"GIF87a", "GIF image data"),
            (b"GIF89a", "GIF image data"),
            (b"%PDF-", "PDF document"),
        ):
            if data.startswith(magic):
                embedded = self._describe_embedded_payload(data)
                return f"{label}, {embedded}" if embedded else label

        if data.startswith(b"#!"):
            line = data.splitlines()[0].decode("latin-1", errors="replace")
            interpreter = os.path.basename(line[2:].strip().split()[0]) if line[2:].strip() else "script"
            return f"{interpreter} script text executable"

        text_desc = self._describe_text(data)
        if text_desc:
            return text_desc

        return "data"

    def _describe_embedded_payload(self, data: bytes):
        payload = None
        try:
            if data.startswith(b"\x1f\x8b\x08"):
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as fp:
                    payload = fp.read(1024 * 1024)
            elif data.startswith(b"\xfd7zXZ\x00"):
                with lzma.LZMAFile(io.BytesIO(data)) as fp:
                    payload = fp.read(1024 * 1024)
            elif data.startswith(b"BZh"):
                payload = bz2.BZ2Decompressor().decompress(data, max_length=1024 * 1024)
            elif data.startswith(b"\x28\xb5\x2f\xfd"):
                if zstandard is None:
                    return None
                payload = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read(1024 * 1024)
            elif data.startswith((b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18")):
                if lz4_frame is None:
                    return None
                payload = lz4_frame.decompress(data[:8 * 1024 * 1024])
        except Exception:
            return None

        if not payload:
            return None

        cpio = self._describe_cpio(payload, embedded=True)
        if cpio:
            return cpio
        kernel = self._describe_linux_kernel(payload)
        if kernel:
            return kernel
        return None

    def _describe_linux_kernel(self, data: bytes):
        if len(data) < 0x220:
            return None

        boot_flag = data[0x1FE:0x200]
        header = data[0x202:0x206]
        if boot_flag != b"\x55\xaa" or header != b"HdrS":
            return None

        protocol = int.from_bytes(data[0x206:0x208], "little")
        setup_sects = data[0x1F1] or 4
        loadflags = data[0x211]
        kernel_kind = "bzImage" if (loadflags & 0x01) else "zImage"
        relocatable = ", relocatable" if (loadflags & 0x10) else ""

        return (
            f"Linux kernel x86 boot executable {kernel_kind}, "
            f"setup={setup_sects} sectors, "
            f"version=0x{protocol:04x}{relocatable}"
        )

    def _describe_cpio(self, data: bytes, embedded: bool = False):
        label = None
        if data.startswith(b"070701"):
            label = "ASCII cpio archive (SVR4 with no CRC)"
        elif data.startswith(b"070702"):
            label = "ASCII cpio archive (SVR4 with CRC)"
        elif data.startswith(b"070707"):
            label = "ASCII cpio archive (pre-SVR4 or odc)"
        else:
            return None

        meta = self._parse_cpio_metadata(data)
        suffix_parts = []
        if meta["entry_count"] is not None:
            suffix_parts.append(f"entries={meta['entry_count']}")
        if meta["has_trailer"]:
            suffix_parts.append("trailer")
        if meta.get("microcode"):
            suffix_parts.append("early-microcode")
        if meta.get("module_count"):
            suffix_parts.append(f"modules={meta['module_count']}")
        if meta.get("firmware_count"):
            suffix_parts.append(f"firmware={meta['firmware_count']}")
        if meta["generator"]:
            suffix_parts.append(f"generator={meta['generator']}")
        if meta["looks_like_initramfs"]:
            suffix_parts.append("likely initramfs")

        suffix = f", {', '.join(suffix_parts)}" if suffix_parts else ""
        if embedded:
            return f"embedded {label}{suffix}"
        return f"{label}{suffix}"

    def _parse_cpio_metadata(self, data: bytes):
        names = []
        entry_count = 0
        has_trailer = False
        offset = 0
        max_entries = 512
        limit = min(len(data), 2 * 1024 * 1024)

        if data.startswith((b"070701", b"070702")):
            while offset + 110 <= limit and entry_count < max_entries:
                header = data[offset:offset + 110]
                if header[:6] not in (b"070701", b"070702"):
                    break

                try:
                    filesize = int(header[54:62], 16)
                    namesize = int(header[94:102], 16)
                except ValueError:
                    break

                name_start = offset + 110
                name_end = name_start + namesize
                if name_end > limit or namesize <= 0:
                    break

                raw_name = data[name_start:name_end]
                name = raw_name.rstrip(b"\x00").decode("latin-1", errors="replace")
                names.append(name)
                entry_count += 1
                if name == "TRAILER!!!":
                    has_trailer = True
                    break

                file_start = (name_end + 3) & ~3
                offset = (file_start + filesize + 3) & ~3
            return self._build_cpio_meta(names, entry_count, has_trailer)

        if data.startswith(b"070707"):
            # Old ASCII cpio (odc) has a 76-byte header followed by NUL-terminated path.
            while offset + 76 <= limit and entry_count < max_entries:
                header = data[offset:offset + 76]
                if header[:6] != b"070707":
                    break
                try:
                    namesize = int(header[59:65], 8)
                    filesize = int(header[65:76], 8)
                except ValueError:
                    break

                name_start = offset + 76
                name_end = name_start + namesize
                if name_end > limit or namesize <= 0:
                    break

                raw_name = data[name_start:name_end]
                name = raw_name.rstrip(b"\x00").decode("latin-1", errors="replace")
                names.append(name)
                entry_count += 1
                if name == "TRAILER!!!":
                    has_trailer = True
                    break

                offset = name_end + filesize
                if offset & 1:
                    offset += 1
            return self._build_cpio_meta(names, entry_count, has_trailer)

        return {
            "entry_count": None,
            "has_trailer": b"TRAILER!!!" in data[:1024 * 1024],
            "generator": None,
            "looks_like_initramfs": b"TRAILER!!!" in data[:1024 * 1024],
        }

    def _build_cpio_meta(self, names: list[str], entry_count: int, has_trailer: bool):
        names_set = {name for name in names if name}

        generator = None
        if any("initcpio" in name for name in names_set) or any(name.startswith("usr/lib/initcpio/") for name in names_set):
            generator = "mkinitcpio"
        elif any(name.startswith("usr/lib/dracut/") or name.startswith("lib/dracut/") for name in names_set):
            generator = "dracut"
        elif any(name.startswith("scripts/init-") for name in names_set) or "conf/initramfs.conf" in names_set:
            generator = "initramfs-tools"

        looks_like_initramfs = has_trailer or any(
            name in names_set
            for name in ("init", "initrd", "etc/initrd-release", "usr/lib/initcpio/init")
        ) or any(name.startswith("kernel/") or name.startswith("usr/lib/modules/") for name in names_set)

        microcode = any(
            name.startswith("kernel/x86/microcode/") or name.startswith("early/")
            for name in names_set
        )
        module_count = sum(
            1 for name in names_set
            if name.startswith("usr/lib/modules/") and name.endswith(".ko")
        )
        firmware_count = sum(
            1 for name in names_set
            if name.startswith("usr/lib/firmware/") or name.startswith("lib/firmware/")
        )

        return {
            "entry_count": entry_count,
            "has_trailer": has_trailer,
            "generator": generator,
            "looks_like_initramfs": looks_like_initramfs,
            "microcode": microcode,
            "module_count": module_count,
            "firmware_count": firmware_count,
        }

    def _describe_filesystem_image(self, data: bytes):
        if data.startswith(b"hsqs") and len(data) >= 0x1C:
            inode_count = int.from_bytes(data[4:8], "little", signed=False)
            block_size = int.from_bytes(data[12:16], "little", signed=False)
            major = int.from_bytes(data[28:30], "little", signed=False)
            minor = int.from_bytes(data[30:32], "little", signed=False)
            return (
                f"Squashfs filesystem, little endian, version {major}.{minor}, "
                f"blocksize={block_size}, inodes={inode_count}"
            )

        if len(data) >= 2048 and data[1024 + 0x38:1024 + 0x3A] == b"\x53\xef":
            rev = int.from_bytes(data[1024 + 0x4C:1024 + 0x50], "little", signed=False)
            block_log = int.from_bytes(data[1024 + 0x18:1024 + 0x1C], "little", signed=False)
            block_size = 1024 << block_log
            compat = int.from_bytes(data[1024 + 0x5C:1024 + 0x60], "little", signed=False)
            incompat = int.from_bytes(data[1024 + 0x60:1024 + 0x64], "little", signed=False)
            ro_compat = int.from_bytes(data[1024 + 0x64:1024 + 0x68], "little", signed=False)
            volume = data[1024 + 0x78:1024 + 0x88].split(b"\x00", 1)[0].decode("latin-1", errors="replace")
            has_journal = bool(compat & 0x0004)
            ext4_features = bool(incompat & 0x0040 or ro_compat & 0x0040 or ro_compat & 0x0080 or incompat & 0x0200)
            if ext4_features:
                kind = "ext4 filesystem"
            elif has_journal:
                kind = "ext3 filesystem"
            else:
                kind = "ext2 filesystem"
            details = f"{kind}, blocksize={block_size}"
            if volume:
                details += f', volume="{volume}"'
            if rev:
                details += f", dynamic-revision={rev}"
            return details

        try:
            info = detect_ufs(io.BytesIO(data), 0)
        except Exception:
            info = None
        if info:
            return f"{info['kind'].upper()} filesystem, superblock=0x{info['superblock_offset']:x}"

        return None

    def _describe_dtb_or_fit(self, data: bytes):
        if len(data) < 40:
            return None
        if data[:4] != b"\xd0\x0d\xfe\xed":
            return None

        total_size = int.from_bytes(data[4:8], "big", signed=False)
        version = int.from_bytes(data[20:24], "big", signed=False)
        summary = self._parse_fdt_summary(data)
        if b"images\x00" in data[:4096] and b"configurations\x00" in data[:4096]:
            details = f"U-Boot FIT image, size={total_size}, version={version}"
            if summary.get("description"):
                details += f', description="{summary["description"]}"'
            if summary.get("default"):
                details += f', default="{summary["default"]}"'
            if summary.get("compatible"):
                details += f', compatible="{summary["compatible"]}"'
            if summary.get("image_nodes"):
                details += f", images={','.join(summary['image_nodes'][:4])}"
            if summary.get("config_nodes"):
                details += f", configs={','.join(summary['config_nodes'][:4])}"
            return details

        details = f"Device Tree Blob, size={total_size}, version={version}"
        if summary.get("model"):
            details += f', model="{summary["model"]}"'
        if summary.get("compatible"):
            details += f', compatible="{summary["compatible"]}"'
        return details

    def _parse_fdt_summary(self, data: bytes):
        result = {}
        image_nodes = []
        config_nodes = []
        if len(data) < 40:
            return result

        try:
            off_struct = int.from_bytes(data[8:12], "big", signed=False)
            off_strings = int.from_bytes(data[12:16], "big", signed=False)
            size_strings = int.from_bytes(data[32:36], "big", signed=False)
            size_struct = int.from_bytes(data[36:40], "big", signed=False)
        except Exception:
            return result

        if off_struct + size_struct > len(data) or off_strings + size_strings > len(data):
            return result

        strings = data[off_strings:off_strings + size_strings]
        struct_block = data[off_struct:off_struct + size_struct]
        pos = 0
        path = []

        while pos + 4 <= len(struct_block):
            token = int.from_bytes(struct_block[pos:pos + 4], "big", signed=False)
            pos += 4

            if token == 1:  # FDT_BEGIN_NODE
                end = struct_block.find(b"\x00", pos)
                if end == -1:
                    break
                node_name = struct_block[pos:end].decode("latin-1", errors="replace")
                current_path = "/".join(part for part in path if part)
                if current_path == "images" and node_name:
                    image_nodes.append(node_name)
                elif current_path == "configurations" and node_name:
                    config_nodes.append(node_name)
                path.append(node_name)
                pos = (end + 4) & ~3
            elif token == 2:  # FDT_END_NODE
                if path:
                    path.pop()
            elif token == 3:  # FDT_PROP
                if pos + 8 > len(struct_block):
                    break
                prop_len = int.from_bytes(struct_block[pos:pos + 4], "big", signed=False)
                name_off = int.from_bytes(struct_block[pos + 4:pos + 8], "big", signed=False)
                pos += 8
                if pos + prop_len > len(struct_block):
                    break
                value = struct_block[pos:pos + prop_len]
                pos = (pos + prop_len + 3) & ~3
                name = self._fdt_string(strings, name_off)
                current_path = "/".join(part for part in path if part)

                if current_path == "":
                    if name in ("model", "compatible", "description"):
                        rendered = self._fdt_value_string(value)
                        if rendered:
                            result[name] = rendered
                elif current_path == "configurations" and name == "default":
                    rendered = self._fdt_value_string(value)
                    if rendered:
                        result["default"] = rendered
            elif token == 4:  # FDT_NOP
                continue
            elif token == 9:  # FDT_END
                break
            else:
                break

        if image_nodes:
            result["image_nodes"] = image_nodes
        if config_nodes:
            result["config_nodes"] = config_nodes
        return result

    def _fdt_string(self, strings: bytes, offset: int):
        if offset < 0 or offset >= len(strings):
            return ""
        end = strings.find(b"\x00", offset)
        if end == -1:
            end = len(strings)
        return strings[offset:end].decode("latin-1", errors="replace")

    def _fdt_value_string(self, value: bytes):
        if not value:
            return ""
        if b"\x00" not in value:
            return value.decode("latin-1", errors="replace")
        parts = [part.decode("latin-1", errors="replace") for part in value.split(b"\x00") if part]
        return ", ".join(parts[:4])

    def _describe_uboot_image(self, data: bytes):
        if len(data) < 64:
            return None
        magic = int.from_bytes(data[:4], "big", signed=False)
        if magic != 0x27051956:
            return None

        timestamp = int.from_bytes(data[8:12], "big", signed=False)
        size = int.from_bytes(data[12:16], "big", signed=False)
        load = int.from_bytes(data[16:20], "big", signed=False)
        entry = int.from_bytes(data[20:24], "big", signed=False)
        os_id = data[28]
        arch_id = data[29]
        type_id = data[30]
        comp_id = data[31]
        name = data[32:64].split(b"\x00", 1)[0].decode("latin-1", errors="replace")

        os_name = {
            5: "Linux",
            17: "EFI",
        }.get(os_id, f"os-{os_id}")
        arch_name = {
            2: "ARM",
            3: "x86",
            24: "AArch64",
        }.get(arch_id, f"arch-{arch_id}")
        type_name = {
            2: "kernel",
            4: "multi-file",
            5: "firmware",
            6: "script",
            8: "ramdisk",
            11: "filesystem",
            14: "flatdt",
        }.get(type_id, f"type-{type_id}")
        comp_name = {
            0: "uncompressed",
            1: "gzip",
            2: "bzip2",
            3: "lzma",
            5: "lz4",
            6: "zstd",
        }.get(comp_id, f"comp-{comp_id}")

        details = f"U-Boot legacy uImage, {os_name}/{arch_name}, {type_name}, {comp_name}, size={size}, load=0x{load:x}, entry=0x{entry:x}"
        if name:
            details += f', name="{name}"'
        if timestamp:
            details += f", timestamp={timestamp}"
        return details

    def _describe_pe_efi(self, data: bytes):
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        pe_off = int.from_bytes(data[0x3C:0x40], "little", signed=False)
        if pe_off + 0x60 > len(data):
            return None
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return None

        machine = int.from_bytes(data[pe_off + 4:pe_off + 6], "little", signed=False)
        optional_magic = int.from_bytes(data[pe_off + 24:pe_off + 26], "little", signed=False)
        subsystem = int.from_bytes(data[pe_off + 24 + 68:pe_off + 24 + 70], "little", signed=False)

        machine_name = {
            0x014c: "Intel 80386",
            0x8664: "x86-64",
            0x01c0: "ARM",
            0xaa64: "AArch64",
        }.get(machine, f"machine-0x{machine:04x}")
        pe_kind = "PE32+" if optional_magic == 0x20B else "PE32" if optional_magic == 0x10B else f"PE-0x{optional_magic:x}"
        subsystem_name = {
            10: "EFI application",
            11: "EFI boot service driver",
            12: "EFI runtime driver",
        }.get(subsystem)
        if subsystem_name:
            return f"{pe_kind} executable ({subsystem_name}) {machine_name}"
        return f"{pe_kind} executable {machine_name}"

    def _describe_text(self, data: bytes):
        if not data:
            return "empty"
        if b"\x00" in data:
            return None

        decoded = None
        encoding_name = None
        for name, encoding in (("ASCII text", "ascii"), ("UTF-8 text", "utf-8")):
            try:
                decoded = data.decode(encoding)
                encoding_name = name
                break
            except UnicodeDecodeError:
                continue

        if decoded is None:
            return None

        printable = 0
        for ch in decoded:
            if ch.isprintable() or ch in "\r\n\t":
                printable += 1

        if printable / max(len(decoded), 1) < 0.9:
            return None
        return encoding_name
