import datetime
import math
import os
import stat
import time
from typing import IO, List

import const_define as const


UFS1_MAGIC = 0x00011954
UFS2_MAGIC = 0x19540119
UFS_MAGIC_OFFSET = 0x55C
UFS_ROOT_INO = 2
UFS2_SB_OFFSET_CANDIDATES = (0x10000, 0x2000)
UFS2_INODE_SIZE = 256
UFS_INLINE_SYMLINK_MAX = 120

UFS_FILETYPE_MAP = {
    0: "unknown",
    1: "fifo",
    2: "char",
    4: "dir",
    6: "block",
    8: "file",
    10: "link",
    12: "socket",
    14: "whiteout",
}


def detect_ufs(file, start_base: int):
    for sb_offset in UFS2_SB_OFFSET_CANDIDATES:
        magic_offset = start_base + sb_offset + UFS_MAGIC_OFFSET
        magic = const.u(const.read_data(file, magic_offset, 4))

        if magic == UFS1_MAGIC:
            return {
                "kind": "ufs1",
                "superblock_offset": start_base + sb_offset,
                "magic_offset": magic_offset,
                "magic": magic,
            }

        if magic == UFS2_MAGIC:
            return {
                "kind": "ufs2",
                "superblock_offset": start_base + sb_offset,
                "magic_offset": magic_offset,
                "magic": magic,
            }

    return None


class UFS2FS:
    UF_NODUMP = 0x00000001
    UF_IMMUTABLE = 0x00000002
    UF_APPEND = 0x00000004
    UF_OPAQUE = 0x00000008
    SF_ARCHIVED = 0x00010000
    SF_IMMUTABLE = 0x00020000
    SF_APPEND = 0x00040000
    SF_NOUNLINK = 0x00100000
    SF_SNAPSHOT = 0x00200000

    def __init__(self, fileName: str = None, fp: IO = None, start_base: int = 0, size_bytes: int = None):
        self.file = fp if fp else open(fileName, "rb")
        self.start_base = start_base
        self.size_bytes = size_bytes

        info = detect_ufs(self.file, self.start_base)
        if not info or info["kind"] != "ufs2":
            raise ValueError("not a UFS2 filesystem")

        self.superblock_offset = info["superblock_offset"]
        self.sb_data = const.read_data(self.file, self.superblock_offset, 0x800)

        self.fs_magic = const.u(self.sb_data[0x55C:0x560])
        self.fs_sblkno = const.u(self.sb_data[0x08:0x0C])
        self.fs_cblkno = const.u(self.sb_data[0x0C:0x10])
        self.fs_iblkno = const.u(self.sb_data[0x10:0x14])
        self.fs_dblkno = const.u(self.sb_data[0x14:0x18])
        self.fs_ncg = const.u(self.sb_data[0x2C:0x30])
        self.block_size = const.u(self.sb_data[0x30:0x34])
        self.frag_size = const.u(self.sb_data[0x34:0x38])
        self.frag = const.u(self.sb_data[0x38:0x3C])
        self.fragshift = const.u(self.sb_data[0x60:0x64])
        self.fsbtodb = const.u(self.sb_data[0x64:0x68])
        self.fs_sbsize = const.u(self.sb_data[0x68:0x6C])
        self.inode_block_frag = const.u(self.sb_data[0x10:0x14])
        self.indirect_per_block = const.u(self.sb_data[0x74:0x78])
        self.inodes_per_block = const.u(self.sb_data[0x78:0x7C])
        self.cgsize = const.u(self.sb_data[0xA0:0xA4])
        self.inodes_per_group = const.u(self.sb_data[0xB8:0xBC])
        self.frags_per_group = const.u(self.sb_data[0xBC:0xC0])
        self.mount_name = self.sb_data[0xD4:0xD4 + 468].split(b"\x00", 1)[0].decode("latin-1", errors="replace")
        self.volume_name = self.sb_data[0x2A8:0x2A8 + 32].split(b"\x00", 1)[0].decode("latin-1", errors="replace")

        self.inode_size = UFS2_INODE_SIZE
        if self.fs_ncg == 0 and self.size_bytes:
            self.fs_ncg = (self.size_bytes // self.frag_size + self.frags_per_group - 1) // self.frags_per_group

        if self.block_size == 0 or self.frag_size == 0:
            raise ValueError("invalid UFS2 superblock")

    def _inode_offset(self, inode_num: int):
        cg = inode_num // self.inodes_per_group
        local = inode_num % self.inodes_per_group

        fragno = (
            cg * self.frags_per_group +
            self.inode_block_frag +
            (local // self.inodes_per_block) * self.frag
        )

        return (
            self.start_base +
            fragno * self.frag_size +
            (local % self.inodes_per_block) * self.inode_size
        )

    def _get_inode(self, inode_num: int):
        inode_offset = self._inode_offset(inode_num)
        data = const.read_data(self.file, inode_offset, self.inode_size)

        inode = {
            "inode_num": inode_num,
            "inode_offset": inode_offset,
            "i_mode": const.u(data[0x00:0x02]),
            "i_nlink": const.u(data[0x02:0x04]),
            "i_uid": const.u(data[0x04:0x08]),
            "i_gid": const.u(data[0x08:0x0C]),
            "i_blksize": const.u(data[0x0C:0x10]),
            "i_size": const.u(data[0x10:0x18]),
            "recode_i_size_addr_8_bytes": inode_offset + 0x10,
            "i_blocks": const.u(data[0x18:0x20]),
            "i_atime": const.u(data[0x20:0x28]),
            "i_mtime": const.u(data[0x28:0x30]),
            "i_ctime": const.u(data[0x30:0x38]),
            "i_birthtime": const.u(data[0x38:0x40]),
            "i_atimensec": const.u(data[0x40:0x44]),
            "i_mtimensec": const.u(data[0x44:0x48]),
            "i_ctimensec": const.u(data[0x48:0x4C]),
            "i_birthnsec": const.u(data[0x4C:0x50]),
            "i_gen": const.u(data[0x50:0x54]),
            "i_kernflags": const.u(data[0x54:0x58]),
            "i_flags": const.u(data[0x58:0x5C]),
            "i_extsize": const.u(data[0x5C:0x60]),
            "i_db": [],
            "i_ib": [],
            "raw_data": data,
        }

        for idx in range(12):
            start = 0x70 + idx * 8
            inode["i_db"].append(const.u(data[start:start + 8]))

        for idx in range(3):
            start = 0xD0 + idx * 8
            inode["i_ib"].append(const.u(data[start:start + 8]))

        return inode

    def _read_pointer_block(self, block_id: int):
        if block_id == 0:
            return []

        data = const.read_data(
            self.file,
            self.start_base + block_id * self.frag_size,
            self.block_size,
        )

        result = []
        for i in range(0, self.block_size, 8):
            result.append(const.u(data[i:i + 8]))

        return result

    def _iter_data_blocks(self, inode: dict):
        needed = math.ceil(inode["i_size"] / self.block_size) if inode["i_size"] else 0
        yielded = 0

        for block_id in inode["i_db"]:
            if yielded >= needed:
                return
            yield block_id
            yielded += 1

        for block_id in self._read_pointer_block(inode["i_ib"][0]):
            if yielded >= needed:
                return
            yield block_id
            yielded += 1

        for level1 in self._read_pointer_block(inode["i_ib"][1]):
            for block_id in self._read_pointer_block(level1):
                if yielded >= needed:
                    return
                yield block_id
                yielded += 1

        for level2 in self._read_pointer_block(inode["i_ib"][2]):
            for level1 in self._read_pointer_block(level2):
                for block_id in self._read_pointer_block(level1):
                    if yielded >= needed:
                        return
                    yield block_id
                    yielded += 1

    def _read_inode_bytes(self, inode: dict) -> bytes:
        if stat.S_ISLNK(inode["i_mode"]) and inode["i_size"] <= UFS_INLINE_SYMLINK_MAX and inode["i_blocks"] == 0:
            return inode["raw_data"][0x70:0x70 + inode["i_size"]]

        data = bytearray()
        total_size = inode["i_size"]
        read_size = 0

        for block_id in self._iter_data_blocks(inode):
            if read_size >= total_size:
                break

            chunk_size = min(self.block_size, total_size - read_size)

            if block_id == 0:
                data.extend(b"\x00" * chunk_size)
            else:
                data.extend(const.read_data(
                    self.file,
                    self.start_base + block_id * self.frag_size,
                    chunk_size,
                ))

            read_size += chunk_size

        return bytes(data)

    def _parse_dir_entries(self, inode: dict):
        if not inode or not stat.S_ISDIR(inode["i_mode"]):
            return []

        dir_data = self._read_inode_bytes(inode)
        entries = []

        offset = 0
        while offset + 8 <= len(dir_data):
            inode_num = const.u(dir_data[offset:offset + 4])
            rec_len = const.u(dir_data[offset + 4:offset + 6])
            file_type = const.u(dir_data[offset + 6:offset + 7])
            name_len = const.u(dir_data[offset + 7:offset + 8])

            if rec_len == 0:
                break

            if inode_num == 0:
                offset += rec_len
                continue

            name = dir_data[offset + 8:offset + 8 + name_len].decode("latin-1", errors="replace")
            if name not in [".", ".."]:
                child_inode = self._get_inode(inode_num)
                entries.append({
                    "name": name,
                    "inode": inode_num,
                    "file_type": file_type,
                    "file_type_name": UFS_FILETYPE_MAP.get(file_type, f"unknown-{file_type}"),
                    "i_mode": child_inode["i_mode"],
                    "i_size": child_inode["i_size"],
                    "is_dir": stat.S_ISDIR(child_inode["i_mode"]),
                    "is_file": stat.S_ISREG(child_inode["i_mode"]),
                    "inode_obj": child_inode,
                })

            offset += rec_len

        return entries

    def find_file(self, absFileName: str):
        parts = [p for p in absFileName.split("/") if p]
        current_inode_num = UFS_ROOT_INO

        if not parts:
            return self._get_inode(current_inode_num)

        for part in parts:
            inode = self._get_inode(current_inode_num)

            if not stat.S_ISDIR(inode["i_mode"]):
                return None

            found = None
            for entry in self._parse_dir_entries(inode):
                if entry["name"] == part:
                    found = entry["inode"]
                    break

            if found is None:
                return None

            current_inode_num = found

        return self._get_inode(current_inode_num)

    def list_dir(self, path: str = "/"):
        inode = self.find_file(path)
        if inode is None or not stat.S_ISDIR(inode["i_mode"]):
            return []
        return self._parse_dir_entries(inode)

    def tree(self, path: str = "/", max_depth: int = 3):
        root_inode = self.find_file(path)

        if root_inode is None:
            print(f"path not found: {path}")
            return

        if not stat.S_ISDIR(root_inode["i_mode"]):
            print(f"not a directory: {path}")
            return

        print(path)
        self._tree_walk(path, prefix="", depth=0, max_depth=max_depth)

    def _tree_walk(self, path: str, prefix: str = "", depth: int = 0, max_depth: int = 3):
        if depth >= max_depth:
            return

        entries = self.list_dir(path)

        for idx, entry in enumerate(entries):
            is_last = idx == len(entries) - 1
            branch, pad = const.tree_branch(is_last)
            next_prefix = prefix + pad

            icon = const.dir_icon(entry["is_dir"])
            size = entry["i_size"]
            print(f"{prefix}{branch}{icon} {entry['name']} ({size} bytes)")

            if entry["is_dir"]:
                child_path = path.rstrip("/") + "/" + entry["name"]
                self._tree_walk(child_path, prefix=next_prefix, depth=depth + 1, max_depth=max_depth)

    def extract_file(self, absFileName: str, out_directory: str):
        inode = self.find_file(absFileName)
        counter = 1

        if inode is None or stat.S_ISDIR(inode["i_mode"]):
            return False

        if not os.path.exists(out_directory):
            os.makedirs(out_directory)

        filename = os.path.basename(absFileName)
        save_path = os.path.join(out_directory, filename)
        while os.path.exists(save_path):
            save_path = os.path.join(out_directory, f"{filename}_{counter}")
            counter += 1

        try:
            with open(save_path, "wb") as f_out:
                f_out.write(self._read_inode_bytes(inode))
            return True
        except Exception:
            return False

    def read_file_by_inode(self, inode: dict) -> bytes:
        return self._read_inode_bytes(inode)

    def get_replace_info(self, absFileName: str):
        inode = self.find_file(absFileName)

        if inode is None:
            return None

        if stat.S_ISDIR(inode["i_mode"]):
            raise IsADirectoryError(absFileName)

        blocks = []
        total_size = inode["i_size"]
        done = 0

        for block_id in self._iter_data_blocks(inode):
            if done >= total_size:
                break

            length = min(self.block_size, total_size - done)
            blocks.append({
                "block_id": block_id,
                "virtual_offset": self.start_base + block_id * self.frag_size if block_id != 0 else None,
                "length": length,
                "file_offset": done,
            })
            done += length

        return {
            "path": absFileName,
            "inode": inode,
            "size": inode["i_size"],
            "inode_size_virtual_offset": inode["recode_i_size_addr_8_bytes"],
            "inode_size_length": 8,
            "block_size": self.block_size,
            "blocks": blocks,
        }

    def _write_inode_u16(self, inode: dict, offset: int, value: int):
        const.write_data(self.file, inode["inode_offset"] + offset, const.p16(value))

    def _write_inode_u32(self, inode: dict, offset: int, value: int):
        const.write_data(self.file, inode["inode_offset"] + offset, const.p32(value))

    def chmod(self, absFileName: str, mode: int):
        inode = self.find_file(absFileName)
        if inode is None:
            return False

        old_mode = inode["i_mode"]
        new_mode = (old_mode & 0xF000) | (mode & 0x0FFF)
        self._write_inode_u16(inode, 0x00, new_mode)
        return True

    def format_ufs_flags(self, flags: int):
        items = [
            ("dump", self.UF_NODUMP),
            ("uchg", self.UF_IMMUTABLE),
            ("uappnd", self.UF_APPEND),
            ("opaque", self.UF_OPAQUE),
            ("arch", self.SF_ARCHIVED),
            ("schg", self.SF_IMMUTABLE),
            ("sappnd", self.SF_APPEND),
            ("sunlnk", self.SF_NOUNLINK),
            ("snap", self.SF_SNAPSHOT),
        ]
        return ",".join(name for name, bit in items if flags & bit) or "-"

    def lsattr(self, path="/"):
        entries = self.list_dir(path)
        for entry in entries:
            inode = entry["inode_obj"]
            flags = self.format_ufs_flags(inode["i_flags"])
            name = entry["name"] + ("/" if entry["is_dir"] else "")
            print(f"{flags:<32} 0x{inode['i_flags']:08x} {name}")

    def chattr(self, absFileName: str, op: str):
        inode = self.find_file(absFileName)
        if inode is None:
            return False

        if len(op) < 2 or op[0] not in "+-":
            raise ValueError("usage: chattr +i|-i|+a|-a <path>")

        attr_map = {
            "i": self.UF_IMMUTABLE,
            "a": self.UF_APPEND,
            "I": self.SF_IMMUTABLE,
            "A": self.SF_APPEND,
            "d": self.UF_NODUMP,
            "o": self.UF_OPAQUE,
        }

        flags = inode["i_flags"]
        action = op[0]

        for ch in op[1:]:
            if ch not in attr_map:
                raise ValueError(f"unsupported attr: {ch}")

            if action == "+":
                flags |= attr_map[ch]
            else:
                flags &= ~attr_map[ch]

        self._write_inode_u32(inode, 0x58, flags)
        return True

    def _split_parent_child(self, path: str):
        norm = "/" + "/".join(p for p in path.split("/") if p)
        if norm == "/":
            raise ValueError("invalid path: /")

        parent, _, name = norm.rpartition("/")
        if not parent:
            parent = "/"
        if not name:
            raise ValueError(f"invalid path: {path}")

        return parent, name

    def _entry_actual_len(self, name_len: int):
        return const.align_up(8 + name_len, 4)

    def _dir_entry_type_for_mode(self, mode: int):
        if stat.S_ISREG(mode):
            return 8
        if stat.S_ISDIR(mode):
            return 4
        if stat.S_ISCHR(mode):
            return 2
        if stat.S_ISBLK(mode):
            return 6
        if stat.S_ISFIFO(mode):
            return 1
        if stat.S_ISSOCK(mode):
            return 12
        if stat.S_ISLNK(mode):
            return 10
        return 0

    def _pack_dir_entry(self, inode_num: int, name: str, file_type: int, rec_len: int = None):
        name_bytes = name.encode("latin-1")
        actual_len = self._entry_actual_len(len(name_bytes))
        if rec_len is None:
            rec_len = actual_len

        return (
            const.p32(inode_num) +
            const.p16(rec_len) +
            const.p8(file_type) +
            const.p8(len(name_bytes)) +
            name_bytes +
            b"\x00" * (rec_len - 8 - len(name_bytes))
        )

    def _iter_dir_entry_records(self, inode: dict):
        dir_data = self._read_inode_bytes(inode)
        offset = 0

        while offset + 8 <= len(dir_data):
            inode_num = const.u(dir_data[offset:offset + 4])
            rec_len = const.u(dir_data[offset + 4:offset + 6])
            file_type = const.u(dir_data[offset + 6:offset + 7])
            name_len = const.u(dir_data[offset + 7:offset + 8])

            if rec_len == 0:
                break

            name = dir_data[offset + 8:offset + 8 + name_len].decode("latin-1", errors="replace")
            block_index = offset // self.block_size
            block_offset = offset % self.block_size
            block_id = self._get_logical_block_ptr(inode, block_index)
            actual_len = self._entry_actual_len(name_len)

            yield {
                "inode": inode_num,
                "rec_len": rec_len,
                "actual_len": actual_len,
                "name_len": name_len,
                "file_type": file_type,
                "name": name,
                "offset": offset,
                "block_index": block_index,
                "block_offset": block_offset,
                "block_id": block_id,
            }

            offset += rec_len

    def _find_dir_entry(self, dir_inode: dict, name: str):
        prev = None
        for entry in self._iter_dir_entry_records(dir_inode):
            if entry["inode"] != 0 and entry["name"] == name:
                return prev, entry
            prev = entry
        return None, None

    def _write_inode_u64(self, inode: dict, offset: int, value: int):
        const.write_data(self.file, inode["inode_offset"] + offset, const.p64(value))

    def _write_inode_ids(self, inode: dict, uid: int, gid: int):
        self._write_inode_u32(inode, 0x04, uid)
        self._write_inode_u32(inode, 0x08, gid)
        inode["i_uid"] = uid
        inode["i_gid"] = gid

    def _write_inode_size(self, inode: dict, size: int):
        self._write_inode_u64(inode, 0x10, size)
        inode["i_size"] = size

    def _write_inode_blocks(self, inode: dict, sectors: int):
        self._write_inode_u64(inode, 0x18, sectors)
        inode["i_blocks"] = sectors

    def _write_inode_links(self, inode: dict, links: int):
        self._write_inode_u16(inode, 0x02, links)
        inode["i_nlink"] = links

    def _write_inode_times(self, inode: dict, now: int):
        self._write_inode_u64(inode, 0x20, now)
        self._write_inode_u64(inode, 0x28, now)
        self._write_inode_u64(inode, 0x30, now)
        self._write_inode_u64(inode, 0x38, now)

    def _write_inode_db_ptr(self, inode: dict, index: int, value: int):
        const.write_data(self.file, inode["inode_offset"] + 0x70 + index * 8, const.p64(value))
        inode["i_db"][index] = value

    def _write_inode_ib_ptr(self, inode: dict, index: int, value: int):
        const.write_data(self.file, inode["inode_offset"] + 0xD0 + index * 8, const.p64(value))
        inode["i_ib"][index] = value

    def _write_pointer_block_entry(self, frag_addr: int, index: int, value: int):
        const.write_data(
            self.file,
            self.start_base + frag_addr * self.frag_size + index * 8,
            const.p64(value)
        )

    def _read_pointer_block_entry(self, frag_addr: int, index: int):
        return const.u(const.read_data(
            self.file,
            self.start_base + frag_addr * self.frag_size + index * 8,
            8
        ))

    def _cg_offset(self, cg: int):
        return self.start_base + (cg * self.frags_per_group + self.fs_cblkno) * self.frag_size

    def _read_cg(self, cg: int):
        data = bytearray(const.read_data(self.file, self._cg_offset(cg), self.cgsize or self.frag_size))
        return {
            "index": cg,
            "offset": self._cg_offset(cg),
            "data": data,
            "cg_magic": const.u(data[0x04:0x08]),
            "cg_cgx": const.u(data[0x0C:0x10]),
            "cg_ndblk": const.u(data[0x14:0x18]),
            "cg_cs_ndir": const.u(data[0x18:0x1C]),
            "cg_cs_nbfree": const.u(data[0x1C:0x20]),
            "cg_cs_nifree": const.u(data[0x20:0x24]),
            "cg_cs_nffree": const.u(data[0x24:0x28]),
            "cg_rotor": const.u(data[0x28:0x2C]),
            "cg_frotor": const.u(data[0x2C:0x30]),
            "cg_irotor": const.u(data[0x30:0x34]),
            "cg_iusedoff": const.u(data[0x5C:0x60]),
            "cg_freeoff": const.u(data[0x60:0x64]),
            "cg_nextfreeoff": const.u(data[0x64:0x68]),
            "cg_clustersumoff": const.u(data[0x68:0x6C]),
            "cg_clusteroff": const.u(data[0x6C:0x70]),
            "cg_nclusterblks": const.u(data[0x70:0x74]),
            "cg_niblk": const.u(data[0x74:0x78]),
            "cg_initediblk": const.u(data[0x78:0x7C]),
        }

    def _write_cg(self, cginfo: dict):
        const.write_data(self.file, cginfo["offset"], bytes(cginfo["data"]))

    def _bitmap_set(self, bitmap: bytearray, bit_index: int, value: int):
        byte_index = bit_index // 8
        bit_mask = 1 << (bit_index % 8)
        if value:
            bitmap[byte_index] |= bit_mask
        else:
            bitmap[byte_index] &= ~bit_mask & 0xFF

    def _bitmap_get(self, bitmap: bytes, bit_index: int):
        return (bitmap[bit_index // 8] >> (bit_index % 8)) & 1

    def _cg_write_u32(self, cginfo: dict, offset: int, value: int):
        cginfo["data"][offset:offset + 4] = const.p32(value)

    def _cg_adjust_counts(self, cginfo: dict, nifree: int = 0):
        if nifree:
            cginfo["cg_cs_nifree"] += nifree
            self._cg_write_u32(cginfo, 0x20, cginfo["cg_cs_nifree"])

    def _alloc_inode(self):
        for cg in range(max(self.fs_ncg, 1)):
            cginfo = self._read_cg(cg)
            bitmap = cginfo["data"]
            base = cginfo["cg_iusedoff"]

            for bit in range(self.inodes_per_group):
                inode_num = cg * self.inodes_per_group + bit
                if inode_num < UFS_ROOT_INO:
                    continue
                if self._bitmap_get(bitmap[base:], bit):
                    continue

                self._bitmap_set(bitmap, base * 8 + bit, 1)
                self._cg_adjust_counts(cginfo, nifree=-1)
                self._write_cg(cginfo)

                inode_real = inode_num
                inode = self._get_inode(inode_real)
                const.write_data(self.file, inode["inode_offset"], b"\x00" * self.inode_size)
                return inode_real

        raise RuntimeError("no free UFS2 inode")

    def _free_inode_bitmap(self, inode_num: int):
        cg = inode_num // self.inodes_per_group
        bit = inode_num % self.inodes_per_group
        cginfo = self._read_cg(cg)
        self._bitmap_set(cginfo["data"], cginfo["cg_iusedoff"] * 8 + bit, 0)
        self._cg_adjust_counts(cginfo, nifree=1)
        self._write_cg(cginfo)

    def _alloc_frag_run(self, frags_needed: int, block_aligned: bool = False):
        for cg in range(max(self.fs_ncg, 1)):
            cginfo = self._read_cg(cg)
            bitmap = cginfo["data"]
            base = cginfo["cg_freeoff"]
            limit = min(self.frags_per_group, cginfo["cg_ndblk"])

            start = 0
            while start + frags_needed <= limit:
                if block_aligned and start % self.frag != 0:
                    start += 1
                    continue

                ok = True
                for j in range(frags_needed):
                    if self._bitmap_get(bitmap[base:], start + j) == 0:
                        ok = False
                        start += j + 1
                        break

                if not ok:
                    continue

                for j in range(frags_needed):
                    self._bitmap_set(bitmap, base * 8 + start + j, 0)

                self._write_cg(cginfo)

                frag_addr = cg * self.frags_per_group + start
                const.write_data(self.file, self.start_base + frag_addr * self.frag_size, b"\x00" * (frags_needed * self.frag_size))
                return frag_addr

            # next cg

        raise RuntimeError("no free UFS2 fragment run")

    def _free_frag_run(self, frag_addr: int, frags_used: int):
        cg = frag_addr // self.frags_per_group
        local = frag_addr % self.frags_per_group
        cginfo = self._read_cg(cg)
        for j in range(frags_used):
            self._bitmap_set(cginfo["data"], cginfo["cg_freeoff"] * 8 + local + j, 1)
        self._write_cg(cginfo)

    def _logical_block_frags_for_size(self, size: int, lbn: int):
        if size <= 0:
            return 0

        start = lbn * self.block_size
        if start >= size:
            return 0

        remain = size - start
        if remain >= self.block_size:
            return self.frag

        return (remain + self.frag_size - 1) // self.frag_size

    def _get_logical_block_ptr(self, inode: dict, logical_index: int):
        if logical_index < 12:
            return inode["i_db"][logical_index]

        logical_index -= 12
        per = self.indirect_per_block

        if logical_index < per:
            if inode["i_ib"][0] == 0:
                return 0
            return self._read_pointer_block_entry(inode["i_ib"][0], logical_index)

        logical_index -= per
        span = per * per
        if logical_index < span:
            if inode["i_ib"][1] == 0:
                return 0
            block1 = self._read_pointer_block_entry(inode["i_ib"][1], logical_index // per)
            if block1 == 0:
                return 0
            return self._read_pointer_block_entry(block1, logical_index % per)

        logical_index -= span
        if inode["i_ib"][2] == 0:
            return 0
        block1 = self._read_pointer_block_entry(inode["i_ib"][2], logical_index // span)
        if block1 == 0:
            return 0
        rem = logical_index % span
        block2 = self._read_pointer_block_entry(block1, rem // per)
        if block2 == 0:
            return 0
        return self._read_pointer_block_entry(block2, rem % per)

    def _set_logical_block_ptr(self, inode: dict, logical_index: int, frag_addr: int):
        per = self.indirect_per_block
        meta_blocks = []

        if logical_index < 12:
            self._write_inode_db_ptr(inode, logical_index, frag_addr)
            return meta_blocks

        logical_index -= 12
        if logical_index < per:
            if inode["i_ib"][0] == 0:
                inode["i_ib"][0] = self._alloc_frag_run(self.frag, block_aligned=True)
                meta_blocks.append(inode["i_ib"][0])
                self._write_inode_ib_ptr(inode, 0, inode["i_ib"][0])
            self._write_pointer_block_entry(inode["i_ib"][0], logical_index, frag_addr)
            return meta_blocks

        logical_index -= per
        span = per * per
        if logical_index < span:
            if inode["i_ib"][1] == 0:
                inode["i_ib"][1] = self._alloc_frag_run(self.frag, block_aligned=True)
                meta_blocks.append(inode["i_ib"][1])
                self._write_inode_ib_ptr(inode, 1, inode["i_ib"][1])

            outer = logical_index // per
            inner = logical_index % per
            block1 = self._read_pointer_block_entry(inode["i_ib"][1], outer)
            if block1 == 0:
                block1 = self._alloc_frag_run(self.frag, block_aligned=True)
                meta_blocks.append(block1)
                self._write_pointer_block_entry(inode["i_ib"][1], outer, block1)
            self._write_pointer_block_entry(block1, inner, frag_addr)
            return meta_blocks

        logical_index -= span
        idx1 = logical_index // span
        rem = logical_index % span
        idx2 = rem // per
        idx3 = rem % per

        if inode["i_ib"][2] == 0:
            inode["i_ib"][2] = self._alloc_frag_run(self.frag, block_aligned=True)
            meta_blocks.append(inode["i_ib"][2])
            self._write_inode_ib_ptr(inode, 2, inode["i_ib"][2])

        block1 = self._read_pointer_block_entry(inode["i_ib"][2], idx1)
        if block1 == 0:
            block1 = self._alloc_frag_run(self.frag, block_aligned=True)
            meta_blocks.append(block1)
            self._write_pointer_block_entry(inode["i_ib"][2], idx1, block1)

        block2 = self._read_pointer_block_entry(block1, idx2)
        if block2 == 0:
            block2 = self._alloc_frag_run(self.frag, block_aligned=True)
            meta_blocks.append(block2)
            self._write_pointer_block_entry(block1, idx2, block2)

        self._write_pointer_block_entry(block2, idx3, frag_addr)
        return meta_blocks

    def _collect_file_runs(self, inode: dict):
        if stat.S_ISLNK(inode["i_mode"]) and inode["i_blocks"] == 0:
            return []

        runs = []
        total_size = inode["i_size"]
        count = (total_size + self.block_size - 1) // self.block_size if total_size else 0
        for lbn in range(count):
            ptr = self._get_logical_block_ptr(inode, lbn)
            frags = self._logical_block_frags_for_size(total_size, lbn)
            if ptr:
                runs.append((ptr, frags))
        return runs

    def _collect_meta_blocks(self, inode: dict):
        result = []

        def walk(block: int, depth: int):
            if block == 0:
                return
            result.append(block)
            if depth == 0:
                return
            for i in range(self.indirect_per_block):
                ptr = self._read_pointer_block_entry(block, i)
                if ptr == 0:
                    continue
                walk(ptr, depth - 1)

        walk(inode["i_ib"][0], 0)
        walk(inode["i_ib"][1], 1)
        walk(inode["i_ib"][2], 2)
        return result

    def _insert_dir_entry(self, dir_inode: dict, inode_num: int, name: str, file_type: int):
        need_len = self._entry_actual_len(len(name.encode("latin-1")))

        for entry in self._iter_dir_entry_records(dir_inode):
            if entry["block_id"] == 0:
                continue

            if entry["inode"] == 0 and entry["rec_len"] >= need_len:
                virtual = self.start_base + entry["block_id"] * self.frag_size + entry["block_offset"]
                const.write_data(self.file, virtual, self._pack_dir_entry(inode_num, name, file_type, entry["rec_len"]))
                return

            slack = entry["rec_len"] - entry["actual_len"]
            if slack < need_len:
                continue

            entry_virtual = self.start_base + entry["block_id"] * self.frag_size + entry["block_offset"]
            const.write_data(self.file, entry_virtual + 4, const.p16(entry["actual_len"]))
            const.write_data(
                self.file,
                entry_virtual + entry["actual_len"],
                self._pack_dir_entry(inode_num, name, file_type, slack)
            )
            return

        old_size = dir_inode["i_size"]
        lbn = old_size // self.block_size
        offset_in_lbn = old_size % self.block_size
        new_rec = self._pack_dir_entry(inode_num, name, file_type, 512)
        old_ptr = self._get_logical_block_ptr(dir_inode, lbn)
        old_frags = self._logical_block_frags_for_size(old_size, lbn)
        new_frags = self._logical_block_frags_for_size(old_size + 512, lbn)

        if old_ptr == 0:
            new_ptr = self._alloc_frag_run(max(new_frags, 1), block_aligned=(new_frags == self.frag))
            meta = self._set_logical_block_ptr(dir_inode, lbn, new_ptr)
            if meta:
                self._write_inode_blocks(dir_inode, dir_inode["i_blocks"] + len(meta) * (self.block_size // 512))
            const.write_data(self.file, self.start_base + new_ptr * self.frag_size, new_rec)
            self._write_inode_blocks(dir_inode, dir_inode["i_blocks"] + max(new_frags, 1) * (self.frag_size // 512))
        else:
            if new_frags > old_frags:
                new_ptr = self._alloc_frag_run(new_frags, block_aligned=(new_frags == self.frag))
                copy_len = old_frags * self.frag_size
                old_data = const.read_data(self.file, self.start_base + old_ptr * self.frag_size, copy_len)
                const.write_data(self.file, self.start_base + new_ptr * self.frag_size, old_data + b"\x00" * (new_frags * self.frag_size - copy_len))
                self._free_frag_run(old_ptr, old_frags)
                self._set_logical_block_ptr(dir_inode, lbn, new_ptr)
                self._write_inode_blocks(dir_inode, dir_inode["i_blocks"] + (new_frags - old_frags) * (self.frag_size // 512))
                old_ptr = new_ptr

            const.write_data(self.file, self.start_base + old_ptr * self.frag_size + offset_in_lbn, new_rec)

        self._write_inode_size(dir_inode, old_size + 512)

    def _remove_dir_entry(self, dir_inode: dict, name: str):
        prev, entry = self._find_dir_entry(dir_inode, name)
        if entry is None:
            raise FileNotFoundError(name)

        entry_virtual = self.start_base + entry["block_id"] * self.frag_size + entry["block_offset"]
        if prev and prev["block_index"] == entry["block_index"]:
            prev_virtual = self.start_base + prev["block_id"] * self.frag_size + prev["block_offset"]
            const.write_data(self.file, prev_virtual + 4, const.p16(prev["rec_len"] + entry["rec_len"]))
        else:
            const.write_data(self.file, entry_virtual, const.p32(0))

        return entry

    def create_file_from_host(self, src_file: str, dst_path: str):
        with open(src_file, "rb") as fp:
            data = fp.read()

        self.create_file_from_bytes(data, dst_path, mode=(os.stat(src_file).st_mode & 0o777), uid=0, gid=0)

    def create_file_from_bytes(self, data: bytes, dst_path: str, mode: int = 0o644, uid: int = 0, gid: int = 0):
        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not stat.S_ISDIR(parent_inode["i_mode"]):
            raise FileNotFoundError(parent_path)
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        inode_num = self._alloc_inode()
        inode = self._get_inode(inode_num)

        file_mode = stat.S_IFREG | (mode & 0o777)
        now = int(time.time())

        self._write_inode_u16(inode, 0x00, file_mode)
        self._write_inode_u16(inode, 0x02, 1)
        self._write_inode_ids(inode, uid, gid)
        self._write_inode_u32(inode, 0x0C, self.block_size)
        self._write_inode_size(inode, len(data))
        self._write_inode_blocks(inode, 0)
        self._write_inode_times(inode, now)
        self._write_inode_u32(inode, 0x50, 0)
        self._write_inode_u32(inode, 0x54, 0)
        self._write_inode_u32(inode, 0x58, 0)
        self._write_inode_u32(inode, 0x5C, 0)

        total_sectors = 0
        meta_blocks = 0
        count = (len(data) + self.block_size - 1) // self.block_size if data else 0
        for lbn in range(count):
            start = lbn * self.block_size
            end = min(start + self.block_size, len(data))
            chunk = data[start:end]
            frags = self._logical_block_frags_for_size(len(data), lbn)
            ptr = self._alloc_frag_run(frags, block_aligned=(frags == self.frag))
            meta = self._set_logical_block_ptr(inode, lbn, ptr)
            meta_blocks += len(meta)
            total_sectors += frags * (self.frag_size // 512)
            for meta_ptr in meta:
                total_sectors += self.block_size // 512

            alloc_bytes = frags * self.frag_size
            const.write_data(
                self.file,
                self.start_base + ptr * self.frag_size,
                chunk + b"\x00" * (alloc_bytes - len(chunk))
            )

        self._write_inode_blocks(inode, total_sectors)

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._insert_dir_entry(parent_live, inode_num, name, 8)
        self._write_inode_times(parent_live, now)

    def _clear_inode_blocks(self, inode: dict):
        for i in range(12):
            self._write_inode_db_ptr(inode, i, 0)
        for i in range(3):
            self._write_inode_ib_ptr(inode, i, 0)

    def _rewrite_regular_inode(self, inode: dict, data: bytes):
        for ptr, frags in self._collect_file_runs(inode):
            self._free_frag_run(ptr, frags)
        for ptr in self._collect_meta_blocks(inode):
            self._free_frag_run(ptr, self.frag)

        self._clear_inode_blocks(inode)
        self._write_inode_size(inode, 0)
        self._write_inode_blocks(inode, 0)

        total_sectors = 0
        count = (len(data) + self.block_size - 1) // self.block_size if data else 0
        for lbn in range(count):
            start = lbn * self.block_size
            end = min(start + self.block_size, len(data))
            chunk = data[start:end]
            frags = self._logical_block_frags_for_size(len(data), lbn)
            ptr = self._alloc_frag_run(frags, block_aligned=(frags == self.frag))
            meta = self._set_logical_block_ptr(inode, lbn, ptr)
            total_sectors += frags * (self.frag_size // 512)
            for _ in meta:
                total_sectors += self.block_size // 512

            alloc_bytes = frags * self.frag_size
            const.write_data(
                self.file,
                self.start_base + ptr * self.frag_size,
                chunk + b"\x00" * (alloc_bytes - len(chunk))
            )

        self._write_inode_size(inode, len(data))
        self._write_inode_blocks(inode, total_sectors)
        self._write_inode_times(inode, int(time.time()))

    def delete_file(self, dst_path: str):
        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not stat.S_ISDIR(parent_inode["i_mode"]):
            raise FileNotFoundError(parent_path)

        inode = self.find_file(dst_path)
        if inode is None:
            raise FileNotFoundError(dst_path)
        if stat.S_ISDIR(inode["i_mode"]):
            raise IsADirectoryError(dst_path)

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._remove_dir_entry(parent_live, name)
        self._write_inode_times(parent_live, int(time.time()))

        if inode["i_nlink"] > 1:
            self._write_inode_links(inode, inode["i_nlink"] - 1)
            return

        for ptr, frags in self._collect_file_runs(inode):
            self._free_frag_run(ptr, frags)
        for ptr in self._collect_meta_blocks(inode):
            self._free_frag_run(ptr, self.frag)

        const.write_data(self.file, inode["inode_offset"], b"\x00" * self.inode_size)
        self._free_inode_bitmap(inode["inode_num"])

    def _set_dotdot_entry(self, dir_inode: dict, parent_inode_num: int):
        for entry in self._iter_dir_entry_records(dir_inode):
            if entry["name"] == "..":
                virtual = self.start_base + entry["block_id"] * self.frag_size + entry["block_offset"]
                const.write_data(self.file, virtual, const.p32(parent_inode_num))
                return
        raise RuntimeError("directory missing .. entry")

    def _dir_is_empty(self, dir_inode: dict):
        for entry in self._iter_dir_entry_records(dir_inode):
            if entry["inode"] == 0:
                continue
            if entry["name"] in (".", ".."):
                continue
            return False
        return True

    def create_directory(self, dst_path: str, mode: int = 0o755):
        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not stat.S_ISDIR(parent_inode["i_mode"]):
            raise FileNotFoundError(parent_path)
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        inode_num = self._alloc_inode()
        inode = self._get_inode(inode_num)
        frag_addr = self._alloc_frag_run(1)
        now = int(time.time())

        self._write_inode_u16(inode, 0x00, stat.S_IFDIR | (mode & 0o777))
        self._write_inode_u16(inode, 0x02, 2)
        self._write_inode_u32(inode, 0x04, 0)
        self._write_inode_u32(inode, 0x08, 0)
        self._write_inode_u32(inode, 0x0C, self.block_size)
        self._write_inode_size(inode, 512)
        self._write_inode_blocks(inode, self.frag_size // 512)
        self._write_inode_times(inode, now)
        self._write_inode_u32(inode, 0x50, 0)
        self._write_inode_u32(inode, 0x54, 0)
        self._write_inode_u32(inode, 0x58, 0)
        self._write_inode_u32(inode, 0x5C, 0)
        self._write_inode_db_ptr(inode, 0, frag_addr)

        dot = self._pack_dir_entry(inode_num, ".", 4, 12)
        dotdot = self._pack_dir_entry(parent_inode["inode_num"], "..", 4, 500)
        const.write_data(
            self.file,
            self.start_base + frag_addr * self.frag_size,
            dot + dotdot + b"\x00" * (self.frag_size - 512)
        )

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._insert_dir_entry(parent_live, inode_num, name, 4)
        self._write_inode_links(parent_live, parent_live["i_nlink"] + 1)
        self._write_inode_times(parent_live, now)

    def remove_directory(self, dst_path: str):
        if dst_path == "/":
            raise ValueError("cannot remove root directory")

        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not stat.S_ISDIR(parent_inode["i_mode"]):
            raise FileNotFoundError(parent_path)

        inode = self.find_file(dst_path)
        if inode is None:
            raise FileNotFoundError(dst_path)
        if not stat.S_ISDIR(inode["i_mode"]):
            raise NotADirectoryError(dst_path)
        if not self._dir_is_empty(inode):
            raise OSError("directory not empty")

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._remove_dir_entry(parent_live, name)
        now = int(time.time())
        self._write_inode_links(parent_live, max(0, parent_live["i_nlink"] - 1))
        self._write_inode_times(parent_live, now)

        for ptr, frags in self._collect_file_runs(inode):
            self._free_frag_run(ptr, frags)
        for ptr in self._collect_meta_blocks(inode):
            self._free_frag_run(ptr, self.frag)

        const.write_data(self.file, inode["inode_offset"], b"\x00" * self.inode_size)
        self._free_inode_bitmap(inode["inode_num"])

    def create_hard_link(self, src_path: str, dst_path: str):
        src_inode = self.find_file(src_path)
        if src_inode is None:
            raise FileNotFoundError(src_path)
        if stat.S_ISDIR(src_inode["i_mode"]):
            raise IsADirectoryError(src_path)

        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not stat.S_ISDIR(parent_inode["i_mode"]):
            raise FileNotFoundError(parent_path)
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        src_live = self._get_inode(src_inode["inode_num"])
        parent_live = self._get_inode(parent_inode["inode_num"])
        self._insert_dir_entry(
            parent_live,
            src_live["inode_num"],
            name,
            self._dir_entry_type_for_mode(src_live["i_mode"])
        )
        self._write_inode_links(src_live, src_live["i_nlink"] + 1)
        now = int(time.time())
        self._write_inode_times(parent_live, now)
        self._write_inode_times(src_live, now)

    def create_symlink(self, target_path: str, dst_path: str, mode: int = 0o777):
        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not stat.S_ISDIR(parent_inode["i_mode"]):
            raise FileNotFoundError(parent_path)
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        target_bytes = target_path.encode("latin-1")
        inode_num = self._alloc_inode()
        inode = self._get_inode(inode_num)
        now = int(time.time())

        self._write_inode_u16(inode, 0x00, stat.S_IFLNK | (mode & 0o777))
        self._write_inode_u16(inode, 0x02, 1)
        self._write_inode_u32(inode, 0x04, 0)
        self._write_inode_u32(inode, 0x08, 0)
        self._write_inode_u32(inode, 0x0C, self.block_size)
        self._write_inode_size(inode, len(target_bytes))
        self._write_inode_times(inode, now)
        self._write_inode_u32(inode, 0x50, 0)
        self._write_inode_u32(inode, 0x54, 0)
        self._write_inode_u32(inode, 0x58, 0)
        self._write_inode_u32(inode, 0x5C, 0)

        if len(target_bytes) <= UFS_INLINE_SYMLINK_MAX:
            const.write_data(
                self.file,
                inode["inode_offset"] + 0x70,
                target_bytes + b"\x00" * (UFS_INLINE_SYMLINK_MAX - len(target_bytes))
            )
            self._write_inode_blocks(inode, 0)
        else:
            frags = max(1, (len(target_bytes) + self.frag_size - 1) // self.frag_size)
            ptr = self._alloc_frag_run(frags, block_aligned=(frags == self.frag))
            self._write_inode_db_ptr(inode, 0, ptr)
            const.write_data(
                self.file,
                self.start_base + ptr * self.frag_size,
                target_bytes + b"\x00" * (frags * self.frag_size - len(target_bytes))
            )
            self._write_inode_blocks(inode, frags * (self.frag_size // 512))

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._insert_dir_entry(parent_live, inode_num, name, 10)
        self._write_inode_times(parent_live, now)

    def rename_path(self, src_path: str, dst_path: str):
        if src_path == "/" or dst_path == "/":
            raise ValueError("invalid rename path")

        src_parent_path, src_name = self._split_parent_child(src_path)
        dst_parent_path, dst_name = self._split_parent_child(dst_path)

        src_parent = self.find_file(src_parent_path)
        dst_parent = self.find_file(dst_parent_path)
        inode = self.find_file(src_path)
        if src_parent is None or dst_parent is None or inode is None:
            raise FileNotFoundError(src_path)
        if not stat.S_ISDIR(src_parent["i_mode"]) or not stat.S_ISDIR(dst_parent["i_mode"]):
            raise NotADirectoryError("parent path is not a directory")
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        src_parent_live = self._get_inode(src_parent["inode_num"])
        dst_parent_live = self._get_inode(dst_parent["inode_num"])
        moved_live = self._get_inode(inode["inode_num"])

        self._remove_dir_entry(src_parent_live, src_name)
        self._insert_dir_entry(
            dst_parent_live,
            moved_live["inode_num"],
            dst_name,
            self._dir_entry_type_for_mode(moved_live["i_mode"])
        )

        now = int(time.time())
        self._write_inode_times(src_parent_live, now)
        self._write_inode_times(dst_parent_live, now)

        if stat.S_ISDIR(moved_live["i_mode"]) and src_parent_live["inode_num"] != dst_parent_live["inode_num"]:
            self._set_dotdot_entry(moved_live, dst_parent_live["inode_num"])
            self._write_inode_links(src_parent_live, max(0, src_parent_live["i_nlink"] - 1))
            self._write_inode_links(dst_parent_live, dst_parent_live["i_nlink"] + 1)

    def touch(self, dst_path: str):
        inode = self.find_file(dst_path)
        if inode is None:
            self.create_file_from_bytes(b"", dst_path, mode=0o644, uid=0, gid=0)
            return
        self._write_inode_times(inode, int(time.time()))

    def truncate_file(self, dst_path: str, size: int):
        inode = self.find_file(dst_path)
        if inode is None:
            raise FileNotFoundError(dst_path)
        if not stat.S_ISREG(inode["i_mode"]):
            raise IsADirectoryError(dst_path)
        if size < 0:
            raise ValueError("size must be >= 0")

        old = self._read_inode_bytes(inode)
        if len(old) >= size:
            new_data = old[:size]
        else:
            new_data = old + b"\x00" * (size - len(old))

        live = self._get_inode(inode["inode_num"])
        self._rewrite_regular_inode(live, new_data)

    def print_info(self, inode: dict):
        if not inode:
            print("Inode is None")
            return

        def fmt_time(ts):
            return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

        mode = inode["i_mode"]
        perms = stat.filemode(mode)

        file_type = "Unknown"
        if stat.S_ISREG(mode):
            file_type = "Regular File"
        elif stat.S_ISDIR(mode):
            file_type = "Directory"
        elif stat.S_ISLNK(mode):
            file_type = "Symbolic Link"
        elif stat.S_ISBLK(mode):
            file_type = "Block Device"
        elif stat.S_ISCHR(mode):
            file_type = "Character Device"
        elif stat.S_ISFIFO(mode):
            file_type = "FIFO/Pipe"
        elif stat.S_ISSOCK(mode):
            file_type = "Socket"

        size = inode["i_size"]
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.2f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.2f} MB"

        print("-" * 40)
        print(f"File Type:   {file_type} ({perms})")
        print(f"Size:        {size_str} ({size} bytes)")
        print(f"inode_num:   {inode['inode_num']}")
        print(f"inode_off:   0x{inode['inode_offset']:x}")
        print(f"UID/GID:     {inode['i_uid']} / {inode['i_gid']}")
        print(f"Links:       {inode['i_nlink']}")
        print(f"Flags:       0x{inode['i_flags']:08x} ({self.format_ufs_flags(inode['i_flags'])})")
        print("-" * 40)
        print(f"Access Time: {fmt_time(inode['i_atime'])}")
        print(f"Modify Time: {fmt_time(inode['i_mtime'])}")
        print(f"Change Time: {fmt_time(inode['i_ctime'])}")
        print(f"Birth Time:  {fmt_time(inode['i_birthtime'])}")
        print("-" * 40)
        print(f"Total Blocks:{inode['i_blocks']} (512-byte sectors)")
        print(f"Direct Ptrs: {[hex(b) for b in inode['i_db'][:12]]}")
