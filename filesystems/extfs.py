import datetime
import stat
import os
import time
import const_define as const
from typing import IO, List

class EXTFS:
    def __init__(self, fileName: str = None, fp: IO = None, start_base: int = 0, size_bytes: int = None):
        self.file = fp if fp else open(fileName, "rb")
        self.start_base = start_base
        self.size_bytes = size_bytes

        sb_offset = self.start_base + 1024
        self.file.seek(sb_offset)
        self.sb_data = self.file.read(1024)

        self.inodes_count = const.u(self.sb_data[0x00:0x04])
        self.blocks_count = const.u(self.sb_data[0x04:0x08])
        self.r_blocks_count = const.u(self.sb_data[0x08:0x0C])
        self.free_blocks_count = const.u(self.sb_data[0x0C:0x10])
        self.free_inodes_count = const.u(self.sb_data[0x10:0x14])
        self.first_data_block = const.u(self.sb_data[0x14:0x18])
        self.log_block_size = const.u(self.sb_data[0x18:0x1C])
        self.block_size = 1024 << self.log_block_size

        _frag_val = const.u(self.sb_data[0x1C:0x20])
        if _frag_val > 2147483647: 
            _frag_val -= 4294967296
        if _frag_val >= 0:
            self.frag_size = 1024 << _frag_val
        else:
            self.frag_size = 1024 >> (-_frag_val)

        self.blocks_per_group = const.u(self.sb_data[0x20:0x24])
        self.frags_per_group = const.u(self.sb_data[0x24:0x28])
        self.inodes_per_group = const.u(self.sb_data[0x28:0x2C])
        self.mtime = const.u(self.sb_data[0x2C:0x30])
        self.wtime = const.u(self.sb_data[0x30:0x34])
        self.mnt_count = const.u(self.sb_data[0x34:0x36])
        self.max_mnt_count = const.u(self.sb_data[0x36:0x38])
        self.magic = const.u(self.sb_data[0x38:0x3A])
        self.state = const.u(self.sb_data[0x3A:0x3C])
        self.errors = const.u(self.sb_data[0x3C:0x3E])
        self.minor_rev_level = const.u(self.sb_data[0x3E:0x40])
        self.lastcheck = const.u(self.sb_data[0x40:0x44])
        self.checkinterval = const.u(self.sb_data[0x44:0x48])
        self.creator_os = const.u(self.sb_data[0x48:0x4C])
        self.rev_level = const.u(self.sb_data[0x4C:0x50])
        self.def_resuid = const.u(self.sb_data[0x50:0x52])
        self.def_resgid = const.u(self.sb_data[0x52:0x54])

        if self.rev_level >= const.EXT2_DYNAMIC_REV:
            self.first_ino = const.u(self.sb_data[0x54:0x58])
            self.inode_size = const.u(self.sb_data[0x58:0x5A])
            self.block_group_nr = const.u(self.sb_data[0x5A:0x5C])
            self.feature_compat = const.u(self.sb_data[0x5C:0x60])
            self.feature_incompat = const.u(self.sb_data[0x60:0x64])
            self.feature_ro_compat = const.u(self.sb_data[0x64:0x68])
            self.uuid = self.sb_data[0x68:0x78]
            self.volume_name = self.sb_data[0x78:0x88].decode('latin-1').rstrip('\x00')
            self.last_mounted = self.sb_data[0x88:0xC8].decode('latin-1').rstrip('\x00')
            self.algo_bitmap = const.u(self.sb_data[0xC8:0xCC])
            self.prealloc_blocks = const.u(self.sb_data[0xCC:0xCD])
            self.prealloc_dir_blocks = const.u(self.sb_data[0xCD:0xCE])
            self.journal_uuid = self.sb_data[0xD0:0xE0]
            self.journal_inum = const.u(self.sb_data[0xE0:0xE4])
            self.journal_dev = const.u(self.sb_data[0xE4:0xE8])
            self.last_orphan = const.u(self.sb_data[0xE8:0xEC])
            self.hash_seed = [
                const.u(self.sb_data[0xEC:0xF0]),
                const.u(self.sb_data[0xF0:0xF4]),
                const.u(self.sb_data[0xF4:0xF8]),
                const.u(self.sb_data[0xF8:0xFC])
            ]
            self.def_hash_version = const.u(self.sb_data[0xFC:0xFD])
            self.default_mount_options = const.u(self.sb_data[0x100:0x104])
            self.first_meta_bg = const.u(self.sb_data[0x104:0x108])
        else:
            self.first_ino = const.EXT2_GOOD_OLD_FIRST_INO
            self.inode_size = const.EXT2_GOOD_OLD_INODE_SIZE
            self.feature_compat = 0
            self.feature_incompat = 0
            self.feature_ro_compat = 0
            self.uuid = b'\x00' * 16
            self.volume_name = ""
            self.last_mounted = ""
            self.algo_bitmap = 0
            self.prealloc_blocks = 0
            self.prealloc_dir_blocks = 0
            self.journal_uuid = b'\x00' * 16
            self.journal_inum = 0
            self.journal_dev = 0
            self.last_orphan = 0
            self.hash_seed = [0, 0, 0, 0]
            self.def_hash_version = 0
            self.default_mount_options = 0
            self.first_meta_bg = 0

        self.groups_count = (self.blocks_count + self.blocks_per_group - 1) // self.blocks_per_group
        
        gdt_start_block = self.first_data_block + 1
        gdt_offset = self.start_base + (gdt_start_block * self.block_size)
        
        self.file.seek(gdt_offset)
        self.group_descriptors = []
        
        for _ in range(self.groups_count):
            gdt_data = self.file.read(const.EXT2_DESC_SIZE)
            if len(gdt_data) < const.EXT2_DESC_SIZE:
                break
            
            desc = {
                "bg_block_bitmap": const.u(gdt_data[0x00:0x04]),
                "bg_inode_bitmap": const.u(gdt_data[0x04:0x08]),
                "bg_inode_table": const.u(gdt_data[0x08:0x0C]),
                "bg_free_blocks_count": const.u(gdt_data[0x0C:0x0E]),
                "bg_free_inodes_count": const.u(gdt_data[0x0E:0x10]),
                "bg_used_dirs_count": const.u(gdt_data[0x10:0x12]),
                "bg_pad": const.u(gdt_data[0x12:0x14]),
                "bg_reserved": gdt_data[0x14:0x20]
            }
            self.group_descriptors.append(desc)


    
    def _get_inode(self, inode_num: int):
        group_idx = (inode_num - 1) // self.inodes_per_group
        inode_idx = (inode_num - 1) % self.inodes_per_group
        
        group_desc = self.group_descriptors[group_idx]
        inode_table_block = group_desc["bg_inode_table"]
        
        inode_offset = self.start_base + (inode_table_block * self.block_size) + (inode_idx * self.inode_size)
        self.file.seek(inode_offset)
        data = self.file.read(self.inode_size)
        
        inode = {
            "inode_num": inode_num,
            "i_mode": const.u(data[0x00:0x02]),
            "i_uid": const.u(data[0x02:0x04]),
            "i_size": const.u(data[0x04:0x08]),
            "recode_i_size_addr_4_bytes": inode_offset + 4, 
            "i_atime": const.u(data[0x08:0x0C]),
            "i_ctime": const.u(data[0x0C:0x10]),
            "i_mtime": const.u(data[0x10:0x14]),
            "i_dtime": const.u(data[0x14:0x18]),
            "i_gid": const.u(data[0x18:0x1A]),
            "i_links_count": const.u(data[0x1A:0x1C]),
            "i_blocks": const.u(data[0x1C:0x20]),
            "i_flags": const.u(data[0x20:0x24]),
            "i_osd1": const.u(data[0x24:0x28]),
            "inode_offset": inode_offset,
            "i_block": [],
            "raw_i_block": []
        }
        
        raw_pointers = []
        for i in range(15):
            start = 0x28 + (i * 4)
            block_ptr = const.u(data[start:start+4])
            raw_pointers.append(block_ptr)

        final_block_list = []
        final_block_list.extend(raw_pointers[:12])

        if raw_pointers[12] != 0:
            indirect_1 = self._get_block_ids_from_pointer_block(raw_pointers[12])
            final_block_list.extend(indirect_1)

        if raw_pointers[13] != 0:
            indirect_2_ptrs = self._get_block_ids_from_pointer_block(raw_pointers[13])
            for ptr in indirect_2_ptrs:
                if ptr != 0:
                    indirect_2_data = self._get_block_ids_from_pointer_block(ptr)
                    final_block_list.extend(indirect_2_data)

        if raw_pointers[14] != 0:
            indirect_3_ptrs = self._get_block_ids_from_pointer_block(raw_pointers[14])
            for ptr2 in indirect_3_ptrs:
                if ptr2 != 0:
                    indirect_2_data = self._get_block_ids_from_pointer_block(ptr2)
                    for ptr1 in indirect_2_data:
                         if ptr1 != 0:
                             final_block_list.extend(self._get_block_ids_from_pointer_block(ptr1))

        inode["i_block"] = final_block_list
        inode["raw_i_block"] = raw_pointers
             
        return inode

    def _read_inode_bytes(self, inode: dict) -> bytes:
        if stat.S_ISLNK(inode["i_mode"]) and inode["i_size"] <= 60 and inode["i_blocks"] == 0:
            raw = const.read_data(self.file, inode["inode_offset"] + 0x28, 60)
            return raw[:inode["i_size"]]

        data = b""
        total_size = inode["i_size"]
        read_size = 0
        
        for block_id in inode["i_block"]:
            if read_size >= total_size:
                break
            
            chunk_size = self.block_size
            if read_size + chunk_size > total_size:
                chunk_size = total_size - read_size

            if block_id == 0:
                data += b'\x00' * chunk_size
            else:
                self.file.seek(self.start_base + (block_id * self.block_size))
                data += self.file.read(chunk_size)
            
            read_size += chunk_size
            
        return data

    def find_file(self, asbFileName: str):
        parts = [p for p in asbFileName.split("/") if p]
        current_inode_num = const.EXT2_ROOT_INO
        
        for part in parts:
            inode = self._get_inode(current_inode_num)
            
            if not (inode["i_mode"] & 0x4000): 
                return None
            
            dir_data = self._read_inode_bytes(inode)
            
            offset = 0
            found = False
            
            while offset < len(dir_data):
                if offset + 8 > len(dir_data):
                    break

                ptr_inode = const.u(dir_data[offset:offset+4])
                rec_len = const.u(dir_data[offset+4:offset+6])
                name_len = const.u(dir_data[offset+6:offset+7])
                # file_type = const.u(dir_data[offset+7:offset+8])
                
                if rec_len == 0:
                    break
                
                if offset + 8 + name_len > len(dir_data):
                    break

                name_bytes = dir_data[offset+8 : offset+8+name_len]
                name = name_bytes.decode('latin-1')
                
                if name == part:
                    current_inode_num = ptr_inode
                    found = True
                    break
                    
                offset += rec_len
                
            if not found:
                return None
                
        return self._get_inode(current_inode_num)
    
    def _get_block_ids_from_pointer_block(self, pointer_block_id: int) -> List[int]:
        if pointer_block_id == 0:
            return []

        self.file.seek(self.start_base + (pointer_block_id * self.block_size))
        data = self.file.read(self.block_size)
        
        ids = []
        for i in range(0, len(data), 4):
            block_id = const.u(data[i:i+4])
            ids.append(block_id)
        return ids

    def _get_all_file_blocks(self, inode: dict) -> List[int]:
        all_blocks = []

        all_blocks.extend(inode['i_block'][:12])

        if inode['i_block'][12] != 0:
            indirect_1 = self._get_block_ids_from_pointer_block(inode['i_block'][12])
            all_blocks.extend(indirect_1)

        if inode['i_block'][13] != 0:
            indirect_2_ptrs = self._get_block_ids_from_pointer_block(inode['i_block'][13])
            for ptr in indirect_2_ptrs:
                if ptr != 0:
                    indirect_2_data = self._get_block_ids_from_pointer_block(ptr)
                    all_blocks.extend(indirect_2_data)
        
        return all_blocks

    def extract_file(self, absFileName: str, out_directory: str):
        inode = self.find_file(absFileName)
        counter = 1
        
        if inode is None:
            return False

        if inode['i_mode'] & 0x4000:
            return False

        if not os.path.exists(out_directory):
            os.makedirs(out_directory)
            
        filename = os.path.basename(absFileName)
        save_path = os.path.join(out_directory, filename)
        while os.path.exists(save_path):
            new_filename = f"{filename}_{counter}"
            save_path = os.path.join(out_directory, new_filename)
            counter += 1

        block_ids = inode['i_block']

        bytes_written = 0
        total_size = inode['i_size']
        
        try:
            with open(save_path, "wb") as f_out:
                for bid in block_ids:
                    if bytes_written >= total_size:
                        break
                    
                    chunk_size = self.block_size
                    if bytes_written + chunk_size > total_size:
                        chunk_size = total_size - bytes_written
                    
                    if bid == 0:
                        f_out.write(b'\x00' * chunk_size)
                    else:
                        self.file.seek(self.start_base + (bid * self.block_size))
                        data = self.file.read(chunk_size)
                        f_out.write(data)
                        
                    bytes_written += chunk_size
            return True
        except Exception:
            return False
    
    def _parse_dir_entries(self, inode: dict):
        if not inode or not (inode["i_mode"] & 0x4000):
            return []

        dir_data = self._read_inode_bytes(inode)
        entries = []

        offset = 0
        while offset < len(dir_data):
            if offset + 8 > len(dir_data):
                break

            inode_num = const.u(dir_data[offset:offset + 4])
            rec_len = const.u(dir_data[offset + 4:offset + 6])
            name_len = const.u(dir_data[offset + 6:offset + 7])
            file_type = const.u(dir_data[offset + 7:offset + 8])

            if rec_len == 0:
                break

            if inode_num == 0:
                offset += rec_len
                continue

            name_bytes = dir_data[offset + 8: offset + 8 + name_len]
            name = name_bytes.decode("latin-1", errors="replace")

            if name not in [".", ".."]:
                child_inode = self._get_inode(inode_num)

                entries.append({
                    "name": name,
                    "inode": inode_num,
                    "file_type": file_type,
                    "i_mode": child_inode["i_mode"],
                    "i_size": child_inode["i_size"],
                    "is_dir": bool(child_inode["i_mode"] & 0x4000),
                    "is_file": bool(child_inode["i_mode"] & 0x8000),
                    "inode_obj": child_inode,
                })

            offset += rec_len

        return entries

    def _format_mode(self, mode: int):
        return stat.filemode(mode)

    def list_dir(self, path: str = "/"):
        inode = self.find_file(path)

        if inode is None:
            return []

        if not (inode["i_mode"] & 0x4000):
            return []

        return self._parse_dir_entries(inode)

    def format_ext_attrs(self, flags: int) -> str:
        attrs = [
            ("s", 0x00000001),  # secure deletion
            ("u", 0x00000002),  # undelete
            ("c", 0x00000004),  # compressed
            ("S", 0x00000008),  # synchronous updates
            ("i", 0x00000010),  # immutable
            ("a", 0x00000020),  # append only
            ("d", 0x00000040),  # no dump
            ("A", 0x00000080),  # no atime updates
            ("j", 0x00004000),  # journal data
            ("D", 0x00010000),  # synchronous directory updates
            ("t", 0x00040000),  # no tail-merging
            ("T", 0x00080000),  # top of directory hierarchy
            # ("e", 0x00080000),  # extents，注意和 T 有历史重叠问题
        ]

        s = ""
        for ch, bit in attrs:
            s += ch if flags & bit else "-"

        return s


    def tree(self, path: str = "/", max_depth: int = 3):
        root_inode = self.find_file(path)

        if root_inode is None:
            print(f"path not found: {path}")
            return

        if not (root_inode["i_mode"] & 0x4000):
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
                self._tree_walk(
                    child_path,
                    prefix=next_prefix,
                    depth=depth + 1,
                    max_depth=max_depth
                )
    
    def lsattr(self, path="/"):
        entries = self.list_dir(path)

        for entry in entries:
            inode = entry["inode_obj"]
            attrs = self.format_ext_attrs(inode["i_flags"])
            name = entry["name"] + ("/" if entry["is_dir"] else "")
            print(f"{attrs} {name}")
    
    def read_file_by_inode(self, inode: dict) -> bytes:
        return self._read_inode_bytes(inode)


    def set_inode_size(self, inode: dict, size: int):
        const.write_data(
            self.file,
            inode["recode_i_size_addr_4_bytes"],
            const.p32(size)
        )
    
    def get_replace_info(self, absFileName: str):
        inode = self.find_file(absFileName)

        if inode is None:
            return None

        if inode["i_mode"] & 0x4000:
            raise IsADirectoryError(absFileName)

        blocks = []
        total_size = inode["i_size"]
        done = 0

        for block_id in inode["i_block"]:
            if done >= total_size:
                break

            length = min(self.block_size, total_size - done)

            blocks.append({
                "block_id": block_id,
                "virtual_offset": self.start_base + block_id * self.block_size if block_id != 0 else None,
                "length": length,
                "file_offset": done,
            })

            done += length

        return {
            "path": absFileName,
            "inode": inode,
            "size": inode["i_size"],
            "inode_size_virtual_offset": inode["recode_i_size_addr_4_bytes"],
            "block_size": self.block_size,
            "blocks": blocks,
        }

    def _write_inode_u16(self, inode: dict, offset: int, value: int):
        const.write_data(
            self.file,
            inode["inode_offset"] + offset,
            const.p16(value)
        )


    def _write_inode_u32(self, inode: dict, offset: int, value: int):
        const.write_data(
            self.file,
            inode["inode_offset"] + offset,
            const.p32(value)
        )
    
    def chmod(self, absFileName: str, mode: int):
        inode = self.find_file(absFileName)

        if inode is None:
            return False

        old_mode = inode["i_mode"]

        new_mode = (old_mode & 0xF000) | (mode & 0x0FFF)

        self._write_inode_u16(inode, 0x00, new_mode)

        return True

    def chattr(self, absFileName: str, op: str):
        inode = self.find_file(absFileName)

        if inode is None:
            return False

        flags = inode["i_flags"]

        attr_map = {
            "s": 0x00000001,
            "u": 0x00000002,
            "c": 0x00000004,
            "S": 0x00000008,
            "i": 0x00000010,
            "a": 0x00000020,
            "d": 0x00000040,
            "A": 0x00000080,
            "j": 0x00004000,
            "D": 0x00010000,
            "t": 0x00040000,
            "T": 0x00080000,
        }

        if len(op) < 2 or op[0] not in "+-":
            raise ValueError("usage: chattr +i|-i|+a|-a <path>")

        action = op[0]

        for ch in op[1:]:
            if ch not in attr_map:
                raise ValueError(f"unsupported attr: {ch}")

            if action == "+":
                flags |= attr_map[ch]
            else:
                flags &= ~attr_map[ch]

        self._write_inode_u32(inode, 0x20, flags)

        return True

    def _inode_is_dir(self, inode: dict):
        return bool(inode["i_mode"] & 0x4000)

    def _inode_is_reg(self, inode: dict):
        return bool(inode["i_mode"] & 0x8000)

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
            return 1
        if stat.S_ISDIR(mode):
            return 2
        if stat.S_ISCHR(mode):
            return 3
        if stat.S_ISBLK(mode):
            return 4
        if stat.S_ISFIFO(mode):
            return 5
        if stat.S_ISSOCK(mode):
            return 6
        if stat.S_ISLNK(mode):
            return 7
        return 0

    def _pack_dir_entry(self, inode_num: int, name: str, file_type: int, rec_len: int = None):
        name_bytes = name.encode("latin-1")
        actual_len = self._entry_actual_len(len(name_bytes))
        if rec_len is None:
            rec_len = actual_len

        return (
            const.p32(inode_num) +
            const.p16(rec_len) +
            const.p8(len(name_bytes)) +
            const.p8(file_type) +
            name_bytes +
            b"\x00" * (rec_len - 8 - len(name_bytes))
        )

    def _iter_dir_entry_records(self, inode: dict):
        dir_data = self._read_inode_bytes(inode)
        offset = 0

        while offset < len(dir_data):
            if offset + 8 > len(dir_data):
                break

            inode_num = const.u(dir_data[offset:offset + 4])
            rec_len = const.u(dir_data[offset + 4:offset + 6])
            name_len = const.u(dir_data[offset + 6:offset + 7])
            file_type = const.u(dir_data[offset + 7:offset + 8])

            if rec_len == 0:
                break

            name_bytes = dir_data[offset + 8: offset + 8 + name_len]
            name = name_bytes.decode("latin-1", errors="replace")

            block_index = offset // self.block_size
            block_offset = offset % self.block_size
            block_id = inode["i_block"][block_index] if block_index < len(inode["i_block"]) else 0
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

    def _group_desc_offset(self, group_idx: int):
        gdt_start_block = self.first_data_block + 1
        gdt_offset = self.start_base + (gdt_start_block * self.block_size)
        return gdt_offset + group_idx * const.EXT2_DESC_SIZE

    def _write_group_desc_counts(self, group_idx: int):
        desc = self.group_descriptors[group_idx]
        base = self._group_desc_offset(group_idx)
        const.write_data(self.file, base + 0x0C, const.p16(desc["bg_free_blocks_count"]))
        const.write_data(self.file, base + 0x0E, const.p16(desc["bg_free_inodes_count"]))
        const.write_data(self.file, base + 0x10, const.p16(desc["bg_used_dirs_count"]))

    def _adjust_used_dirs(self, inode_num: int, delta: int):
        group_idx = (inode_num - 1) // self.inodes_per_group
        self.group_descriptors[group_idx]["bg_used_dirs_count"] += delta
        self._write_group_desc_counts(group_idx)

    def _adjust_super_counts(self, free_blocks_delta: int = 0, free_inodes_delta: int = 0):
        self.free_blocks_count += free_blocks_delta
        self.free_inodes_count += free_inodes_delta
        const.write_data(self.file, self.start_base + 1024 + 0x0C, const.p32(self.free_blocks_count))
        const.write_data(self.file, self.start_base + 1024 + 0x10, const.p32(self.free_inodes_count))

    def _bitmap_get(self, bitmap: bytes, bit_index: int):
        return (bitmap[bit_index // 8] >> (bit_index % 8)) & 1

    def _bitmap_set(self, bitmap: bytearray, bit_index: int, value: int):
        byte_index = bit_index // 8
        bit_mask = 1 << (bit_index % 8)
        if value:
            bitmap[byte_index] |= bit_mask
        else:
            bitmap[byte_index] &= ~bit_mask & 0xFF

    def _alloc_inode(self):
        for group_idx, desc in enumerate(self.group_descriptors):
            if desc["bg_free_inodes_count"] == 0:
                continue

            bitmap_offset = self.start_base + desc["bg_inode_bitmap"] * self.block_size
            bitmap = bytearray(const.read_data(self.file, bitmap_offset, self.block_size))

            for bit in range(self.inodes_per_group):
                inode_num = group_idx * self.inodes_per_group + bit + 1
                if inode_num > self.inodes_count:
                    break
                if inode_num < self.first_ino:
                    continue
                if self._bitmap_get(bitmap, bit):
                    continue

                self._bitmap_set(bitmap, bit, 1)
                const.write_data(self.file, bitmap_offset, bytes(bitmap))

                desc["bg_free_inodes_count"] -= 1
                self._write_group_desc_counts(group_idx)
                self._adjust_super_counts(free_inodes_delta=-1)

                inode_offset = self.start_base + desc["bg_inode_table"] * self.block_size + bit * self.inode_size
                const.write_data(self.file, inode_offset, b"\x00" * self.inode_size)
                return inode_num

        raise RuntimeError("no free inode")

    def _free_inode_bitmap(self, inode_num: int):
        group_idx = (inode_num - 1) // self.inodes_per_group
        bit = (inode_num - 1) % self.inodes_per_group
        desc = self.group_descriptors[group_idx]

        bitmap_offset = self.start_base + desc["bg_inode_bitmap"] * self.block_size
        bitmap = bytearray(const.read_data(self.file, bitmap_offset, self.block_size))
        self._bitmap_set(bitmap, bit, 0)
        const.write_data(self.file, bitmap_offset, bytes(bitmap))

        desc["bg_free_inodes_count"] += 1
        self._write_group_desc_counts(group_idx)
        self._adjust_super_counts(free_inodes_delta=1)

    def _alloc_block(self):
        for group_idx, desc in enumerate(self.group_descriptors):
            if desc["bg_free_blocks_count"] == 0:
                continue

            bitmap_offset = self.start_base + desc["bg_block_bitmap"] * self.block_size
            bitmap = bytearray(const.read_data(self.file, bitmap_offset, self.block_size))

            for bit in range(self.blocks_per_group):
                block_num = group_idx * self.blocks_per_group + bit + self.first_data_block
                if block_num >= self.blocks_count:
                    break
                if self._bitmap_get(bitmap, bit):
                    continue

                self._bitmap_set(bitmap, bit, 1)
                const.write_data(self.file, bitmap_offset, bytes(bitmap))

                desc["bg_free_blocks_count"] -= 1
                self._write_group_desc_counts(group_idx)
                self._adjust_super_counts(free_blocks_delta=-1)

                const.write_data(self.file, self.start_base + block_num * self.block_size, b"\x00" * self.block_size)
                return block_num

        raise RuntimeError("no free block")

    def _free_block(self, block_num: int):
        group_idx = (block_num - self.first_data_block) // self.blocks_per_group
        bit = (block_num - self.first_data_block) % self.blocks_per_group
        desc = self.group_descriptors[group_idx]

        bitmap_offset = self.start_base + desc["bg_block_bitmap"] * self.block_size
        bitmap = bytearray(const.read_data(self.file, bitmap_offset, self.block_size))
        self._bitmap_set(bitmap, bit, 0)
        const.write_data(self.file, bitmap_offset, bytes(bitmap))

        desc["bg_free_blocks_count"] += 1
        self._write_group_desc_counts(group_idx)
        self._adjust_super_counts(free_blocks_delta=1)

    def _write_inode_block_ptr(self, inode: dict, index: int, value: int):
        const.write_data(
            self.file,
            inode["inode_offset"] + 0x28 + index * 4,
            const.p32(value)
        )
        inode["raw_i_block"][index] = value

    def _write_pointer_block_entry(self, block_num: int, index: int, value: int):
        const.write_data(
            self.file,
            self.start_base + block_num * self.block_size + index * 4,
            const.p32(value)
        )

    def _set_logical_block(self, inode: dict, logical_index: int, block_num: int):
        ptrs_per_block = self.block_size // 4
        allocated_meta = []

        if logical_index < 12:
            self._write_inode_block_ptr(inode, logical_index, block_num)
            return allocated_meta

        logical_index -= 12
        if logical_index < ptrs_per_block:
            if inode["raw_i_block"][12] == 0:
                inode["raw_i_block"][12] = self._alloc_block()
                allocated_meta.append(inode["raw_i_block"][12])
                self._write_inode_block_ptr(inode, 12, inode["raw_i_block"][12])
            self._write_pointer_block_entry(inode["raw_i_block"][12], logical_index, block_num)
            return allocated_meta

        logical_index -= ptrs_per_block
        span = ptrs_per_block * ptrs_per_block
        if logical_index < span:
            if inode["raw_i_block"][13] == 0:
                inode["raw_i_block"][13] = self._alloc_block()
                allocated_meta.append(inode["raw_i_block"][13])
                self._write_inode_block_ptr(inode, 13, inode["raw_i_block"][13])

            outer = logical_index // ptrs_per_block
            inner = logical_index % ptrs_per_block
            block1 = const.u(const.read_data(
                self.file,
                self.start_base + inode["raw_i_block"][13] * self.block_size + outer * 4,
                4
            ))
            if block1 == 0:
                block1 = self._alloc_block()
                allocated_meta.append(block1)
                self._write_pointer_block_entry(inode["raw_i_block"][13], outer, block1)

            self._write_pointer_block_entry(block1, inner, block_num)
            return allocated_meta

        logical_index -= span
        span2 = ptrs_per_block * ptrs_per_block * ptrs_per_block
        if logical_index >= span2:
            raise RuntimeError("file too large for ext block pointer implementation")

        if inode["raw_i_block"][14] == 0:
            inode["raw_i_block"][14] = self._alloc_block()
            allocated_meta.append(inode["raw_i_block"][14])
            self._write_inode_block_ptr(inode, 14, inode["raw_i_block"][14])

        idx1 = logical_index // span
        rem = logical_index % span
        idx2 = rem // ptrs_per_block
        idx3 = rem % ptrs_per_block

        block1 = const.u(const.read_data(
            self.file,
            self.start_base + inode["raw_i_block"][14] * self.block_size + idx1 * 4,
            4
        ))
        if block1 == 0:
            block1 = self._alloc_block()
            allocated_meta.append(block1)
            self._write_pointer_block_entry(inode["raw_i_block"][14], idx1, block1)

        block2 = const.u(const.read_data(
            self.file,
            self.start_base + block1 * self.block_size + idx2 * 4,
            4
        ))
        if block2 == 0:
            block2 = self._alloc_block()
            allocated_meta.append(block2)
            self._write_pointer_block_entry(block1, idx2, block2)

        self._write_pointer_block_entry(block2, idx3, block_num)
        return allocated_meta

    def _write_inode_times(self, inode: dict, now: int):
        self._write_inode_u32(inode, 0x08, now)
        self._write_inode_u32(inode, 0x0C, now)
        self._write_inode_u32(inode, 0x10, now)

    def _write_inode_size(self, inode: dict, size: int):
        self._write_inode_u32(inode, 0x04, size)
        inode["i_size"] = size

    def _write_inode_blocks_sectors(self, inode: dict, sectors: int):
        self._write_inode_u32(inode, 0x1C, sectors)
        inode["i_blocks"] = sectors

    def _write_inode_links(self, inode: dict, links: int):
        self._write_inode_u16(inode, 0x1A, links)
        inode["i_links_count"] = links

    def _write_inode_ids(self, inode: dict, uid: int, gid: int):
        self._write_inode_u16(inode, 0x02, uid)
        self._write_inode_u16(inode, 0x18, gid)
        inode["i_uid"] = uid
        inode["i_gid"] = gid

    def _get_logical_block_ptr(self, inode: dict, logical_index: int):
        ptrs_per_block = self.block_size // 4

        if logical_index < 12:
            return inode["raw_i_block"][logical_index]

        logical_index -= 12
        if logical_index < ptrs_per_block:
            if inode["raw_i_block"][12] == 0:
                return 0
            return const.u(const.read_data(
                self.file,
                self.start_base + inode["raw_i_block"][12] * self.block_size + logical_index * 4,
                4
            ))

        logical_index -= ptrs_per_block
        span = ptrs_per_block * ptrs_per_block
        if logical_index < span:
            if inode["raw_i_block"][13] == 0:
                return 0
            outer = logical_index // ptrs_per_block
            inner = logical_index % ptrs_per_block
            block1 = const.u(const.read_data(
                self.file,
                self.start_base + inode["raw_i_block"][13] * self.block_size + outer * 4,
                4
            ))
            if block1 == 0:
                return 0
            return const.u(const.read_data(
                self.file,
                self.start_base + block1 * self.block_size + inner * 4,
                4
            ))

        logical_index -= span
        if inode["raw_i_block"][14] == 0:
            return 0
        idx1 = logical_index // span
        rem = logical_index % span
        idx2 = rem // ptrs_per_block
        idx3 = rem % ptrs_per_block

        block1 = const.u(const.read_data(
            self.file,
            self.start_base + inode["raw_i_block"][14] * self.block_size + idx1 * 4,
            4
        ))
        if block1 == 0:
            return 0

        block2 = const.u(const.read_data(
            self.file,
            self.start_base + block1 * self.block_size + idx2 * 4,
            4
        ))
        if block2 == 0:
            return 0

        return const.u(const.read_data(
            self.file,
            self.start_base + block2 * self.block_size + idx3 * 4,
            4
        ))

    def _clear_inode_blocks(self, inode: dict):
        for i in range(15):
            self._write_inode_block_ptr(inode, i, 0)
        inode["i_block"] = []

    def _collect_indirect_blocks(self, block_num: int, depth: int):
        if block_num == 0:
            return []

        result = [block_num]
        if depth == 0:
            return result

        data = const.read_data(self.file, self.start_base + block_num * self.block_size, self.block_size)
        for i in range(0, self.block_size, 4):
            ptr = const.u(data[i:i + 4])
            if ptr == 0:
                continue
            result.extend(self._collect_indirect_blocks(ptr, depth - 1))

        return result

    def _collect_file_blocks_and_metadata(self, inode: dict):
        if stat.S_ISLNK(inode["i_mode"]) and inode["i_blocks"] == 0:
            return [], []

        data_blocks = []
        total_size = inode["i_size"]
        need = (total_size + self.block_size - 1) // self.block_size if total_size else 0
        count = 0

        for block_id in inode["raw_i_block"][:12]:
            if count >= need:
                break
            if block_id:
                data_blocks.append(block_id)
            count += 1

        meta_blocks = []

        def walk(block_num: int, depth: int):
            nonlocal count
            if block_num == 0 or count >= need:
                return
            meta_blocks.append(block_num)
            data = const.read_data(self.file, self.start_base + block_num * self.block_size, self.block_size)
            for i in range(0, self.block_size, 4):
                ptr = const.u(data[i:i + 4])
                if ptr == 0:
                    continue
                if depth == 1:
                    if count >= need:
                        break
                    data_blocks.append(ptr)
                    count += 1
                else:
                    walk(ptr, depth - 1)
                    if count >= need:
                        break

        walk(inode["raw_i_block"][12], 1)
        walk(inode["raw_i_block"][13], 2)
        walk(inode["raw_i_block"][14], 3)

        return data_blocks, meta_blocks

    def _insert_dir_entry(self, dir_inode: dict, inode_num: int, name: str, file_type: int):
        need_len = self._entry_actual_len(len(name.encode("latin-1")))

        for entry in self._iter_dir_entry_records(dir_inode):
            if entry["block_id"] == 0:
                continue

            if entry["inode"] == 0 and entry["rec_len"] >= need_len:
                virtual = self.start_base + entry["block_id"] * self.block_size + entry["block_offset"]
                const.write_data(self.file, virtual, self._pack_dir_entry(inode_num, name, file_type, entry["rec_len"]))
                return

            slack = entry["rec_len"] - entry["actual_len"]
            if slack < need_len:
                continue

            entry_virtual = self.start_base + entry["block_id"] * self.block_size + entry["block_offset"]
            const.write_data(self.file, entry_virtual + 4, const.p16(entry["actual_len"]))
            const.write_data(
                self.file,
                entry_virtual + entry["actual_len"],
                self._pack_dir_entry(inode_num, name, file_type, slack)
            )
            return

        new_block = self._alloc_block()
        current_blocks = (dir_inode["i_size"] + self.block_size - 1) // self.block_size
        meta_blocks = self._set_logical_block(dir_inode, current_blocks, new_block)
        block_virtual = self.start_base + new_block * self.block_size
        const.write_data(self.file, block_virtual, self._pack_dir_entry(inode_num, name, file_type, self.block_size))
        self._write_inode_size(dir_inode, dir_inode["i_size"] + self.block_size)
        sectors = dir_inode["i_blocks"] + (1 + len(meta_blocks)) * (self.block_size // 512)
        self._write_inode_blocks_sectors(dir_inode, sectors)

    def _remove_dir_entry(self, dir_inode: dict, name: str):
        prev, entry = self._find_dir_entry(dir_inode, name)
        if entry is None:
            raise FileNotFoundError(name)

        entry_virtual = self.start_base + entry["block_id"] * self.block_size + entry["block_offset"]
        if prev and prev["block_index"] == entry["block_index"]:
            prev_virtual = self.start_base + prev["block_id"] * self.block_size + prev["block_offset"]
            const.write_data(self.file, prev_virtual + 4, const.p16(prev["rec_len"] + entry["rec_len"]))
        else:
            const.write_data(self.file, entry_virtual, const.p32(0))

        return entry

    def _set_dotdot_entry(self, dir_inode: dict, parent_inode_num: int):
        for entry in self._iter_dir_entry_records(dir_inode):
            if entry["name"] == "..":
                entry_virtual = self.start_base + entry["block_id"] * self.block_size + entry["block_offset"]
                const.write_data(self.file, entry_virtual, const.p32(parent_inode_num))
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

    def create_file_from_host(self, src_file: str, dst_path: str):
        with open(src_file, "rb") as fp:
            data = fp.read()

        host_mode = os.stat(src_file).st_mode & 0o777
        self.create_file_from_bytes(data, dst_path, mode=host_mode, uid=0, gid=0)

    def create_file_from_bytes(self, data: bytes, dst_path: str, mode: int = 0o644, uid: int = 0, gid: int = 0):
        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not self._inode_is_dir(parent_inode):
            raise FileNotFoundError(parent_path)
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        inode_num = self._alloc_inode()
        inode = self._get_inode(inode_num)

        file_mode = stat.S_IFREG | (mode & 0o777)
        now = int(time.time())

        self._write_inode_u16(inode, 0x00, file_mode)
        self._write_inode_ids(inode, uid, gid)
        self._write_inode_links(inode, 1)
        self._write_inode_times(inode, now)
        self._write_inode_u32(inode, 0x14, 0)
        self._write_inode_u32(inode, 0x20, 0)
        self._write_inode_size(inode, len(data))

        data_blocks = []
        meta_blocks = []
        for logical_index in range((len(data) + self.block_size - 1) // self.block_size):
            block_num = self._alloc_block()
            data_blocks.append(block_num)
            meta_blocks.extend(self._set_logical_block(inode, logical_index, block_num))

            start = logical_index * self.block_size
            end = start + self.block_size
            chunk = data[start:end]
            if len(chunk) < self.block_size:
                chunk += b"\x00" * (self.block_size - len(chunk))
            const.write_data(self.file, self.start_base + block_num * self.block_size, chunk)

        total_alloc_blocks = len(data_blocks) + len(meta_blocks)
        self._write_inode_blocks_sectors(inode, total_alloc_blocks * (self.block_size // 512))

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._insert_dir_entry(parent_live, inode_num, name, 1)
        self._write_inode_times(parent_live, now)

    def _rewrite_regular_inode(self, inode: dict, data: bytes):
        data_blocks, meta_blocks = self._collect_file_blocks_and_metadata(inode)
        for block_num in data_blocks + meta_blocks:
            self._free_block(block_num)

        self._clear_inode_blocks(inode)
        self._write_inode_size(inode, 0)
        self._write_inode_blocks_sectors(inode, 0)

        total_alloc_blocks = 0
        for logical_index in range((len(data) + self.block_size - 1) // self.block_size):
            block_num = self._alloc_block()
            meta = self._set_logical_block(inode, logical_index, block_num)
            total_alloc_blocks += 1 + len(meta)

            start = logical_index * self.block_size
            end = start + self.block_size
            chunk = data[start:end]
            if len(chunk) < self.block_size:
                chunk += b"\x00" * (self.block_size - len(chunk))
            const.write_data(self.file, self.start_base + block_num * self.block_size, chunk)

        self._write_inode_size(inode, len(data))
        self._write_inode_blocks_sectors(inode, total_alloc_blocks * (self.block_size // 512))
        self._write_inode_times(inode, int(time.time()))

    def delete_file(self, dst_path: str):
        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not self._inode_is_dir(parent_inode):
            raise FileNotFoundError(parent_path)

        inode = self.find_file(dst_path)
        if inode is None:
            raise FileNotFoundError(dst_path)
        if self._inode_is_dir(inode):
            raise IsADirectoryError(dst_path)

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._remove_dir_entry(parent_live, name)

        now = int(time.time())
        self._write_inode_times(parent_live, now)

        if inode["i_links_count"] > 1:
            self._write_inode_links(inode, inode["i_links_count"] - 1)
            self._write_inode_u32(inode, 0x0C, now)
            self._write_inode_u32(inode, 0x10, now)
            return

        data_blocks, meta_blocks = self._collect_file_blocks_and_metadata(inode)
        for block_num in data_blocks + meta_blocks:
            self._free_block(block_num)

        const.write_data(self.file, inode["inode_offset"], b"\x00" * self.inode_size)
        self._free_inode_bitmap(inode["inode_num"])

    def create_directory(self, dst_path: str, mode: int = 0o755):
        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not self._inode_is_dir(parent_inode):
            raise FileNotFoundError(parent_path)
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        inode_num = self._alloc_inode()
        inode = self._get_inode(inode_num)
        block_num = self._alloc_block()
        now = int(time.time())

        self._write_inode_u16(inode, 0x00, stat.S_IFDIR | (mode & 0o777))
        self._write_inode_ids(inode, 0, 0)
        self._write_inode_size(inode, self.block_size)
        self._write_inode_blocks_sectors(inode, self.block_size // 512)
        self._write_inode_links(inode, 2)
        self._write_inode_times(inode, now)
        self._write_inode_u32(inode, 0x14, 0)
        self._write_inode_u32(inode, 0x20, 0)
        self._write_inode_block_ptr(inode, 0, block_num)

        dot = self._pack_dir_entry(inode_num, ".", 2, 12)
        dotdot = self._pack_dir_entry(parent_inode["inode_num"], "..", 2, self.block_size - 12)
        const.write_data(self.file, self.start_base + block_num * self.block_size, dot + dotdot)

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._insert_dir_entry(parent_live, inode_num, name, 2)
        self._write_inode_links(parent_live, parent_live["i_links_count"] + 1)
        self._write_inode_times(parent_live, now)
        self._adjust_used_dirs(inode_num, 1)

    def remove_directory(self, dst_path: str):
        if dst_path == "/":
            raise ValueError("cannot remove root directory")

        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not self._inode_is_dir(parent_inode):
            raise FileNotFoundError(parent_path)

        inode = self.find_file(dst_path)
        if inode is None:
            raise FileNotFoundError(dst_path)
        if not self._inode_is_dir(inode):
            raise NotADirectoryError(dst_path)
        if not self._dir_is_empty(inode):
            raise OSError("directory not empty")

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._remove_dir_entry(parent_live, name)
        now = int(time.time())
        self._write_inode_links(parent_live, max(0, parent_live["i_links_count"] - 1))
        self._write_inode_times(parent_live, now)

        data_blocks, meta_blocks = self._collect_file_blocks_and_metadata(inode)
        for block_num in data_blocks + meta_blocks:
            self._free_block(block_num)

        const.write_data(self.file, inode["inode_offset"], b"\x00" * self.inode_size)
        self._free_inode_bitmap(inode["inode_num"])
        self._adjust_used_dirs(inode["inode_num"], -1)

    def create_hard_link(self, src_path: str, dst_path: str):
        src_inode = self.find_file(src_path)
        if src_inode is None:
            raise FileNotFoundError(src_path)
        if self._inode_is_dir(src_inode):
            raise IsADirectoryError(src_path)

        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not self._inode_is_dir(parent_inode):
            raise FileNotFoundError(parent_path)
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        parent_live = self._get_inode(parent_inode["inode_num"])
        src_live = self._get_inode(src_inode["inode_num"])
        self._insert_dir_entry(
            parent_live,
            src_live["inode_num"],
            name,
            self._dir_entry_type_for_mode(src_live["i_mode"])
        )
        self._write_inode_links(src_live, src_live["i_links_count"] + 1)
        now = int(time.time())
        self._write_inode_times(parent_live, now)
        self._write_inode_times(src_live, now)

    def create_symlink(self, target_path: str, dst_path: str, mode: int = 0o777):
        parent_path, name = self._split_parent_child(dst_path)
        parent_inode = self.find_file(parent_path)
        if parent_inode is None or not self._inode_is_dir(parent_inode):
            raise FileNotFoundError(parent_path)
        if self.find_file(dst_path):
            raise FileExistsError(dst_path)

        target_bytes = target_path.encode("latin-1")
        inode_num = self._alloc_inode()
        inode = self._get_inode(inode_num)
        now = int(time.time())

        self._write_inode_u16(inode, 0x00, stat.S_IFLNK | (mode & 0o777))
        self._write_inode_ids(inode, 0, 0)
        self._write_inode_links(inode, 1)
        self._write_inode_times(inode, now)
        self._write_inode_u32(inode, 0x14, 0)
        self._write_inode_u32(inode, 0x20, 0)
        self._write_inode_size(inode, len(target_bytes))
        block_num = self._alloc_block()
        self._write_inode_block_ptr(inode, 0, block_num)
        const.write_data(
            self.file,
            self.start_base + block_num * self.block_size,
            target_bytes + b"\x00" * (self.block_size - len(target_bytes))
        )
        self._write_inode_blocks_sectors(inode, self.block_size // 512)

        parent_live = self._get_inode(parent_inode["inode_num"])
        self._insert_dir_entry(parent_live, inode_num, name, 7)
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
        if not self._inode_is_dir(src_parent) or not self._inode_is_dir(dst_parent):
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

        if self._inode_is_dir(moved_live) and src_parent_live["inode_num"] != dst_parent_live["inode_num"]:
            self._set_dotdot_entry(moved_live, dst_parent_live["inode_num"])
            self._write_inode_links(src_parent_live, max(0, src_parent_live["i_links_count"] - 1))
            self._write_inode_links(dst_parent_live, dst_parent_live["i_links_count"] + 1)

    def touch(self, dst_path: str):
        inode = self.find_file(dst_path)
        now = int(time.time())
        if inode is None:
            self.create_file_from_bytes(b"", dst_path, mode=0o644, uid=0, gid=0)
            return
        self._write_inode_times(inode, now)

    def truncate_file(self, dst_path: str, size: int):
        inode = self.find_file(dst_path)
        if inode is None:
            raise FileNotFoundError(dst_path)
        if not self._inode_is_reg(inode):
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

        # 1. 解析文件类型和权限 (i_mode)
        mode = inode['i_mode']
        perms = stat.filemode(mode)  # 例如: -rwxr-xr-x
        
        file_type = "Unknown"
        if stat.S_ISREG(mode): file_type = "Regular File"
        elif stat.S_ISDIR(mode): file_type = "Directory"
        elif stat.S_ISLNK(mode): file_type = "Symbolic Link"
        elif stat.S_ISBLK(mode): file_type = "Block Device"
        elif stat.S_ISCHR(mode): file_type = "Character Device"
        elif stat.S_ISFIFO(mode): file_type = "FIFO/Pipe"
        elif stat.S_ISSOCK(mode): file_type = "Socket"

        # 2. 解析时间 (Unix Timestamp -> String)
        def fmt_time(ts):
            return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        atime = fmt_time(inode['i_atime'])
        ctime = fmt_time(inode['i_ctime'])
        mtime = fmt_time(inode['i_mtime'])

        # 3. 解析大小 (Human Readable)
        recode_i_size_addr_4_bytes = inode['recode_i_size_addr_4_bytes']
        size = inode['i_size']
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.2f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.2f} MB"

        # 4. 打印输出
        print("-" * 40)
        print(f"File Type:   {file_type} ({perms})")
        print(f"Size:        {size_str} ({size} bytes)")
        print(f"recode_i_size_addr_4_bytes 0x{recode_i_size_addr_4_bytes:x}")
        print(f"UID/GID:     {inode['i_uid']} / {inode['i_gid']}")
        print(f"Links:       {inode['i_links_count']}")
        print(f"Flags:       {hex(inode['i_flags'])}")
        print("-" * 40)
        print(f"Access Time: {atime}")
        print(f"Modify Time: {mtime}")
        print(f"Change Time: {ctime}")
        print("-" * 40)
        
        # 5. 块信息解析
        print(f"Total Blocks:{inode['i_blocks']} (512-byte sectors)")

        hex_blocks = [hex(b) for b in inode['i_block'][:12]]
        print(f"Block Ptrs(show all direct blocks):  {hex_blocks} ...") # 只显示直接块
