import json
import hashlib
import stat
import mmap
import os
import const_define as const
from typing import IO, List
import shutil
from crypto_state import probe_container
from filesystems.extfs import EXTFS
from filesystems.squashfs import SQUASHFS
from filesystems.ufs import UFS2FS, detect_ufs
from partitions.bsdpartition import BSDPartition
from partitions.gptpartition import GPTPartition
from partitions.mbrpartition import MBRPartition
from vmdk_shell_ops import VMDKShellOps
        

class VMDKVirtualFile:
    def __init__(self, vmdk):
        self.vmdk = vmdk
        self.pos = 0
        self.closed = False

    def seek(self, offset: int, whence: int = 0):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = self.vmdk.capacity * self.vmdk.sector_size + offset
        else:
            raise ValueError("invalid whence")
        return self.pos

    def tell(self):
        return self.pos

    def read(self, size: int = -1):
        if size < 0:
            size = self.vmdk.capacity * self.vmdk.sector_size - self.pos

        data = self.vmdk.read_virtual(self.pos, size)
        self.pos += len(data)
        return data

    def write(self, data: bytes):
        written = self.vmdk.write_virtual(self.pos, data)
        self.pos += written
        return written
    
    def close(self):
        self.closed = True


class VMDK(VMDKShellOps):
    HEADER_SIZE = 512
    file: IO =  None
    raw_f: IO = None
    _virtual_file_class = VMDKVirtualFile

    def __init__(self, filePath: str, sector_size: int = 0x200, init: bool = True):
        if not os.path.exists(filePath):
            raise FileNotFoundError("filePath error")
        
        self.file: IO =  None
        self.raw_f: IO = None
        self.fileName = filePath
        self.bak_f: IO = None
        self.config_file = os.path.dirname(self.fileName).replace("\\", "/") + '/' + os.path.basename(self.fileName) + ".config"

        self.want_partition = None
        self.standalone_filesystems = []
        self.unlocked_items = []
        self.unlock_write_records = {}


        # header fields
        self.magic: bytes = b""
        self.version: int = 0
        self.flags: int = 0
        self.capacity: int = 0
        self.grainsize: int = 0
        self.descriptoroffset: int = 0
        self.descriptrsize: int = 0
        self.numGTEsPerGT: int = 0
        self.rgdOffset: int = 0
        self.gdOffset: int = 0
        self.overHead: int = 0
        self.uncleanShutdown: bool = False
        self.sigleEndLineChar: int = 0
        self.nonEndLineChar: int = 0
        self.doubleEndLineChar1: int = 0
        self.doubleEndLineChar2: int = 0
        self.compressAlgorithm: int = 0
        self.pad: bytes = b""
        self.gpt: GPTPartition = None
        self.mbr: MBRPartition = None

        self.sector_size:int = sector_size
        self.gd_start: int = 0

        self.gt_start: int = 0
        self.gt_index: int = 0

        self.grain_start: int = 0
        self.grain_index: int = 0
        
        if init:
            self.__header_init()

    @classmethod
    def open_image(
        cls,
        filePath: str,
        sector_size: int = 0x200,
        partition: str | int | None = None,
        unlock_key_file: str | None = None,
        auto_unlock: bool = True,
    ):
        with open(filePath, "rb") as fp:
            magic = fp.read(4)

        is_vmdk = magic == b"KDMV"
        obj = cls(filePath, sector_size=sector_size, init=is_vmdk)

        if is_vmdk:
            obj.analyze_virtual_disk()
        else:
            obj.analyze_raw(filePath)

        obj.prepare_runtime(
            partition=partition,
            unlock_key_file=unlock_key_file,
            auto_unlock=auto_unlock,
        )
        return obj

    def prepare_runtime(
        self,
        partition: str | int | None = None,
        unlock_key_file: str | None = None,
        auto_unlock: bool = True,
    ):
        if partition is not None:
            self.set_partition(partition)

        if unlock_key_file:
            if auto_unlock:
                self.try_unlock_with_key(
                    unlock_key_file,
                    stop_after_first=True,
                    select_result=False,
                )
            else:
                self.unlock_filesystem(unlock_key_file)

        return self
    
    def set_partition(self, partition):
        if partition is None:
            self.want_partition = None
            return

        if isinstance(partition, str):
            partition = partition.strip()

            if partition.lower() in ("", "all", "*"):
                self.want_partition = None
                return

            if partition.isdigit():
                partition = int(partition)

        self.want_partition = partition

    def _reset_analysis_state(self):
        self.gpt = None
        self.mbr = None
        self.standalone_filesystems = []
        self.unlocked_items = []
        self.unlock_write_records = {}

    def _register_standalone_filesystem(self, fp: IO, start_offset: int = 0, size_bytes: int = None, name: str = None):
        fs_info = self._detect_filesystem_info(fp, start_offset)
        fs_class = fs_info["class"]

        if size_bytes is None:
            current = fp.tell()
            fp.seek(0, 2)
            size_bytes = max(0, fp.tell() - start_offset)
            fp.seek(current)

        part_name = name or os.path.basename(getattr(fp, "name", "") or self.fileName) or "filesystem_1"
        partition = {
            "index": 1,
            "name": part_name,
            "first_lba": 0,
            "start_byte": start_offset,
            "size_bytes": size_bytes,
        }

        fs = None
        if fs_class is not None:
            fs = fs_class(
                fp=self.raw_f,
                start_base=start_offset,
                size_bytes=size_bytes,
            )
        elif not fs_info.get("container_kind"):
            raise Exception("not support filesystem")

        self.standalone_filesystems = [{
            "index": 1,
            "display_index": 1,
            "source_index": 1,
            "name": part_name,
            "standalone": True,
            "partition": partition,
            "fs_kind": fs_info["kind"],
            "fs_class": fs_class,
            "fs_detail": fs_info["detail"],
            "container_kind": fs_info.get("container_kind"),
            "container_detail": fs_info.get("container_detail"),
            "container_display": fs_info.get("container_display"),
            "is_encrypted": fs_info.get("is_encrypted", False),
            "fs": fs,
        }]

    def _expand_lvm2_volumes(self, items: list):
        result = list(items)
        next_index = len(result) + 1

        for item in items:
            if item.get("container_kind") != "lvm2-pv":
                continue

            detail = item.get("container_detail") or {}
            extent_size = detail.get("extent_size")
            physical_volumes = detail.get("physical_volumes") or {}
            logical_volumes = detail.get("logical_volumes") or []
            vg_name = detail.get("vg_name") or item["name"]

            if extent_size is None or len(physical_volumes) != 1:
                continue

            pv_name, pv_info = next(iter(physical_volumes.items()))
            pe_start = pv_info.get("pe_start")
            if pe_start is None:
                continue

            for lv in logical_volumes:
                if lv.get("segment_type") != "striped" or lv.get("stripe_count") != 1:
                    continue
                if lv.get("pv_name") != pv_name:
                    continue

                lv_start_sector = item["partition"]["first_lba"] + pe_start + lv["pv_extent_start"] * extent_size
                lv_size_bytes = lv["extent_count"] * extent_size * self.sector_size
                fs_info = self._detect_filesystem_info(
                    self.raw_f,
                    lv_start_sector * self.sector_size,
                )
                fs_class = fs_info["class"]
                fs = None
                if fs_class is not None:
                    fs = fs_class(
                        fp=self.raw_f,
                        start_base=lv_start_sector * self.sector_size,
                        size_bytes=lv_size_bytes,
                    )

                result.append({
                    "index": next_index,
                    "display_index": next_index,
                    "source_index": next_index,
                    "name": f"{vg_name}/{lv['name']}",
                    "partition": {
                        "index": next_index,
                        "name": f"{vg_name}/{lv['name']}",
                        "first_lba": lv_start_sector,
                        "start_byte": lv_start_sector * self.sector_size,
                        "size_bytes": lv_size_bytes,
                        "parent_partition": item["partition"],
                        "lvm_volume": lv,
                    },
                    "fs_kind": fs_info["kind"],
                    "fs_class": fs_class,
                    "fs_detail": fs_info["detail"],
                    "container_kind": fs_info.get("container_kind"),
                    "container_detail": fs_info.get("container_detail"),
                    "container_display": fs_info.get("container_display"),
                    "is_encrypted": fs_info.get("is_encrypted", False),
                    "fs": fs,
                })
                next_index += 1

        return result
    
    def __del__(self):
        if self.raw_f:
            self.raw_f.close()
        if self.file:
            self.file.close()

    def _read_u32(self) -> int:
        return const.u(self.file.read(4))

    def _read_u(self) -> int:
        return const.u(self.file.read(8))
    
    def read_data(self, offset: int, size: int) -> bytes:
        return const.read_data(self.file, offset, size)
    
    def write_data(self, offset: int, data: bytes):
        const.write_data(self.file, offset, data)
    
    def u(self, data: bytes) -> int:
        return const.u(data)

    def __header_init(self):
        self.file = open(self.fileName, "rb")
        self.file.seek(0)

        # magic (raw bytes)
        self.magic = self.file.read(4)

        # version / flags
        self.version = self._read_u32()
        self.flags = self._read_u32()

        # capacity, grainsize, descriptor offset/size
        self.capacity = self._read_u()
        self.grainsize = self._read_u()
        self.descriptoroffset = self._read_u()
        self.descriptrsize = self._read_u()

        # numGTEsPerGT
        self.numGTEsPerGT = self._read_u32()

        # rgdOffset / gdOffset / overHead
        self.rgdOffset = self._read_u()
        self.gdOffset = self._read_u()
        self.overHead = self._read_u()

        # flags
        self.uncleanShutdown = bool(const.u(self.file.read(1)))

        # newline chars
        self.sigleEndLineChar = const.u(self.file.read(1))
        self.nonEndLineChar = const.u(self.file.read(1))
        self.doubleEndLineChar1 = const.u(self.file.read(1))
        self.doubleEndLineChar2 = const.u(self.file.read(1))

        # compression algo
        self.compressAlgorithm = const.u(self.file.read(2))

        # padding
        self.pad = self.file.read(433)

        # check header size
        assert self.file.tell() == VMDK.HEADER_SIZE, \
            f"Header size mismatch: {self.file.tell()} != 512"

        self.gd_start = self.gdOffset * self.sector_size
        self.gt_index = 0 
        # self.gt_start = self.u(self.read_data(self.gd_start, 4)) * self.sector_size
        # self.analyze_sectors()

    def virtual_to_physical(self, virtual_offset: int) -> int | None:
        grain_bytes = self.grainsize * self.sector_size

        grain_number = virtual_offset // grain_bytes
        grain_offset = virtual_offset % grain_bytes

        gd_index = grain_number // self.numGTEsPerGT
        gt_index = grain_number % self.numGTEsPerGT

        gd_entry_offset = self.gdOffset * self.sector_size + gd_index * 4
        gt_sector = self.u(self.read_data(gd_entry_offset, 4))

        if gt_sector == 0:
            return None

        gt_entry_offset = gt_sector * self.sector_size + gt_index * 4
        grain_sector = self.u(self.read_data(gt_entry_offset, 4))

        if grain_sector == 0 or grain_sector == 1:
            return None

        return grain_sector * self.sector_size + grain_offset
    
    def read_virtual(self, offset: int, size: int) -> bytes:
        result = bytearray()

        while size > 0:
            grain_bytes = self.grainsize * self.sector_size
            grain_remain = grain_bytes - (offset % grain_bytes)
            chunk_size = min(size, grain_remain)

            physical = self.virtual_to_physical(offset)

            if physical is None:
                result.extend(b"\x00" * chunk_size)
            else:
                result.extend(self.read_data(physical, chunk_size))

            offset += chunk_size
            size -= chunk_size

        return bytes(result)

    def write_virtual(self, offset: int, data: bytes) -> int:
        total = 0
        size = len(data)
        data_offset = 0

        while size > 0:
            grain_bytes = self.grainsize * self.sector_size
            grain_remain = grain_bytes - (offset % grain_bytes)
            chunk_size = min(size, grain_remain)

            physical = self.virtual_to_physical(offset)
            if physical is None:
                raise RuntimeError(f"unallocated virtual offset: 0x{offset:x}")

            chunk = data[data_offset:data_offset + chunk_size]
            self.write_data(physical, chunk)

            offset += chunk_size
            data_offset += chunk_size
            size -= chunk_size
            total += chunk_size

        return total

    def extract_vmdk_base(self):
        if os.path.exists(self.config_file):
            choice = input("config alreadly exist, del it? y/n:" )
            if len(choice) != 1 and choice.lower() != 'y':
                exit(0)
        
        f = open(self.config_file, "wb")

        header_data = self.read_data(0, self.sector_size)
        if len(header_data) < self.sector_size:
            header_data += b'\x00' * (self.sector_size - len(header_data))
        f.write(header_data)
        
        if self.descriptrsize > 0:
            descript_data = self.read_data(self.descriptoroffset * self.sector_size, self.descriptrsize * self.sector_size).rstrip(b'\x00')
            descript_size = len(descript_data)
            total_size = const.align_up(descript_size + 4, 0x10)
            
            padding_len = total_size - descript_size - 4
            f.write(const.p32(descript_size) + descript_data + b'\x00' * padding_len)
        
        total_grains = self.capacity // self.grainsize
        num_gd_entries = (total_grains + self.numGTEsPerGT - 1) // self.numGTEsPerGT
        gd_size_bytes = const.align_up(num_gd_entries * 4, self.sector_size)
        
        gd_data = self.read_data(self.gdOffset * self.sector_size, gd_size_bytes)
        
        if len(gd_data) < gd_size_bytes:
            gd_data += b'\x00' * (gd_size_bytes - len(gd_data))
        f.write(gd_data)

        gt_data_size = self.numGTEsPerGT * 4

        for gd_index in range(num_gd_entries):
            if (gd_index * 4) + 4 > len(gd_data):
                break

            gt_entry_bytes = gd_data[gd_index * 4 : gd_index * 4 + 4]
            gt_sector = const.u(gt_entry_bytes)

            if gt_sector == 0:
                continue
            
            gt_offset = gt_sector * self.sector_size
            gt_data = self.read_data(gt_offset, gt_data_size)
            
            if len(gt_data) < gt_data_size:
                gt_data += b'\x00' * (gt_data_size - len(gt_data))
            
            f.write(const.p32(gd_index))
            f.write(gt_data)
        
        f.close()
                

    def convert_to_raw(self, raw_file: str):
        if not os.path.exists(self.config_file):
            self.extract_vmdk_base()
        
        cf = open(self.config_file, "rb")

        current_offset = self.sector_size

        if self.descriptrsize > 0:
            cf.seek(current_offset)
            size_bytes = cf.read(4)
            if len(size_bytes) == 4:
                d_size = const.u(size_bytes)
                skip = const.align_up(d_size + 4, 0x10)
                current_offset += skip
            else:
                pass
        
        total_grains = self.capacity // self.grainsize
        num_gd_entries = (total_grains + self.numGTEsPerGT - 1) // self.numGTEsPerGT
        gd_size_bytes = const.align_up(num_gd_entries * 4, self.sector_size)
        
        current_offset += gd_size_bytes

        cf.seek(current_offset)

        virtual_size = self.capacity * self.sector_size
        gt_data_size = self.numGTEsPerGT * 4
        
        with open(raw_file, "wb") as f:
            f.truncate(virtual_size)
            
            while True:
                gd_idx_bytes = cf.read(4)
                if len(gd_idx_bytes) < 4:
                    break
                
                gd_index = const.u(gd_idx_bytes)
                
                gt_data = cf.read(gt_data_size)
                if len(gt_data) < gt_data_size:
                    break

                for gt_index in range(self.numGTEsPerGT):
                    idx_start = gt_index * 4
                    grain_entry_bytes = gt_data[idx_start : idx_start + 4]
                    grain_sector = const.u(grain_entry_bytes)

                    if grain_sector == 0 or grain_sector == 1:
                        continue

                    grain_number = gd_index * self.numGTEsPerGT + gt_index
                    virtual_offset = grain_number * self.grainsize * self.sector_size

                    vmdk_offset = grain_sector * self.sector_size
                    
                    grain_data = self.read_data(vmdk_offset, self.grainsize * self.sector_size)

                    f.seek(virtual_offset)
                    f.write(grain_data)
        
        cf.close()
    
    def convert_to_vmdk(self, raw_path, vmdk_path):
        if not os.path.exists(self.config_file):
            print("Config file not found! Cannot reconstruct VMDK.")
            return

        cf = open(self.config_file, "rb")
        raw_f = open(raw_path, "rb")
        vmdk_f = open(vmdk_path, "wb")

        
        # write header
        header_data = cf.read(self.sector_size)
        vmdk_f.write(header_data)
        
        current_offset = self.sector_size

        # write descript
        if self.descriptrsize > 0:
            size_bytes = cf.read(4)
            descript_size = const.u(size_bytes)
            
            config_skip = const.align_up(descript_size + 4, 0x10)
            
            cf.seek(current_offset)
            desc_block = cf.read(config_skip)
            
            real_desc_data = desc_block[4:]
            
            vmdk_f.seek(self.descriptoroffset * self.sector_size)
            vmdk_f.write(real_desc_data)
            
            current_offset += config_skip
        
        # write gd data
        total_grains = self.capacity // self.grainsize
        num_gd_entries = (total_grains + self.numGTEsPerGT - 1) // self.numGTEsPerGT
        gd_size_bytes = const.align_up(num_gd_entries * 4, self.sector_size)
        
        cf.seek(current_offset)
        gd_data = cf.read(gd_size_bytes)
        
        vmdk_f.seek(self.gdOffset * self.sector_size)
        vmdk_f.write(gd_data)
        
        current_offset += gd_size_bytes
        
        # write gt data
        
        gt_data_size = self.numGTEsPerGT * 4
        
        cf.seek(current_offset)
        
        while True:
            gd_idx_bytes = cf.read(4)
            if len(gd_idx_bytes) < 4:
                break 
            
            gd_index = const.u(gd_idx_bytes)
            
            gt_data = cf.read(gt_data_size)
            if len(gt_data) < gt_data_size:
                break
            
            gd_entry_bytes = gd_data[gd_index * 4 : gd_index * 4 + 4]
            gt_sector = const.u(gd_entry_bytes)
            
            if gt_sector != 0:
                vmdk_f.seek(gt_sector * self.sector_size)
                vmdk_f.write(gt_data)
            
            for gt_index in range(self.numGTEsPerGT):
                idx_start = gt_index * 4
                grain_entry_bytes = gt_data[idx_start : idx_start + 4]
                grain_sector = const.u(grain_entry_bytes)
                
                if grain_sector == 0 or grain_sector == 1:
                    continue
                
                grain_number = gd_index * self.numGTEsPerGT + gt_index
                virtual_offset = grain_number * self.grainsize * self.sector_size
                
                vmdk_offset = grain_sector * self.sector_size
                
                raw_f.seek(virtual_offset)
                grain_data = raw_f.read(self.grainsize * self.sector_size)
                
                if len(grain_data) < self.grainsize * self.sector_size:
                    grain_data += b'\x00' * ((self.grainsize * self.sector_size) - len(grain_data))

                vmdk_f.seek(vmdk_offset)
                vmdk_f.write(grain_data)

        cf.close()
        raw_f.close()
        vmdk_f.close()
        print("Convert raw to vmdk finished.")
    
    def parse_gpt(self) -> None:
        if not self.gpt:
            self.gpt = GPTPartition(file=self.raw_f, sector_size=self.sector_size)
        self.gpt.parse_gpt_partition()


    def parse_mbr(self) -> None:
        # print("this is mbr")
        if not self.mbr:
            self.mbr = MBRPartition(file=self.raw_f, sector_size=self.sector_size)
        self.mbr.parse_mbr_partition()

    def _detect_filesystem_info(self, fp: IO, start_offset: int):
        data = const.read_data(fp, start_offset, 0x2000)

        if len(data) >= 0x43A and data[0x438:0x43A] == b'\x53\xEF':
            return {
                "kind": "ext",
                "class": EXTFS,
                "detail": None,
                "container_kind": None,
                "container_detail": None,
                "container_display": None,
                "is_encrypted": False,
            }

        if data[:4] == b'hsqs':
            return {
                "kind": "squashfs",
                "class": SQUASHFS,
                "detail": None,
                "container_kind": None,
                "container_detail": None,
                "container_display": None,
                "is_encrypted": False,
            }

        ufs_info = detect_ufs(fp, start_offset)
        if ufs_info:
            return {
                "kind": ufs_info["kind"],
                "class": UFS2FS if ufs_info["kind"] == "ufs2" else None,
                "detail": ufs_info,
                "container_kind": None,
                "container_detail": None,
                "container_display": None,
                "is_encrypted": False,
            }

        container = probe_container(data)
        if container is not None:
            return {
                "kind": None,
                "class": None,
                "detail": None,
                "container_kind": container.kind,
                "container_detail": container.details,
                "container_display": container.display_name,
                "is_encrypted": container.is_encrypted,
            }

        return {
            "kind": None,
            "class": None,
            "detail": None,
            "container_kind": None,
            "container_detail": None,
            "container_display": None,
            "is_encrypted": False,
        }

    def _iter_partition_targets(self):
        part = self.gpt or self.mbr
        if not part:
            return

        for partition in part.partitions:
            if partition.get("partition_type") in const.MBR_EXTENDED_TYPES:
                continue

            if partition.get("partition_type") not in (0xA5, 0xA6, 0xA9):
                yield partition
                continue

            label = BSDPartition(
                file=part.file,
                start_base=partition["first_lba"] * self.sector_size,
                sector_size=self.sector_size,
            )
            label.parse()

            for subpart in label.partitions:
                if subpart["fstype_name"] in ("unused", "swap"):
                    continue

                if subpart["offset_lba"] == 0 and subpart["size_lba"] == partition["sectors_count"]:
                    continue

                yield {
                    "index": partition["index"],
                    "name": f"{partition['name']}/{subpart['name']}",
                    "first_lba": partition["first_lba"] + subpart["offset_lba"],
                    "size_bytes": subpart["size_bytes"],
                    "parent_partition": partition,
                    "bsd_partition": subpart,
                }
    
    def _analyze_disk(self, fp: IO):
        if self.raw_f and self.raw_f is not fp:
            self.raw_f.close()

        self.raw_f = fp

        bak_f = self.file
        self.file = fp

        try:
            if self.read_data(0x200, 8) == b'EFI PART':
                self.parse_gpt()

            elif self.read_data(0x1FE, 2) == b'\x55\xAA':
                self.parse_mbr()

            else:
                raise Exception("not support partition")

        finally:
            self.file = bak_f


    def analyze_raw(self, raw_file: str):
        fp = open(raw_file, "rb")
        self._analyze_disk(fp)


    def _analyze_disk(self, fp: IO):
        if self.raw_f and self.raw_f is not fp:
            self.raw_f.close()

        self.raw_f = fp
        self._reset_analysis_state()

        if const.read_data(fp, 0x200, 8) == b'EFI PART':
            self.parse_gpt()

        elif const.read_data(fp, 0x1FE, 2) == b'\x55\xAA':
            self.parse_mbr()

        else:
            self._register_standalone_filesystem(fp)

    def analyze_raw(self, raw_file: str):
        fp = open(raw_file, "rb")
        self._analyze_disk(fp)
    
    def analyze_virtual_disk(self):
        fp = VMDKVirtualFile(self)
        self._analyze_disk(fp)
    
    def write_file_to_vmdk(self, src_file: str, dst_path: str, buffer_size: int = 16 * 1024 * 1024):
        # self.file -> open(vmdk_file)
        # self.gpt.file -> open(raw_file)
        part = None

        if self.gpt:
            part = self.gpt
        elif self.mbr:
            part = self.mbr
        if part:
            for partition in part.partitions:
                print(f"search {dst_path} in {partition['name']}")

                if partition['name'] in part.fs and part.fs[partition['name']]:
                    fs = part.fs[partition['name']]
                elif partition['name'] in part.fs:
                    continue
                else:
                    fs_info = self._detect_filesystem_info(
                        part.file,
                        partition['first_lba'] * self.sector_size
                    )
                    fs_class = fs_info["class"]

                    if fs_class is None:
                        part.fs[partition['name']] = None
                        print(f"not found filesystem type in {partition['name']}")
                        continue
                
                    fs = fs_class(fp=part.file, start_base = partition['first_lba'] * self.sector_size)
                    part.fs[partition['name']] = fs
                
                info = fs.find_file(dst_path)   # i_block

                out_file = os.path.join(os.path.dirname(src_file), os.path.basename(src_file) + ".vmdk")
                if not self.file:
                    self.__header_init()

                print(out_file)
                self.file.seek(0)
                with open(out_file, "wb") as fdst:
                     shutil.copyfileobj(self.file, fdst, length=buffer_size)
                
                total_size = 0
                file_size = info["i_size"]
                
                with open(out_file, 'r+b') as f, open(src_file, "rb") as fp:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:

                        for ids in info["i_block"]:
                            if total_size >= file_size:
                                break

                            fs.file.seek(fs.start_base + ids * fs.block_size)
                            target_bytes = fs.file.read(fs.block_size)
                            replace_bytes = fp.read(fs.block_size)
                            
                            remaining = file_size - total_size
                            write_len = min(len(replace_bytes), remaining)

                            if len(target_bytes.rstrip(b'\x00')) == 0:
                                total_size += write_len
                                continue

                            start_pos = 0
                        
                            while True:
                                index = mm.find(target_bytes, start_pos)
                                
                                if index == -1:
                                    break
                                
                                try:
                                    mm[index : index + write_len] = replace_bytes[:write_len]
                                except:
                                    raise IndexError("mmap slice assignment is wrong size")
                                
                                start_pos = index + len(target_bytes)

                            mm.flush()
                            total_size += write_len

                print(f"replace {total_size} bytes success, from {src_file} to {dst_path} in {out_file}")
                break
        part = None


    def detect_filesystem(self, data: bytes):
        if data[0x400 + 0x38: 0x400 + 0x38 + 2] == b'\x53\xEF':
            return EXTFS
        elif data[:4] == b'hsqs':
            return SQUASHFS
        
    


    def find_file_in_partitions(self, absFileName: str):
        part = None
        if self.gpt:
            part = self.gpt
        elif self.mbr:
            part = self.mbr

        if part:
            for partition in part.partitions:
                print(f"search {absFileName} in {partition['name']}")

                if partition['name'] in part.fs and part.fs[partition['name']]:
                    fs = part.fs[partition['name']]
                elif partition['name'] in part.fs:
                    continue
                else:
                    fs_info = self._detect_filesystem_info(
                        part.file,
                        partition['first_lba'] * self.sector_size
                    )
                    fs_class = fs_info["class"]

                    if fs_class is None:
                        part.fs[partition['name']] = None
                        print(f"not found filesystem type in {partition['name']}")
                        continue
                
                    fs = fs_class(fp=part.file, start_base = partition['first_lba'] * self.sector_size)
                    part.fs[partition['name']] = fs
                
                info = fs.find_file(absFileName)
                if info:
                    print(f"\n----------find {absFileName}, and info: ")
                    fs.print_info(info)

        
        part = None
    
    def list_filesystems(self):
        if self.standalone_filesystems:
            return self.standalone_filesystems + self.unlocked_items

        part = self.gpt or self.mbr
        result = []

        if not part:
            return result

        for idx, partition in enumerate(self._iter_partition_targets(), 1):
            part_name = partition.get("name") or f"partition_{idx}"

            fs_info = self._detect_filesystem_info(
                part.file,
                partition["first_lba"] * self.sector_size
            )
            fs_class = fs_info["class"]

            fs = None
            if fs_class is not None:
                fs = fs_class(
                    fp=self.raw_f,
                    start_base=partition["first_lba"] * self.sector_size,
                    size_bytes=partition.get("size_bytes"),
                )

            result.append({
                "index": idx,
                "display_index": idx,
                "source_index": partition.get("index"),
                "name": part_name,
                "partition": partition,
                "fs_kind": fs_info["kind"],
                "fs_class": fs_class,
                "fs_detail": fs_info["detail"],
                "container_kind": fs_info.get("container_kind"),
                "container_detail": fs_info.get("container_detail"),
                "container_display": fs_info.get("container_display"),
                "is_encrypted": fs_info.get("is_encrypted", False),
                "fs": fs,
            })

        return self._expand_lvm2_volumes(result) + self.unlocked_items

# 拉古 达拉哈马 美嘉 亚斯米尼 呀哒哈 乌拉乌 哈巴努古

_SHELL_OP_NAMES = [
    "print_layout",
    "_iter_filesystems",
    "_find_fs_file",
    "print_tree",
    "_human_size",
    "_ensure_vmdk_file",
    "_print_modified_target",
    "_ensure_unlock_write_record",
    "record_vmdk",
    "is_directory",
    "_build_ls_entry",
    "ls",
    "cat",
    "find",
    "download",
    "_host_safe_name",
    "_single_selected_item",
    "_apply_host_metadata",
    "_extract_entry_to_host",
    "_extract_tree_to_host",
    "extract_filesystem",
    "_export_partition_image",
    "prepare_unlock",
    "_unlock_candidate_items",
    "_unlock_item_with_key",
    "rename_view",
    "clear",
    "lsattr",
    "replace_file_in_vmdk",
    "_copy_current_vmdk",
    "_open_mutation_fs",
    "_split_parent_child",
    "_find_fs_for_create",
    "add_file_to_vmdk",
    "_find_fs_for_existing",
    "_mutate_existing",
    "delete_file_from_vmdk",
    "copy_file_in_vmdk",
    "touch_path_in_vmdk",
    "truncate_file_in_vmdk",
    "_join_path",
    "_instantiate_fs_for_item",
    "_copy_node_recursive",
    "copy_path_in_vmdk",
    "_remove_node_recursive",
    "remove_path_in_vmdk",
    "stat_path",
    "readlink_path",
    "_find_walk",
    "find_paths",
    "make_directory_in_vmdk",
    "remove_directory_from_vmdk",
    "rename_path_in_vmdk",
    "hardlink_in_vmdk",
    "symlink_in_vmdk",
    "restore_replace_from_record",
    "chmod",
    "chattr",
]

for _name in _SHELL_OP_NAMES:
    setattr(VMDK, _name, getattr(VMDKShellOps, _name))
