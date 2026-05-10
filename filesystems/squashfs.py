import const_define as const
from typing import IO


class SQUASHFS:
    root_inode_data: bytes = None

    def __init__(self, fileName: str = None, fp: IO = None, start_base: int = 0):
        self.file = fp if fp else open(fileName, "rb")
        self.start_base = start_base

        sb_offset = self.start_base
        self.file.seek(sb_offset)
        self.sb_data = self.file.read(1024)

        self.magic                 = self.sb_data[0x00:0x04]
        self.inode_count           = const.u(self.sb_data[0x04:0x08])
        self.modification_time     = const.u(self.sb_data[0x08:0x0C])
        self.block_size            = const.u(self.sb_data[0x0C:0x10])
        self.fragment_entry_count  = const.u(self.sb_data[0x10:0x14])

        self.compression_id        = const.u(self.sb_data[0x14:0x16])
        self.block_log             = const.u(self.sb_data[0x16:0x18])
        self.flags                 = const.u(self.sb_data[0x18:0x1A])
        self.id_count              = const.u(self.sb_data[0x1A:0x1C])
        self.version_major         = const.u(self.sb_data[0x1C:0x1E])
        self.version_minor         = const.u(self.sb_data[0x1E:0x20])

        self.root_inode_ref        = const.u(self.sb_data[0x20:0x28])
        self.bytes_used            = const.u(self.sb_data[0x28:0x30])
        self.id_table_start        = const.u(self.sb_data[0x30:0x38])
        self.xattr_id_table_start  = const.u(self.sb_data[0x38:0x40])
        self.inode_table_start     = const.u(self.sb_data[0x40:0x48])
        self.directory_table_start = const.u(self.sb_data[0x48:0x50])
        self.fragment_table_start  = const.u(self.sb_data[0x50:0x58])
        self.export_table_start    = const.u(self.sb_data[0x58:0x60])

        self.compressor = const.compressor_dict[self.compression_id]

        if self.compressor is None:
            raise Exception(f"tools not support {self.compression_id} compress")
    

    def init_structure(self):
        block_offset = self.root_inode_ref >> 0x10
        inode_offset = self.root_inode_ref & 0xFFFF

        root_inode_offset = self.inode_table_start + block_offset

        length = const.u(const.read_data(self.file, root_inode_offset + self.start_base, 0x2))
        data = const.read_data(self.file, root_inode_offset + self.start_base, length)
        

        self.root_inode_data = self.compressor.decompress(const.read_data(data))
        
        
        pass

    def find_file(self, asbFileName: str):
        pass