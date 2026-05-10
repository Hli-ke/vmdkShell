import sys
from typing import Literal
import gzip
import lzma


def p8(number: int, byteorder: Literal["little", "big"] = 'little') -> bytes:
    return number.to_bytes(1, byteorder=byteorder)


def p16(number: int, byteorder: Literal["little", "big"] = 'little') -> bytes:
    return number.to_bytes(2, byteorder=byteorder)


def p32(number: int, byteorder: Literal["little", "big"] = 'little') -> bytes:
    return number.to_bytes(4, byteorder=byteorder)


def p64(number: int, byteorder: Literal["little", "big"] = 'little') -> bytes:
    return number.to_bytes(8, byteorder=byteorder)


def u(data: bytes, byteorder: Literal["little", "big"] = 'little') -> int:
    return int.from_bytes(data, byteorder=byteorder)


def read_data(file, offset: int, size: int) -> bytes:
    file.seek(offset)
    return file.read(size)

def write_data(file, offset: int, data: bytes):
    file.seek(offset)
    file.write(data)


def align_up(value: int, alignment: int = 0x4) -> int:
    if alignment <= 0:
        raise ValueError("alignment error")

    return (value + alignment - 1) // alignment * alignment


def supports_unicode_output() -> bool:
    encoding = getattr(sys.stdout, "encoding", None) or ""
    encoding = encoding.lower()
    return "utf" in encoding


def dir_icon(is_dir: bool) -> str:
    if supports_unicode_output():
        return "📁" if is_dir else "📄"
    return "[D]" if is_dir else "[F]"


def tree_branch(is_last: bool) -> tuple[str, str]:
    if supports_unicode_output():
        if is_last:
            return "└── ", "    "
        return "├── ", "│   "

    if is_last:
        return "`-- ", "    "
    return "|-- ", "|   "

# Magic Number
EXT2_SUPER_MAGIC = 0xEF53

# File System State
EXT2_VALID_FS = 1
EXT2_ERROR_FS = 2

# Error Handling Actions
EXT2_ERRORS_CONTINUE = 1
EXT2_ERRORS_RO = 2
EXT2_ERRORS_PANIC = 3

# Creator OS
EXT2_OS_LINUX = 0
EXT2_OS_HURD = 1
EXT2_OS_MASIX = 2
EXT2_OS_FREEBSD = 3
EXT2_OS_LITES = 4

# Revision Levels
EXT2_GOOD_OLD_REV = 0
EXT2_DYNAMIC_REV = 1

# Defaults for Old Revisions
EXT2_GOOD_OLD_FIRST_INO = 11
EXT2_GOOD_OLD_INODE_SIZE = 128

# Feature Compat
EXT2_FEATURE_COMPAT_DIR_PREALLOC = 0x0001
EXT2_FEATURE_COMPAT_IMAGIC_INODES = 0x0002
EXT3_FEATURE_COMPAT_HAS_JOURNAL = 0x0004
EXT2_FEATURE_COMPAT_EXT_ATTR = 0x0008
EXT2_FEATURE_COMPAT_RESIZE_INO = 0x0010
EXT2_FEATURE_COMPAT_DIR_INDEX = 0x0020

# Feature Incompat
EXT2_FEATURE_INCOMPAT_COMPRESSION = 0x0001
EXT2_FEATURE_INCOMPAT_FILETYPE = 0x0002
EXT3_FEATURE_INCOMPAT_RECOVER = 0x0004
EXT3_FEATURE_INCOMPAT_JOURNAL_DEV = 0x0008
EXT2_FEATURE_INCOMPAT_META_BG = 0x0010

# Feature RO Compat
EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER = 0x0001
EXT2_FEATURE_RO_COMPAT_LARGE_FILE = 0x0002
EXT2_FEATURE_RO_COMPAT_BTREE_DIR = 0x0004

# Compression Algorithms
EXT2_LZV1_ALG = 0x00000001
EXT2_LZRW3A_ALG = 0x00000002
EXT2_GZIP_ALG = 0x00000004
EXT2_BZIP2_ALG = 0x00000008
EXT2_LZO_ALG = 0x00000010

EXT2_ROOT_INO = 2
EXT2_NDIR_BLOCKS = 12
EXT2_DESC_SIZE = 32



MBR_partition_type = {
    0x05: "PARTITION_TYPE_EXTENDED",
    0x0F: "PARTITION_TYPE_EXTENDED_LBA",
    0x07: "PARTITION_TYPE_NTFS", 
    0x0B: "PARTITION_TYPE_FAT32",
    0x85: "PARTITION_TYPE_LINUX_EXTENDED",
    0xA5: "PARTITION_TYPE_FREEBSD",
    0x83: "PARTITION_TYPE_LINUX", 
    0xEE: "PARTITION_TYPE_GPT"
}

MBR_EXTENDED_TYPES = {0x05, 0x0F, 0x85}



#   GZIP:1, LZMA:2, LZO:3, XZ:4, LZ4:5, ZSTD:6
compressor_dict = {
    1: gzip, 
    2: lzma,
    3: None,    
    4: lzma,
    5: None,
    6: None
}
