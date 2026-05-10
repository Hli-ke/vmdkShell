from typing import IO

import const_define as const


class BSDPartition:
    MAGIC = 0x82564557
    LABEL_SECTOR_OFFSET = 0x200
    PARTITION_TABLE_OFFSET = 0x94
    PARTITION_ENTRY_SIZE = 0x10

    FSTYPE_NAMES = {
        0: "unused",
        1: "swap",
        2: "version6",
        3: "version7",
        4: "systemv",
        5: "msdos",
        6: "bsdffs-old",
        7: "ufs",
        8: "msdos",
        9: "lfs",
        10: "unknown10",
        11: "hpfs",
        12: "iso9660",
        13: "boot",
        14: "vinum",
        15: "raid",
        27: "zfs",
    }

    def __init__(self, file: IO, start_base: int, sector_size: int = 0x200):
        self.file = file
        self.start_base = start_base
        self.sector_size = sector_size

        label_offset = self.start_base + self.LABEL_SECTOR_OFFSET
        self.data = const.read_data(self.file, label_offset, sector_size)

        magic = const.u(self.data[0x00:0x04])
        magic2 = const.u(self.data[0x84:0x88])
        if magic != self.MAGIC or magic2 != self.MAGIC:
            raise ValueError("invalid BSD partition label")

        self.npartitions = const.u(self.data[0x8A:0x8C])
        self.bbsize = const.u(self.data[0x8C:0x90])
        self.sbsize = const.u(self.data[0x90:0x94])
        self.partitions = []

    def parse(self):
        if self.partitions:
            return

        max_entries = (len(self.data) - self.PARTITION_TABLE_OFFSET) // self.PARTITION_ENTRY_SIZE
        count = min(self.npartitions, max_entries, 16)

        for idx in range(count):
            entry_offset = self.PARTITION_TABLE_OFFSET + idx * self.PARTITION_ENTRY_SIZE
            entry = self.data[entry_offset: entry_offset + self.PARTITION_ENTRY_SIZE]

            p_size = const.u(entry[0x00:0x04])
            p_offset = const.u(entry[0x04:0x08])
            p_fsize = const.u(entry[0x08:0x0C])
            p_fstype = entry[0x0C]
            p_frag = entry[0x0D]
            p_cpg = const.u(entry[0x0E:0x10])

            if p_size == 0:
                continue

            letter = chr(ord("a") + idx)
            fstype_name = self.FSTYPE_NAMES.get(p_fstype, f"unknown-{p_fstype}")

            self.partitions.append({
                "index": idx + 1,
                "letter": letter,
                "name": f"BSD_Partition_{letter}",
                "offset_lba": p_offset,
                "size_lba": p_size,
                "start_byte": self.start_base + p_offset * self.sector_size,
                "size_bytes": p_size * self.sector_size,
                "fstype": p_fstype,
                "fstype_name": fstype_name,
                "fsize": p_fsize,
                "frag": p_frag,
                "cpg": p_cpg,
            })
