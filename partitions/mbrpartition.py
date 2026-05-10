
from typing import IO
import const_define as const

class MBRPartition:
    def __init__(self, fileName: str = None, file: IO = None, sector_size: int = 0x200):
        self.file = file if file else open(fileName, 'rb')
        self.sector_size = sector_size
        self.fs: dict = {}

        self.file.seek(0)
        self.bootstrap = self.file.read(446)
        self.partition_table_raw = self.file.read(64)
        self.boot_signature = self.file.read(2)

        if self.boot_signature != b'\x55\xaa':
            raise ValueError(f"Invalid MBR signature: {self.boot_signature.hex()}")

        self.partitions = []

    def parse_mbr_partition(self):
        if self.partitions:
            return

        extended_partitions = []
        for i in range(4):
            entry_offset = i * 16
            entry_data = self.partition_table_raw[entry_offset : entry_offset + 16]

            if all(b == 0 for b in entry_data):
                continue

            partition = self._build_partition_entry(
                entry_data,
                index=i + 1,
                first_lba_base=0,
                name=f"MBR_Partition{(len(self.partitions) + 1)}",
            )
            self.partitions.append(partition)

            if partition["partition_type"] in const.MBR_EXTENDED_TYPES:
                extended_partitions.append(partition)

        next_index = 5
        for partition in extended_partitions:
            next_index = self._parse_extended_chain(partition, next_index)

    def _build_partition_entry(self, entry_data: bytes, index: int, first_lba_base: int, name: str, parent_index: int = None):
        active_flag = entry_data[0]
        starting_head = entry_data[1]
        starting_sector_cylinder = int.from_bytes(entry_data[2:4], 'little')
        partition_type = entry_data[4]
        ending_head = entry_data[5]
        ending_sector_cylinder = int.from_bytes(entry_data[6:8], 'little')
        relative_lba = int.from_bytes(entry_data[8:12], 'little')
        sectors_count = int.from_bytes(entry_data[12:16], 'little')
        starting_lba = first_lba_base + relative_lba

        return {
            "index": index,
            "active_flag": active_flag,
            "starting_head": starting_head,
            "starting_sector_cylinder": starting_sector_cylinder,
            "partition_type": partition_type,
            "ending_head": ending_head,
            "ending_sector_cylinder": ending_sector_cylinder,
            "relative_lba": relative_lba,
            "first_lba": starting_lba,
            "sectors_count": sectors_count,
            "start_byte": starting_lba * self.sector_size,
            "size_bytes": sectors_count * self.sector_size,
            "name": name,
            "parent_index": parent_index,
            "is_logical": parent_index is not None,
        }

    def _parse_extended_chain(self, extended_partition: dict, next_index: int):
        base_lba = extended_partition["first_lba"]
        current_ebr_lba = base_lba
        visited = set()

        while current_ebr_lba not in visited:
            visited.add(current_ebr_lba)
            self.file.seek(current_ebr_lba * self.sector_size)
            sector = self.file.read(self.sector_size)
            if len(sector) < self.sector_size or sector[510:512] != b"\x55\xaa":
                break

            first_entry = sector[446:462]
            if not all(b == 0 for b in first_entry):
                logical = self._build_partition_entry(
                    first_entry,
                    index=next_index,
                    first_lba_base=current_ebr_lba,
                    name=f"MBR_LogicalPartition{next_index}",
                    parent_index=extended_partition["index"],
                )
                self.partitions.append(logical)
                next_index += 1

            next_entry = sector[462:478]
            if all(b == 0 for b in next_entry):
                break

            next_type = next_entry[4]
            if next_type not in const.MBR_EXTENDED_TYPES:
                break

            next_rel_lba = int.from_bytes(next_entry[8:12], 'little')
            if next_rel_lba == 0:
                break

            current_ebr_lba = base_lba + next_rel_lba

        return next_index

    def print_partitions(self):
        print("MBR Partition Table:")
        for p in self.partitions:
            print(f"Partition {p['index']}:")
            print(f"  Active Flag : 0x{p['active_flag']:02X}")
            print(f"  Type        : 0x{p['partition_type']:02X} ({const.MBR_partition_type.get(p['partition_type'], 'UNKNOWN')})")
            print(f"  Start Head  : {p['starting_head']}")
            print(f"  Start Cyl   : 0x{p['starting_sector_cylinder']:04X}")
            print(f"  End Head    : {p['ending_head']}")
            print(f"  End Cyl     : 0x{p['ending_sector_cylinder']:04X}")
            print(f"  Start LBA   : {p['first_lba']}")
            print(f"  Sectors     : 0x{p['sectors_count']:x}")
            print(f"  Start (bytes): {p['start_byte']}")
            print(f"  Size (bytes) : {p['size_bytes']}")
            print("")
