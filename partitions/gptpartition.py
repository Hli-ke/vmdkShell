import const_define as const
import uuid
from typing import IO

class GPTPartition:
    def __init__(self, fileName: str = None, file: IO = None, sector_size: int = 0x200):
        self.file = file if file else open(fileName)
        self.sector_size = sector_size
        self.fs: dict = {}

        self.signature = const.read_data(self.file, 0x200, 8).decode()
        if self.signature != 'EFI PART':
            raise ValueError(f"Invalid GPT signature: {self.signature}")
        
        self.revision = const.u(self.file.read(4))
        self.headerSize = const.u(self.file.read(4))
        self.headerCRC = const.u(self.file.read(4))
        self.reserved = const.u(self.file.read(4))


        # currentLBA, backupLBA, firstUsableLBA, lastUsableLBA: 8 bytes each
        self.currentLBA = const.u(self.file.read(8))
        self.backupLBA = const.u(self.file.read(8))
        self.firstUsableLBA = const.u(self.file.read(8))
        self.lastUsableLBA = const.u(self.file.read(8))
        guid_bytes = self.file.read(0x10)
        self.diskGUID = str(uuid.UUID(bytes_le=guid_bytes))
        self.partitionEntriesLBA = const.u(self.file.read(8))
        self.numParts = const.u(self.file.read(4))
        self.sizeOfPartitionEntries = const.u(self.file.read(4))

        self.partitionEntriesCRC = const.u(self.file.read(4))

        self.reserved2 = self.file.read(self.sector_size - 0x5C)

        self.partitions = []
    
    def parse_gpt_partition(self):
        if len(self.partitions) != 0 :
            return
        self.file.seek(self.partitionEntriesLBA * self.sector_size)

        for i in range(self.numParts):
            entry_data = self.file.read(self.sizeOfPartitionEntries)

            if len(entry_data.rstrip(b'\x00')) == 0:
                continue

            part_type_guid = uuid.UUID(bytes_le=entry_data[0:16])
            unique_guid = uuid.UUID(bytes_le=entry_data[16:32])

            first_lba = const.u(entry_data[32:40])
            last_lba = const.u(entry_data[40:48])
            attrs = const.u(entry_data[48:56])

            name = entry_data[56:128].decode("utf-16le").rstrip("\x00")

            self.partitions.append({
                "index": i + 1,
                "type_guid": str(part_type_guid),
                "unique_guid": str(unique_guid),
                "first_lba": first_lba,
                "last_lba": last_lba,
                "start_byte": first_lba * self.sector_size,
                "size_bytes": (last_lba - first_lba + 1) * self.sector_size,
                "attrs": attrs,
                "name": name
            })
    
    def print_partitions(self):
        print("GPT Partition Table:")
        for p in self.partitions:
            print(f"Partition {p['index']}:")
            print(f"  Type GUID   : {p['type_guid']}")
            print(f"  Unique GUID : {p['unique_guid']}")
            print(f"  First LBA   : {p['first_lba']}")
            print(f"  Last LBA    : {p['last_lba']}")
            print(f"  Start (bytes): {p['start_byte']}")
            print(f"  Size (bytes) : {p['size_bytes']}")
            print(f"  Name        : {p['name']}")
            print("")