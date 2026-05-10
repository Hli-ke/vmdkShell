import struct


ELF_CLASS = {
    1: "ELF32",
    2: "ELF64",
}

ELF_DATA = {
    1: "2's complement, little endian",
    2: "2's complement, big endian",
}

ELF_OSABI = {
    0: "UNIX - System V",
    1: "UNIX - HP-UX",
    2: "UNIX - NetBSD",
    3: "UNIX - Linux",
    6: "UNIX - Solaris",
    9: "UNIX - FreeBSD",
    12: "UNIX - OpenBSD",
}

ELF_TYPE = {
    0: "NONE (None)",
    1: "REL (Relocatable file)",
    2: "EXEC (Executable file)",
    3: "DYN (Shared object file)",
    4: "CORE (Core file)",
}

ELF_MACHINE = {
    3: "Intel 80386",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    42: "SuperH",
    50: "IA-64",
    62: "Advanced Micro Devices X86-64",
    183: "AArch64",
    243: "RISC-V",
}

PROGRAM_TYPE = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
    0x6474E550: "GNU_EH_FRAME",
    0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO",
}

SECTION_TYPE = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
    0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFD: "GNU_VERDEF",
    0x6FFFFFFE: "GNU_VERNEED",
    0x6FFFFFFF: "GNU_VERSYM",
}


def _u16(data: bytes, offset: int, endian: str):
    return struct.unpack_from(endian + "H", data, offset)[0]


def _read_c_string(blob: bytes, offset: int):
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = len(blob)
    return blob[offset:end].decode("latin-1", errors="replace")


def parse_elf(data: bytes):
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")

    ei_class = data[4]
    ei_data = data[5]
    ei_version = data[6]
    ei_osabi = data[7]
    ei_abiversion = data[8]

    if ei_class not in (1, 2):
        raise ValueError(f"unsupported ELF class: {ei_class}")
    if ei_data not in (1, 2):
        raise ValueError(f"unsupported ELF data encoding: {ei_data}")

    endian = "<" if ei_data == 1 else ">"

    if ei_class == 1:
        fmt = endian + "HHIIIIIHHHHHH"
    else:
        fmt = endian + "HHIQQQIHHHHHH"

    header_size = 16 + struct.calcsize(fmt)
    if len(data) < header_size:
        raise ValueError("truncated ELF header")

    values = struct.unpack_from(fmt, data, 16)
    header = {
        "class": ei_class,
        "class_name": ELF_CLASS.get(ei_class, f"unknown-{ei_class}"),
        "data": ei_data,
        "data_name": ELF_DATA.get(ei_data, f"unknown-{ei_data}"),
        "version": ei_version,
        "osabi": ei_osabi,
        "osabi_name": ELF_OSABI.get(ei_osabi, f"unknown-{ei_osabi}"),
        "abiversion": ei_abiversion,
        "endian": endian,
        "bits": 32 if ei_class == 1 else 64,
        "e_type": values[0],
        "e_machine": values[1],
        "e_version": values[2],
        "e_entry": values[3],
        "e_phoff": values[4],
        "e_shoff": values[5],
        "e_flags": values[6],
        "e_ehsize": values[7],
        "e_phentsize": values[8],
        "e_phnum": values[9],
        "e_shentsize": values[10],
        "e_shnum": values[11],
        "e_shstrndx": values[12],
    }

    header["type_name"] = ELF_TYPE.get(header["e_type"], f"unknown-{header['e_type']}")
    header["machine_name"] = ELF_MACHINE.get(header["e_machine"], f"machine-{header['e_machine']}")
    return header


def parse_program_headers(data: bytes, header: dict):
    count = header["e_phnum"]
    entry_size = header["e_phentsize"]
    offset = header["e_phoff"]
    if count == 0 or entry_size == 0:
        return []

    headers = []
    for index in range(count):
        start = offset + index * entry_size
        end = start + entry_size
        if end > len(data):
            raise ValueError("truncated program header table")

        if header["class"] == 1:
            values = struct.unpack_from(header["endian"] + "IIIIIIII", data, start)
            item = {
                "p_type": values[0],
                "p_offset": values[1],
                "p_vaddr": values[2],
                "p_paddr": values[3],
                "p_filesz": values[4],
                "p_memsz": values[5],
                "p_flags": values[6],
                "p_align": values[7],
            }
        else:
            values = struct.unpack_from(header["endian"] + "IIQQQQQQ", data, start)
            item = {
                "p_type": values[0],
                "p_flags": values[1],
                "p_offset": values[2],
                "p_vaddr": values[3],
                "p_paddr": values[4],
                "p_filesz": values[5],
                "p_memsz": values[6],
                "p_align": values[7],
            }

        item["type_name"] = PROGRAM_TYPE.get(item["p_type"], f"0x{item['p_type']:x}")
        headers.append(item)

    return headers


def parse_section_headers(data: bytes, header: dict):
    count = header["e_shnum"]
    entry_size = header["e_shentsize"]
    offset = header["e_shoff"]
    if count == 0 or entry_size == 0:
        return []

    sections = []
    for index in range(count):
        start = offset + index * entry_size
        end = start + entry_size
        if end > len(data):
            raise ValueError("truncated section header table")

        if header["class"] == 1:
            values = struct.unpack_from(header["endian"] + "IIIIIIIIII", data, start)
            item = {
                "sh_name": values[0],
                "sh_type": values[1],
                "sh_flags": values[2],
                "sh_addr": values[3],
                "sh_offset": values[4],
                "sh_size": values[5],
                "sh_link": values[6],
                "sh_info": values[7],
                "sh_addralign": values[8],
                "sh_entsize": values[9],
            }
        else:
            values = struct.unpack_from(header["endian"] + "IIQQQQIIQQ", data, start)
            item = {
                "sh_name": values[0],
                "sh_type": values[1],
                "sh_flags": values[2],
                "sh_addr": values[3],
                "sh_offset": values[4],
                "sh_size": values[5],
                "sh_link": values[6],
                "sh_info": values[7],
                "sh_addralign": values[8],
                "sh_entsize": values[9],
            }

        item["index"] = index
        item["type_name"] = SECTION_TYPE.get(item["sh_type"], f"0x{item['sh_type']:x}")
        item["name"] = ""
        sections.append(item)

    shstrndx = header["e_shstrndx"]
    if 0 <= shstrndx < len(sections):
        name_section = sections[shstrndx]
        start = name_section["sh_offset"]
        end = start + name_section["sh_size"]
        if end <= len(data):
            string_table = data[start:end]
            for section in sections:
                section["name"] = _read_c_string(string_table, section["sh_name"])

    return sections


def format_program_flags(flags: int):
    return "".join([
        "R" if flags & 4 else " ",
        "W" if flags & 2 else " ",
        "E" if flags & 1 else " ",
    ])


def format_section_flags(flags: int):
    mapping = (
        ("W", 0x1),
        ("A", 0x2),
        ("X", 0x4),
        ("M", 0x10),
        ("S", 0x20),
        ("I", 0x40),
        ("L", 0x80),
        ("O", 0x100),
        ("G", 0x200),
        ("T", 0x400),
        ("C", 0x800),
        ("E", 0x4000000),
    )
    rendered = "".join(letter for letter, bit in mapping if flags & bit)
    return rendered or "0"


def describe_elf(data: bytes):
    header = parse_elf(data)
    program_headers = parse_program_headers(data, header)
    has_interp = any(item["p_type"] == 3 for item in program_headers)

    if header["e_type"] == 2:
        kind = "executable"
    elif header["e_type"] == 3 and has_interp:
        kind = "pie executable"
    elif header["e_type"] == 3:
        kind = "shared object"
    elif header["e_type"] == 1:
        kind = "relocatable"
    elif header["e_type"] == 4:
        kind = "core file"
    else:
        kind = header["type_name"]

    endian_name = "LSB" if header["data"] == 1 else "MSB"
    result = f"ELF {header['bits']}-bit {endian_name} {kind}, {header['machine_name']}"
    if has_interp:
        result += ", dynamically linked"
    return result


def describe_osabi_value(value: int):
    return ELF_OSABI.get(value, f"unknown-{value}")


def format_magic(data: bytes):
    return " ".join(f"{byte:02x}" for byte in data[:16])


def format_entry_size(bits: int, value: int):
    width = 8 if bits == 32 else 16
    return f"0x{value:0{width}x}"


def parse_interp_name(data: bytes, program_header: dict):
    start = program_header["p_offset"]
    end = start + program_header["p_filesz"]
    if end > len(data):
        return ""
    return data[start:end].split(b"\x00", 1)[0].decode("latin-1", errors="replace")


def read_machine(data: bytes):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    endian = "<" if data[5] == 1 else ">"
    value = _u16(data, 18, endian)
    return ELF_MACHINE.get(value, f"machine-{value}")
