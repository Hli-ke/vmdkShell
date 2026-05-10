from .base import ShellTool
from .elf import (
    describe_osabi_value,
    format_entry_size,
    format_magic,
    format_program_flags,
    format_section_flags,
    parse_elf,
    parse_interp_name,
    parse_program_headers,
    parse_section_headers,
)
from .source_utils import resolve_source


class ReadElfTool(ShellTool):
    name = "readelf"
    description = "inspect ELF headers"
    usage = "readelf [-h] [-l] [-S] <path|@host:path>"

    def run(self, shell, argv):
        show_header = False
        show_programs = False
        show_sections = False
        path_arg = None

        for arg in argv:
            if arg.startswith("-") and len(arg) > 1:
                for flag in arg[1:]:
                    if flag == "h":
                        show_header = True
                    elif flag == "l":
                        show_programs = True
                    elif flag == "S":
                        show_sections = True
                    else:
                        print(f"unsupported option: -{flag}")
                        print(f"usage: {self.usage}")
                        return
            else:
                if path_arg is not None:
                    print(f"usage: {self.usage}")
                    return
                path_arg = arg

        if path_arg is None:
            print(f"usage: {self.usage}")
            return

        if not show_header and not show_programs and not show_sections:
            show_header = True

        source = resolve_source(shell, path_arg)
        data = source.read(0, 32 * 1024 * 1024)
        header = parse_elf(data)
        rendered = False

        if show_header:
            self._print_header(header)
            rendered = True

        if show_programs:
            if rendered:
                print()
            self._print_program_headers(data, header)
            rendered = True

        if show_sections:
            if rendered:
                print()
            self._print_section_headers(data, header)

    def _print_header(self, header: dict):
        ident = b"\x7fELF" + bytes([
            header["class"],
            header["data"],
            header["version"],
            header["osabi"],
            header["abiversion"],
        ]) + (b"\x00" * 7)
        print("ELF Header:")
        print(f"  Magic:                             {format_magic(ident)}")
        print(f"  Class:                             {header['class_name']}")
        print(f"  Data:                              {header['data_name']}")
        print(f"  Version:                           {header['e_version']}")
        print(f"  OS/ABI:                            {describe_osabi_value(header['osabi'])}")
        print(f"  ABI Version:                       {header['abiversion']}")
        print(f"  Type:                              {header['type_name']}")
        print(f"  Machine:                           {header['machine_name']}")
        print(f"  Entry point address:               {format_entry_size(header['bits'], header['e_entry'])}")
        print(f"  Start of program headers:          {header['e_phoff']} (bytes into file)")
        print(f"  Start of section headers:          {header['e_shoff']} (bytes into file)")
        print(f"  Flags:                             0x{header['e_flags']:x}")
        print(f"  Size of this header:               {header['e_ehsize']} (bytes)")
        print(f"  Size of program headers:           {header['e_phentsize']} (bytes)")
        print(f"  Number of program headers:         {header['e_phnum']}")
        print(f"  Size of section headers:           {header['e_shentsize']} (bytes)")
        print(f"  Number of section headers:         {header['e_shnum']}")
        print(f"  Section header string table index: {header['e_shstrndx']}")

    def _print_program_headers(self, data: bytes, header: dict):
        program_headers = parse_program_headers(data, header)
        print("Program Headers:")
        if not program_headers:
            print("  <none>")
            return

        print("  Type           Offset             VirtAddr           PhysAddr           FileSiz            MemSiz              Flg Align")
        for item in program_headers:
            print(
                f"  {item['type_name']:<14} "
                f"{format_entry_size(header['bits'], item['p_offset'])} "
                f"{format_entry_size(header['bits'], item['p_vaddr'])} "
                f"{format_entry_size(header['bits'], item['p_paddr'])} "
                f"{format_entry_size(header['bits'], item['p_filesz'])} "
                f"{format_entry_size(header['bits'], item['p_memsz'])} "
                f"{format_program_flags(item['p_flags']):<3} "
                f"{format_entry_size(header['bits'], item['p_align'])}"
            )

        interp = next((item for item in program_headers if item["p_type"] == 3), None)
        if interp is not None:
            name = parse_interp_name(data, interp)
            if name:
                print(f"\n  [Requesting program interpreter: {name}]")

    def _print_section_headers(self, data: bytes, header: dict):
        sections = parse_section_headers(data, header)
        print("Section Headers:")
        if not sections:
            print("  <none>")
            return

        print("  [Nr] Name              Type             Address            Offset")
        print("       Size              EntSize          Flags  Link Info Align")
        for item in sections:
            print(
                f"  [{item['index']:>2}] "
                f"{item['name'][:17]:<17} "
                f"{item['type_name'][:16]:<16} "
                f"{format_entry_size(header['bits'], item['sh_addr'])} "
                f"{item['sh_offset']:08x}"
            )
            print(
                f"       {format_entry_size(header['bits'], item['sh_size'])} "
                f"{format_entry_size(header['bits'], item['sh_entsize'])} "
                f"{format_section_flags(item['sh_flags']):<6} "
                f"{item['sh_link']:>4} {item['sh_info']:>4} {item['sh_addralign']}"
            )
