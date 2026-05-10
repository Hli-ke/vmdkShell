from .base import ShellTool
from .dd_tool import parse_size_expr
from .source_utils import resolve_source


class HexdumpTool(ShellTool):
    name = "hexdump"
    description = "render file or raw source bytes in hex"
    usage = "hexdump [-C] [-v] [-s offset] [-n length] <path|@disk|@selected|@item:name>"

    def run(self, shell, argv):
        params = self._parse_args(argv)
        if params is None:
            print(f"usage: {self.usage}")
            return

        source = resolve_source(shell, params["path"])
        if source.size is not None:
            start = min(params["offset"], source.size)
            length = source.size - start if params["length"] is None else min(params["length"], source.size - start)
        else:
            start = params["offset"]
            length = params["length"]

        chunk = source.read(start, length)
        if not chunk:
            return

        self._print_canonical(chunk, start)

    def _parse_args(self, argv):
        path = None
        offset = 0
        length = None
        index = 0

        while index < len(argv):
            arg = argv[index]
            if arg in ("-C", "-v"):
                index += 1
                continue
            if arg == "-s":
                index += 1
                if index >= len(argv):
                    return None
                offset = parse_size_expr(argv[index])
                index += 1
                continue
            if arg == "-n":
                index += 1
                if index >= len(argv):
                    return None
                length = parse_size_expr(argv[index])
                index += 1
                continue
            if arg.startswith("-"):
                return None
            if path is not None:
                return None
            path = arg
            index += 1

        if path is None or offset < 0 or (length is not None and length < 0):
            return None
        return {
            "path": path,
            "offset": offset,
            "length": length,
        }

    def _print_canonical(self, data: bytes, base_offset: int):
        for line_offset in range(0, len(data), 16):
            chunk = data[line_offset:line_offset + 16]
            left = " ".join(f"{byte:02x}" for byte in chunk[:8])
            right = " ".join(f"{byte:02x}" for byte in chunk[8:])
            hex_part = f"{left:<23}  {right:<23}"
            text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            print(f"{base_offset + line_offset:08x}  {hex_part}  |{text:<16}|")

        print(f"{base_offset + len(data):08x}")
