import os

from .base import ShellTool
from .source_utils import resolve_source


SIZE_SUFFIXES = {
    "b": 512,
    "k": 1024,
    "m": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
}


def parse_size_expr(value: str):
    text = value.strip().lower()
    if not text:
        raise ValueError("empty numeric value")
    if text[-1].isalpha():
        suffix = text[-1]
        if suffix not in SIZE_SUFFIXES:
            raise ValueError(f"unsupported size suffix: {value}")
        number = int(text[:-1], 0)
        return number * SIZE_SUFFIXES[suffix]
    return int(text, 0)


def parse_option_list(value: str):
    return {
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    }


class DdTool(ShellTool):
    name = "dd"
    description = "copy byte ranges from a virtual file or raw source to host"
    usage = (
        "dd if=<path|@disk|@selected|@item:name> of=<host_file> "
        "[bs=512] [skip=0] [count=<blocks>] "
        "[iflag=skip_bytes,count_bytes] [conv=notrunc,sync] [oflag=append] [status=none|progress]"
    )

    def run(self, shell, argv):
        params = self._parse_args(argv)
        if params is None:
            print(f"usage: {self.usage}")
            print("       dd <src> <host_file> [bs=512] [skip=0] [count=<blocks>]")
            return

        out_file = os.path.abspath(params["of"])
        bs = params["bs"]
        skip_bytes = params["skip_bytes"] + (
            params["skip"] if "skip_bytes" in params["iflag"] else params["skip"] * bs
        )
        seek_bytes = params["seek"] * bs + params["seek_bytes"]
        count_bytes = params["count_bytes"] if params["count_bytes"] is not None else (
            params["count"] if "count_bytes" in params["iflag"] else params["count"] * bs
            if params["count"] is not None else None
        )

        source = resolve_source(shell, params["if"])

        out_dir = os.path.dirname(out_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        total_written = self._copy_to_host(
            source=source,
            out_file=out_file,
            skip_bytes=skip_bytes,
            count_bytes=count_bytes,
            seek_bytes=seek_bytes,
            bs=bs,
            conv=params["conv"],
            oflag=params["oflag"],
            status=params["status"],
        )

        if params["status"] != "none":
            blocks = (total_written + bs - 1) // bs if bs else 0
            print(f"source: {source.label}")
            if skip_bytes:
                print(f"input offset: {skip_bytes} bytes")
            if seek_bytes:
                print(f"output offset: {seek_bytes} bytes")
            if count_bytes is not None:
                print(f"requested: {count_bytes} bytes")
            if params["conv"]:
                print(f"conv: {','.join(sorted(params['conv']))}")
            if params["oflag"]:
                print(f"oflag: {','.join(sorted(params['oflag']))}")
            if params["iflag"]:
                print(f"iflag: {','.join(sorted(params['iflag']))}")
            print(f"{total_written} bytes copied to {out_file}")
            print(f"{blocks} block(s) written, bs={bs}")

    def _copy_to_host(
        self,
        source,
        out_file: str,
        skip_bytes: int,
        count_bytes: int | None,
        seek_bytes: int,
        bs: int,
        conv: set[str],
        oflag: set[str],
        status: str,
    ):
        remaining = count_bytes
        source_offset = skip_bytes
        total_written = 0
        chunk_size = bs

        append_mode = "append" in oflag
        preserve_output = "notrunc" in conv or append_mode or seek_bytes > 0
        if preserve_output:
            mode = "r+b" if os.path.exists(out_file) else "wb+"
        else:
            mode = "wb"

        with open(out_file, mode) as fp:
            if append_mode:
                fp.seek(0, 2)
                if seek_bytes:
                    fp.seek(fp.tell() + seek_bytes)
            elif seek_bytes:
                fp.seek(seek_bytes)

            while True:
                request_size = chunk_size if remaining is None else min(chunk_size, remaining)
                if request_size == 0:
                    break

                chunk = source.read(source_offset, request_size)
                read_size = len(chunk)
                if not chunk and not ("sync" in conv and remaining):
                    break

                if "sync" in conv and len(chunk) < request_size:
                    chunk = chunk + (b"\x00" * (request_size - len(chunk)))

                fp.write(chunk)
                written_size = len(chunk)
                total_written += written_size
                source_offset += read_size

                if status == "progress":
                    print(f"progress: {total_written} bytes")

                if remaining is not None:
                    remaining -= request_size
                    if remaining <= 0:
                        break

        return total_written

    def _parse_args(self, argv):
        params = {
            "if": None,
            "of": None,
            "bs": 512,
            "skip": 0,
            "skip_bytes": 0,
            "seek": 0,
            "seek_bytes": 0,
            "count": None,
            "count_bytes": None,
            "conv": set(),
            "iflag": set(),
            "oflag": set(),
            "status": "default",
        }
        positionals = []
        valid_conv = {"notrunc", "sync"}
        valid_iflag = {"skip_bytes", "count_bytes"}
        valid_oflag = {"append"}
        valid_status = {"default", "none", "progress"}

        for arg in argv:
            if "=" in arg:
                key, value = arg.split("=", 1)
                key = key.strip().lower()
                value = value.strip()
                if key == "if":
                    params["if"] = value
                elif key == "of":
                    params["of"] = value
                elif key == "bs":
                    params["bs"] = parse_size_expr(value)
                elif key == "skip":
                    params["skip"] = parse_size_expr(value)
                elif key == "skip_bytes":
                    params["skip_bytes"] = parse_size_expr(value)
                elif key == "seek":
                    params["seek"] = parse_size_expr(value)
                elif key == "seek_bytes":
                    params["seek_bytes"] = parse_size_expr(value)
                elif key == "count":
                    params["count"] = parse_size_expr(value)
                elif key == "count_bytes":
                    params["count_bytes"] = parse_size_expr(value)
                elif key == "conv":
                    params["conv"] = parse_option_list(value)
                    if not params["conv"] <= valid_conv:
                        raise ValueError(f"unsupported conv option: {value}")
                elif key == "iflag":
                    params["iflag"] = parse_option_list(value)
                    if not params["iflag"] <= valid_iflag:
                        raise ValueError(f"unsupported iflag option: {value}")
                elif key == "oflag":
                    params["oflag"] = parse_option_list(value)
                    if not params["oflag"] <= valid_oflag:
                        raise ValueError(f"unsupported oflag option: {value}")
                elif key == "status":
                    params["status"] = value.strip().lower()
                    if params["status"] not in valid_status:
                        raise ValueError(f"unsupported status option: {value}")
                else:
                    return None
            else:
                positionals.append(arg)

        if params["if"] is None and positionals:
            params["if"] = positionals.pop(0)
        if params["of"] is None and positionals:
            params["of"] = positionals.pop(0)
        if positionals:
            return None
        if params["if"] is None or params["of"] is None:
            return None
        for key in ("skip", "skip_bytes", "seek", "seek_bytes"):
            if params[key] < 0:
                raise ValueError(f"{key} must be >= 0")
        if params["bs"] <= 0:
            raise ValueError("bs must be > 0")
        if params["count"] is not None and params["count"] < 0:
            raise ValueError("count must be >= 0")
        if params["count_bytes"] is not None and params["count_bytes"] < 0:
            raise ValueError("count_bytes must be >= 0")
        return params
