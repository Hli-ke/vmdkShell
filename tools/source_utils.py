import os
import stat


class ResolvedSource:
    def __init__(
        self,
        spec: str,
        label: str,
        size: int | None,
        reader,
        cached_data: bytes | None = None,
        source_type: str = "virtual",
        host_path: str | None = None,
    ):
        self.spec = spec
        self.label = label
        self.size = size
        self._reader = reader
        self._cached_data = cached_data
        self.source_type = source_type
        self.host_path = host_path

    def read(self, offset: int, size: int | None = None):
        if offset < 0:
            raise ValueError("offset must be >= 0")

        if self._cached_data is not None:
            if size is None:
                return self._cached_data[offset:]
            return self._cached_data[offset:offset + size]

        return self._reader(offset, size)


def resolve_host_path(shell, source_spec: str):
    if source_spec.startswith("@host:"):
        raw_path = source_spec[len("@host:"):]
    elif source_spec.startswith("host:"):
        raw_path = source_spec[len("host:"):]
    else:
        raw_path = source_spec

    if not raw_path:
        raise FileNotFoundError("empty host path")

    if os.path.isabs(raw_path):
        host_path = raw_path
    else:
        host_path = os.path.abspath(os.path.join(os.getcwd(), raw_path))

    if not os.path.exists(host_path):
        raise FileNotFoundError(host_path)
    return host_path


def _resolve_host_file_source(shell, source_spec: str):
    host_path = resolve_host_path(shell, source_spec)
    if not os.path.isfile(host_path):
        raise ValueError(f"not a file: {host_path}")

    size = os.path.getsize(host_path)
    return ResolvedSource(
        spec=source_spec,
        label=host_path,
        size=size,
        reader=lambda offset, size=None: _read_host_bytes(host_path, offset, size),
        source_type="host",
        host_path=host_path,
    )


def _resolve_virtual_file_source(shell, source_spec: str, raw_path: str | None = None):
    path = shell.resolve_path(raw_path if raw_path is not None else source_spec)
    _, fs, inode = shell.vmdk.get_path_entry(path)
    if fs is None or inode is None:
        raise FileNotFoundError(path)
    if not stat.S_ISREG(inode["i_mode"]):
        raise ValueError(f"not a file: {path}")
    if not hasattr(fs, "read_file_by_inode"):
        raise NotImplementedError(f"filesystem does not support reading file bytes: {path}")

    data = fs.read_file_by_inode(inode)
    return ResolvedSource(
        spec=source_spec,
        label=path,
        size=len(data),
        reader=lambda offset, size=None: data[offset:] if size is None else data[offset:offset + size],
        cached_data=data,
        source_type="virtual",
    )


def _read_host_bytes(host_path: str, offset: int, size: int | None = None):
    with open(host_path, "rb") as fp:
        fp.seek(offset)
        return fp.read() if size is None else fp.read(size)


def resolve_source(shell, source_spec: str):
    if source_spec.startswith("@host:") or source_spec.startswith("host:"):
        return _resolve_host_file_source(shell, source_spec)
    if source_spec.startswith("@image:") or source_spec.startswith("image:"):
        prefix_len = 7 if source_spec.startswith("@image:") else 6
        return _resolve_virtual_file_source(shell, source_spec, raw_path=source_spec[prefix_len:])

    if source_spec == "@disk":
        size = shell.vmdk.get_raw_size()
        return ResolvedSource(
            spec=source_spec,
            label="disk",
            size=size,
            reader=lambda offset, size=None: shell.vmdk.read_raw_bytes(offset=offset, size=size),
            source_type="raw",
        )

    if source_spec == "@selected":
        item = shell.vmdk.get_selected_item()
        size = item["partition"].get("size_bytes")
        return ResolvedSource(
            spec=source_spec,
            label=f"selected:{item['name']}",
            size=size,
            reader=lambda offset, size=None: shell.vmdk.read_item_bytes(item, offset=offset, size=size),
            source_type="raw",
        )

    if source_spec.startswith("@item:"):
        item_name = source_spec.split(":", 1)[1]
        item = shell.vmdk.get_item_by_name(item_name)
        if item is None:
            raise FileNotFoundError(f"unknown item: {item_name}")
        size = item["partition"].get("size_bytes")
        return ResolvedSource(
            spec=source_spec,
            label=f"item:{item['name']}",
            size=size,
            reader=lambda offset, size=None: shell.vmdk.read_item_bytes(item, offset=offset, size=size),
            source_type="raw",
        )

    tool_view = getattr(shell, "tool_view", "auto")
    if tool_view == "host":
        return _resolve_host_file_source(shell, source_spec)
    if tool_view == "image":
        return _resolve_virtual_file_source(shell, source_spec)

    try:
        return _resolve_virtual_file_source(shell, source_spec)
    except FileNotFoundError:
        return _resolve_host_file_source(shell, source_spec)
