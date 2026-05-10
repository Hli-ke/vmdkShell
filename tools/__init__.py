from .dd_tool import DdTool
from .file_tool import FileTool
from .hexdump_tool import HexdumpTool
from .readelf_tool import ReadElfTool
from .registry import ToolRegistry


def build_default_registry():
    registry = ToolRegistry()
    registry.register(DdTool())
    registry.register(FileTool())
    registry.register(HexdumpTool())
    registry.register(ReadElfTool())
    return registry
