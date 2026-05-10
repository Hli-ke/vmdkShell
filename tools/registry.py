class ToolRegistry:
    def __init__(self):
        self._by_name = {}
        self._tools = []

    def register(self, tool):
        self._tools.append(tool)
        for name in tool.all_names():
            self._by_name[name.lower()] = tool
        return tool

    def get(self, name: str):
        return self._by_name.get(name.lower())

    def iter_tools(self):
        return tuple(self._tools)
