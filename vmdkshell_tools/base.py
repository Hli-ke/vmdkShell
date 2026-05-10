class ShellTool:
    name = ""
    aliases = ()
    description = ""
    usage = ""

    def all_names(self):
        return [self.name, *self.aliases]

    def run(self, shell, argv):
        raise NotImplementedError
