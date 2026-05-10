import os
import shlex

from tools import build_default_registry


class VMDKShell:
    def __init__(self, vmdk):
        self.vmdk = vmdk
        self.cwd = "/"
        self.tool_view = "auto"
        self.tools = build_default_registry()

    def run(self):
        print("VMDK shell. type 'help' for commands.")

        while True:
            try:
                line = input(f"vmdk[{self.tool_view}]:{self.cwd}> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            args = shlex.split(line, posix=(os.name != "nt"))
            cmd = args[0].lower()
            argv = args[1:]

            try:
                if not self.execute_command(cmd, argv):
                    break
            except Exception as e:
                print(f"error: {e}")

    def execute_command(self, cmd, argv):
        if cmd in ("exit", "quit", "q"):
            return False
        if cmd in ("clear", "cls"):
            os.system("cls" if os.name == "nt" else "clear")
            return True
        if cmd == "pwd":
            print(self.cwd)
            return True
        if cmd == "cd":
            target = self.resolve_path(argv[0] if argv else "/")
            if not self.vmdk.is_directory(target):
                print(f"not a directory: {target}")
                return True
            self.cwd = target
            return True
        if cmd == "ls":
            self.cmd_ls(argv)
            return True
        if cmd == "part":
            if not argv:
                current = self.vmdk.want_partition
                print("partition: all" if current is None else f"partition: {current}")
                return True
            self.vmdk.set_partition(argv[0])
            return True
        if cmd == "tree":
            depth = int(argv[0]) if argv else 2
            self.vmdk.print_tree(max_depth=depth)
            return True
        if cmd in ("layout", "parts"):
            self.vmdk.print_layout()
            return True
        if cmd == "record":
            self.cmd_record(argv)
            return True
        if cmd == "unlock":
            if len(argv) < 1:
                print("usage: unlock <out_file> [key_file] [mapping_name]")
                return True
            key_file = argv[1] if len(argv) > 1 else None
            mapping_name = argv[2] if len(argv) > 2 else None
            self.vmdk.prepare_unlock(argv[0], key_file=key_file, mapping_name=mapping_name)
            return True
        if cmd == "unlockfs":
            if len(argv) < 1:
                print("usage: unlockfs <key_file>")
                return True
            self.vmdk.unlock_filesystem(argv[0])
            return True
        if cmd == "renameview":
            if len(argv) < 2:
                print("usage: renameview <old> <new>")
                return True
            self.vmdk.rename_view(argv[0], argv[1])
            return True
        if cmd == "cat":
            self.vmdk.cat(self.resolve_path(argv[0]))
            return True
        if cmd == "chmod":
            if len(argv) < 2:
                print("usage: chmod <mode> <path>")
                return True
            mode = int(argv[0], 8)
            self.vmdk.chmod(self.resolve_path(argv[1]), mode)
            return True
        if cmd == "chattr":
            if len(argv) < 2:
                print("usage: chattr +i|-i|+a|-a <path>")
                return True
            self.vmdk.chattr(self.resolve_path(argv[1]), argv[0])
            return True
        if cmd in ("download", "get"):
            self.vmdk.download(self.resolve_path(argv[0]), argv[1])
            return True
        if cmd == "extractfs":
            if len(argv) < 1:
                print("usage: extractfs <outdir> [path]")
                return True
            src_path = self.resolve_path(argv[1]) if len(argv) > 1 else "/"
            self.vmdk.extract_filesystem(argv[0], src_path)
            return True
        if cmd == "cp":
            if len(argv) < 2:
                print("usage: cp <src> <dst>")
                return True
            if argv[0] == "-r":
                if len(argv) < 3:
                    print("usage: cp -r <src> <dst>")
                    return True
                self.vmdk.copy_path_in_vmdk(
                    self.resolve_path(argv[1]),
                    self.resolve_path(argv[2]),
                    recursive=True,
                )
                return True
            self.vmdk.copy_path_in_vmdk(
                self.resolve_path(argv[0]),
                self.resolve_path(argv[1]),
                recursive=False,
            )
            return True
        if cmd == "touch":
            if len(argv) < 1:
                print("usage: touch <path>")
                return True
            self.vmdk.touch_path_in_vmdk(self.resolve_path(argv[0]))
            return True
        if cmd == "truncate":
            if len(argv) < 2:
                print("usage: truncate <size> <path>")
                return True
            self.vmdk.truncate_file_in_vmdk(self.resolve_path(argv[1]), int(argv[0], 0))
            return True
        if cmd == "mkdir":
            if len(argv) < 1:
                print("usage: mkdir <path>")
                return True
            self.vmdk.make_directory_in_vmdk(self.resolve_path(argv[0]))
            return True
        if cmd == "rmdir":
            if len(argv) < 1:
                print("usage: rmdir <path>")
                return True
            self.vmdk.remove_directory_from_vmdk(self.resolve_path(argv[0]))
            return True
        if cmd in ("add", "put", "upload"):
            if len(argv) < 2:
                print("usage: add <src_file> <dst_path>")
                return True
            self.vmdk.add_file_to_vmdk(argv[0], self.resolve_path(argv[1]))
            return True
        if cmd in ("rm", "del", "delete", "unlink"):
            if len(argv) < 1:
                print("usage: rm <path>")
                return True
            if argv[0] == "-r":
                if len(argv) < 2:
                    print("usage: rm -r <path>")
                    return True
                self.vmdk.remove_path_in_vmdk(self.resolve_path(argv[1]), recursive=True)
                return True
            self.vmdk.remove_path_in_vmdk(self.resolve_path(argv[0]), recursive=False)
            return True
        if cmd in ("mv", "rename"):
            if len(argv) < 2:
                print("usage: mv <src> <dst>")
                return True
            self.vmdk.rename_path_in_vmdk(self.resolve_path(argv[0]), self.resolve_path(argv[1]))
            return True
        if cmd == "ln":
            if len(argv) < 2:
                print("usage: ln [-s] <src> <dst>")
                return True
            if argv[0] == "-s":
                if len(argv) < 3:
                    print("usage: ln -s <target> <dst>")
                    return True
                self.vmdk.symlink_in_vmdk(argv[1], self.resolve_path(argv[2]))
                return True
            self.vmdk.hardlink_in_vmdk(self.resolve_path(argv[0]), self.resolve_path(argv[1]))
            return True
        if cmd == "stat":
            if len(argv) < 1:
                print("usage: stat <path>")
                return True
            self.vmdk.stat_path(self.resolve_path(argv[0]))
            return True
        if cmd == "readlink":
            if len(argv) < 1:
                print("usage: readlink <path>")
                return True
            self.vmdk.readlink_path(self.resolve_path(argv[0]))
            return True
        if cmd == "find":
            start = self.resolve_path(argv[0]) if argv else self.cwd
            pattern = argv[1] if len(argv) > 1 else None
            self.vmdk.find_paths(start, pattern=pattern)
            return True
        if cmd == "replace":
            if len(argv) < 2:
                print("usage: replace <src_file> <dst_path>")
                return True
            self.vmdk.replace_file_in_vmdk(argv[0], self.resolve_path(argv[1]))
            return True
        if cmd == "restore":
            if len(argv) < 1:
                print("usage: restore <record_file>")
                return True
            self.vmdk.restore_replace_from_record(argv[0])
            return True
        if cmd == "lsattr":
            path = self.resolve_path(argv[0]) if argv else self.cwd
            self.vmdk.lsattr(path)
            return True
        if cmd == "tool":
            self.cmd_tool(argv)
            return True
        if cmd == "view":
            self.cmd_view(argv)
            return True
        if cmd == "help":
            self.help()
            return True

        tool = self.tools.get(cmd)
        if tool is not None:
            tool.run(self, argv)
            return True

        print(f"unknown command: {cmd}")
        return True

    def resolve_path(self, path):
        if path.startswith("/"):
            full = path
        else:
            full = self.cwd.rstrip("/") + "/" + path

        parts = []
        for p in full.split("/"):
            if p in ("", "."):
                continue
            if p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)

        return "/" + "/".join(parts)

    def cmd_ls(self, argv):
        if isinstance(argv, str):
            argv = shlex.split(argv, posix=(os.name != "nt"))
            if argv and argv[0].lower() == "ls":
                argv = argv[1:]

        long = False
        path = self.cwd

        for arg in argv:
            if arg == "-l":
                long = True
            else:
                path = self.resolve_path(arg)

        print(f"ls -> {path}")
        self.vmdk.ls(path, long=long)

    def cmd_record(self, argv):
        if len(argv) > 1:
            print("usage: record [out_file]")
            return

        self.vmdk.record_vmdk(argv[0] if argv else None)

    def cmd_tool(self, argv):
        if not argv or argv[0] in ("list", "ls"):
            print("tools:")
            for tool in self.tools.iter_tools():
                print(f"  {tool.name:<10} {tool.description}")
            return

        tool = self.tools.get(argv[0])
        if tool is None:
            print(f"unknown tool: {argv[0]}")
            return
        tool.run(self, argv[1:])

    def cmd_view(self, argv):
        valid = {"auto", "image", "host"}
        if not argv:
            print(f"tool view: {self.tool_view}")
            print("views: auto | image | host")
            print("explicit source prefixes: @host:<path> | @image:<path> | @disk | @selected | @item:<name>")
            return

        mode = argv[0].strip().lower()
        if mode not in valid:
            print("usage: view [auto|image|host]")
            return

        self.tool_view = mode
        print(f"tool view -> {self.tool_view}")

    def help(self):
        print("""
commands:
  help                      show help
  clear | cls               clear screen
  pwd                       print current path
  cd <path>                 change path
  ls [-l] [path]            list directory
  part [number/name/all]    switch partition to show
  layout | parts            show partition/filesystem layout
  record [out_file]         snapshot current vmdk
  unlock <out> [key] [map]  export selected container and write unlock plan
  unlockfs <key>            open selected luks container inside tool
  renameview <old> <new>    rename an unlocked view
  tree [depth]              print directory tree
  cat <path>                print text file
  download <path> <outdir>  extract file
  extractfs <outdir> [path] extract selected filesystem(s)
  add <src> <dst>           add new file into filesystem
  cp <src> <dst>            copy file inside filesystem
  cp -r <src> <dst>         recursive copy directory tree
  touch <path>              create empty file or update times
  truncate <size> <path>    resize regular file
  rm <path>                 delete file from filesystem
  rm -r <path>              recursive remove path
  mkdir <path>              create directory
  rmdir <path>              remove empty directory
  mv <src> <dst>            rename or move path
  ln <src> <dst>            create hard link
  ln -s <target> <dst>      create symbolic link
  stat <path>               show inode/file info
  readlink <path>           print symlink target
  find [path] [pattern]     recursive path search
  chmod <mode> <path>        change file mode
  chattr +/-attrs <path>     change ext attributes
  replace <src> <dst>        replace file in vmdk
  restore <record>           restore replaced file
  lsattr [path]               show ext attributes
  tool [name] [args...]      run builtin analysis tool
  view [auto|image|host]     switch default tool source view
  dd if=<src> of=<out> ...   copy from image/raw/host source
  file <path>                identify image or host file type
  hexdump [-s off] [-n len]  hex dump image/raw/host bytes
  readelf [-h|-l|-S] <path>  inspect ELF from image or host file
  exit                      quit
""".strip())
