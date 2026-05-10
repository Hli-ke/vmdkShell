# vmdk_analyze

`vmdk_analyze` is a local analysis and mutation tool for VMDK and raw disk images.

It can:
- open `VMDK` and raw images
- inspect partition layouts
- detect and browse supported filesystems
- extract or modify files inside supported filesystems
- inspect boot-chain files with built-in `file` / `readelf` / `hexdump` / `dd` style tools
- work against image-internal paths, raw regions, and host files

## Project Layout

- [base_analyze.py](./base_analyze.py): core image abstraction and filesystem/container discovery
- [vmdk_shell.py](./vmdk_shell.py): interactive shell
- [vmdk_shell_ops.py](./vmdk_shell_ops.py): shell-facing operations
- [analyze_vmdk.py](./analyze_vmdk.py): simple local usage sample
- [vmdkshell_tools](./vmdkshell_tools): built-in analysis tools such as `file`, `dd`, `hexdump`, `readelf`
- [tests](./tests): unit tests
- [third_party/file_magic](./third_party/file_magic/README.md): vendored upstream `file/libmagic` rule subset

## Current Status

This repository is currently a practical local tool project, not a polished package release.

The codebase is usable as-is, but the sample entry script in [analyze_vmdk.py](./analyze_vmdk.py) contains machine-local paths and should be treated as an example, not a stable CLI.

## Quick Start

Open [analyze_vmdk.py](./analyze_vmdk.py) and replace the local `filePath` value with your own image path, then run:

```powershell
python analyze_vmdk.py
```

That starts the interactive shell.

## Installation

For local development, editable install is the recommended mode:

```powershell
python -m pip install wheel
python -m pip install -e .
```

After installation, you can start the shell with:

```powershell
vmdk-shell <image_path>
```

Example:

```powershell
vmdk-shell .\sample.vmdk
vmdk-shell .\disk.raw --partition 1
vmdk-shell .\disk.raw --unlock-key-file .\lvmkey
```

If you are in an offline environment but already have `setuptools` and `wheel` installed, this also works:

```powershell
python -m pip install -e . --no-build-isolation
```

## Shell Notes

Example commands:

```text
layout
part 1
ls -l /
tree 2
cat /etc/version
file /flatkc
readelf -h /bin/busybox
hexdump -n 64 /flatkc
dd if=/flatkc of=flatkc.bin count_bytes=4096
```

Tool source views:

```text
view auto
view image
view host
```

Explicit source prefixes:

```text
@host:C:\tmp\sample.bin
@image:/flatkc
@disk
@selected
@item:p1
```

## Supported Analysis Areas

Current built-in coverage includes:
- VMDK virtual block access
- GPT / MBR / BSD partition handling
- ext / UFS / squashfs filesystem detection
- LUKS / LVM related container probing
- boot artifact identification such as Linux kernel images, initramfs/cpio, FIT, DTB, EFI, and common compressed wrappers

## Git / Upload Advice

This repository intentionally ignores local samples and sensitive or oversized files through [.gitignore](./.gitignore), including:
- `initramfs`
- `lvmkey`
- temporary output directories
- generated raw / image artifacts

If you want to publish to GitHub:

```powershell
git init
git branch -M main
git add .
git commit -m "Initial commit"
git remote add origin <your-repo-url>
git push -u origin main
```

Do not commit machine-local keys, customer disk images, or large sample images unless you explicitly move them to Git LFS or external storage.

## License

The main project is released under the [MIT License](./LICENSE).

This repository also vendors a subset of upstream `file/libmagic` rule files under their original license in [third_party/file_magic](./third_party/file_magic/README.md).
