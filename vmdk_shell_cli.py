import argparse
import sys

from base_analyze import VMDK
from vmdk_shell import VMDKShell


def build_parser():
    parser = argparse.ArgumentParser(
        prog="vmdk-shell",
        description="Inspect VMDK and raw disk images with an interactive shell.",
    )
    parser.add_argument("image", help="Path to a VMDK image or raw disk/container file")
    parser.add_argument(
        "-p",
        "--partition",
        help="Initial partition/view selection, for example 1, all, or a named item",
    )
    parser.add_argument(
        "-k",
        "--unlock-key-file",
        help="Optional key file used for auto-unlock probing",
    )
    parser.add_argument(
        "--no-auto-unlock",
        action="store_true",
        help="Disable automatic unlock attempts during startup",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    image = VMDK.open_image(
        args.image,
        partition=args.partition,
        unlock_key_file=args.unlock_key_file,
        auto_unlock=not args.no_auto_unlock,
    )
    shell = VMDKShell(image)
    shell.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
