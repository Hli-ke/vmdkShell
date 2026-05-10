from base_analyze import *
from vmdk_shell import VMDKShell

# import gzip
# import lzma


def run():

    filePath = r'D:\learning\iot\fortinet\vm\fortigate7.6.3 - 副本\fortigate7.6.3-disk1.vmdk'
    # filePath = r'D:\vmware_vm\citrix14\citrix14-disk1.vmdk'
    # filePath = r'D:\vmware_vm\routeros - 副本\routeros-disk1.vmdk'
    # filePath = r'D:\vmware_vm\ivanti_cs\ivanti_cs-disk1.vmdk'
    # filePath = "initramfs"
    # unlock_key_file = r'./lvmkey'
    unlock_key_file = None

    p = VMDK.open_image(
        filePath,
        unlock_key_file=unlock_key_file,
    )

    # p.download("/flatkc", ".")
    # p.print_layout()
    # p.print_tree(2)
    # p.set_partition(2)
    shell = VMDKShell(p)
    shell.run()
    # shell.cmd_ls(["-l", "/"])

    return




if __name__ == "__main__":
    run()



