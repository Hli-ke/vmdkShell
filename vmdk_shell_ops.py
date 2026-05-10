import hashlib
import json
import os
import shutil
import stat

import const_define as const
from crypto_state import build_unlock_plan
from crypto_state.luks_volume import LUKS1Volume


class VMDKShellOps:
    def _ensure_vmdk_file(self, writable: bool = False):
        mode = "r+b" if writable else "rb"

        if self.file and not self.file.closed:
            if not writable or self.file.writable():
                return self.file

            self.file.close()
            self.file = None

        if not self.file:
            self.file = open(self.fileName, mode)

        return self.file

    def _modified_target_for_item(self, item: dict = None):
        if item and item.get("unlock_source"):
            record_path = self.unlock_write_records.get(item["name"])
            if record_path:
                return record_path
        return self.fileName

    def _print_modified_target(self, item: dict = None):
        print(f"modified: {self._modified_target_for_item(item)}")

    def _refresh_item_fs(self, item: dict):
        if not item.get("file_factory") or not item.get("fs_class"):
            return

        fp = self._create_item_fp(item, writable=False)
        item["fs"] = item["fs_class"](
            fp=fp,
            start_base=item.get("fs_start_base", item["partition"]["first_lba"] * self.sector_size),
            size_bytes=item["partition"].get("size_bytes"),
        )

    def _ensure_unlock_write_record(self, item: dict):
        unlock_source = item.get("unlock_source")
        if not unlock_source:
            return

        record_key = item["name"]
        if self.unlock_write_records.get(record_key):
            return

        base_name = self._host_safe_name(record_key)
        out_file = os.path.join(
            os.getcwd(),
            f"{os.path.basename(self.fileName)}.{base_name}.prewrite.vmdk"
        )

        suffix = 1
        while os.path.exists(out_file):
            out_file = os.path.join(
                os.getcwd(),
                f"{os.path.basename(self.fileName)}.{base_name}.prewrite.{suffix}.vmdk"
            )
            suffix += 1

        self.record_vmdk(out_file)
        self.unlock_write_records[record_key] = out_file
        print(f"write snapshot: {out_file}")

    def _create_item_fp(self, item: dict, writable: bool = False):
        if item.get("file_factory"):
            return item["file_factory"](writable)

        if item.get("standalone"):
            return self._ensure_vmdk_file(writable=writable)

        if isinstance(self.raw_f, self._virtual_file_class):
            if writable:
                self._ensure_vmdk_file(writable=True)
            return self._virtual_file_class(self)

        return self._ensure_vmdk_file(writable=writable)

    def _open_backend_for_image(self, image_path: str, writable: bool = False):
        image_path = os.path.abspath(image_path)
        same_image = os.path.normcase(image_path) == os.path.normcase(os.path.abspath(self.fileName))

        if same_image:
            if isinstance(self.raw_f, self._virtual_file_class):
                if writable:
                    self._ensure_vmdk_file(writable=True)
                return self._virtual_file_class(self), self

            mode = "r+b" if writable else "rb"
            return open(image_path, mode), None

        owner = self.__class__.open_image(image_path)
        if isinstance(owner.raw_f, owner._virtual_file_class):
            if writable:
                owner._ensure_vmdk_file(writable=True)
            return owner._virtual_file_class(owner), owner

        mode = "r+b" if writable else "rb"
        return open(image_path, mode), owner

    def record_vmdk(self, out_file: str = None):
        if out_file:
            out_file = os.path.abspath(out_file)
            if os.path.exists(out_file):
                raise FileExistsError(out_file)
        else:
            out_file = os.path.join(
                os.getcwd(),
                f"{os.path.basename(self.fileName)}.record.vmdk"
            )

        if os.path.normcase(os.path.abspath(out_file)) == os.path.normcase(os.path.abspath(self.fileName)):
            raise ValueError("record target must be different from current vmdk")

        self._copy_current_vmdk(out_file)
        print(f"record success: {out_file}")

    def print_layout(self):
        part = self.gpt or self.mbr
        items = self.list_filesystems()

        if not part and not items:
            print("no partition table")
            return

        if self.gpt:
            print("Partition table: GPT")
        elif self.mbr:
            print("Partition table: MBR")
        else:
            print("Filesystem image")

        for item in items:
            partition = item["partition"]
            line = (
                f"[{item['display_index']}] {item['name']}: start_lba={partition['first_lba']} "
                f"size={partition['size_bytes']} bytes"
            )

            source_index = item.get("source_index")
            if source_index is not None:
                line += f" part={source_index}"

            if partition.get("bsd_partition"):
                bsd = partition["bsd_partition"]
                line += f" bsd_type={bsd['fstype_name']}"
            elif "partition_type" in partition:
                line += f" mbr_type=0x{partition['partition_type']:02x}"

            if item["fs_kind"]:
                line += f" fs={item['fs_kind']}"
            elif item.get("container_kind"):
                line += f" container={item.get('container_display') or item['container_kind']}"
                if item.get("is_encrypted"):
                    line += " encrypted=yes"
                detail = item.get("container_detail") or {}
                if detail.get("cipher_name"):
                    mode = detail.get("cipher_mode") or "unknown"
                    line += f" cipher={detail['cipher_name']} mode={mode}"
            else:
                line += " fs=unknown"

            print(line)

    def _iter_filesystems(self):
        filesystems = self.list_filesystems()

        if self.want_partition is None:
            for item in filesystems:
                yield item
            return

        if isinstance(self.want_partition, str):
            if self.want_partition.isdigit():
                selection = int(self.want_partition)
            else:
                for item in filesystems:
                    if item["name"] == self.want_partition:
                        yield item
                return
        else:
            selection = self.want_partition

        source_matches = [
            item for item in filesystems
            if item.get("source_index") == selection
        ]
        if source_matches:
            for item in source_matches:
                yield item
            return

        for item in filesystems:
            if item.get("display_index", item["index"]) == selection:
                yield item

    def _find_fs_file(self, path: str):
        for item in self._iter_filesystems():
            fs = item["fs"]

            if fs is None:
                continue

            info = fs.find_file(path)

            if info:
                return item, fs, info

        return None, None, None

    def get_path_entry(self, path: str):
        return self._find_fs_file(path)

    def read_path_bytes(self, path: str, offset: int = 0, size: int = None, max_size: int = 16 * 1024 * 1024):
        _, fs, inode = self._find_fs_file(path)
        if fs is None or inode is None:
            raise FileNotFoundError(path)
        if stat.S_ISDIR(inode["i_mode"]):
            raise IsADirectoryError(path)
        if not hasattr(fs, "read_file_by_inode"):
            raise NotImplementedError(f"filesystem does not support reading file bytes: {path}")
        if offset < 0:
            raise ValueError("offset must be >= 0")

        data = fs.read_file_by_inode(inode)
        if size is None:
            chunk = data[offset:]
        else:
            if size < 0:
                raise ValueError("size must be >= 0")
            chunk = data[offset:offset + size]

        if len(chunk) > max_size:
            raise ValueError(f"{path} too large: {len(chunk)} bytes")
        return chunk

    def get_selected_item(self):
        return self._single_selected_item()

    def get_item_by_name(self, name: str):
        for item in self.list_filesystems():
            if item["name"] == name:
                return item
        return None

    def get_raw_size(self):
        if self.raw_f is None:
            raise ValueError("raw backend is not initialized")

        current = self.raw_f.tell()
        try:
            self.raw_f.seek(0, 2)
            return self.raw_f.tell()
        finally:
            self.raw_f.seek(current)

    def read_raw_bytes(self, offset: int = 0, size: int = None, max_size: int = 16 * 1024 * 1024):
        if self.raw_f is None:
            raise ValueError("raw backend is not initialized")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if size is not None and size < 0:
            raise ValueError("size must be >= 0")

        total_size = self.get_raw_size()
        if size is None:
            size = max(0, total_size - offset)
        if size > max_size:
            raise ValueError(f"read too large: {size} bytes")

        current = self.raw_f.tell()
        try:
            self.raw_f.seek(offset)
            return self.raw_f.read(size)
        finally:
            self.raw_f.seek(current)

    def read_item_bytes(self, item: dict, offset: int = 0, size: int = None, max_size: int = 16 * 1024 * 1024):
        if offset < 0:
            raise ValueError("offset must be >= 0")

        start = item["partition"].get("start_byte", item["partition"]["first_lba"] * self.sector_size)
        item_size = item["partition"].get("size_bytes")
        if item_size is not None:
            if offset > item_size:
                return b""
            available = item_size - offset
            if size is None:
                size = available
            else:
                size = min(size, available)

        return self.read_raw_bytes(offset=start + offset, size=size, max_size=max_size)

    def print_tree(self, max_depth=1):
        for item in self._iter_filesystems():
            print(f"\n=== {item['name']} ===")

            fs = item["fs"]

            if fs is None:
                detail = item["fs_kind"] or "unknown"
                print(f"unsupported filesystem: {detail}")
                continue

            fs.tree("/", max_depth=max_depth)

    def _human_size(self, size: int) -> str:
        units = ["B", "KB", "MB", "GB", "TB"]
        n = float(size)

        for unit in units:
            if n < 1024:
                return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
            n /= 1024

        return f"{n:.1f}PB"

    def is_directory(self, path: str) -> bool:
        _, fs, inode = self._find_fs_file(path)
        return fs is not None and inode is not None and stat.S_ISDIR(inode["i_mode"])

    def _build_ls_entry(self, path: str, inode: dict):
        name = path.rstrip("/").rpartition("/")[2] or "/"
        return {
            "name": name,
            "i_mode": inode["i_mode"],
            "i_size": inode["i_size"],
            "is_dir": stat.S_ISDIR(inode["i_mode"]),
        }

    def ls(self, path="/", long=False):
        shown = False
        for item in self._iter_filesystems():
            fs = item["fs"]
            if fs is None:
                print(f"\n=== {item['name']}:{path} ===")
                print(f"unsupported filesystem: {item['fs_kind'] or 'unknown'}")
                shown = True
                continue

            inode = fs.find_file(path)
            if inode is None:
                continue

            shown = True
            print(f"\n=== {item['name']}:{path} ===")

            if stat.S_ISDIR(inode["i_mode"]):
                entries = fs.list_dir(path)
            else:
                entries = [self._build_ls_entry(path, inode)]

            if long:
                print(f"{'MODE':<12} {'SIZE':>10}  NAME")
                print("-" * 50)

                for entry in entries:
                    mode = stat.filemode(entry["i_mode"])
                    size = self._human_size(entry["i_size"])

                    name = entry["name"]
                    if entry["is_dir"]:
                        name += "/"

                    print(
                        f"{mode:<12} "
                        f"{size:>10}  "
                        f"{name}"
                    )

                if not entries:
                    print("(empty)")

            else:
                for entry in entries:
                    icon = const.dir_icon(entry["is_dir"])

                    name = entry["name"]
                    if entry["is_dir"]:
                        name += "/"

                    print(f"{icon} {name}")

                if not entries:
                    print("(empty)")

        if not shown:
            print(f"not found: {path}")

    def cat(self, path: str, max_size: int = 1024 * 1024):
        for item in self._iter_filesystems():
            fs = item["fs"]
            if fs is None:
                continue

            inode = fs.find_file(path)
            if not inode:
                continue

            if inode["i_mode"] & 0x4000:
                print(f"{path} is a directory")
                return

            if inode["i_size"] > max_size:
                print(f"{path} too large: {inode['i_size']} bytes")
                return

            data = fs._read_inode_bytes(inode)
            print(data.decode("utf-8", errors="replace"))
            return

        print(f"not found: {path}")

    def find(self, path: str):
        for item in self._iter_filesystems():
            fs = item["fs"]
            if fs is None:
                continue

            info = fs.find_file(path)
            if info:
                print(f"\nfound in {item['name']}: {path}")
                fs.print_info(info)

    def download(self, path: str, out_directory: str):
        for item in self._iter_filesystems():
            fs = item["fs"]
            if fs is None:
                continue

            inode = fs.find_file(path)
            if not inode:
                continue

            ok = fs.extract_file(path, out_directory)
            if ok:
                print(f"download success from {item['name']}: {path}")
            else:
                print(f"download failed from {item['name']}: {path}")
            return

        print(f"not found: {path}")

    def _host_safe_name(self, name: str) -> str:
        bad = '<>:"/\\|?*'
        cleaned = "".join("_" if ch in bad else ch for ch in name).strip().strip(".")
        return cleaned or "filesystem"

    def _single_selected_item(self):
        items = list(self._iter_filesystems())
        if not items:
            raise ValueError("no filesystem selected")
        if len(items) != 1:
            raise ValueError("select exactly one partition/container first")
        return items[0]

    def _unlock_candidate_items(self):
        items = list(self._iter_filesystems())
        encrypted = [item for item in items if item.get("container_kind") == "luks1"]
        if encrypted:
            return encrypted

        all_items = self.list_filesystems()
        return [item for item in all_items if item.get("container_kind") == "luks1"]

    def _apply_host_metadata(self, host_path: str, inode: dict):
        try:
            os.chmod(host_path, inode["i_mode"] & 0o777)
        except OSError:
            pass

        ts = inode.get("i_mtime")
        if ts:
            try:
                os.utime(host_path, (ts, ts), follow_symlinks=False)
            except (OSError, NotImplementedError, ValueError):
                pass

    def _extract_entry_to_host(self, fs, inode: dict, host_path: str):
        mode = inode["i_mode"]

        if stat.S_ISDIR(mode):
            os.makedirs(host_path, exist_ok=True)
            self._apply_host_metadata(host_path, inode)
            return

        if stat.S_ISLNK(mode):
            target = fs.read_file_by_inode(inode).decode("latin-1", errors="replace")
            try:
                os.symlink(target, host_path)
            except OSError:
                with open(host_path, "wb") as f:
                    f.write(target.encode("utf-8", errors="replace"))
            self._apply_host_metadata(host_path, inode)
            return

        with open(host_path, "wb") as f:
            f.write(fs.read_file_by_inode(inode))
        self._apply_host_metadata(host_path, inode)

    def _extract_tree_to_host(self, fs, src_path: str, host_root: str):
        inode = fs.find_file(src_path)
        if inode is None:
            raise FileNotFoundError(src_path)

        self._extract_entry_to_host(fs, inode, host_root)
        if not stat.S_ISDIR(inode["i_mode"]):
            return

        for entry in fs.list_dir(src_path):
            child_src = self._join_path(src_path, entry["name"])
            child_host = os.path.join(host_root, entry["name"])
            self._extract_tree_to_host(fs, child_src, child_host)

    def extract_filesystem(self, out_directory: str, src_path: str = "/"):
        items = list(self._iter_filesystems())
        if not items:
            print("no filesystem selected")
            return

        if not src_path:
            src_path = "/"

        out_directory = os.path.abspath(out_directory)
        os.makedirs(out_directory, exist_ok=True)

        multiple = len(items) > 1
        extracted_any = False
        leaf_name = self._host_safe_name(src_path.rstrip("/").rpartition("/")[2]) if src_path != "/" else ""

        for item in items:
            fs = item["fs"]
            if fs is None:
                print(f"skip {item['name']}: unsupported filesystem")
                continue

            target_root = out_directory
            if multiple:
                target_root = os.path.join(out_directory, self._host_safe_name(item["name"]))

            inode = fs.find_file(src_path)
            if inode is None:
                print(f"skip {item['name']}: not found {src_path}")
                continue

            if src_path == "/":
                extract_root = target_root
            else:
                extract_root = os.path.join(target_root, leaf_name or self._host_safe_name(item["name"]))

            os.makedirs(os.path.dirname(extract_root) or extract_root, exist_ok=True)
            self._extract_tree_to_host(fs, src_path, extract_root)
            print(f"extract success: {item['name']}:{src_path} -> {extract_root}")
            extracted_any = True

        if not extracted_any:
            print("no supported filesystem extracted")

    def _export_partition_image(self, item: dict, out_file: str):
        start = item["partition"].get("start_byte", item["partition"]["first_lba"] * self.sector_size)
        size = item["partition"].get("size_bytes")
        if size is None:
            raise ValueError("partition size is unknown")

        out_file = os.path.abspath(out_file)
        self.raw_f.seek(start)
        remaining = size

        with open(out_file, "wb") as fdst:
            while remaining > 0:
                chunk = self.raw_f.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                fdst.write(chunk)
                remaining -= len(chunk)

        if remaining != 0:
            raise IOError(f"short read while exporting partition: {remaining} bytes missing")

        return out_file

    def prepare_unlock(self, out_file: str, key_file: str = None, mapping_name: str = None):
        item = self._single_selected_item()
        container_kind = item.get("container_kind")
        if not container_kind:
            print(f"selected item is not a recognized container: {item['name']}")
            return

        out_file = self._export_partition_image(item, out_file)
        plan = build_unlock_plan(
            container_kind,
            out_file,
            key_file=os.path.abspath(key_file) if key_file else None,
            mapping_name=mapping_name,
        )

        if plan is None:
            print(f"no unlock handler for container: {container_kind}")
            return

        plan_file = out_file + ".unlock.json"
        payload = {
            "partition": item["name"],
            "container_kind": container_kind,
            "container_detail": item.get("container_detail") or {},
            "exported_image": out_file,
            "unlock": {
                "kind": plan.kind,
                "command": plan.command,
                "details": plan.details,
            },
        }

        with open(plan_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        print(f"export success: {item['name']} -> {out_file}")
        print(f"unlock plan: {plan_file}")
        if plan.command:
            print(f"command: {plan.command}")
        else:
            note = plan.details.get("note")
            if note:
                print(note)

    def _unlock_item_with_key(self, item: dict, key_file: str, mapping_name: str = None, select_result: bool = True):
        container_kind = item.get("container_kind")
        if container_kind != "luks1":
            raise ValueError(f"internal unlock supports luks1 only, got: {container_kind or 'none'}")

        key_file = os.path.abspath(key_file)
        with open(key_file, "rb") as f:
            key_bytes = f.read()

        container_start = item["partition"].get("start_byte", item["partition"]["first_lba"] * self.sector_size)
        container_size = item["partition"].get("size_bytes")
        volume = LUKS1Volume(self._create_item_fp(item, writable=False), container_start, container_size)
        volume.unlock(key_bytes)
        payload_size = volume.payload_size_bytes()

        def file_factory(writable=False):
            image_path = self.unlock_write_records.get(clear_name, self.fileName)
            backend_fp, owner = self._open_backend_for_image(image_path, writable=writable)
            view = LUKS1Volume(backend_fp, container_start, container_size)
            view.master_key = volume.master_key
            mapped = view.open_mapped_file(backend_fp)
            mapped._owner = owner
            return mapped

        clear_name = mapping_name or f"{self._host_safe_name(item['name'])}_clear"
        clear_fp = file_factory(False)
        fs_info = self._detect_filesystem_info(clear_fp, 0)
        fs_class = fs_info["class"]
        fs = None
        if fs_class is not None:
            fs = fs_class(fp=clear_fp, start_base=0, size_bytes=payload_size)

        unlocked_item = {
            "index": len(self.list_filesystems()) + 1,
            "display_index": len(self.list_filesystems()) + 1,
            "source_index": len(self.list_filesystems()) + 1,
            "name": clear_name,
            "partition": {
                "index": len(self.list_filesystems()) + 1,
                "name": clear_name,
                "first_lba": 0,
                "start_byte": 0,
                "size_bytes": payload_size,
                "parent_partition": item["partition"],
                "luks_source": item["name"],
            },
            "standalone": True,
            "fs_start_base": 0,
            "fs_kind": fs_info["kind"],
            "fs_class": fs_class,
            "fs_detail": fs_info["detail"],
            "container_kind": fs_info.get("container_kind"),
            "container_detail": fs_info.get("container_detail"),
            "container_display": fs_info.get("container_display"),
            "is_encrypted": fs_info.get("is_encrypted", False),
            "fs": fs,
            "file_factory": file_factory,
            "unlock_source": {
                "container": item["name"],
                "key_file": key_file,
                "kind": "luks1",
            },
        }

        self.unlocked_items = [u for u in self.unlocked_items if u["name"] != clear_name]
        self.unlocked_items.append(unlocked_item)
        if select_result:
            self.set_partition(clear_name)

        line = f"unlockfs success: {item['name']} -> {clear_name}"
        if fs_info["kind"]:
            line += f" fs={fs_info['kind']}"
        elif fs_info.get("container_kind"):
            line += f" container={fs_info.get('container_display') or fs_info['container_kind']}"
        print(line)
        return unlocked_item

    def unlock_filesystem(self, key_file: str, mapping_name: str = None):
        item = self._single_selected_item()
        try:
            return self._unlock_item_with_key(item, key_file, mapping_name=mapping_name, select_result=True)
        except ValueError as e:
            print(str(e))
            return None

    def rename_view(self, old_name: str, new_name: str):
        new_name = self._host_safe_name(new_name)
        if not new_name:
            raise ValueError("invalid new view name")

        target = None
        for item in self.unlocked_items:
            if item["name"] == old_name:
                target = item
                break

        if target is None:
            raise FileNotFoundError(old_name)

        if any(item["name"] == new_name for item in self.list_filesystems()):
            raise FileExistsError(new_name)

        record_path = self.unlock_write_records.pop(old_name, None)
        target["name"] = new_name
        target["partition"]["name"] = new_name
        if record_path:
            self.unlock_write_records[new_name] = record_path

        if self.want_partition == old_name:
            self.set_partition(new_name)

        print(f"renameview success: {old_name} -> {new_name}")

    def try_unlock_with_key(
        self,
        key_file: str,
        mapping_name: str = None,
        stop_after_first: bool = True,
        select_result: bool = False,
    ):
        candidates = self._unlock_candidate_items()
        if not candidates:
            print("no luks container candidates found for auto-unlock")
            return []

        unlocked = []
        for item in candidates:
            derived_name = mapping_name
            if derived_name is None and (not stop_after_first or len(candidates) > 1):
                derived_name = f"{self._host_safe_name(item['name'])}_clear"

            try:
                result = self._unlock_item_with_key(
                    item,
                    key_file,
                    mapping_name=derived_name,
                    select_result=(select_result and stop_after_first and not unlocked),
                )
                unlocked.append(result)
                if stop_after_first:
                    break
            except Exception as e:
                print(f"auto-unlock skip {item['name']}: {e}")

        if not unlocked:
            print("auto-unlock failed for all candidates")

        return unlocked

    def clear(self):
        os.system("cls" if os.name == "nt" else "clear")

    def lsattr(self, path="/"):
        for item in self._iter_filesystems():
            fs = item["fs"]
            if fs is None:
                print(f"\n=== {item['name']}:{path} ===")
                print(f"unsupported filesystem: {item['fs_kind'] or 'unknown'}")
                continue

            if not hasattr(fs, "lsattr"):
                continue

            print(f"\n=== {item['name']}:{path} ===")
            fs.lsattr(path)

    def replace_file_in_vmdk(self, src_file: str, dst_path: str):
        item, fs, inode = self._find_fs_file(dst_path)

        if fs is None:
            print(f"not found: {dst_path}")
            return

        if item.get("unlock_source"):
            raise ValueError("replace is not supported on unlockfs views; use cp/add/truncate style operations instead")

        replace_info = fs.get_replace_info(dst_path)

        src_size = os.path.getsize(src_file)
        dst_size = replace_info["size"]

        if src_size > dst_size:
            raise ValueError(
                f"src file too large: {src_size} > target size {dst_size}"
            )

        record_file = os.path.join(
            os.path.dirname(src_file),
            os.path.basename(src_file) + ".replace.json"
        )

        backup_file = os.path.join(
            os.path.dirname(src_file),
            os.path.basename(src_file) + ".replace.bak"
        )

        old_data = fs.read_file_by_inode(inode)
        with open(backup_file, "wb") as f:
            f.write(old_data)

        record = {
            "version": 1,
            "vmdk": self.fileName,
            "out_file": self.fileName,
            "partition": item["name"],
            "path": dst_path,
            "original_size": dst_size,
            "replaced_size": src_size,
            "inode_size_virtual_offset": replace_info["inode_size_virtual_offset"],
            "inode_size_length": replace_info.get("inode_size_length", 4),
            "backup_file": backup_file,
            "blocks": [],
        }

        self._ensure_vmdk_file(writable=True)

        with open(src_file, "rb") as fp:
            for block in replace_info["blocks"]:
                if block["virtual_offset"] is None:
                    continue

                physical = self.virtual_to_physical(block["virtual_offset"])

                if physical is None:
                    raise RuntimeError(
                        f"unallocated block: {block['block_id']}"
                    )

                data = fp.read(block["length"])

                if len(data) < block["length"]:
                    data += b"\x00" * (block["length"] - len(data))

                before = self.read_data(physical, block["length"])

                self.write_data(physical, data)

                record["blocks"].append({
                    "block_id": block["block_id"],
                    "virtual_offset": block["virtual_offset"],
                    "physical_offset": physical,
                    "length": block["length"],
                    "sha256_before": hashlib.sha256(before).hexdigest(),
                    "sha256_after": hashlib.sha256(data).hexdigest(),
                })

            inode_size_physical = self.virtual_to_physical(
                replace_info["inode_size_virtual_offset"]
            )

            if inode_size_physical is None:
                raise RuntimeError("inode size field is not allocated")

            inode_size_length = replace_info.get("inode_size_length", 4)
            if inode_size_length == 8:
                size_bytes = const.p64(src_size)
            else:
                size_bytes = const.p32(src_size)

            self.write_data(inode_size_physical, size_bytes)
            record["inode_size_physical_offset"] = inode_size_physical

        with open(record_file, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)

        print(f"replace success: {dst_path}")
        self._print_modified_target(item)
        print(f"record: {record_file}")
        print(f"backup: {backup_file}")

    def _copy_current_vmdk(self, out_file: str):
        self._ensure_vmdk_file()
        self.file.seek(0)
        with open(out_file, "wb") as fdst:
            shutil.copyfileobj(self.file, fdst, length=16 * 1024 * 1024)

    def _open_mutation_fs(self, item: dict):
        fp = self._create_item_fp(item, writable=True)
        return item["fs_class"](
            fp=fp,
            start_base=item.get("fs_start_base", item["partition"]["first_lba"] * self.sector_size),
            size_bytes=item["partition"].get("size_bytes"),
        )

    def _split_parent_child(self, path: str):
        norm = "/" + "/".join(p for p in path.split("/") if p)
        if norm == "/":
            raise ValueError("invalid path: /")

        parent, _, name = norm.rpartition("/")
        if not parent:
            parent = "/"
        if not name:
            raise ValueError(f"invalid path: {path}")

        return parent, name

    def _find_fs_for_create(self, dst_path: str):
        parent_path, _ = self._split_parent_child(dst_path)

        for item in self._iter_filesystems():
            fs = item["fs"]
            if fs is None:
                continue

            parent_inode = fs.find_file(parent_path)
            if not parent_inode:
                continue

            if not stat.S_ISDIR(parent_inode["i_mode"]):
                continue

            if fs.find_file(dst_path):
                raise FileExistsError(dst_path)

            return item

        return None

    def add_file_to_vmdk(self, src_file: str, dst_path: str):
        item = self._find_fs_for_create(dst_path)
        if item is None:
            print(f"not found parent path for: {dst_path}")
            return

        self._ensure_unlock_write_record(item)
        fs = self._open_mutation_fs(item)
        fs.create_file_from_host(src_file, dst_path)
        self._refresh_item_fs(item)

        print(f"add success: {dst_path}")
        self._print_modified_target(item)

    def _find_fs_for_existing(self, path: str):
        item, fs, inode = self._find_fs_file(path)
        if item is None or fs is None or inode is None:
            return None, None, None
        return item, fs, inode

    def _mutate_existing(self, item: dict, callback):
        self._ensure_unlock_write_record(item)
        fs = self._open_mutation_fs(item)
        callback(fs)
        self._refresh_item_fs(item)
        return self.fileName

    def delete_file_from_vmdk(self, dst_path: str):
        item, _, inode = self._find_fs_file(dst_path)
        if item is None or inode is None:
            print(f"not found: {dst_path}")
            return

        self._mutate_existing(item, lambda fs: fs.delete_file(dst_path))

        print(f"delete success: {dst_path}")
        self._print_modified_target(item)

    def copy_file_in_vmdk(self, src_path: str, dst_path: str):
        self.copy_path_in_vmdk(src_path, dst_path, recursive=False)

    def touch_path_in_vmdk(self, dst_path: str):
        item, _, inode = self._find_fs_file(dst_path)
        if item is not None and inode is not None:
            self._mutate_existing(item, lambda fs: fs.touch(dst_path))
        else:
            item = self._find_fs_for_create(dst_path)
            if item is None:
                print(f"not found parent path for: {dst_path}")
                return
            self._mutate_existing(item, lambda fs: fs.touch(dst_path))

        print(f"touch success: {dst_path}")
        self._print_modified_target(item)

    def truncate_file_in_vmdk(self, dst_path: str, size: int):
        item, _, inode = self._find_fs_file(dst_path)
        if item is None or inode is None:
            print(f"not found: {dst_path}")
            return

        self._mutate_existing(item, lambda fs: fs.truncate_file(dst_path, size))

        print(f"truncate success: {dst_path} -> {size}")
        self._print_modified_target(item)

    def _join_path(self, parent: str, name: str):
        if parent == "/":
            return "/" + name
        return parent.rstrip("/") + "/" + name

    def _instantiate_fs_for_item(self, item: dict):
        fp = self._create_item_fp(item, writable=True)
        return item["fs_class"](
            fp=fp,
            start_base=item.get("fs_start_base", item["partition"]["first_lba"] * self.sector_size),
            size_bytes=item["partition"].get("size_bytes"),
        )

    def _copy_node_recursive(self, src_fs, src_path: str, src_inode: dict, dst_fs, dst_path: str):
        mode = src_inode["i_mode"]

        if stat.S_ISDIR(mode):
            dst_exists = dst_fs.find_file(dst_path)
            if dst_exists and not stat.S_ISDIR(dst_exists["i_mode"]):
                raise FileExistsError(dst_path)
            if not dst_exists:
                dst_fs.create_directory(dst_path, mode=mode & 0o777)

            for entry in src_fs.list_dir(src_path):
                child_src = self._join_path(src_path, entry["name"])
                child_dst = self._join_path(dst_path, entry["name"])
                self._copy_node_recursive(src_fs, child_src, entry["inode_obj"], dst_fs, child_dst)
            return

        if stat.S_ISLNK(mode):
            target = src_fs.read_file_by_inode(src_inode).decode("latin-1", errors="replace")
            dst_fs.create_symlink(target, dst_path, mode=mode & 0o777)
            return

        data = src_fs.read_file_by_inode(src_inode)
        dst_fs.create_file_from_bytes(
            data,
            dst_path,
            mode=mode & 0o777,
            uid=src_inode.get("i_uid", 0),
            gid=src_inode.get("i_gid", 0),
        )

    def copy_path_in_vmdk(self, src_path: str, dst_path: str, recursive: bool = False):
        src_item, src_fs, src_inode = self._find_fs_file(src_path)
        if src_item is None or src_fs is None or src_inode is None:
            print(f"not found: {src_path}")
            return

        if stat.S_ISDIR(src_inode["i_mode"]) and not recursive:
            print(f"not support directory copy without -r: {src_path}")
            return

        dst_existing = None
        dst_item_existing, _, dst_existing = self._find_fs_file(dst_path)
        if dst_existing is not None:
            dst_item = dst_item_existing
        else:
            dst_item = self._find_fs_for_create(dst_path)

        if dst_item is None:
            print(f"not found parent path for: {dst_path}")
            return

        self._ensure_unlock_write_record(dst_item)
        src_fs_mut = self._instantiate_fs_for_item(src_item)
        dst_fs_mut = self._instantiate_fs_for_item(dst_item)
        src_inode_mut = src_fs_mut.find_file(src_path)

        actual_dst = dst_path
        dst_existing_mut = dst_fs_mut.find_file(dst_path)
        if dst_existing_mut and stat.S_ISDIR(dst_existing_mut["i_mode"]):
            actual_dst = self._join_path(dst_path, os.path.basename(src_path.rstrip("/")))

        self._copy_node_recursive(src_fs_mut, src_path, src_inode_mut, dst_fs_mut, actual_dst)
        self._refresh_item_fs(dst_item)

        print(f"copy success: {src_path} -> {dst_path}")
        self._print_modified_target(dst_item)

    def _remove_node_recursive(self, fs, path: str, inode: dict):
        if stat.S_ISDIR(inode["i_mode"]):
            for entry in list(fs.list_dir(path)):
                child_path = self._join_path(path, entry["name"])
                self._remove_node_recursive(fs, child_path, entry["inode_obj"])
            fs.remove_directory(path)
            return

        fs.delete_file(path)

    def remove_path_in_vmdk(self, dst_path: str, recursive: bool = False):
        item, _, inode = self._find_fs_file(dst_path)
        if item is None or inode is None:
            print(f"not found: {dst_path}")
            return

        if stat.S_ISDIR(inode["i_mode"]) and not recursive:
            self.remove_directory_from_vmdk(dst_path)
            return

        if not stat.S_ISDIR(inode["i_mode"]) and not recursive:
            self.delete_file_from_vmdk(dst_path)
            return

        self._mutate_existing(
            item,
            lambda fs: self._remove_node_recursive(fs, dst_path, fs.find_file(dst_path))
        )

        print(f"remove success: {dst_path}")
        self._print_modified_target(item)

    def stat_path(self, path: str):
        item, fs, inode = self._find_fs_file(path)
        if fs is None or inode is None:
            print(f"not found: {path}")
            return
        print(f"\n=== {item['name']}: {path} ===")
        fs.print_info(inode)

    def readlink_path(self, path: str):
        item, fs, inode = self._find_fs_file(path)
        if fs is None or inode is None:
            print(f"not found: {path}")
            return
        if not stat.S_ISLNK(inode["i_mode"]):
            print(f"not a symlink: {path}")
            return
        data = fs.read_file_by_inode(inode)
        print(data.decode("latin-1", errors="replace"))

    def _find_walk(self, fs, path: str, pattern: str = None):
        inode = fs.find_file(path)
        if inode is None:
            return

        match = pattern is None or pattern in os.path.basename(path.rstrip("/")) or pattern in path
        if match:
            print(path)

        if stat.S_ISDIR(inode["i_mode"]):
            for entry in fs.list_dir(path):
                self._find_walk(fs, self._join_path(path, entry["name"]), pattern)

    def find_paths(self, start: str, pattern: str = None):
        found_any = False
        for item in self._iter_filesystems():
            fs = item["fs"]
            if fs is None:
                continue
            inode = fs.find_file(start)
            if inode is None:
                continue
            print(f"\n=== {item['name']} ===")
            self._find_walk(fs, start, pattern)
            found_any = True

        if not found_any:
            print(f"not found: {start}")

    def make_directory_in_vmdk(self, dst_path: str):
        item = self._find_fs_for_create(dst_path)
        if item is None:
            print(f"not found parent path for: {dst_path}")
            return

        self._mutate_existing(item, lambda fs: fs.create_directory(dst_path))

        print(f"mkdir success: {dst_path}")
        self._print_modified_target(item)

    def remove_directory_from_vmdk(self, dst_path: str):
        item, _, inode = self._find_fs_file(dst_path)
        if item is None or inode is None:
            print(f"not found: {dst_path}")
            return

        self._mutate_existing(item, lambda fs: fs.remove_directory(dst_path))

        print(f"rmdir success: {dst_path}")
        self._print_modified_target(item)

    def rename_path_in_vmdk(self, src_path: str, dst_path: str):
        item, _, inode = self._find_fs_file(src_path)
        if item is None or inode is None:
            print(f"not found: {src_path}")
            return

        if self._find_fs_file(dst_path)[2]:
            print(f"target exists: {dst_path}")
            return

        self._mutate_existing(item, lambda fs: fs.rename_path(src_path, dst_path))

        print(f"rename success: {src_path} -> {dst_path}")
        self._print_modified_target(item)

    def hardlink_in_vmdk(self, src_path: str, dst_path: str):
        item, _, inode = self._find_fs_file(src_path)
        if item is None or inode is None:
            print(f"not found: {src_path}")
            return

        self._mutate_existing(item, lambda fs: fs.create_hard_link(src_path, dst_path))

        print(f"link success: {src_path} -> {dst_path}")
        self._print_modified_target(item)

    def symlink_in_vmdk(self, target_path: str, dst_path: str):
        item = self._find_fs_for_create(dst_path)
        if item is None:
            print(f"not found parent path for: {dst_path}")
            return

        self._mutate_existing(item, lambda fs: fs.create_symlink(target_path, dst_path))

        print(f"symlink success: {dst_path} -> {target_path}")
        self._print_modified_target(item)

    def restore_replace_from_record(self, record_file: str):
        with open(record_file, "r", encoding="utf-8") as f:
            record = json.load(f)

        out_file = record["out_file"]
        backup_file = record["backup_file"]

        with open(backup_file, "rb") as bf:
            backup_data = bf.read()

        with open(out_file, "r+b") as vf:
            old_file = self.file
            self.file = vf

            try:
                offset = 0

                for block in record["blocks"]:
                    length = block["length"]
                    data = backup_data[offset: offset + length]

                    if len(data) < length:
                        data += b"\x00" * (length - len(data))

                    self.write_data(block["physical_offset"], data)
                    offset += length

                self.write_data(
                    record["inode_size_physical_offset"],
                    const.p64(record["original_size"]) if record.get("inode_size_length", 4) == 8
                    else const.p32(record["original_size"])
                )

            finally:
                self.file = old_file

        print(f"restore success: {record['path']}")

    def chmod(self, path: str, mode: int):
        for item in self._iter_filesystems():
            fs = item["fs"]

            if fs is None:
                continue

            if not hasattr(fs, "chmod"):
                continue

            if fs.chmod(path, mode):
                print(f"chmod success from {item['name']}: {path}")
                return

        print(f"not found: {path}")

    def chattr(self, path: str, op: str):
        for item in self._iter_filesystems():
            fs = item["fs"]

            if fs is None:
                continue

            if not hasattr(fs, "chattr"):
                continue

            if fs.chattr(path, op):
                print(f"chattr success from {item['name']}: {path}")
                return

        print(f"not found: {path}")
