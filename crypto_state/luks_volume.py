import hashlib
import math
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


LUKS_MAGIC = b"LUKS\xba\xbe"
LUKS_KEY_ENABLED = 0x00AC71F3


@dataclass
class LUKSKeyslot:
    index: int
    active: int
    iterations: int
    salt: bytes
    key_material_offset_sectors: int
    stripes: int


@dataclass
class LUKSHeader:
    version: int
    cipher_name: str
    cipher_mode: str
    hash_spec: str
    payload_offset_sectors: int
    key_bytes: int
    mk_digest: bytes
    mk_digest_salt: bytes
    mk_digest_iterations: int
    uuid: str
    keyslots: list[LUKSKeyslot]


def _clean_text(raw: bytes):
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")


def parse_luks1_header(data: bytes):
    if len(data) < 592 or data[:6] != LUKS_MAGIC:
        raise ValueError("not a LUKS header")

    version = int.from_bytes(data[6:8], "big")
    if version != 1:
        raise ValueError(f"unsupported LUKS version: {version}")

    keyslots = []
    offset = 0xD0
    for idx in range(8):
        slot = data[offset + idx * 48: offset + (idx + 1) * 48]
        keyslots.append(LUKSKeyslot(
            index=idx,
            active=int.from_bytes(slot[0:4], "big"),
            iterations=int.from_bytes(slot[4:8], "big"),
            salt=slot[8:40],
            key_material_offset_sectors=int.from_bytes(slot[40:44], "big"),
            stripes=int.from_bytes(slot[44:48], "big"),
        ))

    return LUKSHeader(
        version=version,
        cipher_name=_clean_text(data[8:40]),
        cipher_mode=_clean_text(data[40:72]),
        hash_spec=_clean_text(data[72:104]),
        payload_offset_sectors=int.from_bytes(data[104:108], "big"),
        key_bytes=int.from_bytes(data[108:112], "big"),
        mk_digest=data[112:132],
        mk_digest_salt=data[132:164],
        mk_digest_iterations=int.from_bytes(data[164:168], "big"),
        uuid=_clean_text(data[168:208]),
        keyslots=keyslots,
    )


def _pbkdf2(hash_name: str, password: bytes, salt: bytes, iterations: int, dklen: int):
    return hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen=dklen)


def _hash(hash_name: str, data: bytes):
    h = hashlib.new(hash_name)
    h.update(data)
    return h.digest()


def _xor_bytes(a: bytes, b: bytes):
    return bytes(x ^ y for x, y in zip(a, b))


def _af_diffuse(block: bytes, hash_name: str):
    digest_size = hashlib.new(hash_name).digest_size
    out = bytearray()
    block_index = 0
    for offset in range(0, len(block), digest_size):
        chunk = block[offset:offset + digest_size]
        out.extend(_hash(hash_name, block_index.to_bytes(4, "big") + chunk)[:len(chunk)])
        block_index += 1
    return bytes(out)


def _af_merge_variant_zero_init(data: bytes, block_size: int, stripes: int, hash_name: str):
    blocks = [data[i * block_size:(i + 1) * block_size] for i in range(stripes)]
    acc = b"\x00" * block_size
    for idx in range(stripes - 1):
        acc = _af_diffuse(_xor_bytes(acc, blocks[idx]), hash_name)
    return _xor_bytes(acc, blocks[-1])


def _af_merge_variant_first_block(data: bytes, block_size: int, stripes: int, hash_name: str):
    blocks = [data[i * block_size:(i + 1) * block_size] for i in range(stripes)]
    acc = blocks[0]
    for idx in range(1, stripes - 1):
        acc = _af_diffuse(_xor_bytes(acc, blocks[idx]), hash_name)
    return _xor_bytes(acc, blocks[-1]) if stripes > 1 else acc


def _essiv_iv(cipher_name: str, key: bytes, sector_number: int):
    if cipher_name != "aes":
        raise ValueError(f"unsupported cipher: {cipher_name}")

    salt_key = _hash("sha256", key)[:len(key)]
    plain_iv = sector_number.to_bytes(4, "little") + b"\x00" * 12
    cipher = Cipher(algorithms.AES(salt_key), modes.ECB()).encryptor()
    return cipher.update(plain_iv) + cipher.finalize()


def _crypt_sector(cipher_name: str, key: bytes, sector_data: bytes, sector_number: int, encrypt: bool):
    iv = _essiv_iv(cipher_name, key, sector_number)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    worker = cipher.encryptor() if encrypt else cipher.decryptor()
    return worker.update(sector_data) + worker.finalize()


def _crypt_sectors(cipher_name: str, key: bytes, data: bytes, sector_start: int, sector_size: int, encrypt: bool):
    out = bytearray()
    for index in range(0, len(data), sector_size):
        sector = data[index:index + sector_size]
        out.extend(_crypt_sector(cipher_name, key, sector, sector_start + index // sector_size, encrypt))
    return bytes(out)


class LUKS1MappedFile:
    def __init__(self, backend_fp, container_start: int, payload_offset_sectors: int, size_bytes: int, master_key: bytes, cipher_name: str, close_backend: bool = False):
        self.backend_fp = backend_fp
        self.container_start = container_start
        self.payload_offset_sectors = payload_offset_sectors
        self.size_bytes = size_bytes
        self.master_key = master_key
        self.cipher_name = cipher_name
        self.sector_size = 512
        self.pos = 0
        self.closed = False
        self.close_backend = close_backend

    def seek(self, offset: int, whence: int = 0):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = self.size_bytes + offset
        else:
            raise ValueError("invalid whence")
        return self.pos

    def tell(self):
        return self.pos

    def writable(self):
        return hasattr(self.backend_fp, "write")

    def read(self, size: int = -1):
        if size < 0 or self.pos + size > self.size_bytes:
            size = self.size_bytes - self.pos
        if size <= 0:
            return b""

        start_sector = self.pos // self.sector_size
        end_offset = self.pos + size
        end_sector = math.ceil(end_offset / self.sector_size)
        sector_count = end_sector - start_sector
        encrypted_offset = self.container_start + (self.payload_offset_sectors + start_sector) * self.sector_size

        self.backend_fp.seek(encrypted_offset)
        encrypted = self.backend_fp.read(sector_count * self.sector_size)
        clear = _crypt_sectors(self.cipher_name, self.master_key, encrypted, start_sector, self.sector_size, encrypt=False)

        start_in_sector = self.pos % self.sector_size
        data = clear[start_in_sector:start_in_sector + size]
        self.pos += len(data)
        return data

    def write(self, data: bytes):
        if not data:
            return 0

        start_sector = self.pos // self.sector_size
        end_offset = self.pos + len(data)
        end_sector = math.ceil(end_offset / self.sector_size)
        sector_count = end_sector - start_sector
        encrypted_offset = self.container_start + (self.payload_offset_sectors + start_sector) * self.sector_size

        self.backend_fp.seek(encrypted_offset)
        encrypted = self.backend_fp.read(sector_count * self.sector_size)
        clear = bytearray(_crypt_sectors(self.cipher_name, self.master_key, encrypted, start_sector, self.sector_size, encrypt=False))

        start_in_sector = self.pos % self.sector_size
        clear[start_in_sector:start_in_sector + len(data)] = data

        new_encrypted = _crypt_sectors(self.cipher_name, self.master_key, bytes(clear), start_sector, self.sector_size, encrypt=True)
        self.backend_fp.seek(encrypted_offset)
        self.backend_fp.write(new_encrypted)
        self.pos += len(data)
        return len(data)

    def close(self):
        self.closed = True
        if self.close_backend and hasattr(self.backend_fp, "close"):
            self.backend_fp.close()


class LUKS1Volume:
    def __init__(self, backend_fp, container_start: int, container_size_bytes: int):
        self.backend_fp = backend_fp
        self.container_start = container_start
        self.container_size_bytes = container_size_bytes
        self.header = self._read_header()
        self.master_key = None

    def _read_header(self):
        self.backend_fp.seek(self.container_start)
        return parse_luks1_header(self.backend_fp.read(592))

    def _read_key_material(self, keyslot: LUKSKeyslot):
        key_material_bytes = keyslot.stripes * self.header.key_bytes
        read_len = math.ceil(key_material_bytes / 512) * 512
        self.backend_fp.seek(self.container_start + keyslot.key_material_offset_sectors * 512)
        return self.backend_fp.read(read_len)[:read_len]

    def _decrypt_key_material(self, slot: LUKSKeyslot, candidate_key: bytes, use_absolute_iv: bool):
        encrypted = self._read_key_material(slot)
        sector_start = slot.key_material_offset_sectors if use_absolute_iv else 0
        return _crypt_sectors(
            self.header.cipher_name,
            candidate_key,
            encrypted,
            sector_start,
            512,
            encrypt=False,
        )[:slot.stripes * self.header.key_bytes]

    def _verify_master_key(self, master_key: bytes):
        digest = _pbkdf2(
            self.header.hash_spec,
            master_key,
            self.header.mk_digest_salt,
            self.header.mk_digest_iterations,
            len(self.header.mk_digest),
        )
        return digest == self.header.mk_digest

    def unlock(self, key_material: bytes):
        if self.header.cipher_name != "aes":
            raise ValueError(f"unsupported LUKS cipher: {self.header.cipher_name}")
        if self.header.cipher_mode != "cbc-essiv:sha256":
            raise ValueError(f"unsupported LUKS mode: {self.header.cipher_mode}")

        merge_variants = (
            _af_merge_variant_zero_init,
            _af_merge_variant_first_block,
        )

        for slot in self.header.keyslots:
            if slot.active != LUKS_KEY_ENABLED or slot.iterations <= 0 or slot.stripes <= 0:
                continue

            derived = _pbkdf2(
                self.header.hash_spec,
                key_material,
                slot.salt,
                slot.iterations,
                self.header.key_bytes,
            )

            for use_absolute_iv in (True, False):
                decrypted = self._decrypt_key_material(slot, derived, use_absolute_iv)
                for merge in merge_variants:
                    candidate = merge(decrypted, self.header.key_bytes, slot.stripes, self.header.hash_spec)
                    if self._verify_master_key(candidate):
                        self.master_key = candidate
                        return candidate

        raise ValueError("failed to unlock LUKS1 volume with provided key")

    def payload_size_bytes(self):
        return self.container_size_bytes - self.header.payload_offset_sectors * 512

    def open_mapped_file(self, backend_fp=None):
        if self.master_key is None:
            raise ValueError("volume is locked")

        return LUKS1MappedFile(
            backend_fp=backend_fp or self.backend_fp,
            container_start=self.container_start,
            payload_offset_sectors=self.header.payload_offset_sectors,
            size_bytes=self.payload_size_bytes(),
            master_key=self.master_key,
            cipher_name=self.header.cipher_name,
        )
