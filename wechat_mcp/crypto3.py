"""SQLCipher 3 page format used by WeChat 3.x.

page = AES-CBC(plaintext, key) + IV(16) + HMAC-SHA1(20) + padding(12)
page 1 replaces the 16-byte SQLite header with the KDF salt.
"""

from __future__ import annotations

import hashlib
import hmac
import shutil
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import DecryptError

PAGE_SIZE = 4096
KEY_SIZE = 32
KDF_ITERATIONS = 64000
RESERVE_SIZE = 48
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 20
SQLITE_HEADER = b"SQLite format 3\x00"


def derive_keys(key: bytes, salt: bytes) -> tuple[bytes, bytes]:
    if len(key) != KEY_SIZE:
        raise DecryptError("微信 3.x 密钥必须为 32 字节")
    if len(salt) != SALT_SIZE:
        raise DecryptError("数据库 salt 必须为 16 字节")
    aes_key = hashlib.pbkdf2_hmac("sha1", key, salt, KDF_ITERATIONS, KEY_SIZE)
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha1", aes_key, mac_salt, 2, KEY_SIZE)
    return aes_key, mac_key


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def verify_key(key: bytes, page1: bytes) -> bool:
    if len(page1) < PAGE_SIZE or page1[:16] == SQLITE_HEADER:
        return False
    salt = page1[:16]
    _, mac_key = derive_keys(key, salt)
    mac = hmac.new(mac_key, page1[16:4064], hashlib.sha1)
    mac.update(struct.pack("<I", 1))
    return hmac.compare_digest(mac.digest(), page1[4064:4084])


def decrypt_page(
    aes_key: bytes, page: bytes, pgno: int, skip_salt: bool = True
) -> bytes:
    """Decrypt a single page, optionally treating bytes 0..15 as the salt."""
    if len(page) != PAGE_SIZE:
        raise DecryptError(f"页大小异常：{len(page)}")
    iv = page[4048:4064]
    if pgno == 1 and skip_salt:
        plaintext = _aes_cbc_decrypt(aes_key, iv, page[16:4048])
        return SQLITE_HEADER + plaintext + page[4048:4096]
    return _aes_cbc_decrypt(aes_key, iv, page[0:4048]) + page[4048:4096]


def decrypt_database(data: bytes, key: bytes) -> bytes:
    if len(data) < PAGE_SIZE:
        raise DecryptError("数据库文件过小")
    if data[:16] == SQLITE_HEADER:
        return data

    salt = data[:16]
    if not verify_key(key, data[:PAGE_SIZE]):
        raise DecryptError("密钥校验失败（SQLCipher 3）")

    aes_key, _ = derive_keys(key, salt)
    output = bytearray()
    for offset in range(0, len(data), PAGE_SIZE):
        page = data[offset : offset + PAGE_SIZE]
        if len(page) < PAGE_SIZE:
            break
        if offset == 0:
            ciphertext = page[16:4048]
            iv = page[4048:4064]
            reserve = page[4048:4096]
            output += SQLITE_HEADER
            output += _aes_cbc_decrypt(aes_key, iv, ciphertext)
            output += reserve
        else:
            ciphertext = page[0:4048]
            iv = page[4048:4064]
            output += _aes_cbc_decrypt(aes_key, iv, ciphertext)
            output += page[4048:4096]
    return bytes(output)


def decrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    with src.open("rb") as source:
        first = source.read(PAGE_SIZE)
        if len(first) < PAGE_SIZE:
            raise DecryptError("数据库文件过小")
        if first[:16] == SQLITE_HEADER:
            shutil.copyfile(src, dst)
            return {"encrypted": False, "pages": 0}
        if not verify_key(key, first):
            raise DecryptError("密钥校验失败（SQLCipher 3）")

        aes_key, _ = derive_keys(key, first[:16])
        pages = 0
        with dst.open("wb") as output:
            page = first
            while len(page) == PAGE_SIZE:
                pgno = pages + 1
                output.write(decrypt_page(aes_key, page, pgno, skip_salt=pgno == 1))
                pages += 1
                page = source.read(PAGE_SIZE)
    return {"encrypted": True, "pages": pages}
