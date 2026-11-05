"""SQLCipher 4 page format used by WeChat 4.x.

page = AES-CBC(plaintext, raw_key) + IV(16) + HMAC-SHA512(64)
reserve = 80 bytes; page 1 replaces the 16-byte SQLite header with the salt.
The AES key is the raw 32-byte key; only the HMAC key goes through PBKDF2.
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
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
RESERVE_SIZE = 80
SQLITE_HEADER = b"SQLite format 3\x00"


def derive_mac_key(key: bytes, salt: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise DecryptError("微信 4.x 密钥必须为 32 字节")
    if len(salt) != SALT_SIZE:
        raise DecryptError("数据库 salt 必须为 16 字节")
    mac_salt = bytes(value ^ 0x3A for value in salt)
    return hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, 32)


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def verify_key(key: bytes, page1: bytes) -> bool:
    if len(page1) < PAGE_SIZE or page1[:16] == SQLITE_HEADER:
        return False
    salt = page1[:16]
    mac_key = derive_mac_key(key, salt)
    mac = hmac.new(mac_key, page1[16:4032], hashlib.sha512)
    mac.update(struct.pack("<I", 1))
    return hmac.compare_digest(mac.digest(), page1[4032:4096])


def verify_page(key: bytes, page: bytes, pgno: int, salt: bytes) -> bool:
    if len(page) < PAGE_SIZE:
        return False
    mac_key = derive_mac_key(key, salt)
    start = 16 if pgno == 1 else 0
    mac = hmac.new(mac_key, page[start:4032], hashlib.sha512)
    mac.update(struct.pack("<I", pgno))
    return hmac.compare_digest(mac.digest(), page[4032:4096])


def decrypt_page(key: bytes, page: bytes, pgno: int) -> bytes:
    if len(page) != PAGE_SIZE:
        raise DecryptError(f"页大小异常：{len(page)}")
    iv = page[4016:4032]
    ciphertext = page[16:4016] if pgno == 1 else page[0:4016]
    plaintext = _aes_cbc_decrypt(key, iv, ciphertext)
    if pgno == 1:
        return SQLITE_HEADER + plaintext + b"\x00" * RESERVE_SIZE
    return plaintext + b"\x00" * RESERVE_SIZE


def decrypt_page_full(key: bytes, page: bytes) -> bytes:
    """Decrypt a page whose first 16 bytes are plaintext (no salt)."""
    if len(page) != PAGE_SIZE:
        raise DecryptError(f"页大小异常：{len(page)}")
    plaintext = _aes_cbc_decrypt(key, page[4016:4032], page[0:4016])
    return plaintext + b"\x00" * RESERVE_SIZE


def decrypt_database(data: bytes, key: bytes, verify_pages: bool = False) -> bytes:
    if len(data) < PAGE_SIZE:
        raise DecryptError("数据库文件过小")
    if data[:16] == SQLITE_HEADER:
        return data

    salt = data[:16]
    if not verify_key(key, data[:PAGE_SIZE]):
        raise DecryptError("密钥校验失败（SQLCipher 4）")

    output = bytearray()
    page_count = len(data) // PAGE_SIZE
    for index in range(page_count):
        page = data[index * PAGE_SIZE : (index + 1) * PAGE_SIZE]
        pgno = index + 1
        if verify_pages and not verify_page(key, page, pgno, salt):
            raise DecryptError(f"第 {pgno} 页 HMAC 校验失败")
        output += decrypt_page(key, page, pgno)
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
            raise DecryptError("密钥校验失败（SQLCipher 4）")

        pages = 0
        with dst.open("wb") as output:
            page = first
            while len(page) == PAGE_SIZE:
                pgno = pages + 1
                output.write(decrypt_page(key, page, pgno))
                pages += 1
                page = source.read(PAGE_SIZE)
    return {"encrypted": True, "pages": pages}
