"""Synthetic SQLCipher 3/4 databases and WAL files for tests.

These helpers mirror the page layouts implemented by ``wechat_mcp.crypto3``,
``wechat_mcp.crypto4`` and ``wechat_mcp.wal``.  They do not touch real WeChat
data.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import sqlite3
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from wechat_mcp import crypto3, crypto4

PAGE = 4096
WAL_MAGIC = 0x377F0682


def _encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def make_database(path: Path, rows: int = 120) -> bytes:
    """Create a plaintext SQLite database with at least two pages."""
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    try:
        con.execute("PRAGMA page_size=4096")
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT, blob BLOB)")
        con.executemany(
            "INSERT INTO t(value, blob) VALUES (?, ?)",
            [(f"row-{index:04d}-" + "x" * 100, b"\x01\x02\x03\x04") for index in range(rows)],
        )
        con.commit()
    finally:
        con.close()
    data = path.read_bytes()
    assert len(data) % PAGE == 0
    assert len(data) >= 2 * PAGE
    return data


def mutate_database(source: Path, target: Path, value: str = "CHANGED") -> bytes:
    shutil.copyfile(source, target)
    con = sqlite3.connect(target)
    try:
        con.execute("UPDATE t SET value=? WHERE id=1", (value,))
        con.commit()
    finally:
        con.close()
    data = target.read_bytes()
    assert len(data) == source.stat().st_size
    return data


def usable(data: bytes, version: int) -> bytes:
    """Bytes SQLite sees on each page (salt / IV / HMAC regions excluded)."""
    limit = 4016 if version == 4 else 4048
    return b"".join(data[offset : offset + limit] for offset in range(0, len(data), PAGE))


def _page3(aes_key: bytes, mac_key: bytes, plain: bytes, pgno: int, salt: bytes) -> bytes:
    iv = os.urandom(16)
    start = 16 if pgno == 1 else 0
    ciphertext = _encrypt(aes_key, iv, plain[start:4048])
    mac = hmac.new(mac_key, ciphertext + iv, hashlib.sha1)
    mac.update(struct.pack("<I", pgno))
    body = (salt if pgno == 1 else b"") + ciphertext + iv + mac.digest()
    return body + b"\x00" * (PAGE - len(body))


def _page4(key: bytes, mac_key: bytes, plain: bytes, pgno: int, salt: bytes) -> bytes:
    iv = os.urandom(16)
    start = 16 if pgno == 1 else 0
    ciphertext = _encrypt(key, iv, plain[start:4016])
    mac = hmac.new(mac_key, ciphertext + iv, hashlib.sha512)
    mac.update(struct.pack("<I", pgno))
    body = (salt if pgno == 1 else b"") + ciphertext + iv + mac.digest()
    return body + b"\x00" * (PAGE - len(body))


def _page3_full(aes_key: bytes, mac_key: bytes, plain: bytes, pgno: int) -> bytes:
    iv = os.urandom(16)
    ciphertext = _encrypt(aes_key, iv, plain[0:4048])
    mac = hmac.new(mac_key, ciphertext + iv, hashlib.sha1)
    mac.update(struct.pack("<I", pgno))
    body = ciphertext + iv + mac.digest()
    return body + b"\x00" * (PAGE - len(body))


def _page4_full(key: bytes, mac_key: bytes, plain: bytes, pgno: int) -> bytes:
    iv = os.urandom(16)
    ciphertext = _encrypt(key, iv, plain[0:4016])
    mac = hmac.new(mac_key, ciphertext + iv, hashlib.sha512)
    mac.update(struct.pack("<I", pgno))
    body = ciphertext + iv + mac.digest()
    return body + b"\x00" * (PAGE - len(body))


def encrypt_page(
    page: bytes,
    key: bytes,
    version: int,
    salt: bytes,
    pgno: int,
    full: bool = False,
) -> bytes:
    if version == 3:
        aes_key, mac_key = crypto3.derive_keys(key, salt)
        builder = _page3_full if full else _page3
    else:
        aes_key, mac_key = key, crypto4.derive_mac_key(key, salt)
        builder = _page4_full if full else _page4
    if full:
        return builder(aes_key, mac_key, page, pgno)
    return builder(aes_key, mac_key, page, pgno, salt)


def encrypt_pages(
    plain: bytes,
    key: bytes,
    version: int,
    salt: bytes,
    page1_full: bool = False,
) -> bytes:
    output = bytearray()
    for index in range(len(plain) // PAGE):
        pgno = index + 1
        output += encrypt_page(
            plain[index * PAGE : (index + 1) * PAGE],
            key,
            version,
            salt,
            pgno,
            full=page1_full and pgno == 1,
        )
    return bytes(output)


def encrypt_database(plain: bytes, key: bytes, version: int, salt: bytes | None = None) -> bytes:
    return encrypt_pages(plain, key, version, salt or os.urandom(16))


def build_wal(
    plain: bytes,
    key: bytes,
    version: int,
    salt: bytes,
    commit: bool = True,
    page1_full: bool = False,
    header_salts: tuple[bytes, bytes] | None = None,
) -> bytes:
    """Build a WAL whose frames carry encrypted pages of ``plain``."""
    salt1, salt2 = header_salts or (os.urandom(4), os.urandom(4))
    header = struct.pack(
        ">IIIIIIII",
        WAL_MAGIC,
        3007000,
        PAGE,
        0,
        int.from_bytes(salt1, "big"),
        int.from_bytes(salt2, "big"),
        0,
        0,
    )
    page_count = len(plain) // PAGE
    output = bytearray(header)
    for index in range(page_count):
        pgno = index + 1
        single = plain[index * PAGE : (index + 1) * PAGE]
        encrypted = encrypt_page(
            single, key, version, salt, pgno, full=page1_full and pgno == 1
        )
        db_size = page_count if commit and pgno == page_count else 0
        output += struct.pack(
            ">IIIIII",
            pgno,
            db_size,
            int.from_bytes(salt1, "big"),
            int.from_bytes(salt2, "big"),
            0,
            0,
        )
        output += encrypted
    return bytes(output)
