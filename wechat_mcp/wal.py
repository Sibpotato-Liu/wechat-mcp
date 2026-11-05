"""Merge SQLCipher-encrypted SQLite WAL frames into a decrypted database.

The WAL file keeps encrypted pages, so a normal ``sqlite3`` cannot replay it.
Each frame is authenticated with the same HMAC used by the database pages;
frames from an older WAL generation (different salt) are ignored.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import crypto3, crypto4

WAL_MAGIC = {0x377F0682, 0x377F0683}
SQLITE_HEADER = b"SQLite format 3\x00"
PAGE_SIZE = 4096


@dataclass
class WalResult:
    total_frames: int
    target_pages: int
    pages: list[tuple[int, bytes]] = field(default_factory=list)
    page1_variant: str | None = None
    page1_skipped: bool = False

    @property
    def applied_pages(self) -> int:
        return len(self.pages)


FrameDecoder = Callable[[bytes, int], tuple[bytes | None, str | None]]


def _parse(wal: bytes, decoder: FrameDecoder, page_size: int = PAGE_SIZE) -> WalResult | None:
    if len(wal) < 32:
        return None
    if int.from_bytes(wal[0:4], "big") not in WAL_MAGIC:
        return None

    wal_page_size = int.from_bytes(wal[8:12], "big")
    if wal_page_size == 1:
        wal_page_size = 65536
    if wal_page_size != page_size:
        return None

    wal_salts = wal[16:24]
    offset = 32
    frames: list[tuple[int, int, bytes | None, str | None]] = []
    last_commit: tuple[int, int] | None = None
    page1_variant: str | None = None
    page1_skipped = False

    while offset + 24 + page_size <= len(wal):
        header = wal[offset : offset + 24]
        pgno, db_size = struct.unpack(">II", header[0:8])
        if pgno == 0:
            break
        if header[8:16] != wal_salts:
            break
        page = wal[offset + 24 : offset + 24 + page_size]
        plaintext, variant = decoder(page, pgno)
        if plaintext is None:
            if pgno == 1:
                # Page 1 frames occasionally use a different salt layout.
                # Keep the main DB's page 1 and continue with later frames.
                page1_skipped = True
            else:
                break
        elif pgno == 1:
            page1_variant = variant
        frames.append((pgno, db_size, plaintext, variant))
        if db_size:
            last_commit = (len(frames) - 1, db_size)
        offset += 24 + page_size

    if last_commit is None:
        return None

    commit_index, target_pages = last_commit
    pages = [
        (pgno, plaintext)
        for pgno, _, plaintext, _ in frames[: commit_index + 1]
        if plaintext is not None
    ]
    return WalResult(
        total_frames=len(frames),
        target_pages=target_pages,
        pages=pages,
        page1_variant=page1_variant,
        page1_skipped=page1_skipped,
    )


def apply_wal_bytes(
    db: bytes,
    wal: bytes,
    key: bytes,
    version: int,
    salt: bytes | None = None,
) -> WalResult | None:
    """Apply encrypted WAL frames to ``db`` bytes.

    ``db`` is normally the decrypted database, so the SQLCipher salt of the
    original file must be supplied through ``salt``.
    """
    if len(db) < PAGE_SIZE:
        return None
    if salt is None:
        if db[:16] == SQLITE_HEADER:
            return None
        salt = db[:16]
    decoder = make_decoder4(key, salt) if version == 4 else make_decoder3(key, salt)
    result = _parse(wal, decoder)
    if result is None:
        return None

    needed = result.target_pages * PAGE_SIZE
    out = bytearray(db)
    if len(out) < needed:
        out.extend(b"\x00" * (needed - len(out)))
    for pgno, plaintext in result.pages:
        start = (pgno - 1) * PAGE_SIZE
        if 0 <= start < len(out):
            out[start : start + PAGE_SIZE] = plaintext
    del out[needed:]
    if len(out) < PAGE_SIZE or out[:16] != SQLITE_HEADER:
        return None
    result.pages = [(0, bytes(out))]
    return result


def merge_wal_file(
    db_path: Path,
    wal_path: Path,
    key: bytes,
    version: int,
    salt: bytes | None = None,
) -> WalResult | None:
    """Apply WAL frames in place to an already-decrypted DB file.

    ``salt`` is the SQLCipher salt of the encrypted source database.  When it
    is omitted the file itself must still be encrypted.
    """
    try:
        if salt is None:
            with db_path.open("rb") as handle:
                salt = handle.read(16)
        if not salt or len(salt) < 16 or salt == SQLITE_HEADER:
            return None
        wal = wal_path.read_bytes()
    except OSError:
        return None

    decoder = make_decoder4(key, salt) if version == 4 else make_decoder3(key, salt)
    result = _parse(wal, decoder)
    if result is None:
        return None

    try:
        with db_path.open("r+b") as handle:
            for pgno, plaintext in result.pages:
                handle.seek((pgno - 1) * PAGE_SIZE)
                handle.write(plaintext)
            handle.truncate(result.target_pages * PAGE_SIZE)
    except OSError:
        return None
    return result


def make_decoder4(key: bytes, salt: bytes) -> FrameDecoder:
    mac_key = crypto4.derive_mac_key(key, salt)

    def decoder(page: bytes, pgno: int) -> tuple[bytes | None, str | None]:
        stored = page[4032:4096]
        if pgno != 1:
            mac = hmac.new(mac_key, page[0:4032], hashlib.sha512)
            mac.update(struct.pack("<I", pgno))
            if not hmac.compare_digest(mac.digest(), stored):
                return None, None
            return crypto4.decrypt_page(key, page, pgno), "plain"

        mac = hmac.new(mac_key, page[16:4032], hashlib.sha512)
        mac.update(struct.pack("<I", 1))
        if hmac.compare_digest(mac.digest(), stored):
            plaintext = crypto4.decrypt_page(key, page, 1)
            if plaintext[:16] == SQLITE_HEADER:
                return plaintext, "skip-salt"

        mac = hmac.new(mac_key, page[0:4032], hashlib.sha512)
        mac.update(struct.pack("<I", 1))
        if hmac.compare_digest(mac.digest(), stored):
            plaintext = crypto4.decrypt_page_full(key, page)
            if plaintext[:16] == SQLITE_HEADER:
                return plaintext, "full-page"
        return None, None

    return decoder


def make_decoder3(key: bytes, salt: bytes) -> FrameDecoder:
    aes_key, mac_key = crypto3.derive_keys(key, salt)

    def decoder(page: bytes, pgno: int) -> tuple[bytes | None, str | None]:
        stored = page[4064:4084]
        if pgno != 1:
            mac = hmac.new(mac_key, page[0:4064], hashlib.sha1)
            mac.update(struct.pack("<I", pgno))
            if not hmac.compare_digest(mac.digest(), stored):
                return None, None
            return crypto3.decrypt_page(aes_key, page, pgno, skip_salt=False), "plain"

        mac = hmac.new(mac_key, page[16:4064], hashlib.sha1)
        mac.update(struct.pack("<I", 1))
        if hmac.compare_digest(mac.digest(), stored):
            plaintext = crypto3.decrypt_page(aes_key, page, 1, skip_salt=True)
            if plaintext[:16] == SQLITE_HEADER:
                return plaintext, "skip-salt"

        mac = hmac.new(mac_key, page[0:4064], hashlib.sha1)
        mac.update(struct.pack("<I", 1))
        if hmac.compare_digest(mac.digest(), stored):
            plaintext = crypto3.decrypt_page(aes_key, page, 1, skip_salt=False)
            if plaintext[:16] == SQLITE_HEADER:
                return plaintext, "full-page"
        return None, None

    return decoder
