"""Extract the SQLCipher 3 key from a running WeChat 3.x process.

WeChat 3.x does not expose a stable key offset across releases.  This module
uses the version-independent technique used by PyWxDump: locate the device
marker strings inside ``WeChatWin.dll``, walk backwards over pointer-sized
slots, and verify every candidate key against ``Msg/MicroMsg.db``.

If the pointer chain is not present (some 3.9 builds keep the key in a heap
structure), a second strategy tests raw 32-byte windows around the database
salt and near ASCII hex runs.  Both strategies only use read-only memory
access and validate candidates with the page-1 HMAC.
"""

from __future__ import annotations

import re
from pathlib import Path

from .config import Account
from .crypto3 import verify_key
from .errors import KeyInvalid, KeyNotFound
from .keyutil import parse_key_list
from .paths import contact_db
from .winmem import MemoryReader, ProcessMemory, list_processes

DEVICE_MARKERS = (b"iphone\x00", b"android\x00", b"ipad\x00")
SCAN_SPAN = 2000
SALT_WINDOW_BEFORE = 0x200
SALT_WINDOW_AFTER = 0x80
SALT_CANDIDATE_LIMIT = 192
HEX_RUN_RE = re.compile(rb"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")


def _sample_page(account: Account) -> bytes | None:
    path = contact_db(account)
    try:
        with Path(path).open("rb") as handle:
            page = handle.read(4096)
    except OSError:
        return None
    return page if len(page) == 4096 else None


def _plausible(key: bytes | None) -> bool:
    if not key or len(key) != 32:
        return False
    return len(set(key)) > 4


def _marker_addresses(memory: MemoryReader, start: int | None, end: int | None) -> list[int]:
    addresses: list[int] = []
    for marker in DEVICE_MARKERS:
        count = 0
        for address in memory.find_all(marker, start=start, end=end):
            if start is not None and address < start:
                continue
            if end is not None and address >= end:
                continue
            addresses.append(address)
            count += 1
            if count >= 3:
                break
    return sorted(set(addresses), reverse=True)


def _candidate_keys(
    memory: MemoryReader, start: int | None, end: int | None
) -> list[bytes]:
    pointer_size = getattr(memory, "pointer_size", 8)
    addresses = _marker_addresses(memory, start, end)
    found: dict[bytes, None] = {}

    for address in addresses:
        for slot in range(address, max(0, address - SCAN_SPAN), -pointer_size):
            pointer_bytes = memory.read(slot, pointer_size)
            if pointer_bytes:
                pointer = int.from_bytes(pointer_bytes, "little")
                if pointer > 0x10000:
                    key = memory.read(pointer, 32)
                    if _plausible(key):
                        found.setdefault(key, None)  # type: ignore[arg-type]
            inline = memory.read(slot, 32)
            if _plausible(inline):
                found.setdefault(inline, None)  # type: ignore[arg-type]
    return list(found)


def _salt_candidate_keys(
    memory: MemoryReader, page: bytes, limit: int = SALT_CANDIDATE_LIMIT
) -> list[bytes]:
    """Test key-sized windows around occurrences of the database salt."""
    salt = page[:16]
    found: dict[bytes, None] = {}
    for address in list(memory.find_all(salt))[:4]:
        start = max(0, address - SALT_WINDOW_BEFORE)
        window = memory.read(start, SALT_WINDOW_BEFORE + SALT_WINDOW_AFTER)
        if not window:
            continue
        for offset in range(0, max(0, len(window) - 31)):
            candidate = window[offset : offset + 32]
            if candidate in found or not _plausible(candidate):
                continue
            if verify_key(candidate, page):
                found[candidate] = None
            if len(found) >= limit:
                return list(found)
        for match in HEX_RUN_RE.finditer(window):
            try:
                candidate = bytes.fromhex(match.group(1).decode("ascii"))
            except ValueError:
                continue
            if candidate in found or not verify_key(candidate, page):
                continue
            found[candidate] = None
            if len(found) >= limit:
                return list(found)
    return list(found)


def extract_key3(account: Account, override: str | None = None) -> bytes:
    page = _sample_page(account)
    if page is None:
        raise KeyNotFound("未找到 Msg/MicroMsg.db，无法校验 3.x 密钥")

    if override:
        invalid = None
        for key, _salt in parse_key_list(override):
            if len(key) != 32:
                invalid = "key 必须是 64 位十六进制字符串"
                continue
            if verify_key(key, page):
                return key
        raise KeyInvalid(invalid or "提供的 key 无法校验该 3.x 账号的 MicroMsg.db")

    processes = list_processes(["WeChat.exe"])
    if not processes:
        raise KeyNotFound(
            "未发现正在运行的微信 3.x 进程。请先登录微信，或在工具参数中直接提供 key。"
        )

    for process in processes:
        with ProcessMemory(process.pid) as memory:
            module = memory.find_module("WeChatWin.dll")
            start = module.base if module else None
            end = module.base + module.size if module else None
            for candidate in _candidate_keys(memory, start, end):
                if verify_key(candidate, page):
                    return candidate
            if module is not None:
                # Older builds occasionally keep the key outside the image.
                for candidate in _candidate_keys(memory, None, None):
                    if verify_key(candidate, page):
                        return candidate
            matched = _salt_candidate_keys(memory, page)
            if matched:
                return matched[0]

    raise KeyNotFound(
        "未能在微信 3.x 进程内存中定位密钥（已尝试设备标记指针链与 salt 邻近扫描）。"
        "请确认微信已登录，或以管理员身份运行服务；也可手动提供 key。"
    )
