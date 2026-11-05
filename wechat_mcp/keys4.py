"""Extract SQLCipher 4 keys from a running WeChat 4.x process.

WeChat 4.1+ keeps one key per database.  Each ``Config.Cipher`` object stores
an ``x'<key><salt>'`` string (XOR-obfuscated), and the salt identifies which
database file the key belongs to.  We therefore return a salt -> key map
instead of a single key.

No single memory layout is guaranteed across 4.x releases, so extraction
tries several independent strategies in order:

1. ``Config.Cipher`` objects using the known object name and XOR mask
2. other ``Cipher`` class-name spellings and a user-supplied mask
3. any ``x'<hex>'`` run in readable memory
4. raw key bytes stored near a database salt

Every candidate is verified against a real page-1 HMAC before use.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .config import Account
from .crypto4 import verify_key
from .errors import KeyInvalid, KeyNotFound
from .keyutil import parse_key_hex, parse_key_list, plausible_key
from .paths import key_sample_dbs
from .winmem import MemoryReader, ProcessMemory, list_processes

CONFIG_NEEDLES = (
    b"com.Tencent.WCDB.Config.Cipher",
    b"com.tencent.wcdb.Config.Cipher",
    b"WCDB.Config.Cipher",
    b"Config.Cipher",
)
CONFIG_NEEDLE = CONFIG_NEEDLES[0]
CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
BUILTIN_XOR_MASKS = (CONFIG_XOR_MASK,)
CONFIG_RUN_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
HEX_RUN_RE = re.compile(rb"(?<![0-9a-fA-F])([0-9a-fA-F]{96})(?![0-9a-fA-F])")
SALT_WINDOW_BEFORE = 0x200
SALT_WINDOW_AFTER = 0x100


@dataclass(frozen=True)
class KeyCandidate:
    key: bytes
    salt: bytes | None
    source: str


@dataclass
class KeyMap:
    by_salt: dict[bytes, bytes] = field(default_factory=dict)
    default: bytes | None = None
    verified_salts: set[bytes] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)

    def __bool__(self) -> bool:
        return bool(self.by_salt or self.default)

    @property
    def count(self) -> int:
        return len(self.by_salt) or (1 if self.default else 0)

    def key_for_salt(self, salt: bytes) -> bytes | None:
        key = self.by_salt.get(salt)
        if key is not None:
            return key
        return self.default

    def resolve(self, page1: bytes) -> bytes | None:
        salt = page1[:16]
        key = self.by_salt.get(salt)
        if key is not None and verify_key(key, page1):
            self.verified_salts.add(salt)
            return key
        if self.default and verify_key(self.default, page1):
            return self.default
        seen: set[bytes] = set()
        for candidate in self.by_salt.values():
            if candidate in seen:
                continue
            seen.add(candidate)
            if verify_key(candidate, page1):
                self.by_salt[salt] = candidate
                self.verified_salts.add(salt)
                return candidate
        return None

    def summary(self) -> dict:
        return {
            "keys": self.count,
            "verified": len(self.verified_salts),
            "sources": sorted(self.sources),
        }


def _u64(data: bytes, offset: int) -> int:
    if len(data) < offset + 8:
        return 0
    return struct.unpack_from("<Q", data, offset)[0]


def _xor_repeat(data: bytes, mask: bytes) -> bytes:
    if not mask:
        return data
    repeated = (mask * ((len(data) + len(mask) - 1) // len(mask)))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, repeated))


def _masks(masks: list[bytes] | tuple[bytes, ...] | None = None) -> list[bytes]:
    values: list[bytes] = list(masks if masks is not None else BUILTIN_XOR_MASKS)
    extra = os.environ.get("WECHAT_MCP_XOR_MASK", "").strip()
    if extra:
        try:
            values.append(bytes.fromhex(extra))
        except ValueError:
            pass
    values.append(b"")
    unique: list[bytes] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return unique


def _parse_run(run: bytes, source: str) -> KeyCandidate | None:
    try:
        text = run.decode("ascii")
        key = bytes.fromhex(text[:64])
        salt = bytes.fromhex(text[64:96]) if len(text) >= 96 else None
    except ValueError:
        return None
    return KeyCandidate(key=key, salt=salt, source=source)


def scan_config_cipher(
    memory: MemoryReader,
    needles: tuple[bytes, ...] | list[bytes] | None = None,
    masks: list[bytes] | tuple[bytes, ...] | None = None,
) -> list[KeyCandidate]:
    wanted = tuple(needles or CONFIG_NEEDLES)
    addresses: set[int] = set()
    lengths: set[int] = set()
    for needle in wanted:
        found = set(memory.find_all(needle))
        if found:
            addresses.update(found)
            lengths.add(len(needle))
    if not addresses:
        return []

    patterns = [struct.pack("<Q", address) for address in sorted(addresses)]
    decoded_masks = _masks(masks)
    candidates: dict[tuple[bytes, bytes | None], KeyCandidate] = {}

    for start in range(0, len(patterns), 64):
        group = patterns[start : start + 64]
        pattern = re.compile(b"|".join(re.escape(item) for item in group))
        for base, data in memory.iter_chunks(overlap=0x60):
            for match in pattern.finditer(data):
                query_address = base + match.start()
                node = memory.read(query_address - 0x10, 0x50)
                if not node or len(node) < 0x50:
                    continue
                if _u64(node, 0x10) not in addresses:
                    continue
                if _u64(node, 0x18) not in lengths:
                    continue
                config_pointer = _u64(node, 0x28)
                if not config_pointer:
                    continue

                obj = memory.read(config_pointer + 0x88, 0x28)
                if not obj or len(obj) < 0x28:
                    continue
                data_pointer = _u64(obj, 0x08)
                data_length = _u64(obj, 0x10)
                if not data_pointer or not (0 < data_length <= 4096):
                    continue
                blob = memory.read(data_pointer, data_length)
                if not blob:
                    continue
                for mask in decoded_masks:
                    decoded = _xor_repeat(blob, mask)
                    for run in CONFIG_RUN_RE.findall(decoded):
                        candidate = _parse_run(run, "config-cipher")
                        if candidate:
                            candidates.setdefault(
                                (candidate.key, candidate.salt), candidate
                            )
    return list(candidates.values())


def scan_ascii_keys(memory: MemoryReader) -> list[KeyCandidate]:
    candidates: dict[tuple[bytes, bytes | None], KeyCandidate] = {}
    for _, data in memory.iter_chunks(overlap=256):
        for run in CONFIG_RUN_RE.findall(data):
            candidate = _parse_run(run, "memory-ascii")
            if candidate:
                candidates.setdefault((candidate.key, candidate.salt), candidate)
    return list(candidates.values())


def scan_salt_neighborhood(
    memory: MemoryReader, samples: list[bytes]
) -> list[KeyCandidate]:
    """Find raw key bytes in the memory window surrounding a database salt."""
    candidates: dict[bytes, KeyCandidate] = {}
    for page in samples:
        salt = page[:16]
        for address in list(memory.find_all(salt))[:8]:
            start = max(0, address - SALT_WINDOW_BEFORE)
            window = memory.read(start, SALT_WINDOW_BEFORE + SALT_WINDOW_AFTER)
            if not window:
                continue
            for offset in range(0, max(0, len(window) - 31)):
                candidate = window[offset : offset + 32]
                if candidate in candidates or not plausible_key(candidate):
                    continue
                if verify_key(candidate, page):
                    candidates[candidate] = KeyCandidate(
                        candidate, salt, "salt-neighborhood"
                    )
                    break
            for match in HEX_RUN_RE.finditer(window):
                try:
                    key = bytes.fromhex(match.group(1).decode("ascii"))
                except ValueError:
                    continue
                if key in candidates or not verify_key(key, page):
                    continue
                candidates[key] = KeyCandidate(key, salt, "salt-neighborhood")
    return list(candidates.values())


def _sample_pages(account: Account) -> list[bytes]:
    pages: list[bytes] = []
    for path in key_sample_dbs(account):
        try:
            with path.open("rb") as handle:
                page = handle.read(4096)
        except OSError:
            continue
        if len(page) == 4096:
            pages.append(page)
    return pages


def _build_map(candidates: list[KeyCandidate], samples: list[bytes]) -> KeyMap:
    result = KeyMap()
    for candidate in candidates:
        result.sources.add(candidate.source)
        if candidate.salt:
            result.by_salt.setdefault(candidate.salt, candidate.key)
            continue
        matched = False
        for page in samples:
            if verify_key(candidate.key, page):
                result.by_salt.setdefault(page[:16], candidate.key)
                result.verified_salts.add(page[:16])
                matched = True
        if not matched:
            result.default = candidate.key

    for page in samples:
        salt = page[:16]
        key = result.resolve(page)
        if key:
            result.verified_salts.add(salt)
    return result


def extract_key_map4(account: Account, override: str | None = None) -> KeyMap:
    samples = _sample_pages(account)
    if not samples:
        raise KeyNotFound("该 4.x 账号没有可用的数据库文件，无法校验密钥")

    if override:
        entries = parse_key_list(override)
        result = KeyMap(sources={"manual"})
        for key, salt in entries:
            if salt:
                result.by_salt.setdefault(salt, key)
                continue
            matched = False
            for page in samples:
                if verify_key(key, page):
                    result.by_salt.setdefault(page[:16], key)
                    result.verified_salts.add(page[:16])
                    matched = True
            if not matched:
                result.default = key
        for page in samples:
            if result.resolve(page):
                result.verified_salts.add(page[:16])
        if not result.verified_salts:
            raise KeyInvalid("提供的 key 无法校验该 4.x 账号的任何数据库")
        return result

    processes = list_processes(["Weixin.exe"]) or list_processes(["WeChat.exe"])
    if not processes:
        raise KeyNotFound(
            "未发现正在运行的微信 4.x 进程。请先登录微信，或在工具参数中直接提供 key。"
        )

    strategies = (
        (
            "config-cipher",
            lambda memory: scan_config_cipher(memory, needles=CONFIG_NEEDLES[:1]),
        ),
        (
            "config-cipher-generic",
            lambda memory: scan_config_cipher(memory, needles=CONFIG_NEEDLES[1:]),
        ),
        ("memory-ascii", scan_ascii_keys),
        (
            "salt-neighborhood",
            lambda memory: scan_salt_neighborhood(memory, samples),
        ),
    )

    candidates: list[KeyCandidate] = []
    for process in processes:
        with ProcessMemory(process.pid) as memory:
            for name, strategy in strategies:
                found = strategy(memory)
                if not found:
                    continue
                candidates.extend(found)
                result = _build_map(candidates, samples)
                if result.verified_salts:
                    result.sources.add(name)
                    return result

    if candidates:
        raise KeyInvalid(
            f"在微信进程中找到 {len(candidates)} 个密钥，但都无法校验该账号数据库，"
            "可能登录的是另一个账号。"
        )
    raise KeyNotFound(
        "未能在微信进程内存中定位密钥（已尝试 Config.Cipher、"
        "内存十六进制串与 salt 邻近扫描）。请确认微信已登录，或以管理员身份运行服务；"
        "新版本可设置 WECHAT_MCP_XOR_MASK，或直接提供 key。"
    )


def find_db_key(key_map: KeyMap, db_path: Path) -> bytes | None:
    try:
        with db_path.open("rb") as handle:
            page = handle.read(4096)
    except OSError:
        return None
    if len(page) < 4096:
        return None
    return key_map.resolve(page)


__all__ = [
    "CONFIG_NEEDLE",
    "CONFIG_NEEDLES",
    "CONFIG_XOR_MASK",
    "KeyCandidate",
    "KeyMap",
    "extract_key_map4",
    "find_db_key",
    "parse_key_hex",
    "scan_ascii_keys",
    "scan_config_cipher",
    "scan_salt_neighborhood",
]
