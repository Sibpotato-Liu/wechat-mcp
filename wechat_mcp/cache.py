"""Decrypt account databases into a local cache (source files stay untouched)."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto3, crypto4, wal
from .config import Account
from .errors import DecryptError, KeyNotFound, WeChatMCPError
from .keys3 import extract_key3
from .keys4 import KeyMap, extract_key_map4
from .paths import contact_db, key_sample_dbs, message_dbs, session_db

CACHE_VERSION = 1
SQLITE_HEADER = b"SQLite format 3\x00"
_KEY_CACHE: dict[str, KeyMap] = {}


def cache_root() -> Path:
    override = os.environ.get("WECHAT_MCP_CACHE_DIR")
    if override:
        return Path(os.path.expandvars(os.path.expanduser(override)))
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "wechat-mcp" / "cache"
    return Path.home() / ".cache" / "wechat-mcp"


@dataclass
class DecryptedAccount:
    account: Account
    contact: Path
    session: Path | None
    messages: list[Path]
    cache_dir: Path
    keys_used: int
    key_count: int = 0
    key_sources: list[str] = field(default_factory=list)
    wal_merged: int = 0
    notes: list[str] = field(default_factory=list)

    def all_paths(self) -> list[Path]:
        paths = [self.contact]
        if self.session:
            paths.append(self.session)
        paths.extend(self.messages)
        return paths


def _is_plain(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(16) == SQLITE_HEADER
    except OSError:
        return False


def _stat_fingerprint(path: Path) -> str:
    try:
        stat = path.stat()
        return f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}"
    except OSError:
        return f"{path.resolve()}|missing"


def _key_digest(key: bytes | None) -> str:
    if not key:
        return "nokey"
    return hashlib.sha256(key).hexdigest()[:12]


def _cache_name(source: Path, key: bytes | None, with_wal: bool) -> str:
    wal_path = source.with_name(source.name + "-wal")
    material = "|".join(
        [
            str(CACHE_VERSION),
            _stat_fingerprint(source),
            _stat_fingerprint(wal_path) if with_wal and wal_path.is_file() else "nowal",
            _key_digest(key),
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return f"{source.stem}-{digest}.db"


def _account_cache_dir(account: Account) -> Path:
    return cache_root() / f"v{account.version}" / account.wxid


def _find_reusable(cache_dir: Path, source: Path) -> Path | None:
    if not cache_dir.is_dir():
        return None
    candidates = sorted(
        (path for path in cache_dir.glob(f"{source.stem}-*.db") if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in candidates:
        if _is_plain(path):
            return path
    return None


def _prune_cache(cache_dir: Path, source: Path, keep: Path) -> None:
    """Keep the current cache file plus one previous generation."""
    candidates = sorted(
        (
            path
            for path in cache_dir.glob(f"{source.stem}-*.db")
            if path.is_file() and path != keep
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in candidates[1:]:
        for item in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
            try:
                item.unlink()
            except OSError:
                continue


def _env_key() -> str | None:
    return (
        os.environ.get("WECHAT_MCP_KEY")
        or os.environ.get("WECHAT_MCP_KEY_4X")
        or os.environ.get("WECHAT_MCP_KEY_3X")
    )


def get_key_map(account: Account, override: str | None = None) -> KeyMap:
    if override:
        if account.version == 4:
            key_map = extract_key_map4(account, override)
        else:
            key_map = KeyMap(default=extract_key3(account, override), sources={"manual"})
        _KEY_CACHE[account.account_id] = key_map
        return key_map

    cached = _KEY_CACHE.get(account.account_id)
    if cached:
        return cached

    env = _env_key()
    if account.version == 4:
        key_map = extract_key_map4(account, env)
    else:
        key_map = KeyMap(
            default=extract_key3(account, env),
            sources={"env"} if env else {"memory"},
        )
    _KEY_CACHE[account.account_id] = key_map
    return key_map


def _decrypt_one(
    account: Account,
    source: Path,
    key: bytes,
    cache_dir: Path,
    refresh: bool,
) -> tuple[Path, int]:
    wal_path = source.with_name(source.name + "-wal")
    has_wal = wal_path.is_file()
    source_salt: bytes | None = None
    if has_wal:
        try:
            with source.open("rb") as handle:
                source_salt = handle.read(16)
        except OSError:
            source_salt = None
    target = cache_dir / _cache_name(source, key, has_wal)

    if target.is_file() and not refresh and _is_plain(target):
        return target, 0

    cache_dir.mkdir(parents=True, exist_ok=True)
    part = target.with_suffix(".part")
    if part.exists():
        part.unlink()

    if account.version == 4:
        info = crypto4.decrypt_file(source, part, key)
    else:
        info = crypto3.decrypt_file(source, part, key)

    merged = 0
    if info["encrypted"] and has_wal and source_salt:
        result = wal.merge_wal_file(part, wal_path, key, account.version, salt=source_salt)
        if result is not None:
            merged = result.applied_pages
    os.replace(part, target)
    _prune_cache(cache_dir, source, target)
    return target, merged


def _db_key(key_map: KeyMap, source: Path, version: int) -> bytes | None:
    if version == 3:
        # 3.x uses one SQLCipher 3 key for every database, already validated
        # against MicroMsg.db during extraction.
        return key_map.default
    try:
        with source.open("rb") as handle:
            page = handle.read(4096)
    except OSError:
        return None
    if len(page) < 4096:
        return None
    return key_map.resolve(page)


def decrypt_account(
    account: Account,
    key_override: str | None = None,
    refresh: bool = False,
    include_messages: bool = True,
    include_session: bool = True,
) -> DecryptedAccount:
    sources: list[tuple[str, Path]] = [("contact", contact_db(account))]
    session = session_db(account)
    if include_session and session:
        sources.append(("session", session))
    if include_messages:
        for path in message_dbs(account):
            sources.append((path.stem, path))

    existing = [(kind, path) for kind, path in sources if path.is_file()]
    if not existing:
        raise KeyNotFound("该账号下没有找到可读取的数据库文件")

    encrypted = [(kind, path) for kind, path in existing if not _is_plain(path)]
    key_map: KeyMap | None = None
    key_error: WeChatMCPError | None = None
    if encrypted:
        try:
            key_map = get_key_map(account, key_override)
        except WeChatMCPError as exc:
            key_error = exc

    cache_dir = _account_cache_dir(account)
    resolved: dict[str, Path] = {}
    notes: list[str] = []
    wal_merged = 0
    keys_used: set[bytes] = set()

    for kind, path in existing:
        if _is_plain(path):
            resolved[kind] = path
            continue
        key = _db_key(key_map, path, account.version) if key_map else None
        if key is None:
            reusable = _find_reusable(cache_dir, path)
            if reusable is not None:
                resolved[kind] = reusable
                notes.append(f"{path.name}: 使用已有解密缓存")
                continue
            if key_error is not None:
                raise key_error
            try:
                with path.open("rb") as handle:
                    salt = handle.read(16).hex()
            except OSError:
                salt = "?"
            raise KeyNotFound(
                f"未找到 {path.name} 的数据库密钥（salt={salt[:16]}）。"
                "如刚启动微信，请稍后重试或提供 key。"
            )
        keys_used.add(key)
        try:
            resolved[kind], merged = _decrypt_one(account, path, key, cache_dir, refresh)
            wal_merged += merged
        except DecryptError:
            reusable = _find_reusable(cache_dir, path)
            if reusable is not None and not refresh:
                resolved[kind] = reusable
                notes.append(f"{path.name}: 密钥失效，使用已有解密缓存")
                continue
            raise

    contact_path = resolved.get("contact")
    if contact_path is None:
        raise KeyNotFound("未能解密 contact.db / MicroMsg.db")
    messages = [
        resolved[path.stem]
        for _, path in existing
        if path.stem in resolved and path.stem not in ("contact", "session")
    ]
    return DecryptedAccount(
        account=account,
        contact=contact_path,
        session=resolved.get("session"),
        messages=messages,
        cache_dir=cache_dir,
        keys_used=len(keys_used),
        key_count=key_map.count if key_map else 0,
        key_sources=sorted(key_map.sources) if key_map else [],
        wal_merged=wal_merged,
        notes=notes,
    )


def clear_cache(account: Account | None = None) -> int:
    root = _account_cache_dir(account) if account else cache_root()
    removed = 0
    if root.is_dir():
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in (".db", ".part"):
                path.unlink()
                removed += 1
    return removed


def key_cached(account: Account) -> bool:
    return account.account_id in _KEY_CACHE or bool(_env_key())


def key_available(account: Account) -> bool:
    if key_cached(account):
        return True
    samples = [path for path in key_sample_dbs(account) if path.is_file()]
    return not any(not _is_plain(path) for path in samples)
