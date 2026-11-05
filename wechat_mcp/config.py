"""Locate WeChat data roots and accounts for both 3.x and 4.x."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .errors import DataNotFound

WXID_RE = re.compile(r"^(wxid_[0-9A-Za-z]+)(?:_[0-9a-f]{4})?$")


def _expand(value: str) -> str:
    value = value.strip().strip('"').strip("'")
    return os.path.expandvars(os.path.expanduser(value))


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "gb18030", "utf-16"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        text = text.replace("\x00", "").strip()
        if text:
            return text
    return ""


def _registry_values() -> dict[str, dict[str, str]]:
    if sys.platform != "win32":
        return {}
    try:
        import winreg
    except ImportError:
        return {}

    result: dict[str, dict[str, str]] = {}
    for key_name in (r"Software\Tencent\WeChat", r"Software\Tencent\Weixin"):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_name)
        except OSError:
            continue
        values: dict[str, str] = {}
        try:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                if isinstance(value, str):
                    values[name] = value
                index += 1
        finally:
            key.Close()
        result[key_name.rsplit("\\", 1)[-1]] = values
    return result


def _config_files() -> list[Path]:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return []
    files: list[Path] = []
    for sub in ("Tencent\\xwechat\\config", "Tencent\\WeChat\\All Users\\config"):
        folder = Path(appdata) / sub
        if folder.is_dir():
            files.extend(p for p in folder.iterdir() if p.is_file() and p.suffix.lower() == ".ini")
    return files


def candidate_roots_4x(explicit: list[str] | None = None) -> list[Path]:
    roots: list[Path] = []
    if explicit:
        roots.extend(Path(_expand(item)) for item in explicit)

    for ini in _config_files():
        if "xwechat" not in str(ini).lower():
            continue
        value = _read_text(ini)
        if not value or not os.path.isabs(value):
            continue
        base = Path(value)
        roots.append(base if base.name.lower() == "xwechat_files" else base / "xwechat_files")

    home = Path.home()
    roots.extend(
        [
            home / "Documents" / "xwechat_files",
            home / "xwechat_files",
        ]
    )

    seen: set[str] = set()
    unique: list[Path] = []
    for root in roots:
        key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def candidate_roots_3x(explicit: list[str] | None = None) -> list[Path]:
    roots: list[Path] = []
    if explicit:
        roots.extend(Path(_expand(item)) for item in explicit)

    registry = _registry_values()
    for values in registry.values():
        for name in ("FileSavePath", "OldFileSavePath"):
            value = values.get(name)
            if value:
                roots.append(Path(_expand(value)))

    for ini in _config_files():
        if "xwechat" in str(ini).lower():
            continue
        value = _read_text(ini)
        if value and os.path.isabs(value):
            roots.append(Path(value))

    home = Path.home()
    roots.extend(
        [
            home / "Documents" / "WeChat Files",
            home / "WeChat Files",
        ]
    )

    seen: set[str] = set()
    unique: list[Path] = []
    for root in roots:
        key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


@dataclass
class Account:
    version: int
    wxid: str
    directory: Path
    display_name: str | None = None
    db_storage: Path | None = None
    msg_dir: Path | None = None
    extra: dict = field(default_factory=dict)

    @property
    def account_id(self) -> str:
        return f"{self.version}:{self.wxid}"

    @property
    def label(self) -> str:
        return self.display_name or self.wxid

    def to_dict(self) -> dict:
        result = {
            "account_id": self.account_id,
            "version": self.version,
            "wxid": self.wxid,
            "display_name": self.display_name,
            "directory": str(self.directory),
        }
        if self.db_storage:
            result["db_storage"] = str(self.db_storage)
        if self.msg_dir:
            result["msg_dir"] = str(self.msg_dir)
        return result


def _wxid_from_dir(name: str) -> str | None:
    match = WXID_RE.match(name)
    if match:
        return match.group(1)
    if name.startswith("wxid_"):
        return name
    return None


def _scan_4x(root: Path) -> list[Account]:
    accounts: list[Account] = []
    if not root.is_dir():
        return accounts
    candidates = [root] if (root / "db_storage").is_dir() else list(root.iterdir())
    for directory in candidates:
        if not directory.is_dir():
            continue
        db_storage = directory / "db_storage"
        if not db_storage.is_dir():
            continue
        wxid = _wxid_from_dir(directory.name)
        if not wxid:
            continue
        accounts.append(
            Account(
                version=4,
                wxid=wxid,
                directory=directory,
                db_storage=db_storage,
            )
        )
    return accounts


def _scan_3x(root: Path) -> list[Account]:
    accounts: list[Account] = []
    if not root.is_dir():
        return accounts
    candidates = [root] if (root / "Msg" / "MicroMsg.db").is_file() else list(root.iterdir())
    for directory in candidates:
        if not directory.is_dir():
            continue
        msg_dir = directory / "Msg"
        if not (msg_dir / "MicroMsg.db").is_file():
            continue
        wxid = _wxid_from_dir(directory.name)
        if not wxid:
            continue
        accounts.append(
            Account(
                version=3,
                wxid=wxid,
                directory=directory,
                msg_dir=msg_dir,
            )
        )
    return accounts


def discover_accounts(explicit_roots: list[str] | None = None) -> list[Account]:
    accounts: dict[tuple[int, str], Account] = {}
    for root in candidate_roots_4x(explicit_roots):
        for account in _scan_4x(root):
            accounts.setdefault((4, account.wxid), account)
    for root in candidate_roots_3x(explicit_roots):
        for account in _scan_3x(root):
            accounts.setdefault((3, account.wxid), account)
    if not accounts:
        raise DataNotFound(
            "未找到微信数据目录。请确认微信已登录过，或通过 data_root 参数指定 "
            "xwechat_files / WeChat Files 目录。"
        )
    return sorted(accounts.values(), key=lambda item: (item.version, item.wxid))


def find_account(selector: str, explicit_roots: list[str] | None = None) -> Account:
    selector = selector.strip()
    accounts = discover_accounts(explicit_roots)
    for account in accounts:
        if selector in (
            account.account_id,
            account.wxid,
            account.display_name,
            account.label,
            account.directory.name,
        ):
            return account
    matches = [
        account
        for account in accounts
        if selector.lower() in account.wxid.lower()
        or (account.display_name and selector in account.display_name)
        or selector.lower() in account.directory.name.lower()
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise DataNotFound(f"未找到账号 '{selector}'。可用账号：{', '.join(a.account_id for a in accounts)}")
    raise DataNotFound(
        f"账号 '{selector}' 不唯一，匹配到：{', '.join(a.account_id for a in matches)}"
    )
