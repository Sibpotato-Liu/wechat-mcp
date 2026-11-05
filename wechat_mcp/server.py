"""MCP stdio server exposing read-only WeChat history tools."""

from __future__ import annotations

import datetime as dt
import logging
import os
import re
import sys
from pathlib import Path

from .cache import (
    cache_root,
    clear_cache,
    decrypt_account,
    key_cached,
)
from .chatlog import ChatReader
from .config import Account, discover_accounts, find_account
from .diagnostics import collect_selfcheck
from .errors import DataNotFound, WeChatMCPError
from .export import export_chat
from .paths import message_dbs
from .winmem import list_processes

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP

    _server = FastMCP(
        "wechat-mcp",
        instructions=(
            "只读访问本机微信 3.x / 4.x 聊天记录。首次读取会自动从正在运行的微信进程"
            "提取数据库密钥并在本地缓存解密副本，不会修改微信原始文件。"
        ),
    )
except ImportError:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer

    _server = MCPServer(
        "wechat-mcp",
        instructions=(
            "只读访问本机微信 3.x / 4.x 聊天记录。首次读取会自动从正在运行的微信进程"
            "提取数据库密钥并在本地缓存解密副本，不会修改微信原始文件。"
        ),
    )

LOG = logging.getLogger("wechat_mcp")


def _roots(data_root: str | None) -> list[str] | None:
    value = data_root or os.environ.get("WECHAT_MCP_DATA_ROOT")
    if not value:
        return None
    return [part.strip() for part in re.split(r"[;|]", value) if part.strip()]


def _success(**payload: object) -> dict:
    return {"ok": True, **payload}


def _failure(exc: Exception) -> dict:
    LOG.warning("tool error: %s", exc)
    return {"ok": False, "error": str(exc) or exc.__class__.__name__}


def _parse_time(value: str | int | None, end_of_day: bool = False) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{13}", text):
        return int(text) // 1000
    if re.fullmatch(r"\d{10}", text):
        return int(text)

    parsed: dt.datetime | None = None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"):
            try:
                parsed = dt.datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        raise WeChatMCPError(
            f"时间格式无法识别：{text}。请使用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS。"
        )
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    if len(text) <= 10:
        if end_of_day:
            parsed = parsed.replace(hour=23, minute=59, second=59)
        else:
            parsed = parsed.replace(hour=0, minute=0, second=0)
    return int(parsed.timestamp())


def _account(selector: str, data_root: str | None) -> Account:
    return find_account(selector, _roots(data_root))


def _reader(
    selector: str,
    data_root: str | None,
    key: str | None,
    refresh: bool,
    include_messages: bool = True,
    include_session: bool = True,
) -> ChatReader:
    account = _account(selector, data_root)
    decrypted = decrypt_account(
        account,
        key_override=key,
        refresh=refresh,
        include_messages=include_messages,
        include_session=include_session,
    )
    return ChatReader(decrypted)


@_server.tool()
def wechat_status(data_root: str | None = None) -> dict:
    """检查微信安装/运行状态、可读取账号以及密钥缓存状态。不会解密数据库。"""
    try:
        roots = _roots(data_root)
        try:
            accounts = discover_accounts(roots)
        except DataNotFound as exc:
            accounts = []
            discovery_error = str(exc)
        else:
            discovery_error = None

        processes = []
        try:
            for process in list_processes(["Weixin.exe", "WeChat.exe"]):
                processes.append({"pid": process.pid, "name": process.name})
        except Exception as exc:
            processes.append({"error": str(exc)})

        account_rows = []
        for account in accounts:
            paths = message_dbs(account)
            encrypted = 0
            total_size = 0
            for path in paths:
                try:
                    total_size += path.stat().st_size
                    with path.open("rb") as handle:
                        if handle.read(16) != b"SQLite format 3\x00":
                            encrypted += 1
                except OSError:
                    continue
            account_rows.append(
                {
                    **account.to_dict(),
                    "message_dbs": len(paths),
                    "encrypted_message_dbs": encrypted,
                    "message_db_bytes": total_size,
                    "key_cached": key_cached(account),
                }
            )

        return _success(
            accounts=account_rows,
            processes=processes,
            cache_dir=str(cache_root()),
            discovery_error=discovery_error,
            platform=sys.platform,
        )
    except Exception as exc:
        return _failure(exc)


@_server.tool()
def wechat_list_accounts(data_root: str | None = None) -> dict:
    """列出本机可读取的微信账号（3.x 与 4.x）。"""
    try:
        accounts = discover_accounts(_roots(data_root))
        return _success(accounts=[account.to_dict() for account in accounts])
    except Exception as exc:
        return _failure(exc)


@_server.tool()
def wechat_selfcheck(
    account: str = "",
    data_root: str | None = None,
    key: str | None = None,
    contact: str = "",
    refresh: bool = False,
) -> dict:
    """诊断客户端版本、密钥来源、数据库结构与兼容性，不返回聊天内容。

    首次接触新版本微信时先调用本工具。可选 contact 只验证读取链路与消息数量，
    不会返回消息正文。输出可安全用于反馈问题（不含密钥）。
    """
    try:
        report = collect_selfcheck(
            account_selector=account,
            data_root=_roots(data_root),
            key=key,
            contact=contact,
            refresh=refresh,
        )
        return _success(**report)
    except Exception as exc:
        return _failure(exc)


@_server.tool()
def wechat_list_contacts(
    account: str,
    query: str = "",
    limit: int = 50,
    data_root: str | None = None,
    key: str | None = None,
) -> dict:
    """按 wxid / 昵称 / 备注 / 微信号搜索联系人。account 可填 wxid 或 4:wxid 形式。"""
    try:
        reader = _reader(
            account,
            data_root,
            key,
            refresh=False,
            include_messages=False,
            include_session=False,
        )
        contacts = reader.contacts(query, limit=max(1, min(int(limit), 500)))
        return _success(
            account=reader.account.to_dict(),
            contacts=contacts,
            count=len(contacts),
        )
    except Exception as exc:
        return _failure(exc)


@_server.tool()
def wechat_list_sessions(
    account: str,
    limit: int = 30,
    data_root: str | None = None,
    key: str | None = None,
) -> dict:
    """列出最近会话（按会话时间倒序）。"""
    try:
        reader = _reader(
            account,
            data_root,
            key,
            refresh=False,
            include_messages=False,
            include_session=True,
        )
        sessions = reader.sessions(limit=max(1, min(int(limit), 200)))
        return _success(account=reader.account.to_dict(), sessions=sessions)
    except Exception as exc:
        return _failure(exc)


@_server.tool()
def wechat_get_messages(
    account: str,
    contact: str,
    start_time: str = "",
    end_time: str = "",
    limit: int = 100,
    offset: int = 0,
    ascending: bool = True,
    data_root: str | None = None,
    key: str | None = None,
    refresh: bool = False,
) -> dict:
    """读取与某个联系人的聊天记录。

    contact 支持 wxid、昵称、备注或微信号；start_time/end_time 支持
    2026-10-01、2026-10-01 12:00:00 或 Unix 时间戳（秒/毫秒）。
    日期形式的 end_time 表示当天结束。
    """
    try:
        start = _parse_time(start_time, end_of_day=False)
        end = _parse_time(end_time, end_of_day=True)
        reader = _reader(account, data_root, key, refresh=refresh)
        contact_record, messages, total = reader.messages(
            contact,
            start_time=start,
            end_time=end,
            limit=max(0, min(int(limit), 2000)),
            offset=max(0, int(offset)),
            ascending=bool(ascending),
        )
        return _success(
            account={**reader.account.to_dict(), "display_name": reader.self_name},
            contact=contact_record.to_dict(),
            total=total,
            offset=max(0, int(offset)),
            count=len(messages),
            messages=[message.to_dict() for message in messages],
        )
    except Exception as exc:
        return _failure(exc)


@_server.tool()
def wechat_export_chat(
    account: str,
    contact: str,
    output_path: str,
    start_time: str = "",
    end_time: str = "",
    data_root: str | None = None,
    key: str | None = None,
    refresh: bool = False,
) -> dict:
    """把聊天记录导出为 UTF-8 BOM 的 txt 文件（默认全量，可用时间范围筛选）。"""
    try:
        start = _parse_time(start_time, end_of_day=False)
        end = _parse_time(end_time, end_of_day=True)
        reader = _reader(account, data_root, key, refresh=refresh)
        contact_record, messages, total = reader.messages(
            contact,
            start_time=start,
            end_time=end,
            limit=0,
            offset=0,
            ascending=True,
        )
        info = export_chat(
            reader.account,
            reader.self_name,
            contact_record,
            messages,
            output_path,
            start_time=start,
            end_time=end,
        )
        return _success(
            account=reader.account.to_dict(),
            contact=contact_record.to_dict(),
            total=total,
            **info,
        )
    except Exception as exc:
        return _failure(exc)


@_server.tool()
def wechat_clear_cache(
    account: str | None = None,
    data_root: str | None = None,
) -> dict:
    """删除 wechat-mcp 生成的解密数据库缓存（不会删除或修改微信原始文件）。"""
    try:
        selected = _account(account, data_root) if account else None
        removed = clear_cache(selected)
        return _success(removed=removed, cache_dir=str(cache_root()))
    except Exception as exc:
        return _failure(exc)


def main() -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=os.environ.get("WECHAT_MCP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _server.run()


if __name__ == "__main__":
    main()
