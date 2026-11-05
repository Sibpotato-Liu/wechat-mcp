"""Plain-text chat export with the same layout as the original script."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from .chatlog import Contact, Message
from .config import Account
from .errors import WeChatMCPError


def _format_ts(timestamp: int) -> str:
    return dt.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def _one_line(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.strip() for line in normalized.split("\n")]
    return " / ".join(line for line in lines if line)


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def export_chat(
    account: Account,
    self_name: str,
    contact: Contact,
    messages: list[Message],
    output_path: str,
    start_time: int | None = None,
    end_time: int | None = None,
) -> dict:
    target = Path(output_path).expanduser()
    if _inside(target, account.directory):
        raise WeChatMCPError("不能把导出文件写入微信数据目录，请选择其他位置。")
    if not target.parent.is_dir():
        raise WeChatMCPError(f"输出目录不存在：{target.parent}")

    first = _format_ts(messages[0].timestamp) if messages else None
    last = _format_ts(messages[-1].timestamp) if messages else None

    if start_time is not None and end_time is not None:
        condition = f"{_format_ts(start_time)} 至 {_format_ts(end_time)}"
    elif start_time is not None:
        condition = f"{_format_ts(start_time)} 及之后"
    elif end_time is not None:
        condition = f"{_format_ts(end_time)} 及之前"
    else:
        condition = "全部"

    alias = f"{contact.alias}；" if contact.alias else ""
    header = [
        "微信聊天记录导出",
        f"账号：{self_name}（{account.wxid}）",
        f"联系人：{contact.display}（{alias}{contact.username}）",
        f"消息数量：{len(messages)}",
        f"时间范围：{first or '无'} 至 {last or '无'}",
        f"筛选条件：{condition}",
        f"导出时间：{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    temp = target.with_name(target.name + ".part")
    with temp.open("w", encoding="utf-8-sig", newline="\r\n") as handle:
        for line in header:
            handle.write(line + "\n")
        for message in messages:
            content = _one_line(message.content)
            handle.write(f"[{_format_ts(message.timestamp)}] {message.sender}：{content}\n")
    temp.replace(target)

    return {
        "path": str(target),
        "messages": len(messages),
        "first": first,
        "last": last,
        "bytes": target.stat().st_size,
    }
