"""Version support levels and database-schema compatibility checks."""

from __future__ import annotations

import re

SUPPORTED = "supported"
DEGRADED = "degraded"
UNSUPPORTED = "unsupported"
UNKNOWN = "unknown"

TESTED_CLIENTS = {
    4: ("4.1.15.13",),
    3: (),
}

STATUS_NOTES = {
    "tested": "该版本已用真实账号完成端到端验证",
    "expected": "与已验证版本同一 minor，预期兼容，建议用 selfcheck 确认",
    "untested": "该版本尚未实机验证，请先运行 selfcheck",
    "synthetic-only": "3.x 仅通过合成数据库和模拟内存验证，尚未实机验证",
    "unknown": "未检测到客户端版本，只能按数据库结构判断",
}

_VERSION_RE = re.compile(r"\d+")


def parse_client_version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    parts = [int(item) for item in _VERSION_RE.findall(value)]
    return tuple(parts) if parts else None


def version_support(major: int, client_version: str | None) -> dict:
    parsed = parse_client_version(client_version)
    if major == 3:
        level = "synthetic-only"
    elif major == 4 and parsed:
        tested = [
            parse_client_version(item) for item in TESTED_CLIENTS[4]
        ]
        tested = [item for item in tested if item]
        if parsed in tested:
            level = "tested"
        elif any(parsed[:3] == item[:3] for item in tested):
            level = "expected"
        else:
            level = "untested"
    else:
        level = "unknown"
    return {
        "level": level,
        "client": client_version,
        "parsed": ".".join(str(item) for item in parsed) if parsed else None,
        "tested_clients": list(TESTED_CLIENTS.get(major, ())),
        "note": STATUS_NOTES[level],
    }


def _present(columns: list[str], names: tuple[str, ...]) -> bool:
    lowered = {name.lower() for name in columns}
    return any(name.lower() in lowered for name in names)


def _check(
    key: str,
    columns: list[str],
    alternatives: tuple[str, ...],
    missing: list[str],
    label: str,
) -> None:
    if not columns or not _present(columns, alternatives):
        missing.append(f"{key}（{label}）")


def assess(
    account_version: int,
    schema: dict | None,
    client_version: str | None = None,
) -> dict:
    version = version_support(account_version, client_version)
    warnings: list[str] = []
    core_missing: list[str] = []
    degraded: list[str] = []

    if schema is None:
        return {
            "status": UNKNOWN,
            "core_missing": [],
            "degraded": [],
            "warnings": ["未读取到数据库结构，无法判断兼容性"],
            "version": version,
        }

    contact = schema.get("contact") or {}
    messages = schema.get("messages") or {}
    session = schema.get("session") or {}

    _check(
        "contact.username",
        contact.get("columns") or [],
        ("username", "UserName"),
        core_missing,
        "联系人唯一标识",
    )

    message_columns = messages.get("columns") or []
    has_tables = messages.get("tables", 0) > 0
    if not has_tables:
        if messages.get("files", 0) > 0:
            core_missing.append(
                "message.Msg_*（消息分片表）"
                if account_version == 4
                else "MSG（消息表）"
            )
        else:
            degraded.append("未发现消息数据库，账号可能还没有聊天记录")

    if account_version == 4:
        if has_tables:
            _check(
                "message.time",
                message_columns,
                ("create_time", "CreateTime", "timestamp", "createtime"),
                core_missing,
                "消息时间",
            )
            _check(
                "message.content",
                message_columns,
                (
                    "message_content",
                    "compress_content",
                    "content",
                    "StrContent",
                    "CompressContent",
                ),
                core_missing,
                "消息内容",
            )
            _check(
                "message.type",
                message_columns,
                ("local_type", "type", "msg_type"),
                core_missing,
                "消息类型",
            )
            if not _present(
                message_columns, ("local_id", "server_id", "MsgSvrID")
            ):
                core_missing.append("message.local_id/server_id（消息标识）")
            if not _present(
                message_columns,
                ("real_sender_id", "sender_id", "sender", "IsSender"),
            ):
                degraded.append("缺少发送者字段，发送者名称可能只能按单聊方向推断")
            name2id = messages.get("name2id") or {}
            if not _present(
                name2id.get("columns") or [], ("user_name", "username")
            ):
                degraded.append(
                    "缺少 Name2Id.user_name，群聊发送者与本人识别可能不准确"
                )
            if not _present(message_columns, ("server_id", "MsgSvrID")):
                warnings.append("缺少 server_id，跨分片去重只能使用 local_id")
        if not session.get("columns"):
            degraded.append("缺少可读的 session.db，最近会话列表不可用")
    else:
        if has_tables:
            _check(
                "message.talker",
                message_columns,
                ("StrTalker",),
                core_missing,
                "会话对象",
            )
            _check(
                "message.time",
                message_columns,
                ("CreateTime",),
                core_missing,
                "消息时间",
            )
            _check(
                "message.content",
                message_columns,
                ("StrContent", "CompressContent"),
                core_missing,
                "消息内容",
            )
            _check(
                "message.sender",
                message_columns,
                ("IsSender", "BytesExtra"),
                degraded,
                "发送者方向",
            )
            if not _present(message_columns, ("BytesExtra",)):
                warnings.append("缺少 BytesExtra，群聊具体发送者可能无法区分")
        if not session.get("columns"):
            degraded.append("缺少可读的 Session 表，最近会话列表不可用")

    if core_missing:
        status = UNSUPPORTED
    elif degraded:
        status = DEGRADED
    else:
        status = SUPPORTED

    if version["level"] in ("untested", "unknown", "synthetic-only"):
        warnings.append(version["note"])

    return {
        "status": status,
        "core_missing": core_missing,
        "degraded": degraded,
        "warnings": warnings,
        "version": version,
    }
