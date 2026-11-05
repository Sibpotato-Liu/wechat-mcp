"""Read contacts, sessions, and messages from decrypted databases."""

from __future__ import annotations

import hashlib
import html
import re
import sqlite3
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import zstandard

from .cache import DecryptedAccount
from .config import Account
from .errors import ContactAmbiguous, ContactNotFound, WeChatMCPError

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
WXID_RE = re.compile(r"wxid_[0-9A-Za-z]+")
APP_TYPE_NAMES = {
    5: "链接",
    6: "文件",
    17: "位置共享",
    19: "聊天记录",
    33: "小程序",
    36: "小程序",
    51: "视频号",
    57: "分享",
    2000: "转账",
    2001: "红包",
    2003: "音乐",
}
SIMPLE_TYPE_NAMES = {
    3: "图片",
    34: "语音",
    42: "名片",
    43: "视频",
    47: "表情",
    48: "位置",
    50: "通话",
}
SYSTEM_TYPES = {10000, 10002}


@dataclass
class Contact:
    username: str
    alias: str = ""
    remark: str = ""
    nick_name: str = ""

    @property
    def display(self) -> str:
        return self.nick_name or self.remark or self.alias or self.username

    def to_dict(self) -> dict:
        return {
            "wxid": self.username,
            "alias": self.alias or None,
            "remark": self.remark or None,
            "nick_name": self.nick_name or None,
            "display_name": self.display,
        }


@dataclass
class Message:
    local_id: int
    server_id: int
    timestamp: int
    sort_seq: int
    type: int
    subtype: int
    sender: str
    is_self: bool
    content: str
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "local_id": self.local_id,
            "server_id": self.server_id,
            "timestamp": self.timestamp,
            "time": datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "type": self.type,
            "subtype": self.subtype,
            "sender": self.sender,
            "is_self": self.is_self,
            "content": self.content,
        }


def _connect(path: Path) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    return con


@contextmanager
def _db(path: Path):
    con = _connect(path)
    try:
        yield con
    finally:
        con.close()


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _expr(name: str) -> str:
    return name if name in ("0", "''") else _quote(name)


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name)=lower(?)",
        (table,),
    ).fetchone()
    return row is not None


def _actual_table(con: sqlite3.Connection, *candidates: str) -> str | None:
    for candidate in candidates:
        row = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND lower(name)=lower(?)",
            (candidate,),
        ).fetchone()
        if row:
            return row[0]
    return None


def _columns(con: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in con.execute(f"PRAGMA table_info({_quote(table)})")]


def _column(columns: list[str], *candidates: str) -> str | None:
    lowered = {name.lower(): name for name in columns}
    for candidate in candidates:
        found = lowered.get(candidate.lower())
        if found:
            return found
    return None


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        if value[:4] == ZSTD_MAGIC:
            try:
                return zstandard.ZstdDecompressor().decompress(value).decode("utf-8", "replace")
            except Exception:
                pass
        return value.decode("utf-8", "replace")
    return str(value)


def _as_stored_text(value: object, compressed: bool) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        if compressed or value[:4] == ZSTD_MAGIC:
            try:
                return zstandard.ZstdDecompressor().decompress(value).decode("utf-8", "replace")
            except Exception:
                pass
        return value.decode("utf-8", "replace")
    return str(value)


def _xml_text(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text)


def _strip_xml(text: str) -> str:
    return re.sub(r"\s+", " ", _xml_text(text)).strip()


def _app_message(xml_text: str) -> tuple[int | None, str]:
    app_type: int | None = None
    title = ""
    try:
        root = ET.fromstring(xml_text.strip())
        appmsg = root.find(".//appmsg")
        if appmsg is not None:
            node = appmsg.find("type")
            if node is not None and node.text:
                app_type = int(re.sub(r"\D", "", node.text) or 0)
            node = appmsg.find("title")
            if node is not None and node.text:
                title = node.text.strip()
        if not title:
            node = root.find(".//title")
            if node is not None and node.text:
                title = node.text.strip()
    except Exception:
        match = re.search(r"<type>\s*(\d+)\s*</type>", xml_text)
        if match:
            app_type = int(match.group(1))
        match = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", xml_text, re.S)
        if match:
            title = _xml_text(match.group(1)).strip()
    return app_type, title


def render_content(base_type: int, subtype: int, raw: str) -> str:
    if base_type == 1:
        return raw.strip()
    if base_type in SIMPLE_TYPE_NAMES:
        return f"[{SIMPLE_TYPE_NAMES[base_type]}]"
    if base_type == 49:
        app_type, title = _app_message(raw)
        label = APP_TYPE_NAMES.get(app_type or subtype)
        if label is None:
            label = "应用消息"
        return f"[{label}] {title}".strip()
    if base_type in SYSTEM_TYPES:
        text = _strip_xml(raw)
        text = re.sub(r"(撤回了一条消息)\s*\d+$", r"\1", text)
        return text
    text = _strip_xml(raw)
    if text:
        return text
    return f"[类型{base_type}]"


class ChatReader:
    def __init__(self, decrypted: DecryptedAccount):
        self.decrypted = decrypted
        self.account: Account = decrypted.account
        self._contacts: dict[str, Contact] | None = None
        self.self_contact = self._load_self_contact()

    @property
    def self_name(self) -> str:
        if self.self_contact:
            return self.self_contact.alias or self.self_contact.nick_name or self.account.wxid
        return self.account.wxid

    def _load_self_contact(self) -> Contact | None:
        try:
            contacts = self._load_contacts()
        except WeChatMCPError:
            return None
        return contacts.get(self.account.wxid)

    def _contact_table(self, con: sqlite3.Connection) -> str | None:
        return _actual_table(con, "contact", "Contact")

    def _load_contacts(self) -> dict[str, Contact]:
        if self._contacts is not None:
            return self._contacts
        result: dict[str, Contact] = {}
        with _db(self.decrypted.contact) as con:
            table = self._contact_table(con)
            if not table:
                self._contacts = result
                return result
            cols = _columns(con, table)
            username_col = _column(cols, "username", "UserName", "user_name")
            alias_col = _column(cols, "alias", "Alias")
            remark_col = _column(cols, "remark", "Remark")
            nick_col = _column(cols, "nick_name", "NickName", "nickname", "nickName")
            delete_col = _column(cols, "delete_flag", "DeleteFlag", "is_delete")
            if not username_col:
                self._contacts = result
                return result
            select = [username_col, alias_col or "''", remark_col or "''", nick_col or "''"]
            if delete_col:
                select.append(delete_col)
            query = f"SELECT {', '.join(_expr(col) for col in select)} FROM {_quote(table)}"
            for row in con.execute(query):
                if delete_col and row[4]:
                    continue
                username = _as_text(row[0])
                if not username:
                    continue
                result[username] = Contact(
                    username=username,
                    alias=_as_text(row[1]),
                    remark=_as_text(row[2]),
                    nick_name=_as_text(row[3]),
                )
        self._contacts = result
        return result

    def contacts(self, query: str = "", limit: int = 50) -> list[dict]:
        contacts = self._load_contacts()
        needle = query.strip().lower()
        matches: list[Contact] = []
        for contact in contacts.values():
            if not needle:
                matches.append(contact)
                continue
            haystack = " ".join(
                [contact.username, contact.alias, contact.remark, contact.nick_name]
            ).lower()
            if needle in haystack:
                matches.append(contact)
        matches.sort(key=lambda item: item.display)
        return [contact.to_dict() for contact in matches[: max(1, limit)]]

    def contact_count(self) -> int:
        return len(self._load_contacts())

    def message_stats(self, contact_query: str) -> dict:
        """Count messages and time bounds without loading message content."""
        contact = self.resolve_contact(contact_query)
        total = 0
        first: int | None = None
        last: int | None = None
        for path in self.decrypted.messages:
            try:
                con = _connect(path)
            except sqlite3.Error:
                continue
            try:
                if self.account.version == 4:
                    table = next(
                        (
                            name
                            for name in self._message_tables(contact.username)
                            if _table_exists(con, name)
                        ),
                        None,
                    )
                    if not table:
                        continue
                    cols = _columns(con, table)
                    time_col = _column(
                        cols, "create_time", "createTime", "timestamp", "CreateTime"
                    )
                    where = ""
                    params: list[object] = []
                else:
                    table = _actual_table(con, "MSG")
                    if not table:
                        continue
                    cols = _columns(con, table)
                    talker_col = _column(cols, "StrTalker", "str_talker")
                    time_col = _column(cols, "CreateTime", "create_time")
                    if not talker_col:
                        continue
                    where = f" WHERE {_quote(talker_col)} = ?"
                    params = [contact.username]
                if time_col:
                    sql = (
                        f"SELECT COUNT(*), MIN({_quote(time_col)}), MAX({_quote(time_col)}) "
                        f"FROM {_quote(table)}{where}"
                    )
                else:
                    sql = f"SELECT COUNT(*), NULL, NULL FROM {_quote(table)}{where}"
                row = con.execute(sql, params).fetchone()
                if row:
                    total += int(row[0] or 0)
                    if row[1] is not None:
                        first = int(row[1]) if first is None else min(first, int(row[1]))
                    if row[2] is not None:
                        last = int(row[2]) if last is None else max(last, int(row[2]))
            finally:
                con.close()
        return {
            "contact": contact.to_dict(),
            "total": total,
            "first_timestamp": first,
            "last_timestamp": last,
        }

    def _message_tables(self, username: str) -> list[str]:
        names: list[str] = []
        for value in (username, username.lower()):
            table = "Msg_" + hashlib.md5(value.encode("utf-8")).hexdigest()
            if table not in names:
                names.append(table)
        return names


    def resolve_contact(self, query: str) -> Contact:
        query = query.strip()
        if not query:
            raise ContactNotFound("联系人不能为空")
        contacts = self._load_contacts()

        exact = contacts.get(query)
        if exact:
            return exact

        lowered = query.lower()
        tiers: list[list[Contact]] = [[], [], [], []]
        for contact in contacts.values():
            if contact.alias.lower() == lowered:
                tiers[0].append(contact)
            elif contact.nick_name.lower() == lowered:
                tiers[1].append(contact)
            elif contact.remark.lower() == lowered:
                tiers[2].append(contact)
            elif lowered in (contact.username, contact.alias, contact.nick_name, contact.remark) or (
                lowered in " ".join(
                    [contact.username, contact.alias, contact.remark, contact.nick_name]
                ).lower()
            ):
                tiers[3].append(contact)

        for tier in tiers:
            unique = {contact.username: contact for contact in tier}
            if len(unique) == 1:
                return next(iter(unique.values()))
            if len(unique) > 1:
                names = ", ".join(
                    f"{item.display}({item.username})" for item in list(unique.values())[:10]
                )
                raise ContactAmbiguous(f"联系人 '{query}' 匹配到多个结果：{names}")
        raise ContactNotFound(f"未找到联系人 '{query}'")

    def sessions(self, limit: int = 30) -> list[dict]:
        if self.account.version == 4 and self.decrypted.session:
            return self._sessions4(self.decrypted.session, limit)
        return self._sessions3(limit)

    def _sessions4(self, path: Path, limit: int) -> list[dict]:
        with _db(path) as con:
            table = _actual_table(con, "SessionTable", "session", "Session")
            if not table:
                return []
            cols = _columns(con, table)
            username_col = _column(cols, "username", "user_name", "wxid")
            summary_col = _column(cols, "summary", "digest")
            time_col = _column(
                cols, "sort_timestamp", "last_timestamp", "create_time", "timestamp"
            )
            unread_col = _column(cols, "unread_count")
            if not username_col:
                return []
            select = [username_col, summary_col or "''", time_col or "0", unread_col or "0"]
            rows = con.execute(
                f"SELECT {', '.join(_expr(col) for col in select)} "
                f"FROM {_quote(table)} ORDER BY {_quote(time_col or username_col)} DESC LIMIT ?",
                (max(1, limit),),
            ).fetchall()
        contacts = self._load_contacts()
        result = []
        for row in rows:
            username = _as_text(row[0])
            contact = contacts.get(username)
            result.append(
                {
                    "wxid": username,
                    "display_name": contact.display if contact else username,
                    "summary": _as_text(row[1]),
                    "timestamp": int(row[2] or 0),
                    "unread": int(row[3] or 0),
                }
            )
        return result

    def _sessions3(self, limit: int) -> list[dict]:
        with _db(self.decrypted.contact) as con:
            table = _actual_table(con, "Session", "session")
            if not table:
                return []
            cols = _columns(con, table)
            user_col = _column(cols, "strUsrName", "username", "UserName")
            content_col = _column(cols, "strContent", "summary", "digest")
            time_col = _column(cols, "nTime", "last_timestamp", "sort_timestamp")
            unread_col = _column(cols, "nUnreadCount", "unread_count")
            if not user_col:
                return []
            select = [user_col, content_col or "''", time_col or "0", unread_col or "0"]
            rows = con.execute(
                f"SELECT {', '.join(_expr(col) for col in select)} "
                f"FROM {_quote(table)} ORDER BY {_quote(time_col or user_col)} DESC LIMIT ?",
                (max(1, limit),),
            ).fetchall()
        contacts = self._load_contacts()
        result = []
        for row in rows:
            username = _as_text(row[0])
            contact = contacts.get(username)
            result.append(
                {
                    "wxid": username,
                    "display_name": contact.display if contact else username,
                    "summary": _as_text(row[1]),
                    "timestamp": int(row[2] or 0),
                    "unread": int(row[3] or 0),
                }
            )
        return result

    def messages(
        self,
        contact_query: str,
        start_time: int | None = None,
        end_time: int | None = None,
        limit: int = 100,
        offset: int = 0,
        ascending: bool = True,
    ) -> tuple[Contact, list[Message], int]:
        contact = self.resolve_contact(contact_query)
        if self.account.version == 4:
            messages = self._messages4(contact, start_time, end_time)
        else:
            messages = self._messages3(contact, start_time, end_time)
        messages.sort(key=lambda item: (item.timestamp, item.sort_seq, item.local_id))
        total = len(messages)
        if not ascending:
            messages.reverse()
        if offset:
            messages = messages[offset:]
        if limit:
            messages = messages[:limit]
        return contact, messages, total

    def _messages4(
        self, contact: Contact, start_time: int | None, end_time: int | None
    ) -> list[Message]:
        result: dict[tuple, Message] = {}
        for path in self.decrypted.messages:
            try:
                con = _connect(path)
            except sqlite3.Error:
                continue
            try:
                table = next(
                    (
                        name
                        for name in self._message_tables(contact.username)
                        if _table_exists(con, name)
                    ),
                    None,
                )
                if not table:
                    continue
                sender_map = self._name2id(con)
                cols = _columns(con, table)
                local_id_col = _column(cols, "local_id", "localId", "id") or "0"
                server_id_col = _column(cols, "server_id", "MsgSvrID") or "0"
                type_col = _column(cols, "local_type", "msg_type", "type") or "0"
                sort_col = _column(
                    cols, "sort_seq", "sequence", "Sequence", "sort_sequence"
                ) or "0"
                sender_col = _column(cols, "real_sender_id", "sender_id") or "0"
                time_col = _column(
                    cols, "create_time", "createTime", "timestamp", "CreateTime"
                ) or "0"
                content_col = _column(
                    cols, "message_content", "content", "StrContent"
                ) or "''"
                compress_col = _column(
                    cols, "compress_content", "CompressContent"
                ) or "''"
                content_ct_col = _column(
                    cols, "WCDB_CT_message_content", "ct_message_content"
                )
                compress_ct_col = _column(
                    cols, "WCDB_CT_compress_content", "ct_compress_content"
                )

                select = [
                    local_id_col,
                    server_id_col,
                    type_col,
                    sort_col,
                    sender_col,
                    time_col,
                    content_col,
                    compress_col,
                    content_ct_col or "0",
                    compress_ct_col or "0",
                ]
                self_ids = {
                    sender for sender, username in sender_map.items()
                    if username == self.account.wxid
                }
                where = []
                params: list[object] = []
                if time_col != "0":
                    if start_time is not None:
                        where.append(f"{_quote(time_col)} >= ?")
                        params.append(start_time)
                    if end_time is not None:
                        where.append(f"{_quote(time_col)} <= ?")
                        params.append(end_time)
                sql = f"SELECT {', '.join(_expr(col) for col in select)} FROM {_quote(table)}"
                if where:
                    sql += " WHERE " + " AND ".join(where)
                for row in con.execute(sql, params):
                    local_id = int(row[0] or 0)
                    server_id = int(row[1] or 0)
                    local_type = int(row[2] or 0)
                    sort_seq = int(row[3] or 0)
                    sender_id = int(row[4] or 0)
                    timestamp = int(row[5] or 0)
                    content = _as_stored_text(row[6], int(row[8] or 0) == 4)
                    if not content:
                        content = _as_stored_text(row[7], int(row[9] or 0) == 4)
                    base_type = local_type & 0xFFFFFFFF
                    subtype = local_type >> 32
                    sender_username = sender_map.get(sender_id, "")
                    if base_type in SYSTEM_TYPES:
                        sender_name = "系统消息"
                        is_self = False
                    else:
                        is_self = (
                            sender_username == self.account.wxid
                            or sender_id in self_ids
                        )
                        sender_name = self._sender_name(
                            sender_username, is_self, contact.display
                        )
                    rendered = render_content(base_type, subtype or 0, content)
                    key = (
                        (server_id, timestamp, local_type)
                        if server_id
                        else (path.name, local_id, timestamp, local_type)
                    )
                    result.setdefault(
                        key,
                        Message(
                            local_id=local_id,
                            server_id=server_id,
                            timestamp=timestamp,
                            sort_seq=sort_seq,
                            type=base_type,
                            subtype=subtype,
                            sender=sender_name,
                            is_self=is_self,
                            content=rendered,
                            raw=content,
                        ),
                    )
            finally:
                con.close()
        return list(result.values())

    def _name2id(self, con: sqlite3.Connection) -> dict[int, str]:
        table = _actual_table(con, "Name2Id", "name2id")
        if not table:
            return {}
        cols = _columns(con, table)
        user_col = _column(cols, "user_name", "username", "name")
        if not user_col:
            return {}
        try:
            return {
                int(row[0]): _as_text(row[1])
                for row in con.execute(
                    f"SELECT rowid, {_quote(user_col)} FROM {_quote(table)}"
                )
            }
        except sqlite3.Error:
            return {}

    def _sender_name(self, username: str, is_self: bool, fallback: str) -> str:
        if is_self:
            return self.self_name
        if username:
            contact = self._load_contacts().get(username)
            if contact:
                return contact.display
            return username
        return fallback

    def _messages3(
        self, contact: Contact, start_time: int | None, end_time: int | None
    ) -> list[Message]:
        result: dict[tuple, Message] = {}
        for path in self.decrypted.messages:
            try:
                con = _connect(path)
            except sqlite3.Error:
                continue
            try:
                table = _actual_table(con, "MSG")
                if not table:
                    continue
                cols = _columns(con, table)
                local_col = _column(cols, "localId", "local_id", "id")
                server_col = _column(cols, "MsgSvrID", "server_id")
                type_col = _column(cols, "Type", "type")
                subtype_col = _column(cols, "SubType", "subtype")
                self_col = _column(cols, "IsSender", "is_sender")
                time_col = _column(cols, "CreateTime", "create_time")
                seq_col = _column(cols, "Sequence", "MsgSequence", "sort_seq")
                talker_col = _column(cols, "StrTalker", "str_talker")
                content_col = _column(cols, "StrContent", "message_content", "content")
                compress_col = _column(
                    cols, "CompressContent", "compress_content"
                )
                if not talker_col or not time_col:
                    continue
                select = [
                    local_col or "0",
                    server_col or "0",
                    type_col or "0",
                    subtype_col or "0",
                    self_col or "0",
                    time_col,
                    seq_col or "0",
                    content_col or "''",
                    compress_col or "''",
                ]
                where = [f"{_quote(talker_col)} = ?"]
                params: list[object] = [contact.username]
                if start_time is not None:
                    where.append(f"{_quote(time_col)} >= ?")
                    params.append(start_time)
                if end_time is not None:
                    where.append(f"{_quote(time_col)} <= ?")
                    params.append(end_time)
                sql = (
                    f"SELECT {', '.join(_expr(col) for col in select)} "
                    f"FROM {_quote(table)} WHERE " + " AND ".join(where)
                )
                for row in con.execute(sql, params):
                    local_id = int(row[0] or 0)
                    server_id = int(row[1] or 0)
                    base_type = int(row[2] or 0)
                    subtype = int(row[3] or 0)
                    is_self = bool(row[4])
                    timestamp = int(row[5] or 0)
                    sort_seq = int(row[6] or 0)
                    content = _as_stored_text(row[7], False)
                    if not content:
                        content = _as_stored_text(row[8], True)
                    if base_type in SYSTEM_TYPES:
                        sender_name = "系统消息"
                        is_self = False
                    else:
                        sender_name = self.self_name if is_self else contact.display
                    rendered = render_content(base_type, subtype, content)
                    key = (
                        (server_id, timestamp, base_type)
                        if server_id
                        else (path.name, local_id, timestamp, base_type)
                    )
                    result.setdefault(
                        key,
                        Message(
                            local_id=local_id,
                            server_id=server_id,
                            timestamp=timestamp,
                            sort_seq=sort_seq,
                            type=base_type,
                            subtype=subtype,
                            sender=sender_name,
                            is_self=is_self,
                            content=rendered,
                            raw=content,
                        ),
                    )
            finally:
                con.close()
        return list(result.values())
