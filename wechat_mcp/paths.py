"""Database file layout for WeChat 3.x and 4.x accounts."""

from __future__ import annotations

import re
from pathlib import Path

from .config import Account

MESSAGE_DB_RE = re.compile(r"^(?:message|MSG|BizChatMsg)(\d*)\.db$", re.IGNORECASE)


def contact_db(account: Account) -> Path:
    if account.version == 4 and account.db_storage:
        return account.db_storage / "contact" / "contact.db"
    assert account.msg_dir is not None
    return account.msg_dir / "MicroMsg.db"


def session_db(account: Account) -> Path | None:
    if account.version == 4 and account.db_storage:
        path = account.db_storage / "session" / "session.db"
        return path if path.is_file() else None
    return None


def message_dbs(account: Account) -> list[Path]:
    if account.version == 4 and account.db_storage:
        folder = account.db_storage / "message"
        if not folder.is_dir():
            return []
        return sorted(
            (path for path in folder.iterdir() if re.fullmatch(r"message_\d+\.db", path.name)),
            key=lambda path: path.name,
        )

    assert account.msg_dir is not None
    paths: list[Path] = []
    multi = account.msg_dir / "Multi"
    if multi.is_dir():
        paths.extend(
            path
            for path in multi.iterdir()
            if re.fullmatch(r"MSG\d+\.db", path.name, re.IGNORECASE)
        )
    paths.extend(
        path
        for path in account.msg_dir.iterdir()
        if re.fullmatch(r"MSG\d*\.db", path.name, re.IGNORECASE)
    )
    return sorted(set(paths), key=lambda path: path.name)


def key_sample_dbs(account: Account) -> list[Path]:
    paths: list[Path] = []
    contact = contact_db(account)
    if contact.is_file():
        paths.append(contact)
    session = session_db(account)
    if session:
        paths.append(session)
    paths.extend(message_dbs(account)[:1])
    return paths
