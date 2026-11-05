"""Read-only diagnostics used to validate a WeChat installation and schema.

The report intentionally contains no chat content and no key material.  It is
safe to run on a remote test machine and paste into an issue.
"""

from __future__ import annotations

import re
import sqlite3
import sys
from datetime import datetime
from importlib import metadata
from pathlib import Path

from . import compat
from .cache import cache_root, decrypt_account
from .chatlog import ChatReader, _actual_table, _columns, _connect, _db, _quote
from .config import Account, discover_accounts, find_account
from .errors import WeChatMCPError
from .winmem import file_version, list_processes, process_image_path


def package_version() -> str | None:
    try:
        return metadata.version("wechat-mcp")
    except metadata.PackageNotFoundError:
        return None


def client_processes(include: bool = True) -> tuple[list[dict], str | None]:
    if not include:
        return [], None
    try:
        processes = list_processes(["Weixin.exe", "WeChat.exe"])
    except Exception as exc:  # platform, permissions, or WMI failures
        return [], str(exc)
    rows: list[dict] = []
    for process in processes:
        row: dict = {"pid": process.pid, "name": process.name}
        try:
            path = process_image_path(process.pid)
        except Exception:
            path = None
        row["exe_path"] = path
        try:
            row["version"] = file_version(path)
        except Exception:
            row["version"] = None
        rows.append(row)
    return rows, None


def _pick_client_version(rows: list[dict], account_version: int) -> str | None:
    expected = "weixin.exe" if account_version == 4 else "wechat.exe"
    for row in rows:
        if str(row.get("name", "")).lower() == expected and row.get("version"):
            return str(row["version"])
    for row in rows:
        version = row.get("version")
        if version and str(version).split(".", 1)[0] == str(account_version):
            return str(version)
    return None


def _table_summary(con: sqlite3.Connection, table: str | None) -> dict:
    if not table:
        return {"table": None, "columns": [], "rows": None}
    try:
        rows = int(con.execute(f"SELECT COUNT(*) FROM {_quote(table)}").fetchone()[0])
    except sqlite3.Error:
        rows = None
    return {"table": table, "columns": _columns(con, table), "rows": rows}


def _message_schema(decrypted) -> dict:
    shards = 0
    tables = 0
    rows = 0
    sample_table: str | None = None
    sample_columns: list[str] = []
    name2id: dict | None = None
    warnings: list[str] = []

    for path in decrypted.messages:
        try:
            con = _connect(path)
        except sqlite3.Error as exc:
            warnings.append(f"{path.name}: {exc}")
            continue
        try:
            names = [
                row[0]
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            ]
            if decrypted.account.version == 4:
                message_tables = sorted(
                    name for name in names if name.lower().startswith("msg_")
                )
            else:
                message_tables = [
                    name for name in names if name.lower() == "msg"
                ]
            if not message_tables:
                continue
            shards += 1
            tables += len(message_tables)
            for table in message_tables:
                try:
                    rows += int(
                        con.execute(
                            f"SELECT COUNT(*) FROM {_quote(table)}"
                        ).fetchone()[0]
                    )
                except sqlite3.Error:
                    pass
            if sample_table is None:
                sample_table = message_tables[0]
                sample_columns = _columns(con, sample_table)
            if decrypted.account.version == 4 and name2id is None:
                id_table = _actual_table(con, "Name2Id", "name2id")
                if id_table:
                    name2id = _table_summary(con, id_table)
        finally:
            con.close()

    result = {
        "files": len(decrypted.messages),
        "shards": shards,
        "tables": tables,
        "rows": rows,
        "sample_table": sample_table,
        "columns": sample_columns,
        "name2id": name2id,
        "warnings": warnings,
    }
    return result


def schema_report(decrypted) -> dict:
    warnings: list[str] = []
    with _db(decrypted.contact) as con:
        contact = _table_summary(con, _actual_table(con, "contact", "Contact"))
    session = {"table": None, "columns": [], "rows": None}
    if decrypted.session:
        try:
            with _db(decrypted.session) as con:
                session = _table_summary(
                    con, _actual_table(con, "SessionTable", "session", "Session")
                )
        except sqlite3.Error as exc:
            warnings.append(f"session: {exc}")
    elif decrypted.account.version == 3:
        try:
            with _db(decrypted.contact) as con:
                session = _table_summary(
                    con, _actual_table(con, "Session", "session")
                )
        except sqlite3.Error as exc:
            warnings.append(f"session: {exc}")
    messages = _message_schema(decrypted)
    warnings.extend(messages.pop("warnings", []))
    return {
        "contact": contact,
        "session": session,
        "messages": messages,
        "warnings": warnings,
    }


def _roots(data_root) -> list[str] | None:
    if data_root is None:
        return None
    values = data_root if isinstance(data_root, (list, tuple)) else [data_root]
    result = [
        part.strip()
        for value in values
        for part in re.split(r"[;|]", str(value))
        if part.strip()
    ]
    return result or None


def collect_selfcheck(
    account_selector: str = "",
    data_root=None,
    key: str | None = None,
    contact: str = "",
    refresh: bool = False,
    include_processes: bool = True,
) -> dict:
    roots = _roots(data_root)
    accounts = discover_accounts(roots)
    selected: Account = (
        find_account(account_selector, roots) if account_selector else accounts[0]
    )

    processes, process_error = client_processes(include_processes)
    client_version = _pick_client_version(processes, selected.version)
    report: dict = {
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "package_version": package_version(),
        "cache_dir": str(cache_root()),
        "accounts": [account.to_dict() for account in accounts],
        "selected": selected.to_dict(),
        "client": {
            "version": client_version,
            "processes": processes,
            "error": process_error,
        },
        "readable": False,
    }

    try:
        decrypted = decrypt_account(
            selected,
            key_override=key,
            refresh=refresh,
            include_messages=True,
            include_session=True,
        )
    except Exception as exc:
        message = str(exc) or exc.__class__.__name__
        report["error"] = message
        report["key"] = {"ok": False, "error": message}
        report["compatibility"] = compat.assess(
            selected.version, None, client_version
        )
        return report

    schema = schema_report(decrypted)
    reader = ChatReader(decrypted)
    report["key"] = {
        "ok": True,
        "count": decrypted.key_count,
        "sources": decrypted.key_sources,
    }
    report["schema"] = schema
    report["wal_merged"] = decrypted.wal_merged
    report["notes"] = decrypted.notes
    report["cache_dir"] = str(decrypted.cache_dir)
    report["capabilities"] = {
        "contacts": reader.contact_count(),
        "sessions": bool(decrypted.session) or selected.version == 3,
        "messages": bool(decrypted.messages),
        "export": True,
    }
    report["compatibility"] = compat.assess(
        selected.version, schema, client_version
    )
    report["readable"] = True

    if contact:
        try:
            stats = reader.message_stats(contact)
            contact_info = stats.get("contact") or {}
            stats["contact"] = {
                "wxid": contact_info.get("wxid"),
                "matched": True,
            }
            stats["ok"] = True
            for field in ("first_timestamp", "last_timestamp"):
                value = stats.get(field)
                stats[field.replace("_timestamp", "_time")] = (
                    datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
                    if value
                    else None
                )
            report["probe"] = stats
        except WeChatMCPError as exc:
            report["probe"] = {"ok": False, "error": str(exc)}

    return report
