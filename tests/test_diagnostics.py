import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from wechat_mcp.chatlog import ChatReader
from wechat_mcp.diagnostics import collect_selfcheck

SELF_WXID = "wxid_self"
FRIEND_WXID = "wxid_friend"
FRIEND_ALIAS = "friend_alias"


def _create(path: Path, statements: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    try:
        for statement in statements:
            con.execute(statement)
        con.commit()
    finally:
        con.close()


def build_account(root: Path, alternate: bool = False) -> Path:
    account_dir = root / "wxid_test"
    storage = account_dir / "db_storage"
    _create(
        storage / "contact" / "contact.db",
        [
            "CREATE TABLE contact(username TEXT, alias TEXT, remark TEXT, "
            "nick_name TEXT, delete_flag INTEGER)",
            f"INSERT INTO contact VALUES ('{SELF_WXID}', 'self_alias', '', 'Self', 0)",
            f"INSERT INTO contact VALUES ('{FRIEND_WXID}', '{FRIEND_ALIAS}', '', 'Friend', 0)",
        ],
    )
    _create(
        storage / "session" / "session.db",
        [
            "CREATE TABLE SessionTable(username TEXT, summary TEXT, "
            "sort_timestamp INTEGER, unread_count INTEGER)",
            f"INSERT INTO SessionTable VALUES ('{FRIEND_WXID}', 'hello', 1700000200, 0)",
        ],
    )
    table = "Msg_" + hashlib.md5(FRIEND_WXID.encode()).hexdigest()
    if alternate:
        columns = (
            "local_id INTEGER, server_id INTEGER, type INTEGER, sequence INTEGER, "
            "sender_id INTEGER, timestamp INTEGER, content TEXT"
        )
    else:
        columns = (
            "local_id INTEGER, server_id INTEGER, local_type INTEGER, "
            "sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER, "
            "message_content TEXT, compress_content BLOB, "
            "WCDB_CT_message_content INTEGER, WCDB_CT_compress_content INTEGER"
        )
    rows = (
        [
            f"INSERT INTO \"{table}\" VALUES (1, 1001, 1, 1, 2, 1700000000, 'hello there')",
            f"INSERT INTO \"{table}\" VALUES (2, 1002, 1, 2, 1, 1700000100, 'reply')",
        ]
        if alternate
        else [
            f"INSERT INTO \"{table}\" VALUES "
            "(1, 1001, 1, 1, 2, 1700000000, 'hello there', NULL, 0, 0)",
            f"INSERT INTO \"{table}\" VALUES "
            "(2, 1002, 1, 2, 1, 1700000100, 'reply', NULL, 0, 0)",
        ]
    )
    _create(
        storage / "message" / "message_0.db",
        [
            f'CREATE TABLE "{table}" ({columns})',
            "CREATE TABLE Name2Id(rowid INTEGER PRIMARY KEY, user_name TEXT)",
            f"INSERT INTO Name2Id VALUES (1, '{SELF_WXID}')",
            f"INSERT INTO Name2Id VALUES (2, '{FRIEND_WXID}')",
            *rows,
        ],
    )
    return account_dir


class SelfcheckTests(unittest.TestCase):
    def test_plaintext_v4_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            account_dir = build_account(Path(tmp))
            report = collect_selfcheck(
                account_selector="wxid_test",
                data_root=str(account_dir),
                contact=FRIEND_ALIAS,
                include_processes=False,
            )

            self.assertTrue(report["readable"])
            self.assertEqual(report["compatibility"]["status"], "supported")
            self.assertEqual(report["capabilities"]["contacts"], 2)
            self.assertEqual(report["schema"]["messages"]["tables"], 1)
            self.assertEqual(report["schema"]["messages"]["rows"], 2)
            self.assertEqual(report["key"], {"ok": True, "count": 0, "sources": []})
            self.assertTrue(report["probe"]["ok"])
            self.assertEqual(report["probe"]["total"], 2)
            self.assertEqual(
                report["probe"]["first_time"],
                datetime.fromtimestamp(1700000000).strftime("%Y-%m-%d %H:%M:%S"),
            )
            self.assertEqual(
                report["probe"]["last_time"],
                datetime.fromtimestamp(1700000100).strftime("%Y-%m-%d %H:%M:%S"),
            )

            serialized = json.dumps(report, ensure_ascii=False)
            self.assertNotIn("hello there", serialized)
            self.assertNotIn("reply", serialized)
            self.assertNotIn("key_hex", serialized)

    def test_reader_accepts_alternate_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            account_dir = build_account(Path(tmp), alternate=True)
            report = collect_selfcheck(
                account_selector="wxid_test",
                data_root=str(account_dir),
                include_processes=False,
            )
            self.assertTrue(report["readable"])
            # real_sender_id/name2id are still present, so only the data
            # column names differ; the compat layer should accept it.
            self.assertEqual(report["compatibility"]["status"], "supported")

            from wechat_mcp.cache import decrypt_account
            from wechat_mcp.config import find_account

            account = find_account("wxid_test", [str(account_dir)])
            decrypted = decrypt_account(account)
            reader = ChatReader(decrypted)
            _contact, messages, total = reader.messages(FRIEND_ALIAS, limit=0)
            self.assertEqual(total, 2)
            self.assertEqual(messages[0].content, "hello there")
            self.assertEqual(messages[1].content, "reply")
            self.assertEqual(reader.message_stats(FRIEND_ALIAS)["total"], 2)


if __name__ == "__main__":
    unittest.main()
