import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wechat_mcp.cache import _prune_cache, decrypt_account
from wechat_mcp.config import Account

from .fixtures import encrypt_database, make_database, usable


class PruneCacheTests(unittest.TestCase):
    def test_keeps_current_and_previous_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            source = cache_dir / "message_0.db"
            source.write_bytes(b"source")
            keep = cache_dir / "message_0-current.db"
            previous = cache_dir / "message_0-previous.db"
            stale = cache_dir / "message_0-stale.db"
            for age, path in ((300, keep), (200, previous), (100, stale)):
                path.write_bytes(b"cache")
                os.utime(path, (age, age))
            sidecar = cache_dir / "message_0-stale.db-wal"
            sidecar.write_bytes(b"wal")

            _prune_cache(cache_dir, source, keep)

            self.assertTrue(keep.exists())
            self.assertTrue(previous.exists())
            self.assertFalse(stale.exists())
            self.assertFalse(sidecar.exists())


class DecryptAccount3xTests(unittest.TestCase):
    def test_synthetic_three_x_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            msg_dir = root / "Msg"
            multi = msg_dir / "Multi"
            multi.mkdir(parents=True)
            key = bytes(range(32))

            contact_plain = make_database(root / "contact_plain.db")
            (msg_dir / "MicroMsg.db").write_bytes(
                encrypt_database(contact_plain, key, 3, os.urandom(16))
            )
            shard_plain = make_database(root / "shard_plain.db")
            (multi / "MSG0.db").write_bytes(
                encrypt_database(shard_plain, key, 3, os.urandom(16))
            )

            account = Account(version=3, wxid="wxid_test", directory=root, msg_dir=msg_dir)
            cache_dir = root / "cache"
            with mock.patch.dict(os.environ, {"WECHAT_MCP_CACHE_DIR": str(cache_dir)}):
                decrypted = decrypt_account(account, key_override=key.hex())
                self.assertEqual(decrypted.keys_used, 1)
                self.assertEqual(len(decrypted.messages), 1)
                self.assertEqual(usable(decrypted.contact.read_bytes(), 3), usable(contact_plain, 3))
                self.assertEqual(
                    usable(decrypted.messages[0].read_bytes(), 3), usable(shard_plain, 3)
                )
                self.assertTrue(decrypted.contact.is_relative_to(cache_dir))


if __name__ == "__main__":
    unittest.main()
