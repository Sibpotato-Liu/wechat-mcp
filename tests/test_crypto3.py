import tempfile
import unittest
from pathlib import Path

from wechat_mcp import crypto3
from wechat_mcp.errors import DecryptError

from .fixtures import encrypt_database, make_database, usable


class Crypto3Tests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.plain_path = self.tmp / "plain.db"
        self.plain = make_database(self.plain_path)
        self.key = bytes(range(32))
        self.salt = bytes(range(16, 32))
        self.encrypted = encrypt_database(self.plain, self.key, 3, self.salt)

    def tearDown(self):
        self._tmp.cleanup()

    def test_verify_key(self):
        self.assertTrue(crypto3.verify_key(self.key, self.encrypted[:4096]))
        self.assertFalse(crypto3.verify_key(bytes(reversed(self.key)), self.encrypted[:4096]))
        self.assertFalse(crypto3.verify_key(self.key, self.plain[:4096]))

    def test_decrypt_database_roundtrip(self):
        decrypted = crypto3.decrypt_database(self.encrypted, self.key)
        self.assertEqual(len(decrypted), len(self.plain))
        self.assertEqual(decrypted[:16], crypto3.SQLITE_HEADER)
        self.assertEqual(usable(decrypted, 3), usable(self.plain, 3))

    def test_wrong_key_rejected(self):
        with self.assertRaises(DecryptError):
            crypto3.decrypt_database(self.encrypted, b"\xaa" * 32)

    def test_plaintext_passthrough(self):
        self.assertEqual(crypto3.decrypt_database(self.plain, self.key), self.plain)

    def test_decrypt_file(self):
        source = self.tmp / "encrypted.db"
        source.write_bytes(self.encrypted)
        target = self.tmp / "decrypted.db"
        info = crypto3.decrypt_file(source, target, self.key)
        self.assertTrue(info["encrypted"])
        self.assertEqual(info["pages"], len(self.plain) // 4096)
        self.assertEqual(target.read_bytes(), crypto3.decrypt_database(self.encrypted, self.key))
        self.assertEqual(usable(target.read_bytes(), 3), usable(self.plain, 3))

    def test_derive_keys_requires_32_byte_key(self):
        with self.assertRaises(DecryptError):
            crypto3.derive_keys(b"short", self.salt)
        with self.assertRaises(DecryptError):
            crypto3.derive_keys(self.key, b"short")


if __name__ == "__main__":
    unittest.main()
