import tempfile
import unittest
from pathlib import Path

from wechat_mcp import crypto4
from wechat_mcp.errors import DecryptError
from wechat_mcp.keys4 import KeyMap, parse_key_hex

from .fixtures import encrypt_database, make_database, usable


class Crypto4Tests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.plain = make_database(self.tmp / "plain.db")
        self.key = bytes(range(32))
        self.salt = b"0123456789abcdef"
        self.encrypted = encrypt_database(self.plain, self.key, 4, self.salt)

    def tearDown(self):
        self._tmp.cleanup()

    def test_verify_key_and_pages(self):
        self.assertTrue(crypto4.verify_key(self.key, self.encrypted[:4096]))
        self.assertFalse(crypto4.verify_key(bytes(reversed(self.key)), self.encrypted[:4096]))
        for index in range(len(self.plain) // 4096):
            page = self.encrypted[index * 4096 : (index + 1) * 4096]
            self.assertTrue(crypto4.verify_page(self.key, page, index + 1, self.salt))

    def test_decrypt_database_roundtrip(self):
        decrypted = crypto4.decrypt_database(self.encrypted, self.key, verify_pages=True)
        self.assertEqual(len(decrypted), len(self.plain))
        self.assertEqual(decrypted[:16], crypto4.SQLITE_HEADER)
        self.assertEqual(usable(decrypted, 4), usable(self.plain, 4))

    def test_corrupted_page_hmac(self):
        corrupted = bytearray(self.encrypted)
        corrupted[4096 + 100] ^= 0xFF
        with self.assertRaises(DecryptError):
            crypto4.decrypt_database(bytes(corrupted), self.key, verify_pages=True)

    def test_wrong_key_rejected(self):
        with self.assertRaises(DecryptError):
            crypto4.decrypt_database(self.encrypted, b"\xbb" * 32)

    def test_decrypt_file(self):
        source = self.tmp / "encrypted.db"
        source.write_bytes(self.encrypted)
        target = self.tmp / "decrypted.db"
        info = crypto4.decrypt_file(source, target, self.key)
        self.assertTrue(info["encrypted"])
        self.assertEqual(info["pages"], len(self.plain) // 4096)
        self.assertEqual(usable(target.read_bytes(), 4), usable(self.plain, 4))

    def test_key_map_resolves_by_brute_force(self):
        other_key = bytes(range(32, 64))
        wrong_salt = b"wrongsaltwrongsa"
        key_map = KeyMap(by_salt={self.salt: other_key, wrong_salt: self.key})
        resolved = key_map.resolve(self.encrypted[:4096])
        self.assertEqual(resolved, self.key)
        self.assertEqual(key_map.by_salt[self.salt], self.key)
        self.assertIn(self.salt, key_map.verified_salts)

    def test_parse_key_hex(self):
        key, salt = parse_key_hex("x'" + self.key.hex() + self.salt.hex() + "'")
        self.assertEqual((key, salt), (self.key, self.salt))
        key_only, salt_only = parse_key_hex(self.key.hex())
        self.assertEqual((key_only, salt_only), (self.key, None))


if __name__ == "__main__":
    unittest.main()
