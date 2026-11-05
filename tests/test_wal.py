import tempfile
import unittest
from pathlib import Path

from wechat_mcp import crypto3, crypto4, wal

from .fixtures import build_wal, encrypt_database, make_database, mutate_database, usable


class WalTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.source_path = self.tmp / "source.db"
        self.mutated_path = self.tmp / "mutated.db"
        self.original = make_database(self.source_path)
        self.updated = mutate_database(self.source_path, self.mutated_path)
        self.key = bytes(range(32))
        self.salt = b"wal-salt-1234567"

    def tearDown(self):
        self._tmp.cleanup()

    def _encrypt(self, version):
        return encrypt_database(self.original, self.key, version, self.salt)

    def _decrypt(self, version, encrypted):
        decryptor = crypto4.decrypt_database if version == 4 else crypto3.decrypt_database
        return decryptor(encrypted, self.key)

    def test_apply_wal_both_versions(self):
        for version in (3, 4):
            with self.subTest(version=version):
                encrypted = self._encrypt(version)
                decrypted = self._decrypt(version, encrypted)
                frames = build_wal(self.updated, self.key, version, self.salt)
                result = wal.apply_wal_bytes(decrypted, frames, self.key, version, salt=self.salt)
                self.assertIsNotNone(result)
                self.assertEqual(result.target_pages, len(self.updated) // 4096)
                self.assertEqual(result.page1_variant, "skip-salt")
                merged = result.pages[0][1]
                self.assertEqual(usable(merged, version), usable(self.updated, version))

    def test_full_page_page1_variant(self):
        for version in (3, 4):
            with self.subTest(version=version):
                decrypted = self._decrypt(version, self._encrypt(version))
                frames = build_wal(self.updated, self.key, version, self.salt, page1_full=True)
                result = wal.apply_wal_bytes(decrypted, frames, self.key, version, salt=self.salt)
                self.assertIsNotNone(result)
                self.assertEqual(result.page1_variant, "full-page")
                self.assertEqual(usable(result.pages[0][1], version), usable(self.updated, version))

    def test_uncommitted_wal_is_ignored(self):
        for version in (3, 4):
            with self.subTest(version=version):
                decrypted = self._decrypt(version, self._encrypt(version))
                frames = build_wal(self.updated, self.key, version, self.salt, commit=False)
                self.assertIsNone(
                    wal.apply_wal_bytes(decrypted, frames, self.key, version, salt=self.salt)
                )

    def test_stale_wal_salt_is_ignored(self):
        for version in (3, 4):
            with self.subTest(version=version):
                decrypted = self._decrypt(version, self._encrypt(version))
                frames = bytearray(build_wal(self.updated, self.key, version, self.salt))
                frames[32 + 8 : 32 + 16] = b"\xde\xad\xbe\xef\xde\xad\xbe\xef"
                self.assertIsNone(
                    wal.apply_wal_bytes(decrypted, bytes(frames), self.key, version, salt=self.salt)
                )

    def test_page1_hmac_failure_is_skipped(self):
        for version in (3, 4):
            with self.subTest(version=version):
                decrypted = self._decrypt(version, self._encrypt(version))
                frames = bytearray(build_wal(self.updated, self.key, version, self.salt))
                hmac_offset = 4064 if version == 3 else 4032
                frames[56 + hmac_offset] ^= 0xFF
                result = wal.apply_wal_bytes(decrypted, bytes(frames), self.key, version, salt=self.salt)
                self.assertIsNotNone(result)
                self.assertTrue(result.page1_skipped)
                self.assertIsNone(result.page1_variant)
                merged = result.pages[0][1]
                self.assertEqual(merged[:4096], decrypted[:4096])
                limit = 4016 if version == 4 else 4048
                self.assertEqual(usable(merged, version)[limit:], usable(self.updated, version)[limit:])

    def test_wrong_key_is_rejected(self):
        for version in (3, 4):
            with self.subTest(version=version):
                decrypted = self._decrypt(version, self._encrypt(version))
                frames = build_wal(self.updated, self.key, version, self.salt)
                self.assertIsNone(
                    wal.apply_wal_bytes(decrypted, frames, b"\xcc" * 32, version, salt=self.salt)
                )

    def test_merge_wal_file(self):
        for version in (3, 4):
            with self.subTest(version=version):
                decrypted = self._decrypt(version, self._encrypt(version))
                db_path = self.tmp / f"decrypted-{version}.db"
                db_path.write_bytes(decrypted)
                wal_path = self.tmp / f"decrypted-{version}.db-wal"
                wal_path.write_bytes(build_wal(self.updated, self.key, version, self.salt))
                result = wal.merge_wal_file(
                    db_path, wal_path, self.key, version, salt=self.salt
                )
                self.assertIsNotNone(result)
                self.assertEqual(usable(db_path.read_bytes(), version), usable(self.updated, version))

    def test_merge_requires_salt_for_plaintext_file(self):
        db_path = self.tmp / "plain.db"
        db_path.write_bytes(self.original)
        wal_path = self.tmp / "plain.db-wal"
        wal_path.write_bytes(build_wal(self.updated, self.key, 4, self.salt))
        self.assertIsNone(wal.merge_wal_file(db_path, wal_path, self.key, 4))


if __name__ == "__main__":
    unittest.main()
