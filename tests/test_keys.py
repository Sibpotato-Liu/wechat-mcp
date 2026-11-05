import struct
import tempfile
import unittest
from pathlib import Path

from wechat_mcp.config import Account
from wechat_mcp.keys3 import _candidate_keys
from wechat_mcp.keys4 import (
    CONFIG_NEEDLE,
    CONFIG_NEEDLES,
    CONFIG_XOR_MASK,
    extract_key_map4,
    scan_config_cipher,
    scan_salt_neighborhood,
)
from wechat_mcp.keyutil import parse_key_list

from .fixtures import encrypt_database, make_database


class FakeMemory:
    pointer_size = 8

    def __init__(self, size: int = 0x10000):
        self.data = bytearray(size)

    def write(self, address: int, payload: bytes) -> None:
        self.data[address : address + len(payload)] = payload

    def read(self, address: int, size: int) -> bytes:
        if address < 0 or address >= len(self.data):
            return b""
        return bytes(self.data[address : address + size])

    def find_all(self, needle: bytes, start=None, end=None):
        begin = 0 if start is None else max(0, start)
        limit = len(self.data) if end is None else min(len(self.data), end)
        found = []
        index = self.data.find(needle, begin, limit)
        while index != -1:
            found.append(index)
            index = self.data.find(needle, index + 1, limit)
        return found

    def iter_chunks(self, chunk_size=4 * 1024 * 1024, overlap=0, start=None, end=None):
        yield 0, bytes(self.data)


def xor_repeat(data: bytes, mask: bytes) -> bytes:
    repeated = (mask * ((len(data) + len(mask) - 1) // len(mask)))[: len(data)]
    return bytes(left ^ right for left, right in zip(data, repeated))


def cipher_memory(
    key: bytes,
    salt: bytes,
    needle: bytes = CONFIG_NEEDLE,
    mask: bytes = CONFIG_XOR_MASK,
) -> FakeMemory:
    memory = FakeMemory()
    needle_address = 0x1000
    pointer_address = 0x2000
    config_pointer = 0x3000
    blob_address = 0x5000

    memory.write(needle_address, needle)
    struct.pack_into("<Q", memory.data, pointer_address, needle_address)
    struct.pack_into("<Q", memory.data, pointer_address + 8, len(needle))
    struct.pack_into("<Q", memory.data, pointer_address + 0x18, config_pointer)

    payload = b"x'" + key.hex().encode() + salt.hex().encode() + b"'"
    blob = xor_repeat(payload, mask) if mask else payload
    memory.write(blob_address, blob)
    struct.pack_into("<Q", memory.data, config_pointer + 0x90, blob_address)
    struct.pack_into("<Q", memory.data, config_pointer + 0x98, len(blob))
    return memory


class ConfigCipherScanTests(unittest.TestCase):
    def test_scan_decodes_obfuscated_key(self):
        key = bytes(range(32))
        salt = bytes(range(100, 116))
        candidates = scan_config_cipher(cipher_memory(key, salt))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].key, key)
        self.assertEqual(candidates[0].salt, salt)
        self.assertEqual(candidates[0].source, "config-cipher")

    def test_scan_alternate_needle_and_plain_blob(self):
        key = bytes(range(32))
        salt = bytes(range(100, 116))
        candidates = scan_config_cipher(
            cipher_memory(key, salt, needle=CONFIG_NEEDLES[2], mask=b"")
        )
        self.assertEqual([item.key for item in candidates], [key])

    def test_scan_returns_empty_without_needle(self):
        self.assertEqual(scan_config_cipher(FakeMemory()), [])


class SaltNeighborhoodTests(unittest.TestCase):
    def test_finds_key_next_to_salt(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = make_database(Path(tmp) / "plain.db")
            key = bytes(range(32))
            encrypted = encrypt_database(plain, key, 4)
            page = encrypted[:4096]

            memory = FakeMemory(0x10000)
            memory.write(0x4000, page[:16])
            memory.write(0x4050, key)

            candidates = scan_salt_neighborhood(memory, [page])
            self.assertEqual([item.key for item in candidates], [key])
            self.assertEqual(candidates[0].salt, page[:16])


class ManualKeyTests(unittest.TestCase):
    def test_parse_key_list(self):
        key1 = bytes(range(32))
        key2 = bytes(range(32, 64))
        parsed = parse_key_list(f"{key1.hex()};{key2.hex()}")
        self.assertEqual([item[0] for item in parsed], [key1, key2])

    def test_multiple_manual_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            storage = root / "db_storage"
            contact = storage / "contact"
            contact.mkdir(parents=True)
            plain = make_database(root / "plain.db")
            key1 = bytes(range(32))
            key2 = bytes(range(32, 64))
            (contact / "contact.db").write_bytes(encrypt_database(plain, key2, 4))

            account = Account(
                version=4, wxid="wxid_test", directory=root, db_storage=storage
            )
            key_map = extract_key_map4(
                account, override=f"{key1.hex()};{key2.hex()}"
            )
            self.assertTrue(key_map.verified_salts)
            self.assertIn(key2, key_map.by_salt.values())


class PointerChainScanTests(unittest.TestCase):
    def test_finds_pointer_key(self):
        memory = FakeMemory(0x20000)
        key = bytes(range(32))
        key_address = 0x15000
        marker_address = 0x2000
        memory.write(key_address, key)
        memory.write(marker_address, b"iphone\x00")
        struct.pack_into("<Q", memory.data, marker_address - 0x18, key_address)

        candidates = _candidate_keys(memory, None, None)
        self.assertIn(key, candidates)

    def test_finds_inline_key(self):
        memory = FakeMemory()
        key = bytes(range(100, 132))
        marker_address = 0x3000
        memory.write(marker_address, b"android\x00")
        memory.write(marker_address - 0x40, key)

        candidates = _candidate_keys(memory, None, None)
        self.assertIn(key, candidates)

    def test_range_excludes_marker(self):
        memory = FakeMemory()
        key = bytes(range(32))
        memory.write(0x5000, key)
        memory.write(0x2000, b"ipad\x00")
        struct.pack_into("<Q", memory.data, 0x2000 - 0x18, 0x5000)

        self.assertEqual(_candidate_keys(memory, 0x4000, 0x6000), [])


if __name__ == "__main__":
    unittest.main()
