import unittest

from wechat_mcp import compat


def schema4(**overrides) -> dict:
    result = {
        "contact": {"table": "contact", "columns": ["username"], "rows": 2},
        "session": {
            "table": "SessionTable",
            "columns": ["username", "sort_timestamp"],
            "rows": 2,
        },
        "messages": {
            "files": 1,
            "shards": 1,
            "tables": 1,
            "sample_table": "Msg_abc",
            "columns": [
                "local_id",
                "server_id",
                "local_type",
                "create_time",
                "message_content",
                "real_sender_id",
            ],
            "name2id": {"table": "Name2Id", "columns": ["user_name"], "rows": 2},
        },
    }
    result.update(overrides)
    return result


def schema3(**overrides) -> dict:
    result = {
        "contact": {"table": "Contact", "columns": ["UserName"], "rows": 2},
        "session": {"table": "Session", "columns": ["strUsrName"], "rows": 2},
        "messages": {
            "files": 1,
            "shards": 1,
            "tables": 1,
            "sample_table": "MSG",
            "columns": [
                "StrTalker",
                "CreateTime",
                "StrContent",
                "IsSender",
                "BytesExtra",
            ],
            "name2id": None,
        },
    }
    result.update(overrides)
    return result


class VersionTests(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(compat.parse_client_version("v4.1.15.13"), (4, 1, 15, 13))
        self.assertEqual(compat.parse_client_version("Weixin 4.1"), (4, 1))
        self.assertIsNone(compat.parse_client_version(""))

    def test_support_levels(self):
        self.assertEqual(compat.version_support(4, "4.1.15.13")["level"], "tested")
        self.assertEqual(compat.version_support(4, "4.1.15.20")["level"], "expected")
        self.assertEqual(compat.version_support(4, "4.1.16.1")["level"], "untested")
        self.assertEqual(compat.version_support(4, None)["level"], "unknown")
        self.assertEqual(
            compat.version_support(3, "3.9.10.19")["level"], "synthetic-only"
        )


class AssessTests(unittest.TestCase):
    def test_v4_supported(self):
        result = compat.assess(4, schema4(), "4.1.15.13")
        self.assertEqual(result["status"], compat.SUPPORTED)
        self.assertEqual(result["core_missing"], [])
        self.assertEqual(result["version"]["level"], "tested")

    def test_v4_missing_name2id_is_degraded(self):
        schema = schema4()
        schema["messages"]["name2id"] = {"columns": []}
        result = compat.assess(4, schema, "4.1.15.13")
        self.assertEqual(result["status"], compat.DEGRADED)
        self.assertTrue(any("Name2Id" in item for item in result["degraded"]))

    def test_v4_missing_contact_is_unsupported(self):
        schema = schema4()
        schema["contact"]["columns"] = []
        result = compat.assess(4, schema, "4.1.15.13")
        self.assertEqual(result["status"], compat.UNSUPPORTED)
        self.assertTrue(any("contact.username" in item for item in result["core_missing"]))

    def test_v4_missing_message_table_is_unsupported(self):
        schema = schema4()
        schema["messages"]["tables"] = 0
        result = compat.assess(4, schema, "4.1.15.13")
        self.assertEqual(result["status"], compat.UNSUPPORTED)

    def test_empty_account_is_degraded(self):
        schema = schema4()
        schema["messages"].update({"tables": 0, "files": 0, "columns": []})
        result = compat.assess(4, schema, "4.1.15.13")
        self.assertEqual(result["status"], compat.DEGRADED)
        self.assertEqual(result["core_missing"], [])

    def test_v3_supported(self):
        result = compat.assess(3, schema3(), "3.9.10.19")
        self.assertEqual(result["status"], compat.SUPPORTED)
        self.assertEqual(result["version"]["level"], "synthetic-only")

    def test_v3_missing_content_is_unsupported(self):
        schema = schema3()
        schema["messages"]["columns"] = ["StrTalker", "CreateTime", "IsSender"]
        result = compat.assess(3, schema, "3.9.10.19")
        self.assertEqual(result["status"], compat.UNSUPPORTED)

    def test_unknown_schema(self):
        result = compat.assess(4, None, "4.1.15.13")
        self.assertEqual(result["status"], compat.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
