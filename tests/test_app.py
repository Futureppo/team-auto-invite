import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as invite_app


class RedeemApiTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_database_path = invite_app.DATABASE_PATH
        self.original_token_cache = invite_app._token_cache

        invite_app.DATABASE_PATH = str(Path(self.temp_dir.name) / "test.db")
        invite_app._token_cache = None
        invite_app.init_db()

        self.client = invite_app.app.test_client()

    def tearDown(self) -> None:
        invite_app.DATABASE_PATH = self.original_database_path
        invite_app._token_cache = self.original_token_cache
        self.temp_dir.cleanup()

    def fetch_code_row(self, code: str):
        with invite_app.db_connection() as conn:
            return conn.execute(
                """
                SELECT code, status, reserved_by_email, used_by_email
                FROM redeem_codes
                WHERE code = ?
                """,
                (code,),
            ).fetchone()

    def fetch_invite_records(self):
        with invite_app.db_connection() as conn:
            rows = conn.execute(
                """
                SELECT email, code, invite_status, invite_message
                FROM invite_records
                ORDER BY id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def test_create_redeem_codes_normalizes_and_skips_duplicates(self) -> None:
        result = invite_app.create_redeem_codes([" test-001 ", "TEST-001", "test-002"])

        self.assertEqual(result["inserted"], ["TEST-001", "TEST-002"])
        self.assertEqual(result["skipped"], ["TEST-001"])

    def test_redeem_api_marks_code_used_after_successful_invite(self) -> None:
        invite_app.create_redeem_codes(["success-001"])

        with patch.object(
            invite_app,
            "check_token_status",
            return_value={"ok": True, "account_id": "acct_123", "email": "admin@example.com"},
        ), patch.object(
            invite_app,
            "send_invite",
            return_value={"success": True, "message": "邀请发送成功，请检查邮箱"},
        ):
            response = self.client.post(
                "/api/redeem",
                json={"email": "user@example.com", "code": "success-001"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"success": True, "message": "邀请发送成功，请检查邮箱"})

        code_row = self.fetch_code_row("SUCCESS-001")
        self.assertEqual(code_row["status"], "used")
        self.assertEqual(code_row["used_by_email"], "user@example.com")

        self.assertEqual(
            self.fetch_invite_records(),
            [
                {
                    "email": "user@example.com",
                    "code": "SUCCESS-001",
                    "invite_status": "success",
                    "invite_message": "邀请发送成功，请检查邮箱",
                }
            ],
        )

    def test_redeem_api_releases_code_when_invite_fails(self) -> None:
        invite_app.create_redeem_codes(["fail-001"])

        with patch.object(
            invite_app,
            "check_token_status",
            return_value={"ok": True, "account_id": "acct_123", "email": "admin@example.com"},
        ), patch.object(
            invite_app,
            "send_invite",
            return_value={"success": False, "message": "团队已满，无法继续邀请"},
        ):
            response = self.client.post(
                "/api/redeem",
                json={"email": "user@example.com", "code": "fail-001"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"success": False, "message": "团队已满，无法继续邀请"})

        code_row = self.fetch_code_row("FAIL-001")
        self.assertEqual(code_row["status"], "unused")
        self.assertIsNone(code_row["reserved_by_email"])
        self.assertIsNone(code_row["used_by_email"])

        self.assertEqual(
            self.fetch_invite_records(),
            [
                {
                    "email": "user@example.com",
                    "code": "FAIL-001",
                    "invite_status": "invite_failed",
                    "invite_message": "团队已满，无法继续邀请",
                }
            ],
        )

    def test_redeem_api_returns_400_for_invalid_code(self) -> None:
        with patch.object(
            invite_app,
            "check_token_status",
            return_value={"ok": True, "account_id": "acct_123", "email": "admin@example.com"},
        ):
            response = self.client.post(
                "/api/redeem",
                json={"email": "user@example.com", "code": "missing-code"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"success": False, "message": "兑换码无效"})
        self.assertEqual(
            self.fetch_invite_records(),
            [
                {
                    "email": "user@example.com",
                    "code": "MISSING-CODE",
                    "invite_status": "invalid_code",
                    "invite_message": "兑换码无效",
                }
            ],
        )

    def test_redeem_api_returns_503_when_token_is_invalid(self) -> None:
        invite_app.create_redeem_codes(["token-001"])

        with patch.object(
            invite_app,
            "check_token_status",
            return_value={"ok": False, "error": "Token 解码失败: Invalid header padding"},
        ):
            response = self.client.post(
                "/api/redeem",
                json={"email": "user@example.com", "code": "token-001"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json(),
            {"success": False, "message": "Token 解码失败: Invalid header padding"},
        )

        code_row = self.fetch_code_row("TOKEN-001")
        self.assertEqual(code_row["status"], "unused")
        self.assertIsNone(code_row["reserved_by_email"])
        self.assertIsNone(code_row["used_by_email"])

        self.assertEqual(
            self.fetch_invite_records(),
            [
                {
                    "email": "user@example.com",
                    "code": "TOKEN-001",
                    "invite_status": "token_error",
                    "invite_message": "Token 解码失败: Invalid header padding",
                }
            ],
        )

    def test_redeem_api_rejects_non_string_code(self) -> None:
        with patch.object(
            invite_app,
            "check_token_status",
            return_value={"ok": True, "account_id": "acct_123", "email": "admin@example.com"},
        ):
            response = self.client.post(
                "/api/redeem",
                json={"email": "user@example.com", "code": 123},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"success": False, "message": "兑换码不能为空"})
        self.assertEqual(self.fetch_invite_records(), [])

    def test_redeem_api_rejects_non_string_email(self) -> None:
        with patch.object(
            invite_app,
            "check_token_status",
            return_value={"ok": True, "account_id": "acct_123", "email": "admin@example.com"},
        ):
            response = self.client.post(
                "/api/redeem",
                json={"email": ["user@example.com"], "code": "valid-001"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"success": False, "message": "邮箱格式不正确"})
        self.assertEqual(self.fetch_invite_records(), [])

    def test_invite_api_rejects_non_string_email(self) -> None:
        response = self.client.post(
            "/api/invite",
            json={"email": {"address": "user@example.com"}},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"success": False, "message": "邮箱格式不正确"})


if __name__ == "__main__":
    unittest.main()
