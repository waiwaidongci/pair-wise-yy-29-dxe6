import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import ApiError, CredentialService, ReceiptService, Store
from store import iso, now


class ReceiptFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.receipts = self.service.receipts
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True}, {"name": "gpa", "required": False}],
            365,
        )
        self.credential = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice",
            {"name": "Alice", "degree": "BSc", "gpa": "3.8"}, "issue-1",
        )

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def present(self, fields=("name", "degree"), ttl=None):
        return self.service.present("alice", "holder", self.credential["id"], list(fields), ttl)

    def record_count(self):
        return self.service.store.conn.execute("SELECT COUNT(*) FROM receipt_records").fetchone()[0]

    def test_receipt_carries_only_disclosed_fields(self):
        receipt = self.present(["name", "degree"])["receipt"]
        self.assertIsInstance(self.receipts, ReceiptService)
        self.assertEqual("pending", receipt["status"])
        self.assertEqual({"name", "degree"}, set(receipt["disclosed_fields"]))
        self.assertEqual({"name": "Alice", "degree": "BSc"}, receipt["claims"])
        self.assertNotIn("gpa", json.dumps(receipt, ensure_ascii=False))
        self.assertGreater(receipt["expires_at"], receipt["issued_at"])

    def test_consume_once_then_used_without_new_record(self):
        receipt = self.present()["receipt"]
        first = self.receipts.consume("verifier-1", receipt["receipt_id"])
        self.assertTrue(first["valid"])
        self.assertEqual("consumed", first["status"])
        self.assertEqual({"name", "degree"}, set(first["claims"]))
        self.assertEqual(1, self.record_count())
        again = self.receipts.consume("verifier-2", receipt["receipt_id"])
        self.assertFalse(again["valid"])
        self.assertEqual("used", again["status"])
        self.assertEqual("verifier-1", again["consumed_by"])
        self.assertEqual(1, self.record_count())

    def test_expired_receipt_returns_expired_without_record(self):
        receipt = self.present(ttl=30)["receipt"]
        result = self.receipts.consume("verifier-1", receipt["receipt_id"], at=iso(now() + timedelta(seconds=60)))
        self.assertFalse(result["valid"])
        self.assertEqual("expired", result["status"])
        self.assertEqual(0, self.record_count())

    def test_revoked_credential_returns_revoked_without_record(self):
        receipt = self.present()["receipt"]
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "持有人申请撤销")
        result = self.receipts.consume("verifier-1", receipt["receipt_id"])
        self.assertFalse(result["valid"])
        self.assertEqual("revoked", result["status"])
        self.assertEqual(0, self.record_count())

    def test_disputed_credential_is_unavailable(self):
        receipt = self.present()["receipt"]
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "撤销依据错误")
        self.service.dispute("alice", "holder", self.credential["id"], "撤销依据错误")
        result = self.receipts.consume("verifier-1", receipt["receipt_id"])
        self.assertFalse(result["valid"])
        self.assertEqual("disputed", result["status"])
        self.assertEqual(0, self.record_count())

    def test_unknown_receipt_missing_actor_and_ttl_bounds(self):
        with self.assertRaises(ApiError) as not_found:
            self.receipts.consume("verifier-1", "rcpt_missing")
        self.assertEqual(404, not_found.exception.status)
        receipt = self.present()["receipt"]
        with self.assertRaises(ApiError) as unauthorized:
            self.receipts.consume(None, receipt["receipt_id"])
        self.assertEqual(401, unauthorized.exception.status)
        with self.assertRaises(ApiError):
            self.present(ttl=0)
        with self.assertRaises(ApiError):
            self.present(ttl=7200)


if __name__ == "__main__":
    unittest.main()
