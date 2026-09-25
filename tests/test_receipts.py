import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store, iso, now


class ReceiptFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True}, {"name": "gpa", "required": False}], 365)
        self.credential = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice",
            {"name": "Alice", "degree": "BSc", "gpa": "3.8"}, "issue-1")

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def present(self, fields=("name", "degree"), ttl=300):
        return self.service.present("alice", "holder", self.credential["id"], list(fields), ttl)

    def test_receipt_carries_only_disclosed_fields_with_expiry(self):
        receipt = self.present(fields=("name",), ttl=60)["receipt"]
        self.assertEqual(["name"], receipt["disclosed_fields"])
        self.assertEqual({"name": "Alice"}, receipt["claims"])
        self.assertNotIn("gpa", str(receipt))
        self.assertEqual("issued", receipt["status"])
        self.assertIsNotNone(receipt["expires_at"])

    def test_expired_receipt_returns_status_without_new_record(self):
        receipt = self.present(ttl=60)["receipt"]
        future = iso(now() + timedelta(seconds=120))
        outcome = self.service.receipts.consume("verifier-1", "verifier", receipt["id"], "approved", at=future)
        self.assertEqual({"valid": False, "status": "expired"}, {k: outcome[k] for k in ("valid", "status")})
        stored = self.service.receipts.get(receipt["id"])
        self.assertEqual("issued", stored["status"])
        self.assertIsNone(stored["consumed_by"])
        self.assertIsNone(stored["consume_result"])

    def test_consume_records_result_and_blocks_reuse(self):
        receipt = self.present()["receipt"]
        first = self.service.receipts.consume("verifier-1", "verifier", receipt["id"], "approved")
        self.assertTrue(first["valid"])
        self.assertEqual("consumed", first["status"])
        self.assertEqual({"name": "Alice", "degree": "BSc"}, first["claims"])
        second = self.service.receipts.consume("verifier-2", "verifier", receipt["id"], "approved")
        self.assertEqual("used", second["status"])
        self.assertFalse(second["valid"])
        self.assertEqual("verifier-1", second["consumed_by"])
        stored = self.service.receipts.get(receipt["id"])
        self.assertEqual("consumed", stored["status"])
        self.assertEqual("verifier-1", stored["consumed_by"])
        self.assertEqual("approved", stored["consume_result"])

    def test_revoked_then_disputed_credential_blocks_consume_and_present(self):
        receipt = self.present()["receipt"]
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "证件丢失")
        revoked = self.service.receipts.consume("verifier-1", "verifier", receipt["id"], "ok")
        self.assertEqual("revoked", revoked["status"])
        self.assertEqual("issued", self.service.receipts.get(receipt["id"])["status"])
        with self.assertRaises(ApiError) as ctx:
            self.present()
        self.assertEqual(409, ctx.exception.status)
        self.service.dispute("alice", "holder", self.credential["id"], "非本人申请撤销")
        disputed = self.service.receipts.consume("verifier-1", "verifier", receipt["id"], "ok")
        self.assertEqual("disputed", disputed["status"])
        with self.assertRaises(ApiError) as ctx:
            self.present()
        self.assertEqual(409, ctx.exception.status)
        self.assertEqual("issued", self.service.receipts.get(receipt["id"])["status"])

    def test_consume_requires_verifier_role(self):
        receipt = self.present()["receipt"]
        with self.assertRaises(ApiError) as ctx:
            self.service.receipts.consume("alice", "holder", receipt["id"], "ok")
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.service.receipts.consume(None, "verifier", receipt["id"], "ok")
        self.assertEqual(401, ctx.exception.status)


if __name__ == "__main__":
    unittest.main()
