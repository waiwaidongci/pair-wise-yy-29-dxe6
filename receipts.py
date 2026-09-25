"""核验凭条处理：签发、消费与查询。

与页面入口（static/）和持久化记录（Store 中的 receipts 表）分开实现。
凭条只携带本次披露的字段，有过期时间，且只能被消费一次。
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import timedelta

from common import ApiError, iso, now, parse_time

RECEIPT_TTL_SECONDS = 300
RECEIPT_MAX_TTL_SECONDS = 3600


class ReceiptService:
    """Single-use, expiring verification receipts bound to one disclosure."""

    def __init__(self, store):
        self.store = store
        self.conn = store.conn

    def issue(self, credential: sqlite3.Row, disclosed: list[str], claims: dict, token: str, ttl_seconds: int | None = None) -> dict:
        ttl = RECEIPT_TTL_SECONDS if ttl_seconds is None else int(ttl_seconds)
        if not 1 <= ttl <= RECEIPT_MAX_TTL_SECONDS:
            raise ApiError(400, f"凭条有效期需在 1 到 {RECEIPT_MAX_TTL_SECONDS} 秒之间")
        created = now()
        expires = created + timedelta(seconds=ttl)
        receipt_no = "R" + secrets.token_hex(8)
        with self.conn:
            cur = self.conn.execute(
                """INSERT INTO receipts(receipt_no,credential_id,issuer,holder_id,disclosed_fields_json,claims_json,token,status,expires_at,created_at)
                   VALUES(?,?,?,?,?,?,?,'issued',?,?)""",
                (
                    receipt_no, credential["id"], credential["issuer"], credential["holder_id"],
                    json.dumps(list(disclosed), ensure_ascii=False), json.dumps(claims, ensure_ascii=False),
                    token, iso(expires), iso(created),
                ),
            )
            self.store.audit(credential["holder_id"], "receipt.issue", "receipt", cur.lastrowid,
                             {"receipt_no": receipt_no, "credential_id": credential["id"],
                              "disclosed_fields": list(disclosed), "expires_at": iso(expires)})
        return self.get(cur.lastrowid)

    def get(self, receipt_id: int) -> dict:
        row = self.conn.execute("SELECT * FROM receipts WHERE id=?", (receipt_id,)).fetchone()
        if not row:
            raise ApiError(404, "凭条不存在")
        return self._dict(row)

    def list(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM receipts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._dict(row) for row in rows]

    def consume(self, actor: str | None, role: str | None, receipt_id: int, result: str, at: str | None = None) -> dict:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != "verifier":
            raise ApiError(403, "需要角色 verifier")
        row = self.conn.execute("SELECT * FROM receipts WHERE id=?", (receipt_id,)).fetchone()
        if not row:
            raise ApiError(404, "凭条不存在")
        check_at = parse_time(at)
        receipt = self._dict(row)
        base = {"receipt_id": row["id"], "receipt_no": row["receipt_no"], "disclosed_fields": receipt["disclosed_fields"]}
        if row["status"] == "consumed":
            return {**base, "valid": False, "status": "used", "consumed_by": row["consumed_by"],
                    "consumed_at": row["consumed_at"], "consume_result": row["consume_result"]}
        if check_at >= parse_time(row["expires_at"]):
            self._reject(row, actor, "expired")
            return {**base, "valid": False, "status": "expired", "expires_at": row["expires_at"]}
        credential = self.conn.execute("SELECT * FROM credentials WHERE id=?", (row["credential_id"],)).fetchone()
        if credential["status"] == "revoked":
            self._reject(row, actor, "revoked")
            return {**base, "valid": False, "status": "revoked", "reason": credential["revocation_reason"]}
        if credential["status"] == "disputed":
            self._reject(row, actor, "disputed")
            return {**base, "valid": False, "status": "disputed"}
        consume_result = result.strip() or "recorded"
        with self.conn:
            cur = self.conn.execute(
                "UPDATE receipts SET status='consumed',consumed_by=?,consumed_at=?,consume_result=? WHERE id=? AND status='issued'",
                (actor, iso(check_at), consume_result, row["id"]),
            )
            if cur.rowcount == 0:  # 并发下已被其他受理方消费
                fresh = self.get(row["id"])
                return {**base, "valid": False, "status": "used", "consumed_by": fresh["consumed_by"],
                        "consumed_at": fresh["consumed_at"], "consume_result": fresh["consume_result"]}
            self.store.audit(actor, "receipt.consume", "receipt", row["id"],
                             {"receipt_no": row["receipt_no"], "result": consume_result,
                              "disclosed_fields": receipt["disclosed_fields"]})
        return {**base, "valid": True, "status": "consumed", "claims": receipt["claims"],
                "consumed_by": actor, "consumed_at": iso(check_at), "consume_result": consume_result}

    def _reject(self, row: sqlite3.Row, actor: str, status: str) -> None:
        # 失败只留审计痕迹，不生成新的有效消费记录
        with self.conn:
            self.store.audit(actor, "receipt.consume_rejected", "receipt", row["id"],
                             {"receipt_no": row["receipt_no"], "status": status})

    def _dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "receipt_no": row["receipt_no"], "credential_id": row["credential_id"],
            "issuer": row["issuer"], "holder_id": row["holder_id"],
            "disclosed_fields": json.loads(row["disclosed_fields_json"]),
            "claims": json.loads(row["claims_json"]),
            "status": row["status"], "expires_at": row["expires_at"], "created_at": row["created_at"],
            "consumed_by": row["consumed_by"], "consumed_at": row["consumed_at"],
            "consume_result": row["consume_result"],
        }
