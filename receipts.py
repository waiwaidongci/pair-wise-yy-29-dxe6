"""凭条处理：持有人出示时签发短时效核验凭条，受理方一次性消费。

凭条只携带本次披露的字段；消费结果持久化到 receipt_records。
凭条过期、凭证被撤销、凭条已消费或凭证处于争议中时，返回对应状态且不生成新的有效记录。
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import timedelta

from store import ApiError, Store, iso, now, parse_time

DEFAULT_TTL_SECONDS = 300
MAX_TTL_SECONDS = 3600


class ReceiptService:
    """核验凭条的签发与一次性消费，保证同一张凭条不能被反复使用。"""

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn

    def issue(self, credential: sqlite3.Row, disclosed_fields: list[str], claims: dict, ttl_seconds: int | None = None) -> dict:
        """出示时生成凭条，只带本次披露的字段，并设置过期时间。"""
        ttl = DEFAULT_TTL_SECONDS if ttl_seconds is None else int(ttl_seconds)
        if not 1 <= ttl <= MAX_TTL_SECONDS:
            raise ApiError(400, f"凭条有效期需在 1 到 {MAX_TTL_SECONDS} 秒之间")
        issued_at = now()
        expires_at = issued_at + timedelta(seconds=ttl)
        receipt_id = f"rcpt_{secrets.token_urlsafe(18)}"
        with self.conn:
            self.conn.execute(
                """INSERT INTO receipts(receipt_id,credential_id,holder_id,disclosed_fields_json,claims_json,issued_at,expires_at,status)
                   VALUES(?,?,?,?,?,?,?,'pending')""",
                (
                    receipt_id,
                    credential["id"],
                    credential["holder_id"],
                    json.dumps(list(disclosed_fields), ensure_ascii=False),
                    json.dumps(claims, ensure_ascii=False),
                    iso(issued_at),
                    iso(expires_at),
                ),
            )
            self.store.audit(
                credential["holder_id"], "receipt.issue", "receipt", receipt_id,
                {"credential_id": credential["id"], "disclosed_fields": list(disclosed_fields), "expires_at": iso(expires_at)},
            )
        return self._receipt_dict(self._row(receipt_id))

    def consume(self, actor: str | None, receipt_id: str, at: str | None = None) -> dict:
        """受理方消费凭条：成功则记录结果；异常状态只返回状态，不生成有效记录。"""
        if not actor:
            raise ApiError(401, "缺少身份")
        row = self.conn.execute("SELECT * FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        if not row:
            raise ApiError(404, "凭条不存在")
        check_at = parse_time(at)
        if row["status"] == "consumed":
            return self._reject(actor, row, "used", "凭条已被消费，不能重复使用")
        if check_at >= parse_time(row["expires_at"]):
            return self._reject(actor, row, "expired", "凭条已过期")
        credential = self.conn.execute("SELECT * FROM credentials WHERE id=?", (row["credential_id"],)).fetchone()
        if credential["status"] == "revoked":
            return self._reject(actor, row, "revoked", "凭证已被撤销")
        if credential["status"] == "disputed":
            return self._reject(actor, row, "disputed", "凭证处于争议处理中，暂不可用")
        with self.conn:
            cur = self.conn.execute(
                "UPDATE receipts SET status='consumed', consumed_at=?, consumed_by=? WHERE receipt_id=? AND status='pending'",
                (iso(check_at), actor, receipt_id),
            )
            if cur.rowcount:
                record = self.conn.execute(
                    """INSERT INTO receipt_records(receipt_id,credential_id,verifier,disclosed_fields_json,claims_json,result,consumed_at)
                       VALUES(?,?,?,?,?,'consumed',?)""",
                    (receipt_id, row["credential_id"], actor, row["disclosed_fields_json"], row["claims_json"], iso(check_at)),
                )
                self.store.audit(actor, "receipt.consume", "receipt", receipt_id, {"credential_id": row["credential_id"], "record_id": record.lastrowid})
        if not cur.rowcount:
            # 并发下另一请求已抢先消费同一张凭条。
            return self._reject(actor, self._row(receipt_id), "used", "凭条已被消费，不能重复使用")
        return {
            "valid": True,
            "status": "consumed",
            "receipt_id": receipt_id,
            "credential_id": row["credential_id"],
            "disclosed_fields": json.loads(row["disclosed_fields_json"]),
            "claims": json.loads(row["claims_json"]),
            "consumed_by": actor,
            "consumed_at": iso(check_at),
            "record_id": record.lastrowid,
        }

    def _reject(self, actor: str, row: sqlite3.Row, status: str, reason: str) -> dict:
        """记录一次失败的消费尝试（仅审计，不生成有效消费记录）。"""
        self.store.audit(actor, "receipt.consume_rejected", "receipt", row["receipt_id"], {"status": status, "reason": reason})
        self.conn.commit()
        return {
            "valid": False,
            "status": status,
            "reason": reason,
            "receipt_id": row["receipt_id"],
            "credential_id": row["credential_id"],
            "consumed_by": row["consumed_by"],
            "consumed_at": row["consumed_at"],
        }

    def _row(self, receipt_id: str) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        if not row:
            raise ApiError(404, "凭条不存在")
        return row

    def _receipt_dict(self, row: sqlite3.Row) -> dict:
        return {
            "receipt_id": row["receipt_id"],
            "credential_id": row["credential_id"],
            "holder_id": row["holder_id"],
            "disclosed_fields": json.loads(row["disclosed_fields_json"]),
            "claims": json.loads(row["claims_json"]),
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "status": row["status"],
            "consumed_by": row["consumed_by"],
            "consumed_at": row["consumed_at"],
        }

    def list_receipts(self) -> list[dict]:
        return [self._receipt_dict(row) for row in self.conn.execute("SELECT * FROM receipts ORDER BY id DESC")]

    def list_records(self) -> list[dict]:
        return [
            {
                "id": row["id"],
                "receipt_id": row["receipt_id"],
                "credential_id": row["credential_id"],
                "verifier": row["verifier"],
                "disclosed_fields": json.loads(row["disclosed_fields_json"]),
                "result": row["result"],
                "consumed_at": row["consumed_at"],
            }
            for row in self.conn.execute("SELECT * FROM receipt_records ORDER BY id DESC")
        ]
