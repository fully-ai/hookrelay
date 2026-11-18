"""Async SQLite storage for multi-tenant webhook delivery, rotation, retries, and DLQ."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite


def utcnow() -> datetime:
    return datetime.now(UTC)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    url TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    event_patterns_json TEXT NOT NULL,
    custom_headers_json TEXT NOT NULL DEFAULT '{}',
    primary_secret TEXT NOT NULL,
    previous_secret TEXT,
    previous_secret_expires_at TEXT,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    base_delay_ms INTEGER NOT NULL DEFAULT 1000,
    backoff_multiplier REAL NOT NULL DEFAULT 2.0,
    timeout_ms INTEGER NOT NULL DEFAULT 5000,
    enabled INTEGER NOT NULL DEFAULT 1,
    health_status TEXT NOT NULL DEFAULT 'healthy',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    idempotency_key TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_events_idemp
    ON events(tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS deliveries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    status TEXT NOT NULL, -- pending | delivered | dlq
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    next_attempt_at TEXT NOT NULL,
    last_status_code INTEGER,
    last_latency_ms REAL,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    id TEXT PRIMARY KEY,
    delivery_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    status_code INTEGER,
    latency_ms REAL NOT NULL,
    response_body TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (delivery_id) REFERENCES deliveries(id) ON DELETE CASCADE
);
"""


class HookRelayDB:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA_SQL)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not initialized")
        return self._conn

    async def create_tenant(self, name: str) -> dict[str, Any]:
        tid = uuid.uuid4().hex
        now = utcnow_iso()
        await self.conn.execute(
            "INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)",
            (tid, name, now),
        )
        raw_key = f"hr_live_{secrets.token_urlsafe(24)}"
        kid = uuid.uuid4().hex
        await self.conn.execute(
            "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (kid, tid, "default", raw_key[:14], hash_api_key(raw_key), now),
        )
        await self.conn.commit()
        return {"id": tid, "name": name, "created_at": now, "api_key": raw_key}

    async def list_tenants(self) -> list[dict[str, Any]]:
        cur = await self.conn.execute("SELECT * FROM tenants ORDER BY created_at DESC")
        return [dict(r) for r in await cur.fetchall()]

    async def resolve_api_key(self, raw_key: str) -> str | None:
        cur = await self.conn.execute(
            "SELECT tenant_id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
            (hash_api_key(raw_key),),
        )
        row = await cur.fetchone()
        return str(row["tenant_id"]) if row else None

    async def create_api_key(self, tenant_id: str, name: str) -> dict[str, Any]:
        raw_key = f"hr_live_{secrets.token_urlsafe(24)}"
        kid = uuid.uuid4().hex
        now = utcnow_iso()
        await self.conn.execute(
            "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (kid, tenant_id, name, raw_key[:14], hash_api_key(raw_key), now),
        )
        await self.conn.commit()
        return {"id": kid, "name": name, "key_prefix": raw_key[:14], "api_key": raw_key, "created_at": now}

    async def list_api_keys(self, tenant_id: str) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT id, name, key_prefix, created_at, revoked_at "
            "FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        )
        return [dict(r) for r in await cur.fetchall()]

    async def revoke_api_key(self, tenant_id: str, key_id: str) -> bool:
        cur = await self.conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL",
            (utcnow_iso(), key_id, tenant_id),
        )
        await self.conn.commit()
        return cur.rowcount > 0

    def _deserialize_endpoint(self, row: aiosqlite.Row) -> dict[str, Any]:
        d = dict(row)
        d["event_patterns"] = json.loads(d.pop("event_patterns_json"))
        d["custom_headers"] = json.loads(d.pop("custom_headers_json"))
        d["enabled"] = bool(d["enabled"])
        return d

    async def create_endpoint(
        self,
        tenant_id: str,
        url: str,
        description: str,
        event_patterns: list[str],
        custom_headers: dict[str, str],
        max_attempts: int,
        base_delay_ms: int,
        backoff_multiplier: float,
        timeout_ms: int,
    ) -> dict[str, Any]:
        eid = uuid.uuid4().hex
        secret = f"whsec_{secrets.token_hex(24)}"
        now = utcnow_iso()
        await self.conn.execute(
            """
            INSERT INTO endpoints (
                id, tenant_id, url, description, event_patterns_json, custom_headers_json,
                primary_secret, max_attempts, base_delay_ms, backoff_multiplier, timeout_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                eid,
                tenant_id,
                url,
                description,
                json.dumps(event_patterns or ["*"]),
                json.dumps(custom_headers),
                secret,
                max_attempts,
                base_delay_ms,
                backoff_multiplier,
                timeout_ms,
                now,
            ),
        )
        await self.conn.commit()
        ep = await self.get_endpoint(tenant_id, eid)
        assert ep is not None
        return ep

    async def get_endpoint(self, tenant_id: str, endpoint_id: str) -> dict[str, Any] | None:
        cur = await self.conn.execute(
            "SELECT * FROM endpoints WHERE id = ? AND tenant_id = ?",
            (endpoint_id, tenant_id),
        )
        row = await cur.fetchone()
        return self._deserialize_endpoint(row) if row else None

    async def list_endpoints(self, tenant_id: str) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM endpoints WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        )
        return [self._deserialize_endpoint(r) for r in await cur.fetchall()]

    async def rotate_endpoint_secret(
        self,
        tenant_id: str,
        endpoint_id: str,
        grace_seconds: int = 3600,
    ) -> dict[str, Any] | None:
        ep = await self.get_endpoint(tenant_id, endpoint_id)
        if ep is None:
            return None
        new_secret = f"whsec_{secrets.token_hex(24)}"
        expires_at = (utcnow() + timedelta(seconds=grace_seconds)).isoformat() if grace_seconds > 0 else None
        prev_secret = ep["primary_secret"] if grace_seconds > 0 else None
        await self.conn.execute(
            """
            UPDATE endpoints
            SET primary_secret = ?, previous_secret = ?, previous_secret_expires_at = ?
            WHERE id = ? AND tenant_id = ?
            """,
            (new_secret, prev_secret, expires_at, endpoint_id, tenant_id),
        )
        await self.conn.commit()
        return await self.get_endpoint(tenant_id, endpoint_id)

    async def delete_endpoint(self, tenant_id: str, endpoint_id: str) -> bool:
        cur = await self.conn.execute("DELETE FROM endpoints WHERE id = ? AND tenant_id = ?", (endpoint_id, tenant_id))
        await self.conn.commit()
        return cur.rowcount > 0

    async def publish_event(
        self,
        tenant_id: str,
        event_type: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], int, bool]:
        if idempotency_key:
            cur = await self.conn.execute(
                "SELECT * FROM events WHERE tenant_id = ? AND idempotency_key = ?",
                (tenant_id, idempotency_key),
            )
            existing = await cur.fetchone()
            if existing:
                return dict(existing), 0, True

        ev_id = uuid.uuid4().hex
        now = utcnow_iso()
        payload_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        await self.conn.execute(
            "INSERT INTO events (id, tenant_id, event_type, payload_json, idempotency_key, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ev_id, tenant_id, event_type, payload_str, idempotency_key, now),
        )

        endpoints = await self.list_endpoints(tenant_id)
        queued = 0
        for ep in endpoints:
            if not ep["enabled"]:
                continue
            if any(fnmatch.fnmatchcase(event_type, pat) for pat in ep["event_patterns"]):
                did = uuid.uuid4().hex
                await self.conn.execute(
                    """
                    INSERT INTO deliveries (
                        id, tenant_id, event_id, endpoint_id, status, attempt_count,
                        max_attempts, next_attempt_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)
                    """,
                    (did, tenant_id, ev_id, ep["id"], ep["max_attempts"], now, now, now),
                )
                queued += 1

        await self.conn.commit()
        ev_doc = {
            "id": ev_id,
            "tenant_id": tenant_id,
            "event_type": event_type,
            "idempotency_key": idempotency_key,
            "created_at": now,
        }
        return (ev_doc, queued, False)

    async def list_events(self, tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
            (tenant_id, limit),
        )
        return [dict(r) for r in await cur.fetchall()]

    async def fetch_due_deliveries(self, limit: int = 20) -> list[dict[str, Any]]:
        now = utcnow_iso()
        cur = await self.conn.execute(
            """
            SELECT d.*, e.event_type, e.payload_json,
                   ep.url, ep.custom_headers_json, ep.primary_secret,
                   ep.previous_secret, ep.previous_secret_expires_at,
                   ep.base_delay_ms, ep.backoff_multiplier, ep.timeout_ms
            FROM deliveries d
            JOIN events e ON e.id = d.event_id
            JOIN endpoints ep ON ep.id = d.endpoint_id
            WHERE d.status = 'pending' AND d.next_attempt_at <= ?
            ORDER BY d.next_attempt_at ASC
            LIMIT ?
            """,
            (now, limit),
        )
        rows = [dict(r) for r in await cur.fetchall()]
        for r in rows:
            r["custom_headers"] = json.loads(r.pop("custom_headers_json"))
        return rows

    async def record_delivery_result(
        self,
        delivery: dict[str, Any],
        *,
        success: bool,
        status_code: int | None,
        latency_ms: float,
        response_body: str,
        error_message: str,
    ) -> str:
        attempt_no = int(delivery["attempt_count"]) + 1
        now = utcnow_iso()
        await self.conn.execute(
            """
            INSERT INTO delivery_attempts (
                id, delivery_id, attempt_number, status_code, latency_ms, response_body, error_message, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                delivery["id"],
                attempt_no,
                status_code,
                latency_ms,
                response_body[:2048],
                error_message[:500],
                now,
            ),
        )

        if success:
            new_status = "delivered"
            next_at = now
            await self.conn.execute(
                "UPDATE endpoints SET health_status = 'healthy', consecutive_failures = 0 WHERE id = ?",
                (delivery["endpoint_id"],),
            )
        elif attempt_no >= int(delivery["max_attempts"]):
            new_status = "dlq"
            next_at = now
            await self.conn.execute(
                "UPDATE endpoints SET consecutive_failures = consecutive_failures + 1, "
                "health_status = 'circuit_open' WHERE id = ?",
                (delivery["endpoint_id"],),
            )
        else:
            new_status = "pending"
            delay_ms = float(delivery["base_delay_ms"]) * (float(delivery["backoff_multiplier"]) ** (attempt_no - 1))
            next_at = (utcnow() + timedelta(milliseconds=min(delay_ms, 300_000.0))).isoformat()
            await self.conn.execute(
                "UPDATE endpoints SET consecutive_failures = consecutive_failures + 1, "
                "health_status = 'degraded' WHERE id = ?",
                (delivery["endpoint_id"],),
            )

        await self.conn.execute(
            """
            UPDATE deliveries
            SET status = ?, attempt_count = ?, next_attempt_at = ?,
                last_status_code = ?, last_latency_ms = ?, last_error = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_status, attempt_no, next_at, status_code, latency_ms, error_message[:500], now, delivery["id"]),
        )
        await self.conn.commit()
        return new_status

    async def list_deliveries(
        self, tenant_id: str, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if status:
            cur = await self.conn.execute(
                """
                SELECT d.*, e.event_type, ep.url
                FROM deliveries d
                JOIN events e ON e.id = d.event_id
                JOIN endpoints ep ON ep.id = d.endpoint_id
                WHERE d.tenant_id = ? AND d.status = ?
                ORDER BY d.updated_at DESC LIMIT ?
                """,
                (tenant_id, status, limit),
            )
        else:
            cur = await self.conn.execute(
                """
                SELECT d.*, e.event_type, ep.url
                FROM deliveries d
                JOIN events e ON e.id = d.event_id
                JOIN endpoints ep ON ep.id = d.endpoint_id
                WHERE d.tenant_id = ?
                ORDER BY d.updated_at DESC LIMIT ?
                """,
                (tenant_id, limit),
            )
        return [dict(r) for r in await cur.fetchall()]

    async def get_delivery_attempts(self, tenant_id: str, delivery_id: str) -> list[dict[str, Any]] | None:
        cur = await self.conn.execute(
            "SELECT id FROM deliveries WHERE id = ? AND tenant_id = ?",
            (delivery_id, tenant_id),
        )
        if await cur.fetchone() is None:
            return None
        cur2 = await self.conn.execute(
            "SELECT * FROM delivery_attempts WHERE delivery_id = ? ORDER BY attempt_number ASC",
            (delivery_id,),
        )
        return [dict(r) for r in await cur2.fetchall()]

    async def replay_delivery(self, tenant_id: str, delivery_id: str) -> bool:
        now = utcnow_iso()
        cur = await self.conn.execute(
            """
            UPDATE deliveries
            SET status = 'pending', next_attempt_at = ?, attempt_count = 0, updated_at = ?
            WHERE id = ? AND tenant_id = ?
            """,
            (now, now, delivery_id, tenant_id),
        )
        await self.conn.commit()
        return cur.rowcount > 0

    async def replay_dlq(self, tenant_id: str) -> int:
        now = utcnow_iso()
        cur = await self.conn.execute(
            """
            UPDATE deliveries
            SET status = 'pending', next_attempt_at = ?, attempt_count = 0, updated_at = ?
            WHERE tenant_id = ? AND status = 'dlq'
            """,
            (now, now, tenant_id),
        )
        await self.conn.commit()
        return cur.rowcount

    async def tenant_stats(self, tenant_id: str) -> dict[str, Any]:
        cur = await self.conn.execute(
            "SELECT status, COUNT(*) AS cnt FROM deliveries WHERE tenant_id = ? GROUP BY status",
            (tenant_id,),
        )
        counts = {"pending": 0, "delivered": 0, "dlq": 0}
        for row in await cur.fetchall():
            counts[str(row["status"])] = int(row["cnt"])
        cur2 = await self.conn.execute(
            "SELECT AVG(last_latency_ms) AS avg_lat FROM deliveries WHERE tenant_id = ? AND status = 'delivered'",
            (tenant_id,),
        )
        avg_row = await cur2.fetchone()
        avg_val = avg_row["avg_lat"] if avg_row else None
        return {
            **counts,
            "avg_latency_ms": round(float(avg_val), 2) if avg_val is not None else 0.0,
        }
