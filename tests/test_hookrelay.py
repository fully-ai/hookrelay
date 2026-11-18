"""Integration tests for HookRelay multi-tenancy, SSRF guard, HMAC rotation, retry/DLQ, replay, and SDKs."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))
from hookrelay_sdk import verify_signature  # noqa: E402

from hookrelay.app import create_app
from hookrelay.config import Settings
from hookrelay.ssrf import SSRFBlockedError, validate_webhook_target


def test_ssrf_blocks_private_loopback_and_metadata_targets() -> None:
    for bad in [
        "http://127.0.0.1:8080/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.15/internal",
        "http://192.168.1.1/admin",
        "http://localhost:9000/hook",
        "ftp://example.com/file",
    ]:
        with pytest.raises(SSRFBlockedError):
            validate_webhook_target(bad, allow_private=False)


def test_multi_tenant_delivery_hmac_rotation_retry_dlq_and_replay(tmp_path: Path) -> None:
    received: list[dict[str, object]] = []
    fail_target = True

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/fail" and fail_target:
            return httpx.Response(503, text="upstream unavailable")
        received.append(
            {
                "path": request.url.path,
                "sig": request.headers.get("X-HookRelay-Signature", ""),
                "event": request.headers.get("X-HookRelay-Event", ""),
                "body": request.content,
            }
        )
        return httpx.Response(200, json={"received": True})

    cfg = Settings(
        data_dir=tmp_path / "hr",
        admin_token="admin-secret-test",
        allow_private_targets=True,
    )
    app = create_app(cfg, delivery_transport=httpx.MockTransport(mock_handler), start_worker=False)

    with TestClient(app) as tc:
        # 1. Create two tenants and ensure tenant isolation
        t1 = tc.post("/api/tenants", headers={"X-Admin-Token": "admin-secret-test"}, json={"name": "acme"}).json()
        t2 = tc.post("/api/tenants", headers={"X-Admin-Token": "admin-secret-test"}, json={"name": "globex"}).json()
        h1 = {"Authorization": f"Bearer {t1['api_key']}"}
        h2 = {"Authorization": f"Bearer {t2['api_key']}"}

        # 2. Register endpoint with event pattern and rotate secret (dual-secret grace period)
        ep_ok = tc.post(
            "/api/endpoints",
            headers=h1,
            json={"url": "https://hooks.example.test/ok", "event_patterns": ["order.*"]},
        ).json()
        old_secret = ep_ok["primary_secret"]
        rotated = tc.post(
            f"/api/endpoints/{ep_ok['id']}/rotate-secret",
            headers=h1,
            json={"grace_seconds": 3600},
        ).json()
        new_secret = rotated["primary_secret"]
        assert new_secret != old_secret

        # Register failing endpoint with max_attempts=1 so first failure sends it straight to DLQ
        tc.post(
            "/api/endpoints",
            headers=h1,
            json={
                "url": "https://hooks.example.test/fail",
                "event_patterns": ["order.created"],
                "max_attempts": 1,
                "base_delay_ms": 50,
            },
        )

        # 3. Publish event with idempotency key (second call must deduplicate)
        ev1 = tc.post(
            "/api/events",
            headers=h1,
            json={"event_type": "order.created", "payload": {"id": 42}, "idempotency_key": "idem-42"},
        ).json()
        assert ev1["queued_deliveries"] == 2
        assert ev1["deduplicated"] is False

        ev_dup = tc.post(
            "/api/events",
            headers=h1,
            json={"event_type": "order.created", "payload": {"id": 42}, "idempotency_key": "idem-42"},
        ).json()
        assert ev_dup["deduplicated"] is True

        # Tenant 2 cannot see Tenant 1's endpoints
        assert tc.get("/api/endpoints", headers=h2).json()["endpoints"] == []

        # 4. Flush worker once
        assert tc.post("/api/worker/flush", headers=h1).json()["processed"] == 2

        # Verify delivered payload signed with BOTH primary (v1) and previous (v0) secrets via SDK
        assert len(received) == 1
        rec = received[0]
        body_bytes = rec["body"]
        assert isinstance(body_bytes, bytes)
        sig_hdr = str(rec["sig"])
        assert verify_signature(body_bytes, sig_hdr, new_secret) is True
        assert verify_signature(body_bytes, sig_hdr, old_secret) is True
        assert json.loads(body_bytes.decode("utf-8")) == {"id": 42}

        # Confirm failed endpoint landed in DLQ and attempt body is captured
        dlq_list = tc.get("/api/deliveries?status=dlq", headers=h1).json()["deliveries"]
        assert len(dlq_list) == 1
        attempts = tc.get(f"/api/deliveries/{dlq_list[0]['id']}/attempts", headers=h1).json()["attempts"]
        assert attempts[0]["status_code"] == 503
        assert "unavailable" in attempts[0]["response_body"]

        # 5. Replay DLQ after upstream recovers
        fail_target = False
        replayed = tc.post("/api/dlq/replay", headers=h1).json()
        assert replayed["requeued"] == 1
        assert tc.post("/api/worker/flush", headers=h1).json()["processed"] == 1
        stats = tc.get("/api/stats", headers=h1).json()
        assert stats["delivered"] == 2
        assert stats["dlq"] == 0
