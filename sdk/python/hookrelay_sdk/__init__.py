"""Official Python SDK for HookRelay."""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

import httpx


def verify_signature(
    payload: bytes | str,
    header: str,
    secret: str,
    *,
    tolerance_sec: int = 300,
) -> bool:
    """Verify X-HookRelay-Signature header using constant-time HMAC-SHA256 comparison."""
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    pairs: dict[str, list[str]] = {}
    for item in header.split(","):
        if "=" not in item:
            continue
        k, v = item.strip().split("=", 1)
        pairs.setdefault(k, []).append(v)

    ts_list = pairs.get("t", [])
    if not ts_list:
        return False
    try:
        ts = int(ts_list[0])
    except ValueError:
        return False
    if tolerance_sec > 0 and abs(int(time.time()) - ts) > tolerance_sec:
        return False

    expected = hmac.new(secret.encode("utf-8"), f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, cand) for cand in pairs.get("v1", []) + pairs.get("v0", []))


class HookRelayClient:
    def __init__(self, api_url: str, api_key: str, timeout: float = 10.0) -> None:
        self.api_url = api_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.api_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )

    def create_endpoint(self, url: str, event_patterns: list[str] | None = None) -> dict[str, Any]:
        resp = self._client.post(
            "/api/endpoints",
            json={"url": url, "event_patterns": event_patterns or ["*"]},
        )
        resp.raise_for_status()
        return dict(resp.json())

    def publish_event(
        self,
        event_type: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        resp = self._client.post(
            "/api/events",
            json={"event_type": event_type, "payload": payload, "idempotency_key": idempotency_key},
        )
        resp.raise_for_status()
        return dict(resp.json())

    def close(self) -> None:
        self._client.close()
