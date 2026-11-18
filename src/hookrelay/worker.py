"""Async background delivery worker with SSRF protection, HMAC signing, and backoff."""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from hookrelay.db import HookRelayDB
from hookrelay.signing import build_signature_header
from hookrelay.ssrf import SSRFBlockedError, validate_webhook_target


class DeliveryWorker:
    def __init__(
        self,
        db: HookRelayDB,
        *,
        allow_private_targets: bool = False,
        poll_interval_sec: float = 0.25,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.db = db
        self.allow_private_targets = allow_private_targets
        self.poll_interval_sec = poll_interval_sec
        self._client = httpx.AsyncClient(follow_redirects=False, transport=transport)
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.live_events: list[dict[str, Any]] = []

    def start(self) -> None:
        if self._task is None:
            self._stop_event.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        await self._client.aclose()

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                processed = await self.process_due_once()
                if processed == 0:
                    await asyncio.sleep(self.poll_interval_sec)
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(self.poll_interval_sec)

    async def process_due_once(self, batch_size: int = 20) -> int:
        due = await self.db.fetch_due_deliveries(limit=batch_size)
        for job in due:
            await self._dispatch_job(job)
        return len(due)

    async def _dispatch_job(self, job: dict[str, Any]) -> None:
        payload_bytes = str(job["payload_json"]).encode("utf-8")
        prev_secret: str | None = job.get("previous_secret")
        exp = job.get("previous_secret_expires_at")
        if prev_secret and exp:
            try:
                if datetime.now(UTC) > datetime.fromisoformat(str(exp)):
                    prev_secret = None
            except ValueError:
                prev_secret = None

        sig_header = build_signature_header(
            payload_bytes,
            str(job["primary_secret"]),
            previous_secret=prev_secret,
        )
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "HookRelay/0.1.0",
            "X-HookRelay-Event": str(job["event_type"]),
            "X-HookRelay-Delivery": str(job["id"]),
            "X-HookRelay-Signature": sig_header,
        }
        for k, v in (job.get("custom_headers") or {}).items():
            if str(k).lower() not in {"host", "content-length", "x-hookrelay-signature"}:
                headers[str(k)] = str(v)

        t0 = time.perf_counter()
        status_code: int | None = None
        body_text = ""
        err_msg = ""
        success = False

        try:
            # Re-verify target right before outbound connection to defeat DNS rebinding
            target_url = validate_webhook_target(str(job["url"]), allow_private=self.allow_private_targets)
            timeout_s = max(0.5, float(job["timeout_ms"]) / 1000.0)
            resp = await self._client.post(target_url, content=payload_bytes, headers=headers, timeout=timeout_s)
            status_code = resp.status_code
            body_text = resp.text[:2048]
            success = 200 <= resp.status_code < 300
            if not success:
                err_msg = f"HTTP {resp.status_code}"
        except SSRFBlockedError as exc:
            err_msg = f"SSRF blocked: {exc}"
        except Exception as exc:
            err_msg = str(exc)

        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        final_state = await self.db.record_delivery_result(
            job,
            success=success,
            status_code=status_code,
            latency_ms=latency_ms,
            response_body=body_text,
            error_message=err_msg,
        )
        self.live_events.append(
            {
                "delivery_id": job["id"],
                "event_type": job["event_type"],
                "status": final_state,
                "status_code": status_code,
                "latency_ms": latency_ms,
            }
        )
        if len(self.live_events) > 200:
            self.live_events = self.live_events[-200:]
