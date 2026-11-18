"""FastAPI application for HookRelay multi-tenant webhook delivery."""

from __future__ import annotations

import asyncio
import hmac
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from hookrelay.config import Settings
from hookrelay.db import HookRelayDB
from hookrelay.ssrf import SSRFBlockedError, validate_webhook_target
from hookrelay.worker import DeliveryWorker

STATIC_DIR = Path(__file__).parent / "static"


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64)


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class EndpointCreate(BaseModel):
    url: str = Field(min_length=8, max_length=1024)
    description: str = Field(default="", max_length=300)
    event_patterns: list[str] = Field(default_factory=lambda: ["*"])
    custom_headers: dict[str, str] = Field(default_factory=dict)
    max_attempts: int = Field(default=5, ge=1, le=20)
    base_delay_ms: int = Field(default=500, ge=50, le=60000)
    backoff_multiplier: float = Field(default=2.0, ge=1.0, le=10.0)
    timeout_ms: int = Field(default=5000, ge=500, le=30000)


class RotateSecretRequest(BaseModel):
    grace_seconds: int = Field(default=3600, ge=0, le=604800)


class EventPublish(BaseModel):
    event_type: str = Field(min_length=1, max_length=120)
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=128)


class SlidingRateLimiter:
    def __init__(self, limit_per_min: int) -> None:
        self.limit = limit_per_min
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > 60.0:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


def create_app(
    settings: Settings | None = None,
    *,
    delivery_transport: httpx.AsyncBaseTransport | None = None,
    start_worker: bool = True,
) -> FastAPI:
    cfg = settings or Settings()
    cfg.ensure_directories()
    db = HookRelayDB(cfg.db_path)
    worker = DeliveryWorker(
        db,
        allow_private_targets=cfg.allow_private_targets,
        poll_interval_sec=cfg.worker_poll_interval_sec,
        transport=delivery_transport,
    )
    limiter = SlidingRateLimiter(cfg.rate_limit_per_min)

    @asynccontextmanager
    async def lifespan(app_inst: FastAPI) -> AsyncIterator[None]:
        await db.connect()
        if start_worker:
            worker.start()
        app_inst.state.db = db
        app_inst.state.worker = worker
        try:
            yield
        finally:
            await worker.stop()
            await db.close()

    app = FastAPI(title="HookRelay", version="0.1.0", lifespan=lifespan)

    def require_admin(x_admin_token: str = Header(default="")) -> None:
        if not x_admin_token or not hmac.compare_digest(x_admin_token, cfg.admin_token):
            raise HTTPException(status_code=401, detail="Invalid X-Admin-Token")

    async def require_tenant(authorization: str = Header(default="")) -> str:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer API key")
        raw_key = authorization[7:].strip()
        tenant_id = await db.resolve_api_key(raw_key)
        if tenant_id is None:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")
        if not limiter.allow(tenant_id):
            raise HTTPException(status_code=429, detail="Tenant rate limit exceeded")
        return tenant_id

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/tenants", status_code=201, dependencies=[Depends(require_admin)])
    async def create_tenant(req: TenantCreate) -> dict[str, Any]:
        try:
            return await db.create_tenant(req.name.strip())
        except Exception as exc:
            raise HTTPException(status_code=409, detail="Tenant name already exists") from exc

    @app.get("/api/tenants", dependencies=[Depends(require_admin)])
    async def list_tenants() -> dict[str, Any]:
        return {"tenants": await db.list_tenants()}

    @app.get("/api/api-keys")
    async def list_keys(tenant_id: str = Depends(require_tenant)) -> dict[str, Any]:
        return {"api_keys": await db.list_api_keys(tenant_id)}

    @app.post("/api/api-keys", status_code=201)
    async def create_key(req: ApiKeyCreate, tenant_id: str = Depends(require_tenant)) -> dict[str, Any]:
        return await db.create_api_key(tenant_id, req.name.strip())

    @app.delete("/api/api-keys/{key_id}")
    async def revoke_key(key_id: str, tenant_id: str = Depends(require_tenant)) -> dict[str, str]:
        if not await db.revoke_api_key(tenant_id, key_id):
            raise HTTPException(status_code=404, detail="API key not found")
        return {"status": "revoked"}

    @app.get("/api/endpoints")
    async def list_endpoints(tenant_id: str = Depends(require_tenant)) -> dict[str, Any]:
        eps = await db.list_endpoints(tenant_id)
        for ep in eps:
            ep["secret_preview"] = str(ep.pop("primary_secret"))[:12] + "..."
            ep.pop("previous_secret", None)
        return {"endpoints": eps}

    @app.post("/api/endpoints", status_code=201)
    async def create_endpoint(req: EndpointCreate, tenant_id: str = Depends(require_tenant)) -> dict[str, Any]:
        try:
            safe_url = validate_webhook_target(req.url, allow_private=cfg.allow_private_targets)
        except SSRFBlockedError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return await db.create_endpoint(
            tenant_id=tenant_id,
            url=safe_url,
            description=req.description,
            event_patterns=req.event_patterns,
            custom_headers=req.custom_headers,
            max_attempts=req.max_attempts,
            base_delay_ms=req.base_delay_ms,
            backoff_multiplier=req.backoff_multiplier,
            timeout_ms=req.timeout_ms,
        )

    @app.post("/api/endpoints/{endpoint_id}/rotate-secret")
    async def rotate_secret(
        endpoint_id: str,
        req: RotateSecretRequest,
        tenant_id: str = Depends(require_tenant),
    ) -> dict[str, Any]:
        ep = await db.rotate_endpoint_secret(tenant_id, endpoint_id, grace_seconds=req.grace_seconds)
        if ep is None:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return ep

    @app.delete("/api/endpoints/{endpoint_id}")
    async def delete_endpoint(endpoint_id: str, tenant_id: str = Depends(require_tenant)) -> dict[str, str]:
        if not await db.delete_endpoint(tenant_id, endpoint_id):
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return {"status": "deleted"}

    @app.post("/api/events", status_code=202)
    async def publish_event(
        req: EventPublish,
        tenant_id: str = Depends(require_tenant),
        idempotency_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        idem = req.idempotency_key or idempotency_key
        ev, queued, deduplicated = await db.publish_event(tenant_id, req.event_type, req.payload, idem)
        return {"event": ev, "queued_deliveries": queued, "deduplicated": deduplicated}

    @app.get("/api/events")
    async def list_events(tenant_id: str = Depends(require_tenant)) -> dict[str, Any]:
        return {"events": await db.list_events(tenant_id)}

    @app.get("/api/deliveries")
    async def list_deliveries(status: str | None = None, tenant_id: str = Depends(require_tenant)) -> dict[str, Any]:
        return {"deliveries": await db.list_deliveries(tenant_id, status=status)}

    @app.get("/api/deliveries/{delivery_id}/attempts")
    async def delivery_attempts(delivery_id: str, tenant_id: str = Depends(require_tenant)) -> dict[str, Any]:
        attempts = await db.get_delivery_attempts(tenant_id, delivery_id)
        if attempts is None:
            raise HTTPException(status_code=404, detail="Delivery not found")
        return {"attempts": attempts}

    @app.post("/api/deliveries/{delivery_id}/replay")
    async def replay_delivery(delivery_id: str, tenant_id: str = Depends(require_tenant)) -> dict[str, str]:
        if not await db.replay_delivery(tenant_id, delivery_id):
            raise HTTPException(status_code=404, detail="Delivery not found")
        return {"status": "requeued"}

    @app.post("/api/dlq/replay")
    async def replay_dlq(tenant_id: str = Depends(require_tenant)) -> dict[str, int]:
        count = await db.replay_dlq(tenant_id)
        return {"requeued": count}

    @app.post("/api/worker/flush")
    async def flush_worker(tenant_id: str = Depends(require_tenant)) -> dict[str, int]:
        _ = tenant_id
        processed = await worker.process_due_once()
        return {"processed": processed}

    @app.get("/api/stats")
    async def stats(tenant_id: str = Depends(require_tenant)) -> dict[str, Any]:
        return await db.tenant_stats(tenant_id)

    @app.get("/api/stream")
    async def stream_deliveries(request: Request, tenant_id: str = Depends(require_tenant)) -> StreamingResponse:
        _ = tenant_id

        async def gen() -> AsyncIterator[str]:
            seen = len(worker.live_events)
            yield f"data: {{\"connected\": true, \"recent\": {seen}}}\n\n"
            for _ in range(20):
                if await request.is_disconnected():
                    break
                if len(worker.live_events) > seen:
                    for ev in worker.live_events[seen:]:
                        import json

                        yield f"data: {json.dumps(ev)}\n\n"
                    seen = len(worker.live_events)
                await asyncio.sleep(0.5)

        return StreamingResponse(gen(), media_type="text/event-stream")

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app
