# HookRelay Architecture

1. **Multi-Tenant API (`src/hookrelay/app.py`)**: Authenticates tenant requests using SHA-256 hashed Bearer API keys (`hr_live_...`), applies per-tenant sliding-window rate limits, deduplicates events by `(tenant_id, idempotency_key)`, and matches endpoint wildcard event patterns.
2. **SSRF Guard (`src/hookrelay/ssrf.py`)**: Validates schemes (`http`/`https`), resolves DNS, rejects loopback/RFC1918/link-local/CGNAT/multicast/metadata IPs both at endpoint creation and immediately prior to outbound dispatch, and disables HTTP redirects (`follow_redirects=False`).
3. **Async Worker & DLQ (`src/hookrelay/worker.py`, `db.py`)**: Polls pending SQLite deliveries, signs payloads with dual-secret HMAC-SHA256 (`X-HookRelay-Signature`), records attempt latency & HTTP response previews, schedules exponential backoff retries, transitions exhausted deliveries to DLQ, and updates endpoint health state (`healthy`, `degraded`, `circuit_open`).
