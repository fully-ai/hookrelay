# Changelog

## [0.1.0] - 2026-11-18

### Added
- Multi-tenant tenant/API-key auth (`hr_live_...` SHA-256 hashed keys) and per-tenant sliding-window rate limiter.
- Strict SSRF target validation (`src/hookrelay/ssrf.py`) blocking loopback, RFC1918, link-local/metadata, CGNAT, and redirects.
- Endpoint registry with wildcard event filtering, dual-secret HMAC-SHA256 signing & rotation grace periods, idempotent event ingestion, async retry worker with exponential backoff, Dead Letter Queue (DLQ), and single/bulk replay.
- Web dashboard (`src/hookrelay/static/index.html`) plus official Python (`sdk/python`) and TypeScript (`sdk/typescript`) SDKs.
