# Security Policy

## Reporting a Vulnerability

Please report security issues responsibly via GitHub Security Advisories without publicly disclosing exploit vectors prior to remediation.

## SSRF & Delivery Security Controls

1. **Outbound Target Validation (`src/hookrelay/ssrf.py`):** Every registered webhook URL and every outbound delivery resolves DNS and rejects loopback, RFC1918 private networks, link-local / cloud metadata (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), multicast, and non-HTTP(S) schemes unless `HOOKRELAY_ALLOW_PRIVATE_TARGETS=true` is explicitly enabled for local testing.
2. **Redirect Blocking:** Outbound `httpx` client enforces `follow_redirects=False` so a public URL cannot 302-redirect into internal infrastructure.
3. **Cryptographic Signing & Dual-Secret Rotation:** Deliveries carry `X-HookRelay-Signature: t=<ts>,v1=<hmac_sha256>` (plus `v0=` during secret rotation grace periods) using constant-time verification in both Python and TypeScript SDKs.
4. **Hashed Tenant API Keys:** Tenant API keys are stored as SHA-256 hashes in SQLite.
