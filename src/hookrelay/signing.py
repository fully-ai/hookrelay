"""HMAC-SHA256 webhook payload signing and verification."""

from __future__ import annotations

import hashlib
import hmac
import time


def build_signature_header(
    payload: bytes,
    primary_secret: str,
    previous_secret: str | None = None,
    timestamp: int | None = None,
) -> str:
    """Create X-HookRelay-Signature header supporting dual-secret rotation."""
    ts = int(time.time()) if timestamp is None else timestamp
    signed_input = f"{ts}.".encode() + payload
    v1 = hmac.new(primary_secret.encode("utf-8"), signed_input, hashlib.sha256).hexdigest()
    parts = [f"t={ts}", f"v1={v1}"]
    if previous_secret:
        v0 = hmac.new(previous_secret.encode("utf-8"), signed_input, hashlib.sha256).hexdigest()
        parts.append(f"v0={v0}")
    return ",".join(parts)


def verify_signature(
    payload: bytes,
    header: str,
    secret: str,
    *,
    tolerance_sec: int = 300,
    now: int | None = None,
) -> bool:
    """Verify X-HookRelay-Signature against primary or grace-period signature."""
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

    cur = int(time.time()) if now is None else now
    if tolerance_sec > 0 and abs(cur - ts) > tolerance_sec:
        return False

    signed_input = f"{ts}.".encode() + payload
    expected = hmac.new(secret.encode("utf-8"), signed_input, hashlib.sha256).hexdigest()
    candidates = pairs.get("v1", []) + pairs.get("v0", [])
    return any(hmac.compare_digest(expected, cand) for cand in candidates)
