"""Strict SSRF validator for outbound webhook target URLs."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFBlockedError(ValueError):
    """Raised when a target URL resolves to a restricted or non-HTTP(S) destination."""


def _is_forbidden_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    # Explicitly guard IPv4 CGNAT (100.64.0.0/10)
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False


def validate_webhook_target(url: str, *, allow_private: bool = False) -> str:
    """Validate scheme, hostname, and resolved IP addresses before registering or dispatching."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise SSRFBlockedError(f"Unsupported webhook scheme '{parsed.scheme}'; only http/https allowed")
    if not parsed.hostname:
        raise SSRFBlockedError("Webhook URL missing hostname")
    if parsed.username or parsed.password:
        raise SSRFBlockedError("Embedded URL credentials are not permitted")

    if allow_private:
        return url.strip()

    host = parsed.hostname.strip("[]")
    if host.lower() in {"localhost", "metadata.google.internal", "metadata"}:
        raise SSRFBlockedError(f"Blocked internal hostname '{host}'")

    # Direct IP literal check first
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if _is_forbidden_ip(host):
            raise SSRFBlockedError(f"Target IP '{host}' is in a restricted/private range")
        return url.strip()

    # Resolve hostname and reject if any resolved record is private/loopback/link-local
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"Failed to resolve webhook hostname '{host}': {exc}") from exc

    if not infos:
        raise SSRFBlockedError(f"Hostname '{host}' resolved to zero addresses")

    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        if _is_forbidden_ip(addr):
            raise SSRFBlockedError(f"Resolved IP '{addr}' for '{host}' is in a restricted/private range")

    return url.strip()
