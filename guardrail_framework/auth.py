"""
API key authentication middleware.

Keys are loaded from the GUARDRAIL_API_KEYS env var (comma-separated).
Set GUARDRAIL_AUTH_ENABLED=false to disable auth (dev only).

Example::
    GUARDRAIL_API_KEYS=key1,key2
    GUARDRAIL_AUTH_ENABLED=true
"""

import logging
import os
import secrets
from typing import Set

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("auth")

# Paths that never require the X-API-Key header from this middleware.
# /push/events is included because the native browser EventSource API cannot
# send custom headers. Auth is enforced inside the route handler via the
# mandatory ?api_key= query parameter instead.
_PUBLIC_PATHS: Set[str] = {
    "/health",
    "/ready",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/metrics/prometheus",   # Prometheus scrape — secure at network level
    "/push/events",          # auth handled in route handler via ?api_key= query param
}


def load_api_keys() -> Set[str]:
    raw = os.getenv("GUARDRAIL_API_KEYS", "").strip()
    if not raw:
        key = secrets.token_hex(32)
        logger.warning("GUARDRAIL_API_KEYS not configured — generated ephemeral key for this process.")
        # Print directly to stderr so the key bypasses log shippers (Datadog, CloudWatch, etc.)
        import sys
        print(f"  Ephemeral API key: {key}", file=sys.stderr)
        print("  Set GUARDRAIL_API_KEYS=<key> in your environment to make it persistent.", file=sys.stderr)
        return {key}
    keys = {k.strip() for k in raw.split(",") if k.strip()}
    logger.info(f"Loaded {len(keys)} API key(s) from environment.")
    return keys


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated requests with 401."""

    def __init__(self, app, api_keys: Set[str], enabled: bool = True):
        super().__init__(app)
        self._keys = api_keys
        self._enabled = enabled

    async def dispatch(self, request: Request, call_next):
        if not self._enabled:
            return await call_next(request)

        path = request.url.path
        if path in _PUBLIC_PATHS:
            return await call_next(request)

        key = request.headers.get("X-API-Key")
        if not key or key not in self._keys:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid API key. Pass it in the X-API-Key header."},
            )
        return await call_next(request)
