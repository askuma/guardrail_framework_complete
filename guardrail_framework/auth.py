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

# Paths that never require auth
_PUBLIC_PATHS: Set[str] = {
    "/health",
    "/ready",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/metrics/prometheus",   # Prometheus scrape — secure at network level
}

# SSE endpoint: browsers cannot set custom headers on EventSource.
# Secure this at the reverse-proxy / network level in production.
_SSE_PATH = "/push/events"


def load_api_keys() -> Set[str]:
    raw = os.getenv("GUARDRAIL_API_KEYS", "").strip()
    if not raw:
        key = secrets.token_hex(32)
        logger.warning("GUARDRAIL_API_KEYS not configured — generated ephemeral key for this process.")
        logger.warning(f"  Key: {key}")
        logger.warning("  Set GUARDRAIL_API_KEYS=<key> in your environment to make it persistent.")
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
        if path in _PUBLIC_PATHS or path == _SSE_PATH:
            return await call_next(request)

        key = (
            request.headers.get("X-API-Key")
            or request.query_params.get("api_key")
        )
        if not key or key not in self._keys:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid API key. Pass it in the X-API-Key header."},
            )
        return await call_next(request)
