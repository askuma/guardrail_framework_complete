"""
Token-bucket rate limiter used by the RATE_LIMIT guardrail action.

One bucket is maintained per (policy_id, user_id) pair.
Bucket capacity and refill rate are derived from the policy rule
  "max_requests_per_minute" (default: 60).
"""

import threading
import time
from typing import Dict, Optional


class TokenBucket:
    """Thread-safe token bucket."""

    __slots__ = ("capacity", "refill_rate", "_tokens", "_last", "_lock")

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate          # tokens added per second
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, n: int = 1) -> bool:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self.capacity,
                self._tokens + (now - self._last) * self.refill_rate,
            )
            self._last = now
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    @property
    def available(self) -> float:
        with self._lock:
            return self._tokens


class PolicyRateLimiter:
    """
    Per-(policy, user) rate limiting.

    Usage::
        limiter = PolicyRateLimiter()
        allowed = limiter.check(policy_id="…", user_id="u1", max_per_minute=60)
        if not allowed:
            # return RATE_LIMIT result
    """

    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def check(
        self,
        policy_id: str,
        user_id: Optional[str],
        max_per_minute: int = 60,
    ) -> bool:
        key = f"{policy_id}:{user_id or '__anon__'}"
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(
                    capacity=max_per_minute,
                    refill_rate=max_per_minute / 60.0,
                )
        return self._buckets[key].consume()

    def purge_stale(self):
        """Remove buckets for inactive users to prevent unbounded memory growth."""
        with self._lock:
            self._buckets.clear()


# Module-level singleton shared across all guardrail checks
policy_rate_limiter = PolicyRateLimiter()
