from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class RateLimiter:
    """Simple, process-local rate limiter.

    This intentionally stays basic (no jitter, no token bucket) to be easy to understand and
    replicate.
    """

    requests_per_second: float = 1.0
    _next_allowed_at: float = 0.0

    def wait(self) -> None:
        if self.requests_per_second <= 0:
            return
        now = time.monotonic()
        if now < self._next_allowed_at:
            time.sleep(self._next_allowed_at - now)
        self._next_allowed_at = time.monotonic() + (1.0 / self.requests_per_second)
