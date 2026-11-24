"""Thread-safe per-provider rate limiting."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateLimiter:
    """Spaces calls evenly so that at most ``calls`` happen per ``period`` seconds.

    Each caller reserves the next free slot under a lock and then sleeps outside it,
    so concurrent workers queue up fairly without holding the lock while waiting.
    """

    def __init__(
        self,
        calls: int,
        period: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if calls <= 0 or period <= 0:
            raise ValueError("calls and period must be positive")
        self.interval = period / calls
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_slot = 0.0

    def wait(self) -> float:
        """Block until the caller may proceed; returns the time slept."""
        with self._lock:
            now = self._clock()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self.interval
        delay = slot - now
        if delay > 0:
            self._sleep(delay)
        return delay
