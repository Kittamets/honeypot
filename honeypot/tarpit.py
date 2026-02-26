"""
Tarpit / progressive-delay middleware.

Every request from the same source IP is tracked within a rolling time window.
After a configurable free-request threshold, each additional request incurs an
exponentially growing async sleep — starving automated scanners without blocking
the aiohttp event loop for other connections.

Delay schedule example (base=1s, multiplier=2.5, threshold=3, max=30s):
  Requests 1-3 : 0 s  (free pass)
  Request 4    : 1.0 s
  Request 5    : 2.5 s
  Request 6    : 6.3 s
  Request 7    : 15.6 s
  Request 8+   : 30 s  (cap)
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

logger = logging.getLogger("honeypot")


class TarpitMiddleware:
    def __init__(self, config: dict):
        t = config["tarpit"]
        self.base_delay: float       = float(t["base_delay"])
        self.multiplier: float       = float(t["multiplier"])
        self.max_delay: float        = float(t["max_delay"])
        self.window_seconds: int     = int(t["window_seconds"])
        self.post_delay: float       = float(t["post_delay"])
        self.threshold: int          = int(t.get("threshold", 3))

        # {ip: [request_timestamps]}  — kept in memory only (resets on restart)
        self._history: Dict[str, List[datetime]] = defaultdict(list)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _prune(self, ip: str) -> None:
        """Remove timestamps older than the rolling window."""
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
        self._history[ip] = [ts for ts in self._history[ip] if ts > cutoff]

    def _count(self, ip: str) -> int:
        self._prune(ip)
        return len(self._history[ip])

    # ── public API ────────────────────────────────────────────────────────────

    def record(self, ip: str) -> None:
        """Call once per incoming request before computing the delay."""
        self._prune(ip)
        self._history[ip].append(datetime.utcnow())

    def delay_seconds(self, ip: str) -> float:
        """
        Return the number of seconds to sleep for this IP's current request.
        Does NOT record the request — call record() first.
        """
        count = self._count(ip)
        if count <= self.threshold:
            return 0.0
        effective = count - self.threshold          # requests beyond free threshold
        delay = self.base_delay * (self.multiplier ** (effective - 1))
        return min(delay, self.max_delay)

    async def apply_delay(self, ip: str, method: str = "GET") -> None:
        """
        Record the request and sleep the appropriate amount.
        Uses asyncio.sleep — non-blocking, other connections continue normally.
        """
        self.record(ip)

        if method.upper() == "POST":
            # Always delay POST requests (simulate authentication processing)
            logger.debug(f"Tarpit POST delay {self.post_delay}s for {ip}")
            await asyncio.sleep(self.post_delay)
            return

        wait = self.delay_seconds(ip)
        if wait > 0:
            logger.debug(f"Tarpit delay {wait:.1f}s for {ip} ({self._count(ip)} reqs in window)")
            await asyncio.sleep(wait)
