"""
In-memory rate limiter for public leaderboard endpoints.

Why hand-rolled instead of slowapi/redis:
  - One file, zero new dependencies.
  - Tex backend is a single Render instance; an in-process dict is the
    correct durability layer (per-instance bucket, no cross-instance
    coordination needed at our scale).
  - If we ever scale horizontally, swap this module's storage for Redis
    without changing any call sites.

Algorithm: fixed-window counter per IP. Simpler than a token bucket and
fine for the "stop crude spam" use case. Each call to `check()`:
  - Looks up the IP's bucket. If it's older than the window, resets.
  - Increments. If the count exceeds the cap, returns False.
  - Otherwise returns True.

This is a *soft* rate limit. Determined attackers can rotate IPs to
defeat it. For a marketing/social leaderboard with bounded score
validation already in place, that's an acceptable threat model.

Memory: O(unique IPs in the last window). On a viral spike with 10k
unique visitors per minute that's ~10k dict entries × ~100 bytes each
= 1 MB. Sweep happens lazily on access; we don't bother with a
background reaper.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock
from typing import Optional

from fastapi import HTTPException, Request, status


@dataclass
class _Bucket:
    window_start: float  # epoch seconds
    count: int


class IPRateLimiter:
    """Fixed-window per-IP rate limiter.

    Args:
      max_per_window: Allowed requests per window per IP.
      window_seconds: Window length in seconds.

    Thread-safety: protected by a single lock. Contention is negligible
    at our request rate; if it ever matters we'd shard by IP hash.
    """

    def __init__(self, *, max_per_window: int, window_seconds: int) -> None:
        self._max = max_per_window
        self._window = window_seconds
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def check(self, ip: str) -> bool:
        """Return True if the request is allowed, False if it should be 429'd."""
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(ip)
            if b is None or (now - b.window_start) >= self._window:
                self._buckets[ip] = _Bucket(window_start=now, count=1)
                return True
            if b.count >= self._max:
                return False
            b.count += 1
            return True

    def reset(self) -> None:
        """Clear all buckets. Used by tests."""
        with self._lock:
            self._buckets.clear()


def client_ip(request: Request) -> str:
    """Best-effort client IP extraction.

    Render terminates TLS at its edge and forwards the original IP in
    `x-forwarded-for`. We trust the leftmost entry there. If absent
    (local dev, direct internal calls), fall back to the socket peer.
    """
    xff: Optional[str] = request.headers.get("x-forwarded-for")
    if xff:
        # The header can be a comma-separated list of IPs. The leftmost
        # is the original client.
        return xff.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return "unknown"


def enforce(limiter: IPRateLimiter, request: Request) -> None:
    """Raise 429 if the limiter says this IP is over its quota."""
    ip = client_ip(request)
    if not limiter.check(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many requests; please slow down",
            headers={"Retry-After": "30"},
        )
