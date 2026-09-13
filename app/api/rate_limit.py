"""
In-memory per-client rate limiting for cost-bearing endpoints.

A sliding-window cap so a deployed instance cannot be looped into draining
provider quota. Single-process state — appropriate for one uvicorn worker;
scale out to Redis if multi-worker deployments ever need a shared budget.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from fastapi import HTTPException, Request

from app.config import RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS

_hits: dict[str, deque[float]] = {}
_lock = threading.Lock()


def _client_key(request: Request) -> str:
    """Identify the caller — trust the platform proxy header when present."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def rate_limit(request: Request) -> None:
    """Raise HTTP 429 when the client exceeds the sliding-window cap."""
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS

    with _lock:
        hits = _hits.setdefault(_client_key(request), deque())
        while hits and hits[0] <= window_start:
            hits.popleft()
        if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Rate limit exceeded — max {RATE_LIMIT_MAX_REQUESTS} requests "
                    f"per {RATE_LIMIT_WINDOW_SECONDS}s per client. Try again shortly."
                ),
            )
        hits.append(now)
