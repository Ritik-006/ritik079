"""Tiny in-memory sliding-window rate limiter (per process; use Redis for multi-server setups)."""
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, jsonify, request

_hits = defaultdict(deque)


def _identity():
    key = request.headers.get("X-API-Key")
    return f"key:{key}" if key else f"ip:{request.remote_addr or 'unknown'}"


def allowed():
    limit = current_app.config["RATE_LIMIT_PER_MIN"]
    now = time.monotonic()
    window = _hits[_identity()]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    return True


def rate_limited(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not allowed():
            if request.path.startswith("/api/"):
                return jsonify(error="Rate limit exceeded. Try again in a minute."), 429
            abort(429)
        return view(*args, **kwargs)
    return wrapper
