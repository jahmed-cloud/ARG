"""
Login lockout: MAX_LOGIN_ATTEMPTS wrong passwords for one account from one address lock that pair for
LOCKOUT_DURATION_MINUTES. Keyed by account + address so an attacker cannot lock the real owner out from elsewhere.
Counters live in Redis (shared by every backend process); without Redis they fall back to this process's memory.
"""
import hashlib
import logging
import time

from backend.core.config import settings

logger = logging.getLogger(__name__)
_memory: dict[str, tuple[int, float]] = {}
_redis = None


def _client():
    global _redis
    if _redis is None:
        import redis.asyncio as redis
        _redis = redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
    return _redis


def _key(username: str, address: str | None) -> str:
    digest = hashlib.sha256(f"{username.strip().lower()}|{address or '-'}".encode()).hexdigest()[:32]
    return f"arg:login-fail:{digest}"


def _window() -> int:
    return settings.LOCKOUT_DURATION_MINUTES * 60


async def retry_after(username: str, address: str | None) -> int:
    """Seconds the pair is still locked for; 0 when it may try."""
    key = _key(username, address)
    try:
        client = _client()
        count = int(await client.get(key) or 0)
        return max(int(await client.ttl(key)), 1) if count >= settings.MAX_LOGIN_ATTEMPTS else 0
    except Exception as exc:
        logger.warning("Login throttle: Redis unavailable (%s) - using process memory", exc.__class__.__name__)
        count, expires = _memory.get(key, (0, 0.0))
        left = int(expires - time.time())
        return left if count >= settings.MAX_LOGIN_ATTEMPTS and left > 0 else 0


async def record_failure(username: str, address: str | None) -> bool:
    """Count one wrong password; True when this attempt locked the pair."""
    key = _key(username, address)
    try:
        client = _client()
        count = int(await client.incr(key))
        if count == 1:
            await client.expire(key, _window())
    except Exception:
        count, expires = _memory.get(key, (0, 0.0))
        if expires <= time.time():
            count, expires = 0, time.time() + _window()
        count += 1
        _memory[key] = (count, expires)
    return count == settings.MAX_LOGIN_ATTEMPTS


async def clear(username: str, address: str | None) -> None:
    key = _key(username, address)
    _memory.pop(key, None)
    try:
        await _client().delete(key)
    except Exception:
        pass
