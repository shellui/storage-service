"""
Redis lock so a scheduled task never runs twice at the same time.

Several containers can run a worker and a beat (replicas, or a web container plus a
dedicated worker container). Each beat sends its own copy of a periodic task, so a
task takes a lock first and skips the run when another worker holds it.

The lock is ``SET key token NX EX ttl``. The TTL bounds how long a crashed worker can
hold it. Release deletes the key only when it still holds our token, so a run that
outlived its TTL never removes the lock of the next run.

Service agnostic: keys start with ``settings.SCHEDULER_LOCK_PREFIX``.
"""

import contextlib
import logging
import secrets

import redis
from django.conf import settings

logger = logging.getLogger(__name__)

_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""

_client = None


def get_lock_client():
    """Redis client on the broker URL, shared by every worker that runs these tasks."""
    global _client
    if _client is None:
        _client = redis.Redis.from_url(
            settings.CELERY_BROKER_URL,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
    return _client


def lock_key(name: str) -> str:
    return f'{settings.SCHEDULER_LOCK_PREFIX}:lock:{name}'


@contextlib.contextmanager
def task_lock(name: str, ttl: int, client=None):
    """
    Yield ``True`` when this run holds the lock, ``False`` when another run does.

    Redis errors while taking the lock propagate, so the task fails and is reported.
    """
    client = client if client is not None else get_lock_client()
    key = lock_key(name)
    token = secrets.token_hex(16)
    acquired = bool(client.set(key, token, nx=True, ex=max(1, int(ttl))))
    try:
        yield acquired
    finally:
        if acquired:
            try:
                client.eval(_RELEASE_SCRIPT, 1, key, token)
            except redis.RedisError:
                logger.warning('Could not release lock %s; it expires after %ss', key, ttl)


# Beat heartbeat: the beat process stores the time it last published a scheduled task.
# One SET per published task, kept for a day so a stopped beat still shows its last tick.
BEAT_HEARTBEAT_TTL = 86400


def beat_heartbeat_key() -> str:
    return f'{settings.SCHEDULER_LOCK_PREFIX}:beat:heartbeat'


def record_beat_heartbeat(now: float | None = None, client=None) -> None:
    """Never raises: a Redis error must not stop beat from publishing the task."""
    import time

    client = client if client is not None else get_lock_client()
    try:
        client.set(beat_heartbeat_key(), f'{now if now is not None else time.time():.3f}', ex=BEAT_HEARTBEAT_TTL)
    except redis.RedisError:
        logger.warning('Could not store the beat heartbeat')


def read_beat_heartbeat(client=None) -> float | None:
    """Unix time of the last task published by beat, or None. Redis errors propagate."""
    client = client if client is not None else get_lock_client()
    raw = client.get(beat_heartbeat_key())
    if raw is None:
        return None
    try:
        return float(raw.decode() if isinstance(raw, bytes) else raw)
    except (TypeError, ValueError):
        return None
