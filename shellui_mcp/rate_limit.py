"""Per-agent MCP rate limiting (cache-backed)."""

from __future__ import annotations

from django.conf import settings
from django.core.cache import cache


def _limit_spec() -> tuple[int, int]:
    limits = getattr(settings, 'MCP_RATE_LIMITS', None) or {}
    spec = limits.get('mcp_agent') or limits.get('default') or {'limit': 120, 'window': 60}
    return int(spec['limit']), int(spec['window'])


def check_agent_rate_limit(agent_id: str) -> bool:
    """Return True when the agent is over the limit."""
    if not getattr(settings, 'AUTH_RATE_LIMIT_ENABLED', True):
        return False
    limit, window = _limit_spec()
    key = f'mcp_rate:agent:{agent_id}'
    try:
        count = cache.incr(key)
    except ValueError:
        cache.add(key, 1, timeout=window)
        count = 1
    return count > limit
