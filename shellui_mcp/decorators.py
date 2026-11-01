"""Mark DRF views whose OpenAPI operations become MCP tools."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar

MCP_TOOL_TAG = 'mcp-tools'

F = TypeVar('F', bound=Callable[..., Any])


def mcp_expose_tool(_fn: F | None = None, *, name: str | None = None, description: str | None = None) -> F | Callable[[F], F]:
    """Only tagged operations are exported as MCP tools. Never tag internal or staff-only endpoints."""

    def decorator(fn: F) -> F:
        meta = getattr(fn, '_mcp_tool_meta', None) or {}
        if name:
            meta['name'] = name
        if description:
            meta['description'] = description
        fn._mcp_tool_meta = meta  # type: ignore[attr-defined]

        @wraps(fn)
        def wrapped(*args, **kwargs):
            return fn(*args, **kwargs)

        wrapped._mcp_tool_meta = meta  # type: ignore[attr-defined]
        wrapped._mcp_expose_tool = True  # type: ignore[attr-defined]
        return wrapped  # type: ignore[return-value]

    if _fn is not None:
        return decorator(_fn)
    return decorator
