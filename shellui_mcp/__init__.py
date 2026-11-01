"""Shared MCP server layer for Shellui services (copy identically into each service repo)."""

from shellui_mcp.decorators import mcp_expose_tool
from shellui_mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    REVOCATION_CACHE_SECONDS,
    build_mcp_approval_assertion,
    verify_mcp_internal_assertion,
)

__all__ = [
    'mcp_expose_tool',
    'APPROVAL_AUDIENCE',
    'APPROVAL_SCOPE',
    'REVOCATION_CACHE_SECONDS',
    'build_mcp_approval_assertion',
    'verify_mcp_internal_assertion',
]
