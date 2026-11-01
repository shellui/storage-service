"""Shared MCP server layer for Shellui services (copy identically into each service repo)."""

from shellui_mcp.decorators import mcp_expose_tool
from shellui_mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    REVOCATION_CACHE_SECONDS,
    REVOCATION_LIST_SCOPE,
    build_mcp_approval_assertion,
    build_mcp_revocation_list_response_assertion,
    parse_trusted_revocation_poll_response,
    verify_mcp_internal_assertion,
    verify_mcp_revocation_list_response,
)

__all__ = [
    'mcp_expose_tool',
    'APPROVAL_AUDIENCE',
    'APPROVAL_SCOPE',
    'REVOCATION_CACHE_SECONDS',
    'REVOCATION_LIST_SCOPE',
    'build_mcp_approval_assertion',
    'build_mcp_revocation_list_response_assertion',
    'parse_trusted_revocation_poll_response',
    'verify_mcp_internal_assertion',
    'verify_mcp_revocation_list_response',
]
