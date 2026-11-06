"""Strict parsing of Identity claims for storage-service MCP."""

from __future__ import annotations

import re
from typing import Any

# Lowercase UUID with hyphens only (JWT string claim for global company id).
_GLOBAL_COMPANY_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
)


def parse_global_company_id(raw: Any) -> str | None:
    """Return normalized global company UUID string, or None when absent. Never int-cast."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower()
    if not s:
        return None
    if _GLOBAL_COMPANY_UUID_RE.match(s):
        return s
    return None


def parse_grant_version(raw: Any) -> int | None:
    """Non-negative int only; legacy JWT may use decimal digit strings (no bool, no float)."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    if isinstance(raw, str):
        s = raw.strip()
        if s.isdigit():
            v = int(s)
            return v if v >= 0 else None
    return None


def parse_company_binding_version(raw: Any) -> int | None:
    """Non-negative int only (0 is valid)."""
    return parse_grant_version(raw)


def parse_global_agent_id(raw: Any) -> str | None:
    """SaaS global agent subject id (UUID string). Same lexical rules as ``global_company_id``."""
    return parse_global_company_id(raw)


def parse_personal_token_id(raw: Any) -> str | None:
    """Optional personal agent token id (UUID string)."""
    return parse_global_company_id(raw)


def parse_trusted_agent_claims(claims: dict[str, Any]) -> tuple[bool, str, dict[str, Any] | None]:
    """
    Validate verified agent access token claims for MCP. No legacy aliases.

    Personal regional tokens omit the global org triple and may omit ``grant_version`` (regional
    staleness uses other signals). When ``global_company_id`` is set, Identity issues the full
    delegated triple including explicit ``0`` for ``company_binding_version`` and ``grant_version``.

    If ``global_agent_id`` is present (SaaS-exchanged subject), the token is not personal: the
    same triple is required. A partial triple with ``global_agent_id`` must not fall back to
    personal rules.

    Returns (ok, reason, normalized) where normalized is set only when ok.
    """
    access = str(claims.get('mcp_access') or 'read_only').strip() or 'read_only'

    raw_company = claims.get('company_id')
    if not isinstance(raw_company, int) or isinstance(raw_company, bool):
        return False, 'invalid_company_id', None
    if raw_company < 0:
        return False, 'invalid_company_id', None

    gcid = parse_global_company_id(claims.get('global_company_id'))
    raw_glob = claims.get('global_company_id')
    if raw_glob is not None and gcid is None:
        return False, 'invalid_global_company_id', None

    raw_global_agent = claims.get('global_agent_id')
    global_agent_id = parse_global_agent_id(raw_global_agent)
    if raw_global_agent is not None and global_agent_id is None:
        return False, 'invalid_global_agent_id', None

    raw_personal_tid = claims.get('personal_token_id')
    personal_token_id = parse_personal_token_id(raw_personal_tid)
    if raw_personal_tid is not None and personal_token_id is None:
        return False, 'invalid_personal_token_id', None

    cbv_raw = claims.get('company_binding_version')
    cbv = parse_company_binding_version(cbv_raw) if cbv_raw is not None else None
    if cbv_raw is not None and cbv is None:
        return False, 'invalid_company_binding_version', None

    gv = parse_grant_version(claims.get('grant_version')) if 'grant_version' in claims else None
    if 'grant_version' in claims and gv is None:
        return False, 'invalid_grant_version', None

    delegated = gcid is not None or global_agent_id is not None
    if delegated:
        if gcid is None:
            return False, 'missing_global_company_id', None
        if cbv is None:
            return False, 'missing_company_binding_version', None
        if gv is None:
            return False, 'missing_grant_version', None
    else:
        if cbv is not None:
            return False, 'unexpected_company_binding_version', None

    normalized = {
        'mcp_access': access,
        'company_id': raw_company,
        'grant_version': gv,
        'global_company_id': gcid,
        'company_binding_version': cbv,
        'global_agent_id': global_agent_id,
        'personal_token_id': personal_token_id,
    }
    return True, '', normalized
