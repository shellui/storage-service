"""Company scope for Shellui Actions envelopes (storage has no local Company model)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CompanyContext:
    """Minimal company block for webhook envelopes (id required; slug/name optional)."""

    id: int
    slug: str = ''
    name: str = ''


def company_context_from_id(company_id: int, *, slug: str = '', name: str = '') -> CompanyContext:
    return CompanyContext(id=int(company_id), slug=(slug or '').strip(), name=(name or '').strip())
