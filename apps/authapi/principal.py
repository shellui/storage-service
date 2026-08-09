"""Authenticated principal extracted from identity-service JWTs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StoragePrincipal:
    """Lightweight stand-in for Django's User, built from JWT claims."""

    user_id: int
    company_id: int | None
    email: str = ''
    username: str = ''
    is_staff: bool = False
    is_company_owner: bool = False
    claims: dict[str, Any] = field(default_factory=dict)

    @property
    def pk(self) -> int:
        return self.user_id

    @property
    def id(self) -> int:
        return self.user_id

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def __str__(self) -> str:
        return self.email or self.username or str(self.user_id)


def principal_from_claims(claims: dict[str, Any]) -> StoragePrincipal:
    user_metadata = claims.get('user_metadata') or {}
    if not isinstance(user_metadata, dict):
        user_metadata = {}

    raw_uid = claims.get('user_id', claims.get('sub'))
    try:
        user_id = int(raw_uid)
    except (TypeError, ValueError) as exc:
        raise ValueError('JWT is missing a numeric user id / sub claim.') from exc

    raw_company = claims.get('company_id')
    company_id: int | None
    if raw_company in (None, ''):
        company_id = None
    else:
        try:
            company_id = int(raw_company)
        except (TypeError, ValueError) as exc:
            raise ValueError('JWT company_id must be an integer.') from exc

    return StoragePrincipal(
        user_id=user_id,
        company_id=company_id,
        email=str(claims.get('email') or user_metadata.get('email') or ''),
        username=str(claims.get('username') or user_metadata.get('username') or ''),
        is_staff=bool(user_metadata.get('is_staff', False)),
        is_company_owner=bool(user_metadata.get('is_company_owner', False)),
        claims=claims,
    )
