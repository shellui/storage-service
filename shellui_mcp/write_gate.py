"""Gate write operations by agent access mode."""

from __future__ import annotations

from typing import Any

ACCESS_READ_ONLY = 'read_only'
ACCESS_ASK = 'ask'
ACCESS_FULL = 'full'

SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})


class WriteGateDecision:
    __slots__ = ('allowed', 'needs_approval', 'reason')

    def __init__(self, *, allowed: bool, needs_approval: bool = False, reason: str = ''):
        self.allowed = allowed
        self.needs_approval = needs_approval
        self.reason = reason


def decide_write(
    *,
    method: str,
    access_mode: str,
    destructive: bool,
    allow_destructive_without_asking: bool,
) -> WriteGateDecision:
    m = (method or 'GET').upper()
    if m in SAFE_METHODS:
        return WriteGateDecision(allowed=True)
    if access_mode == ACCESS_READ_ONLY:
        return WriteGateDecision(allowed=False, reason='Agent is read only.')
    if access_mode == ACCESS_FULL:
        if destructive and not allow_destructive_without_asking:
            return WriteGateDecision(allowed=False, needs_approval=True, reason='Destructive change requires approval.')
        return WriteGateDecision(allowed=True)
    if access_mode == ACCESS_ASK:
        return WriteGateDecision(allowed=False, needs_approval=True, reason='Write requires approval.')
    return WriteGateDecision(allowed=False, reason='Unknown access mode.')


def is_destructive_operation(operation: dict[str, Any] | None) -> bool:
    if not operation:
        return False
    for tag in operation.get('tags') or []:
        if str(tag).lower() in {'destructive', 'mcp-destructive'}:
            return True
    return False
