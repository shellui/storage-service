"""A hook that lets the agent gate look at the result of a write before it is committed.

The gate (``agent_gate.checked``) runs a move, copy or rename inside one transaction. The
services call ``after_write`` once the rows are written and before anything outside the
database is touched (a blob copy). If access widened, ``after_write`` raises
``WriteWouldWiden``, the transaction rolls back and nothing was written anywhere.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Callable


class WriteWouldWiden(BaseException):
    """Raised inside the write's transaction when it would let someone read more.

    A ``BaseException`` so that no ``except Exception`` in a view can swallow it and let the
    write commit. The gate catches it outside the transaction.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_guard: ContextVar[Callable[[dict[Any, Any] | None], None] | None] = ContextVar('storage_write_guard', default=None)


def activate(check: Callable[[dict[Any, Any] | None], None]):
    return _guard.set(check)


def deactivate(token) -> None:
    _guard.reset(token)


def after_write(new_ids: dict[Any, Any] | None = None) -> None:
    """Called by a service after its rows are written. A no-op unless a gate is active.

    ``new_ids`` maps an affected object's id before the write to its id after it. Leave it out
    when the same objects were renamed or moved in place.
    """
    check = _guard.get()
    if check is not None:
        check(new_ids)
