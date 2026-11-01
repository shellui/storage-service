"""Gunicorn access logging that never fails and never prints request headers.

Two guards:
- ``SafeAccessLogger`` keeps only the atoms an access line needs. Request header
  (``{...}i``) and environ (``{...}e``) atoms are dropped, so an Authorization
  bearer token or a cookie can never reach a log record. Missing atoms, such as
  ``{x-request-id}o`` on a response without that header, render as ``-``.
- ``logging.raiseExceptions`` is turned off, so a formatting error is dropped
  silently instead of Python printing the record arguments to stderr.
"""

from __future__ import annotations

import logging

from gunicorn.glogging import Logger

# A failing log call must never print its arguments (headers, tokens) to stderr.
logging.raiseExceptions = False

_SENSITIVE_RESPONSE_HEADERS = ('set-cookie', 'authorization', 'cookie')


class SafeAtoms(dict):
    """Access atoms where any missing key renders as ``-`` (case-insensitive headers)."""

    def __getitem__(self, key):
        if isinstance(key, str) and key.startswith('{'):
            key = key.lower()
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        return '-'

    def __missing__(self, key):
        return '-'


def safe_atoms(atoms) -> SafeAtoms:
    """Keep plain atoms and response header atoms only; never request headers or environ."""
    kept = SafeAtoms()
    for key, value in dict(atoms).items():
        if key.startswith('{'):
            lowered = key.lower()
            if not lowered.endswith('}o'):
                continue
            if any(word in lowered for word in _SENSITIVE_RESPONSE_HEADERS):
                continue
            key = lowered
        if isinstance(value, str):
            value = value.replace('"', '\\"')
        kept[key] = value
    return kept


class SafeAccessLogger(Logger):
    """Gunicorn logger class: ``--logger-class config.safe_access_log.SafeAccessLogger``."""

    atoms_wrapper_class = staticmethod(safe_atoms)
