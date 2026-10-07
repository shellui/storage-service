"""Drop secrets before they are stored or sent.

Webhook envelopes, the event log, and email-service bodies all use this.
A storage catalog payload does not carry credentials. The filter still runs
so a token, sign-in link, signed URL, or secret-shaped field cannot leave
the process.
"""

from __future__ import annotations

import re
from typing import Any

_SENSITIVE_KEYS = frozenset({
    'magic_link',
    'magic_link_url',
    'token',
    'raw_token',
    'access_token',
    'refresh_token',
    'id_token',
    'setup_token',
    'sign_in_url',
    'sign_in_link',
    'signin_url',
    'signin_link',
    'password',
    'passwd',
    'pwd',
    'secret',
    'client_secret',
    'api_key',
    'apikey',
    'authorization',
    'authorization_header',
    'credential',
    'credentials',
    'private_key',
    'signing_secret',
    'signed_url',
    'signedurl',
    'presigned_url',
    'presignedurl',
    'share_token',
    'share_url',
})
# Sign-in URLs, share-link tokens, and credential query parameters. The value is omitted entirely.
_SIGN_IN_URL = re.compile(
    r'magic[-_]link|/sign-?in(?:[/?#]|$)|/share/link/|'
    r'[?&#][a-z0-9_.-]*(?:token|secret|password|api[_-]?key|signature|sig)=|'
    r'X-Amz-(?:Algorithm|Credential|Signature|Security-Token)|AWSAccessKeyId=',
    re.IGNORECASE,
)


def redact_secrets(value: Any) -> Any:
    """Return a copy with secret keys and sign-in URLs removed."""
    cleaned = _without_secrets(value)
    if cleaned is _DROP:
        return {} if isinstance(value, dict) else [] if isinstance(value, list) else ''
    return cleaned


def _sensitive_key(key: str) -> bool:
    name = str(key).strip().lower().replace('-', '_')
    return (
        name in _SENSITIVE_KEYS
        or name.endswith('_token')
        or name.endswith('_tokens')
        or name.endswith('_secret')
        or name.endswith('_password')
        or name.endswith('_api_key')
    )


def _sensitive_string(value: str) -> bool:
    if '://' not in value:
        return False
    return _SIGN_IN_URL.search(value) is not None


def _without_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if _sensitive_key(str(key)):
                continue
            kept = _without_secrets(item)
            if kept is _DROP:
                continue
            cleaned[str(key)] = kept
        return cleaned
    if isinstance(value, list):
        items = []
        for item in value:
            kept = _without_secrets(item)
            if kept is _DROP:
                continue
            items.append(kept)
        return items
    if isinstance(value, str) and _sensitive_string(value):
        return _DROP
    return value


class _Drop:
    """Sentinel for a string that must not be stored or sent."""


_DROP = _Drop()
