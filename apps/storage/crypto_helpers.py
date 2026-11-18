"""Symmetric encryption helpers for connector credentials (Fernet, SECRET_KEY-derived)."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet
from django.conf import settings


def _fernet() -> Fernet:
    raw = (getattr(settings, 'SECRET_KEY', '') or '').encode('utf-8')
    digest = hashlib.sha256(raw).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_connector_secret(plaintext: str) -> str:
    """Encrypt a UTF-8 string; returns url-safe base64 token."""
    if not plaintext:
        return ''
    return _fernet().encrypt(plaintext.encode('utf-8')).decode('ascii')


def decrypt_connector_secret(token: str) -> str:
    """Decrypt to UTF-8 string. Raises on bad token."""
    if not token:
        return ''
    return _fernet().decrypt(token.encode('ascii')).decode('utf-8')
