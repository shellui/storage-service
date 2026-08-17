"""Fetch and cache JWKS documents from identity-service."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import jwt
import requests
from django.conf import settings
from jwt import PyJWK

logger = logging.getLogger(__name__)

_FETCH_HEADERS = {
    'Accept': 'application/json',
    'Accept-Encoding': 'identity',
    'Connection': 'close',
}


class JWKSClient:
    """Thread-safe JWKS cache with TTL refresh."""

    def __init__(
        self,
        url: str,
        ttl: int = 900,
        timeout: float = 15.0,
        retries: int = 2,
    ):
        self.url = url
        self.ttl = ttl
        self.timeout = timeout
        self.retries = max(0, retries)
        self._session = requests.Session()
        self._lock = threading.Lock()
        self._fetched_at = 0.0
        self._keys: dict[str, Any] = {}
        self._raw: dict[str, Any] = {'keys': []}

    def clear(self) -> None:
        with self._lock:
            self._fetched_at = 0.0
            self._keys = {}
            self._raw = {'keys': []}

    def _request_timeout(self) -> float | tuple[float, float]:
        connect = min(5.0, self.timeout)
        return (connect, self.timeout)

    def _fetch_document(self) -> dict[str, Any]:
        attempts = self.retries + 1
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = self._session.get(
                    self.url,
                    timeout=self._request_timeout(),
                    headers=_FETCH_HEADERS,
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException as exc:
                last_error = exc
                logger.warning(
                    'JWKS fetch attempt %s/%s from %s failed: %s',
                    attempt,
                    attempts,
                    self.url,
                    exc,
                )
                if attempt < attempts:
                    time.sleep(0.25 * attempt)
        assert last_error is not None
        raise last_error

    def _refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and self._keys and (now - self._fetched_at) < self.ttl:
            return
        with self._lock:
            now = time.monotonic()
            if not force and self._keys and (now - self._fetched_at) < self.ttl:
                return
            try:
                document = self._fetch_document()
            except requests.RequestException as exc:
                logger.warning('Failed to fetch JWKS from %s: %s', self.url, exc)
                if self._keys:
                    return
                raise

            keys: dict[str, Any] = {}
            for entry in document.get('keys') or []:
                kid = entry.get('kid')
                try:
                    jwk = PyJWK.from_dict(entry)
                except Exception:
                    logger.warning('Skipping invalid JWK entry kid=%s', kid)
                    continue
                if kid:
                    keys[str(kid)] = jwk
                else:
                    keys[f'_anon_{len(keys)}'] = jwk

            self._raw = document
            self._keys = keys
            self._fetched_at = time.monotonic()

    def get_signing_key(self, token: str):
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        self._refresh()
        if kid and kid in self._keys:
            return self._keys[kid]
        if kid:
            self._refresh(force=True)
            if kid in self._keys:
                return self._keys[kid]
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        if not self._keys:
            return None
        raise jwt.InvalidTokenError(f'Unable to find a signing key that matches kid={kid!r}')


_client: JWKSClient | None = None
_client_lock = threading.Lock()


def get_jwks_client() -> JWKSClient:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = JWKSClient(
                    url=settings.IDENTITY_JWKS_URL,
                    ttl=getattr(settings, 'JWKS_CACHE_TTL', 900),
                    timeout=getattr(settings, 'JWKS_TIMEOUT', 15.0),
                    retries=getattr(settings, 'JWKS_RETRIES', 2),
                )
    return _client


def reset_jwks_client() -> None:
    global _client
    with _client_lock:
        _client = None
