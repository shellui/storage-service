"""MIME type helpers — detection, validation against bucket allow-lists."""

from __future__ import annotations

import mimetypes
from pathlib import PurePosixPath

# Ensure common types are registered even if the OS mime.types is sparse.
_EXTRA_TYPES = {
    '.md': 'text/markdown',
    '.markdown': 'text/markdown',
    '.json': 'application/json',
    '.webp': 'image/webp',
    '.avif': 'image/avif',
    '.wasm': 'application/wasm',
    '.ts': 'video/mp2t',
    '.m3u8': 'application/vnd.apple.mpegurl',
    '.yaml': 'application/yaml',
    '.yml': 'application/yaml',
    '.toml': 'application/toml',
    '.svg': 'image/svg+xml',
}

for _ext, _mime in _EXTRA_TYPES.items():
    mimetypes.add_type(_mime, _ext, strict=False)


def guess_mime_type(filename: str, fallback: str = 'application/octet-stream') -> str:
    guessed, _encoding = mimetypes.guess_type(filename, strict=False)
    return guessed or fallback


def normalize_mime_type(value: str | None, filename: str = '') -> str:
    if value:
        cleaned = value.split(';', 1)[0].strip().lower()
        if cleaned and cleaned != 'application/octet-stream':
            return cleaned
    return guess_mime_type(filename)


def mime_allowed(mime_type: str, allowed: list | None) -> bool:
    """
    Return True if mime_type matches the allow-list.

    Empty / None allow-list means all types are permitted.
    Entries may be exact (``image/png``) or prefix wildcards (``image/*``).
    """
    if not allowed:
        return True
    mime = (mime_type or '').split(';', 1)[0].strip().lower()
    for pattern in allowed:
        pattern = str(pattern).strip().lower()
        if not pattern:
            continue
        if pattern.endswith('/*'):
            if mime.startswith(pattern[:-1]):
                return True
        elif mime == pattern:
            return True
    return False


def extension_for_mime(mime_type: str) -> str:
    ext = mimetypes.guess_extension(mime_type.split(';', 1)[0].strip().lower(), strict=False)
    return ext or ''


def safe_object_path(path: str) -> str:
    """Normalize object paths: strip slashes, reject traversal, collapse dots."""
    raw = (path or '').replace('\\', '/').strip('/')
    if not raw:
        raise ValueError('Object path must not be empty.')
    parts: list[str] = []
    for part in PurePosixPath(raw).parts:
        if part in ('', '.'):
            continue
        if part == '..':
            raise ValueError('Object path must not contain parent segments.')
        parts.append(part)
    if not parts:
        raise ValueError('Object path must not be empty.')
    return '/'.join(parts)
