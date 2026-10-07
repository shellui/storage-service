"""Strip secrets from events before they are sent to Sentry."""

from __future__ import annotations

import re
from typing import Any

_DROP_HEADERS = frozenset({
    'authorization',
    'cookie',
    'set-cookie',
    'referer',
    'x-api-key',
    'proxy-authorization',
})
_URL_QUERY_RE = re.compile(r'(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s?#\'"<>]*)[?#][^\s\'"<>]*')
_BEARER_RE = re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}')
_SHARE_LINK_RE = re.compile(r'(/share/link/)[^/\s"?#]+', re.IGNORECASE)


def scrub_sentry_event(event: dict[str, Any], _hint: dict[str, Any] | None = None) -> dict[str, Any]:
    """Drop query strings, Referer, cookies, authorization, and stack locals."""
    request = event.get('request')
    if isinstance(request, dict):
        url = request.get('url')
        if isinstance(url, str):
            request['url'] = _scrub_text(url.split('#', 1)[0].split('?', 1)[0])
        request.pop('query_string', None)
        request.pop('cookies', None)
        request.pop('data', None)
        headers = request.get('headers')
        if isinstance(headers, dict):
            request['headers'] = {
                key: value
                for key, value in headers.items()
                if str(key).lower() not in _DROP_HEADERS
            }
        elif isinstance(headers, list):
            kept = []
            for pair in headers:
                if isinstance(pair, (list, tuple)) and len(pair) >= 1 and str(pair[0]).lower() in _DROP_HEADERS:
                    continue
                kept.append(pair)
            request['headers'] = kept
    message = event.get('message')
    if isinstance(message, str):
        event['message'] = _scrub_text(message)
    _scrub_exception(event.get('exception'))
    _scrub_exception(event.get('threads'))
    return event


def _scrub_exception(container: Any) -> None:
    if not isinstance(container, dict):
        return
    values = container.get('values')
    if not isinstance(values, list):
        return
    for item in values:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get('value'), str):
            item['value'] = _scrub_text(item['value'])
        stack = item.get('stacktrace')
        if not isinstance(stack, dict):
            continue
        frames = stack.get('frames')
        if not isinstance(frames, list):
            continue
        for frame in frames:
            if isinstance(frame, dict):
                frame.pop('vars', None)


def _scrub_text(value: str) -> str:
    value = _URL_QUERY_RE.sub(r'\1', value)
    value = _SHARE_LINK_RE.sub(r'\1[filtered]', value)
    return _BEARER_RE.sub(r'\1 [Filtered]', value)
