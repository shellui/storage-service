"""Redact capability secrets from Gunicorn access lines.

Share links put the secret in the path (`/storage/v1/share/link/<token>`).
The access format already drops the query string and the Referer header.
This step removes the token that remains in the path.
"""

from __future__ import annotations

import logging
import re

_SHARE_LINK = re.compile(r'(/share/link/)[^/\s"?#]+', re.IGNORECASE)
_PATH_KEYS = frozenset({'U', 'r'})


def redact_access_text(value: str) -> str:
    return _SHARE_LINK.sub(r'\1[filtered]', value)


class RedactAccessLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_access_text(record.msg)
        args = record.args
        if isinstance(args, dict):
            cleaned = {}
            for key, item in args.items():
                if key == 'q':
                    cleaned[key] = ''
                elif key == 'f':
                    cleaned[key] = '-'
                elif key in _PATH_KEYS and isinstance(item, str):
                    cleaned[key] = redact_access_text(item)
                else:
                    cleaned[key] = item
            record.args = cleaned
        elif isinstance(args, tuple):
            record.args = tuple(
                redact_access_text(item) if isinstance(item, str) else item for item in args
            )
        return True
