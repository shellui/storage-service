"""Per-request id for log correlation (also echoed as X-Request-ID)."""

from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar('request_id', default='-')


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class RequestIdMiddleware:
    """Assign a short request id (honor inbound X-Request-ID when present)."""

    header = 'X-Request-ID'

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = (request.headers.get(self.header) or '').strip()
        request_id = incoming[:64] if incoming else uuid.uuid4().hex[:12]
        request.request_id = request_id
        request_id_var.set(request_id)
        response = self.get_response(request)
        response[self.header] = request_id
        return response
