"""``GET /health/live``: process liveness for the Docker HEALTHCHECK and load balancers.

Answers first in the middleware stack, before SecurityMiddleware, sessions and the
database, so it needs no auth, does no DB or Redis work, skips host validation and is
never redirected to https. Readiness with versions stays at ``GET /storage/v1/health``.
"""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse

LIVENESS_PATH = '/health/live'


class LivenessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.method in ('GET', 'HEAD') and request.path.rstrip('/') == LIVENESS_PATH:
            return HttpResponse('ok', content_type='text/plain')
        return self.get_response(request)
