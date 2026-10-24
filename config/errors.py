"""Shellui error pages and JSON errors.

Paths under ('/api/', '/storage/v1/') always get JSON, whatever the ``Accept`` header says,
in the same body shape as the API views. Every other path gets a branded HTML
page. Neither one includes the exception, a stack trace, or the requested path.
"""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.template import loader

API_PREFIXES = ('/api/', '/storage/v1/')

_JSON = {
    400: ('Bad request.', 'bad_request'),
    403: ('You do not have permission to perform this action.', 'forbidden'),
    404: ('Not found.', 'not_found'),
    500: ('Server error.', 'server_error'),
}
_CSRF_JSON = ('CSRF check failed. Reload the page and try again.', 'csrf_failed')

_COPY = {
    'home': 'Back to home',
    400: ("This request didn't work", 'The page got a request it could not read. Go back to home and try again.'),
    403: ("You can't open this page", 'Your account does not have access to this page.'),
    404: ("This page doesn't exist", 'The link may be wrong, or the page has moved.'),
    500: ('Something went wrong', 'The service could not finish your request. Try again in a moment.'),
    'csrf': ('This form has expired', 'Reload the page, then send the form again.'),
}

_FALLBACK_HTML = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Shellui Storage</title></head>'
    '<body><h1>Something went wrong</h1><p>Try again in a moment.</p><p><a href="/">Back to home</a></p></body></html>'
)


def is_api_path(request: HttpRequest) -> bool:
    return (request.path or '').startswith(API_PREFIXES)


def _with_request_id(request: HttpRequest, body: dict) -> dict:
    request_id = getattr(request, 'request_id', None)
    if request_id:
        body['request_id'] = request_id
    return body

def _json_body(request: HttpRequest, status: int, code: str, message: str) -> dict:
    if (request.path or '').startswith('/storage/v1/'):
        # Supabase-compatible shape used by the storage API views.
        body = {'statusCode': str(status), 'error': code, 'message': message}
    else:
        body = {'detail': message}
    return _with_request_id(request, body)


def error_response(request: HttpRequest, status: int, *, csrf: bool = False) -> HttpResponse:
    if is_api_path(request):
        message, code = _CSRF_JSON if csrf else _JSON[status]
        return JsonResponse(_json_body(request, status, code, message), status=status)
    title, message = _COPY['csrf' if csrf else status]
    context = {
        'status_code': status,
        'title': title,
        'message': message,
        'home_label': _COPY['home'],
    }
    try:
        # No request context: the 500 page must not depend on sessions, users or the database.
        body = loader.render_to_string('errors/error.html', context)
    except Exception:  # noqa: BLE001 - an error page must never raise
        body = _FALLBACK_HTML
    return HttpResponse(body, status=status, content_type='text/html; charset=utf-8')


def bad_request(request, exception=None):
    return error_response(request, 400)


def permission_denied(request, exception=None):
    return error_response(request, 403)


def page_not_found(request, exception=None):
    return error_response(request, 404)


def server_error(request):
    return error_response(request, 500)


def csrf_failure(request, reason='', template_name=None):
    return error_response(request, 403, csrf=True)
