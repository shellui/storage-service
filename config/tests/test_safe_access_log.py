"""Access log lines never fail on a missing atom and never carry request headers."""

import logging
from datetime import timedelta
from types import SimpleNamespace

from django.test import SimpleTestCase

from config.safe_access_log import SafeAccessLogger, safe_atoms

_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.secret-bearer-token'
_FORMAT = '%(h)s "%(m)s %(U)s %(H)s" %(s)s %(b)s "%(a)s" %(M)sms req=%({x-request-id}o)s'


def _atoms(response_headers):
    from gunicorn.config import Config

    log = SafeAccessLogger(Config())
    environ = {
        'REQUEST_METHOD': 'POST',
        'RAW_URI': '/api/v1/internal/company-deletions',
        'PATH_INFO': '/api/v1/internal/company-deletions',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'HTTP_AUTHORIZATION': f'Bearer {_TOKEN}',
        'HTTP_USER_AGENT': 'python-requests/2.33.0',
        'REMOTE_ADDR': '172.18.0.11',
    }
    resp = SimpleNamespace(status='301 Moved Permanently', sent=0, headers=response_headers)
    req = SimpleNamespace(headers=[('AUTHORIZATION', f'Bearer {_TOKEN}'), ('COOKIE', f'sessionid={_TOKEN}')])
    return log, log.atoms_wrapper_class(log.atoms(resp, req, environ, timedelta(milliseconds=3)))


class SafeAccessLogTests(SimpleTestCase):
    def test_missing_request_id_renders_dash(self):
        _log, atoms = _atoms([])
        line = _FORMAT % atoms
        self.assertTrue(line.endswith('req=-'))
        self.assertIn('"POST /api/v1/internal/company-deletions HTTP/1.1" 301 0', line)

    def test_request_id_is_rendered_when_present(self):
        _log, atoms = _atoms([('X-Request-ID', 'req-abc')])
        self.assertTrue((_FORMAT % atoms).endswith('req=req-abc'))

    def test_request_headers_and_environ_never_reach_the_record(self):
        _log, atoms = _atoms([('Set-Cookie', f'sessionid={_TOKEN}')])
        self.assertNotIn(_TOKEN, repr(atoms))
        self.assertFalse([key for key in atoms if key.endswith('}i') or key.endswith('}e')])

    def test_logging_errors_never_dump_arguments(self):
        self.assertFalse(logging.raiseExceptions)
        _log, atoms = _atoms([])
        record = logging.LogRecord('gunicorn.access', logging.INFO, __file__, 1, '%(nope', (atoms,), None)
        handler = logging.StreamHandler()
        # handleError prints nothing when raiseExceptions is off.
        handler.handleError(record)

    def test_plain_dict_is_made_safe(self):
        atoms = safe_atoms({'m': 'GET', '{authorization}i': _TOKEN})
        self.assertEqual(atoms['{x-request-id}o'], '-')
        self.assertNotIn(_TOKEN, repr(atoms))


class RequestIdOnEveryResponseTests(SimpleTestCase):
    def test_liveness_probe_carries_request_id(self):
        response = self.client.get('/health/live')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get('X-Request-ID'))
