import logging

from django.test import SimpleTestCase

from config.access_log import RedactAccessLogFilter, redact_access_text


class AccessLogRedactionTests(SimpleTestCase):
    def test_share_link_token_is_removed_from_the_path(self):
        raw = 'GET /storage/v1/share/link/sekret-token HTTP/1.1'
        self.assertEqual(
            redact_access_text(raw),
            'GET /storage/v1/share/link/[filtered] HTTP/1.1',
        )
        self.assertNotIn('sekret-token', redact_access_text(raw))

    def test_filter_redacts_formatted_lines_and_path_atoms(self):
        record = logging.LogRecord(
            name='gunicorn.access',
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg='%(m)s %(U)s',
            args={'m': 'GET', 'U': '/storage/v1/share/link/sekret-token', 'q': 'token=secret', 'f': 'https://evil/?token=1'},
            exc_info=None,
        )
        self.assertTrue(RedactAccessLogFilter().filter(record))
        rendered = record.getMessage()
        self.assertIn('/storage/v1/share/link/[filtered]', rendered)
        self.assertNotIn('sekret-token', rendered)
        self.assertEqual(record.args['q'], '')
        self.assertEqual(record.args['f'], '-')
