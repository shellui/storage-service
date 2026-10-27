import re

from django.test import TestCase
from django.urls import reverse

# Hosts that served (or could serve) the docs assets before they were bundled. Any of them, or an
# unpinned @latest build, coming back would make the docs pages depend on a third party again.
CDN_PATTERN = re.compile(r'cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|esm\.sh|@latest')
EXTERNAL_SCRIPT = re.compile(r'<script[^>]*\ssrc="https?://|\sfrom\s+"https?://')


class ApiDocsPagesTests(TestCase):
    def assert_self_hosted(self, url_name, *assets):
        response = self.client.get(reverse(url_name))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        for asset in assets:
            self.assertIn(f'/static/drf_spectacular_sidecar/{asset}', body)
        self.assertIn('/static/vendor/shellui-sdk/0.2.0/sdk.mjs', body)
        self.assertIsNone(CDN_PATTERN.search(body), CDN_PATTERN.search(body))
        self.assertIsNone(EXTERNAL_SCRIPT.search(body), EXTERNAL_SCRIPT.search(body))

    def test_redoc_page_is_self_hosted(self):
        self.assert_self_hosted('redoc', 'redoc/bundles/redoc.standalone.js')

    def test_swagger_page_is_self_hosted(self):
        self.assert_self_hosted(
            'swagger-ui',
            'swagger-ui-dist/swagger-ui-bundle.js',
            'swagger-ui-dist/swagger-ui-standalone-preset.js',
            'swagger-ui-dist/swagger-ui.css',
        )
