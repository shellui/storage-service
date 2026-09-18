"""CORS: Bearer JWT + allow-all origins (no credentials)."""

from django.test import Client, TestCase, override_settings


@override_settings(CORS_ALLOW_ALL_ORIGINS=True, CORS_ALLOW_CREDENTIALS=False)
class PermissiveCorsTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_preflight_allows_random_hosting_preview_origin(self):
        origin = 'https://vpzzsxvzsmp7.shellui.app'
        response = self.client.options(
            '/storage/v1/health',
            HTTP_ORIGIN=origin,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS='authorization',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Access-Control-Allow-Origin'], '*')

    def test_get_exposes_acao_for_preview_origin(self):
        origin = 'https://abcd1234efgh.shellui.app'
        response = self.client.get('/storage/v1/health', HTTP_ORIGIN=origin)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Access-Control-Allow-Origin'], '*')
