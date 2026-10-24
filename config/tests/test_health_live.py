from django.test import Client, TestCase, override_settings


class HealthLiveTests(TestCase):
    def test_health_live_short_circuits_before_session_db(self):
        with self.assertNumQueries(0):
            response = Client().get('/health/live')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'ok')

    @override_settings(SECURE_SSL_REDIRECT=True, ALLOWED_HOSTS=['storage.example.com'])
    def test_health_live_not_redirected_and_ignores_host(self):
        # The Docker HEALTHCHECK calls plain http on 127.0.0.1; it must never get a 301 or 400.
        response = Client().get('/health/live', HTTP_HOST='127.0.0.1:8000')
        self.assertEqual(response.status_code, 200)
