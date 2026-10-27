from django.test import TestCase
from django.urls import reverse


class RedocPageTests(TestCase):
    def test_redoc_loads_the_bundled_script(self):
        response = self.client.get(reverse('redoc'))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn('drf_spectacular_sidecar/redoc/bundles/redoc.standalone.js', body)
        self.assertNotIn('cdn.jsdelivr.net/npm/redoc', body)
