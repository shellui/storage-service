from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

SCRIPT = Path(settings.BASE_DIR) / 'tools' / 'pre-release-check.sh'


class PreReleaseScriptTests(SimpleTestCase):
    def test_smoke_uses_redis_and_keeps_container_logs(self):
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertIn('REDIS_URL', text)
        self.assertIn('redis:8-alpine', text)
        self.assertIn("printf '%s\\n' '--- end docker logs ---'", text)
        self.assertNotIn("printf '--- end docker logs ---\\n'", text)
        self.assertNotIn('docker run --rm -d --name "${CONTAINER_NAME}"', text)
        app_run = text.split('docker run -d --name "${CONTAINER_NAME}"', 1)[1].split('"${IMAGE_TAG}"', 1)[0]
        self.assertIn('--network', app_run)
        self.assertIn('REDIS_URL', app_run)
        self.assertNotIn('--rm', app_run)
