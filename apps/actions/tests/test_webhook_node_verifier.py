import shutil
import subprocess
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from apps.actions.webhook_signing import encode_webhook_envelope, generate_webhook_signing_secret, sign_webhook_body

REPO_ROOT = Path(__file__).resolve().parents[3]
NODE_SCRIPT = REPO_ROOT / 'docs' / 'examples' / 'verify-shellui-webhook.mjs'


class NodeVerifierReferenceTests(SimpleTestCase):
    def test_node_reference_matches_python(self):
        if shutil.which('node') is None:
            self.skipTest('node not installed')
        if not NODE_SCRIPT.is_file():
            self.fail(f'Missing {NODE_SCRIPT}')

        secret = generate_webhook_signing_secret()
        envelope = {
            'id': 'evt-node-ref',
            'type': 'storage.object.uploaded',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': 10, 'slug': '', 'name': ''},
            'data': {'path': 'docs/résumé.pdf'},
        }
        body = encode_webhook_envelope(envelope)
        headers = sign_webhook_body(secret=secret, body=body, webhook_id=envelope['id'])

        with tempfile.NamedTemporaryFile('wb', delete=False) as tmp:
            tmp.write(body)
            body_path = tmp.name

        env = {
            **dict(__import__('os').environ),
            'WEBHOOK_ID': headers['webhook-id'],
            'WEBHOOK_TIMESTAMP': headers['webhook-timestamp'],
            'WEBHOOK_SIGNATURE': headers['webhook-signature'],
        }
        try:
            result = subprocess.run(
                ['node', str(NODE_SCRIPT), secret, body_path],
                env=env,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())

            bad = subprocess.run(
                ['node', str(NODE_SCRIPT), secret, body_path],
                env={**env, 'WEBHOOK_SIGNATURE': 'v1,AAAA'},
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(bad.returncode, 0)
        finally:
            Path(body_path).unlink(missing_ok=True)
