from django.test import SimpleTestCase

from shellui_mcp.masking import redact_mapping
from shellui_mcp.openapi_mcp import marker_tree_for_schema


class McpMaskingTests(SimpleTestCase):
    def test_openapi_secret_and_sensitive_markers(self):
        schema = {
            'components': {
                'schemas': {
                    'Preview': {
                        'type': 'object',
                        'properties': {
                            'html': {'type': 'string'},
                            'email': {'type': 'string', 'x-mcp-sensitive': True},
                            'api_key_hint': {'type': 'string'},
                            'secret': {'type': 'string', 'x-mcp-secret': True},
                        },
                    },
                },
            },
        }
        markers = marker_tree_for_schema({'$ref': '#/components/schemas/Preview'}, schema)
        out = redact_mapping(
            {
                'html': '<p>Hi</p>',
                'email': 'ada@example.com',
                'api_key_hint': 'sk_live_abc',
                'secret': 'plaintext',
            },
            read_sensitive=False,
            markers=markers,
        )
        self.assertEqual(out['html'], '<p>Hi</p>')
        self.assertEqual(out['email'], '[redacted]')
        self.assertEqual(out['api_key_hint'], '[redacted]')
        self.assertEqual(out['secret'], '[redacted]')

    def test_sensitive_visible_in_sensitive_read_mode(self):
        markers = {
            'email': {'secret': False, 'sensitive': True, 'children': {}},
        }
        out = redact_mapping({'email': 'ada@example.com'}, read_sensitive=True, markers=markers)
        self.assertEqual(out['email'], 'ada@example.com')
