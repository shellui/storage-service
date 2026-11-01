from django.test import SimpleTestCase

from shellui_mcp.masking import redact_mapping
from shellui_mcp.write_gate import ACCESS_ASK, ACCESS_FULL, ACCESS_READ_ONLY, decide_write


class ShelluiMcpPackageTests(SimpleTestCase):
    def test_redact_secrets(self):
        out = redact_mapping({'password': 'x', 'name': 'Ada'}, read_sensitive=False)
        self.assertEqual(out['password'], '[redacted]')
        self.assertEqual(out['name'], 'Ada')

    def test_write_gate(self):
        self.assertTrue(decide_write(method='GET', access_mode=ACCESS_READ_ONLY, destructive=False, allow_destructive_without_asking=False).allowed)
        self.assertFalse(
            decide_write(
                method='POST',
                access_mode=ACCESS_READ_ONLY,
                destructive=False,
                allow_destructive_without_asking=False,
                tool_read_only=False,
            ).allowed
        )
        self.assertTrue(decide_write(method='POST', access_mode=ACCESS_FULL, destructive=False, allow_destructive_without_asking=False).allowed)
        ask = decide_write(method='POST', access_mode=ACCESS_ASK, destructive=False, allow_destructive_without_asking=False)
        self.assertTrue(ask.needs_approval)
