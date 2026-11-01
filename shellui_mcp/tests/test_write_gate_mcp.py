from django.test import SimpleTestCase

from shellui_mcp.openapi_mcp import McpSchemaValidationError, validate_read_only_post_tools
from shellui_mcp.write_gate import ACCESS_ASK, ACCESS_FULL, ACCESS_READ_ONLY, decide_write


class McpWriteGateTests(SimpleTestCase):
    def test_read_only_post_tool_allowed_for_read_only_agents(self):
        decision = decide_write(
            method='POST',
            access_mode=ACCESS_READ_ONLY,
            destructive=False,
            allow_destructive_without_asking=False,
            tool_read_only=True,
        )
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.needs_approval)

    def test_untagged_post_still_blocked_for_read_only_agents(self):
        decision = decide_write(
            method='POST',
            access_mode=ACCESS_READ_ONLY,
            destructive=False,
            allow_destructive_without_asking=False,
            tool_read_only=False,
        )
        self.assertFalse(decision.allowed)

    def test_untagged_post_needs_approval_in_ask_mode(self):
        decision = decide_write(
            method='POST',
            access_mode=ACCESS_ASK,
            destructive=False,
            allow_destructive_without_asking=False,
            tool_read_only=False,
        )
        self.assertTrue(decision.needs_approval)

    def test_read_only_post_tool_skips_ask_approval(self):
        decision = decide_write(
            method='POST',
            access_mode=ACCESS_ASK,
            destructive=False,
            allow_destructive_without_asking=False,
            tool_read_only=True,
        )
        self.assertTrue(decision.allowed)

    def test_validate_read_only_post_allowlist(self):
        schema = {
            'paths': {
                '/preview/': {
                    'post': {
                        'operationId': 'render_preview',
                        'x-mcp': {'read_only': True},
                    },
                },
            },
        }
        validate_read_only_post_tools(schema, allowlist=frozenset({'render_preview'}))
        with self.assertRaises(McpSchemaValidationError):
            validate_read_only_post_tools(schema, allowlist=frozenset())
