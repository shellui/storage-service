from django.test import SimpleTestCase

from shellui_mcp.openapi_tools import tools_from_schema


class OpenApiToolsPathParamTests(SimpleTestCase):
    def test_path_params_required_in_input_schema(self):
        schema = {
            'paths': {
                '/api/v1/companies/{company_id}/widgets/': {
                    'get': {
                        'tags': ['mcp-tools'],
                        'operationId': 'list_widgets',
                        'parameters': [{'in': 'query', 'name': 'limit', 'required': True, 'schema': {'type': 'integer'}}],
                    },
                },
            },
        }
        tools = tools_from_schema(schema)
        self.assertEqual(len(tools), 1)
        tool = tools[0]
        self.assertIn('path_params', tool['inputSchema']['properties'])
        self.assertIn('path_params', tool['inputSchema']['required'])
        self.assertEqual(tool['_meta']['path_params'], ['company_id'])
        self.assertEqual(tool['_meta']['query_fields'], ['limit'])
