"""OpenAPI schema generation must describe APIViews without spectacular errors."""

from __future__ import annotations

import tempfile

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase
from drf_spectacular.generators import SchemaGenerator

from apps.authapi.mcp_openapi import (
    MCP_EXCLUDED_PATH_PREFIXES,
    MCP_EXPLICIT_REGISTRY,
    MCP_REQUIRED_OPERATION_IDS,
    MCP_REQUIRED_SECRET_SCHEMA_PROPERTIES,
    validate_mcp_schema,
    validate_mcp_secret_fields,
)


class OpenApiSchemaTests(SimpleTestCase):
    def test_schema_generates_without_spectacular_warnings(self):
        generator = SchemaGenerator()
        with self.assertNoLogs('drf_spectacular', level='WARNING'):
            schema = generator.get_schema(request=None, public=True)
        self.assertIn('/storage/v1/bucket', schema['paths'])
        self.assertIn('/storage/v1/bucket/{bucket_id}', schema['paths'])
        operation_ids = [
            operation['operationId']
            for path_item in schema['paths'].values()
            for operation in path_item.values()
            if isinstance(operation, dict) and 'operationId' in operation
        ]
        self.assertEqual(len(operation_ids), len(set(operation_ids)), operation_ids)
        self.assertIn('storage_v1_bucket_list', operation_ids)
        self.assertIn('storage_v1_bucket_retrieve', operation_ids)
        self.assertIn('storage_v1_object_destroy', operation_ids)
        self.assertIn('storage_v1_object_delete_many', operation_ids)
        self.assertIn('storage_v1_object_sign_create', operation_ids)
        self.assertIn('storage_v1_object_sign_path_create', operation_ids)
        self.assertIn('storage_v1_object_authenticated_retrieve', operation_ids)
        validate_mcp_schema(schema)
        validate_mcp_secret_fields(schema)
        for prefix in MCP_EXCLUDED_PATH_PREFIXES:
            for path in schema['paths']:
                self.assertFalse(path.startswith(prefix), path)

    def test_spectacular_validate_fail_on_warn(self):
        with tempfile.NamedTemporaryFile(suffix='.yml') as handle:
            try:
                call_command(
                    'spectacular',
                    validate=True,
                    fail_on_warn=True,
                    file=handle.name,
                    stdout=handle,
                )
            except CommandError as exc:
                self.fail(str(exc))

    def test_mcp_registry_matches_required_allowlist(self):
        self.assertEqual(set(MCP_EXPLICIT_REGISTRY), MCP_REQUIRED_OPERATION_IDS)

    def test_required_secret_fields_list(self):
        expected = sorted(f'{c}.{p}' for c, p in MCP_REQUIRED_SECRET_SCHEMA_PROPERTIES)
        self.assertIn('ShareLink.token', expected)
        self.assertIn('ActionRuleCreate.secret', expected)
