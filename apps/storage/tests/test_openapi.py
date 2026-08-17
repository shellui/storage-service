"""OpenAPI schema generation must describe APIViews without spectacular errors."""

from __future__ import annotations

from django.test import SimpleTestCase
from drf_spectacular.generators import SchemaGenerator


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
