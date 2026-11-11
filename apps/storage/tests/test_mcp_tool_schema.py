"""Locks MCP tool schemas: enums, flat arguments, copy, and risk annotations.

The ai-service gateway reads this OpenAPI document and ``tools/list``. Both must
carry ``enum`` on fixed-value fields. ``tools/list`` must not ask for HTTP method
or URL.
"""

from __future__ import annotations

import re

from django.test import SimpleTestCase
from drf_spectacular.generators import SchemaGenerator

from apps.actions.models import ActionOutbox
from apps.actions.registry import company_event_types, staff_only_event_types, webhook_event_types
from apps.authapi.mcp_openapi import MCP_EXPLICIT_REGISTRY, MCP_REQUIRED_OPERATION_IDS
from apps.storage.connector_services import CONNECTOR_PROVIDER_CHOICES
from apps.storage.mcp_tool_schema import coerce_mcp_call_arguments, published_mcp_tools
from apps.storage.models import StorageAccessGrant
from apps.storage.openapi_mcp_registry import MCP_SPECS
from shellui_django.mcp.routing import McpToolArgumentError

_BANNED = re.compile(
    r'\b(easy|simple|quick|seamless|robust|powerful|just|very|really|simply)\b',
    re.IGNORECASE,
)
_TRANSPORT_KEYS = frozenset({'method', 'query', 'body', 'path_params'})

# Pure reads. POST object list is a read.
_READ_ONLY = frozenset(
    {
        'storage_v1_bucket_list',
        'storage_v1_bucket_retrieve',
        'storage_v1_connector_list',
        'storage_v1_connector_retrieve',
        'storage_v1_object_list_create',
        'storage_v1_object_id_retrieve',
        'storage_v1_object_retrieve',
        'storage_v1_object_authenticated_retrieve',
        'storage_v1_object_info_authenticated_retrieve',
        'storage_v1_object_prefix_retrieve',
        'storage_v1_access_grant_list',
        'storage_v1_share_list',
        'storage_v1_quota_retrieve',
        'storage_v1_stats_retrieve',
        'api_v1_actions_events_list',
        'api_v1_actions_rules_list',
        'api_v1_actions_rules_retrieve',
        'api_v1_actions_deliveries_list',
        'api_v1_actions_deliveries_retrieve',
        'api_v1_actions_event_log_list',
        'api_v1_actions_event_log_retrieve',
        'api_v1_actions_event_log_types_list',
        'api_v1_actions_event_log_retention_retrieve',
    }
)

# Delete, overwrite a value that cannot be read back, public access, an outside
# send, a delivery re-send, or secret rotation.
_DESTRUCTIVE = frozenset(
    {
        'storage_v1_bucket_empty_create',
        'storage_v1_connector_update',
        'storage_v1_connector_partial_update',
        'storage_v1_connector_destroy',
        'storage_v1_object_destroy',
        'storage_v1_object_delete_many',
        'storage_v1_object_prefix_destroy',
        'storage_v1_object_sign_create',
        'storage_v1_object_sign_path_create',
        'storage_v1_access_grant_destroy',
        'storage_v1_share_create',
        'storage_v1_share_link_destroy',
        'api_v1_actions_rules_destroy',
        'api_v1_actions_rules_rotate_secret',
        'api_v1_actions_rules_send_test',
        'api_v1_actions_deliveries_requeue',
    }
)

# Writes whose result can be read back, including Shellui Actions rule create and update.
_PLAIN_WRITE = frozenset(
    {
        'storage_v1_connector_create',
        'storage_v1_connector_configuration_check_create',
        'storage_v1_connector_configuration_validate_create',
        'storage_v1_connector_configuration_retry_create',
        'storage_v1_object_create',
        'storage_v1_object_update',
        'storage_v1_object_prefix_create',
        'storage_v1_object_move_create',
        'storage_v1_object_copy_create',
        'storage_v1_access_grant_create',
        'storage_v1_quota_company_update',
        'storage_v1_quota_company_user_update',
        'api_v1_actions_rules_create',
        'api_v1_actions_rules_partial_update',
    }
)


def _enum_values(schema: dict) -> list:
    return [value for value in schema.get('enum') or [] if value is not None]


def _walk_enums(schema: dict, prefix: str = ''):
    if not isinstance(schema, dict):
        return
    if isinstance(schema.get('enum'), list):
        yield prefix, schema
    properties = schema.get('properties') or {}
    if isinstance(properties, dict):
        for name, child in properties.items():
            child_prefix = f'{prefix}.{name}' if prefix else str(name)
            yield from _walk_enums(child, child_prefix)
    items = schema.get('items')
    if isinstance(items, dict):
        yield from _walk_enums(items, f'{prefix}[]')


def _resolve(schema: dict, root: dict, seen: frozenset[str] | None = None) -> dict:
    if not isinstance(schema, dict):
        return {}
    seen = seen or frozenset()
    ref = schema.get('$ref')
    if isinstance(ref, str) and ref.startswith('#/components/schemas/'):
        name = ref.rsplit('/', 1)[-1]
        if name in seen:
            return {}
        target = ((root.get('components') or {}).get('schemas') or {}).get(name) or {}
        resolved = _resolve(target, root, seen | {name}) if isinstance(target, dict) else {}
        siblings = {key: value for key, value in schema.items() if key != '$ref'}
        return {**resolved, **siblings}
    all_of = schema.get('allOf')
    if isinstance(all_of, list) and all_of:
        merged: dict = {}
        props: dict = {}
        for part in all_of:
            if not isinstance(part, dict):
                continue
            flat = _resolve(part, root, seen)
            props.update(flat.get('properties') or {})
            merged.update({key: value for key, value in flat.items() if key != 'properties'})
        siblings = {key: value for key, value in schema.items() if key != 'allOf'}
        sibling_props = siblings.pop('properties', None)
        if props or sibling_props:
            merged['properties'] = {**props, **(sibling_props or {})}
        merged.update(siblings)
        return merged
    return schema


def _operation(root: dict, operation_id: str) -> dict:
    for path_item in (root.get('paths') or {}).values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if isinstance(operation, dict) and operation.get('operationId') == operation_id:
                return operation
    raise AssertionError(f'missing operation {operation_id}')


def _path(root: dict, operation_id: str, name: str) -> dict:
    for param in _operation(root, operation_id).get('parameters') or []:
        if isinstance(param, dict) and param.get('in') == 'path' and param.get('name') == name:
            return param.get('schema') or {}
    raise AssertionError(f'missing path {operation_id}.{name}')


def _query(root: dict, operation_id: str, name: str) -> dict:
    for param in _operation(root, operation_id).get('parameters') or []:
        if isinstance(param, dict) and param.get('in') == 'query' and param.get('name') == name:
            return param.get('schema') or {}
    raise AssertionError(f'missing query {operation_id}.{name}')


def _body_prop(root: dict, operation_id: str, name: str) -> dict:
    operation = _operation(root, operation_id)
    content = ((operation.get('requestBody') or {}).get('content') or {}).get('application/json') or {}
    schema = _resolve(content.get('schema') or {}, root)
    prop = (schema.get('properties') or {}).get(name)
    if not isinstance(prop, dict):
        raise AssertionError(f'missing body field {operation_id}.{name}')
    return _resolve(prop, root)


class McpToolSchemaTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.openapi = SchemaGenerator().get_schema(request=None, public=True)
        cls.tools = published_mcp_tools(cls.openapi)
        cls.by_op = {tool['_meta']['operationId']: tool for tool in cls.tools}

    def test_annotation_sets_partition_every_tool(self):
        self.assertEqual(_READ_ONLY | _DESTRUCTIVE | _PLAIN_WRITE, MCP_REQUIRED_OPERATION_IDS)
        self.assertFalse(_READ_ONLY & _DESTRUCTIVE)
        self.assertFalse(_READ_ONLY & _PLAIN_WRITE)
        self.assertFalse(_DESTRUCTIVE & _PLAIN_WRITE)
        for operation_id, tool in self.by_op.items():
            annotations = {
                'readOnlyHint': operation_id in _READ_ONLY,
                'destructiveHint': operation_id in _DESTRUCTIVE,
            }
            self.assertEqual(
                {
                    'readOnlyHint': tool['annotations']['readOnlyHint']
                    if 'annotations' in tool
                    else bool(tool['_meta']['read_only']),
                    'destructiveHint': bool(tool['_meta']['destructive']),
                },
                annotations,
                operation_id,
            )
            self.assertEqual(bool(MCP_SPECS[operation_id].destructive), operation_id in _DESTRUCTIVE)
            self.assertEqual(bool(MCP_EXPLICIT_REGISTRY[operation_id]['destructive']), operation_id in _DESTRUCTIVE)
            self.assertEqual(bool(MCP_EXPLICIT_REGISTRY[operation_id]['read_only']), operation_id in _READ_ONLY)

    def test_descriptions_name_action_arguments_and_result(self):
        for operation_id, tool in self.by_op.items():
            description = tool['description']
            self.assertEqual(description, MCP_SPECS[operation_id].summary)
            self.assertNotIn('—', description, operation_id)
            self.assertNotIn('–', description, operation_id)
            self.assertNotIn('...', description, operation_id)
            self.assertNotRegex(description, _BANNED, operation_id)
            self.assertNotRegex(description, r'\bShellUI\b|\bShellUi\b', operation_id)
            if 'Actions' in description:
                self.assertIn('Shellui Actions', description, operation_id)
            sentences = [part.strip() for part in description.split('.') if part.strip()]
            self.assertLessEqual(len(sentences), 2, description)
            self.assertGreaterEqual(len(sentences), 1, description)
            self.assertNotIn('/storage/', description, operation_id)
            self.assertNotIn('/api/', description, operation_id)

    def test_path_parameters_keep_types_and_descriptions(self):
        checks = (
            ('storage_v1_bucket_retrieve', 'bucket_id', 'string', None),
            ('storage_v1_object_id_retrieve', 'object_id', 'string', 'uuid'),
            ('storage_v1_quota_company_update', 'company_id', 'integer', None),
            ('storage_v1_quota_company_user_update', 'user_id', 'integer', None),
            ('api_v1_actions_rules_retrieve', 'id', 'integer', None),
            ('api_v1_actions_deliveries_retrieve', 'delivery_id', 'string', 'uuid'),
            ('storage_v1_object_retrieve', 'object_path', 'string', None),
        )
        for operation_id, name, schema_type, schema_format in checks:
            published = self.by_op[operation_id]['inputSchema']['properties'][name]
            openapi = _path(self.openapi, operation_id, name)
            for label, prop in (('tool', published), ('openapi', openapi)):
                self.assertEqual(prop.get('type'), schema_type, f'{label} {operation_id}.{name}')
                self.assertTrue(str(prop.get('description') or '').strip(), f'{label} {operation_id}.{name}')
                self.assertNotIn('—', str(prop.get('description')), f'{label} {operation_id}.{name}')
                self.assertNotIn('–', str(prop.get('description')), f'{label} {operation_id}.{name}')
                if schema_format:
                    self.assertEqual(prop.get('format'), schema_format, f'{label} {operation_id}.{name}')
            self.assertIn(name, self.by_op[operation_id]['inputSchema']['required'])

    def test_input_schemas_are_flat(self):
        for tool in self.tools:
            schema = tool['inputSchema']
            self.assertEqual(schema['type'], 'object')
            self.assertIs(schema['additionalProperties'], False)
            properties = schema['properties']
            self.assertFalse(set(properties) & _TRANSPORT_KEYS, tool['name'])
            for name, prop in properties.items():
                self.assertNotIn('const', prop, tool['name'])
                if name == 'path':
                    self.assertIn('object path', str(prop.get('description') or '').lower(), tool['name'])
            required = schema.get('required') or []
            self.assertFalse(set(required) & _TRANSPORT_KEYS, tool['name'])
            for field_path, prop in _walk_enums(schema):
                self.assertTrue(str(prop.get('description') or '').strip(), f'{tool["name"]}.{field_path}')
                self.assertNotIn('—', str(prop.get('description')), tool['name'])
                self.assertNotIn('–', str(prop.get('description')), tool['name'])

    def test_fixed_values_are_enums_on_tools_and_openapi(self):
        providers = [choice[0] for choice in CONNECTOR_PROVIDER_CHOICES]
        events = [event.id for event in webhook_event_types()]
        statuses = [choice[0] for choice in ActionOutbox.STATUS_CHOICES]
        subjects = [choice[0] for choice in StorageAccessGrant.SubjectType.choices]
        resources = [choice[0] for choice in StorageAccessGrant.ResourceType.choices]
        permissions = [choice[0] for choice in StorageAccessGrant.Permission.choices]
        effects = [choice[0] for choice in StorageAccessGrant.Effect.choices]

        cases = {
            'storage_v1_connector_create': {'connector_provider': providers},
            'storage_v1_connector_update': {'connector_provider': providers},
            'storage_v1_connector_partial_update': {'connector_provider': providers},
            'api_v1_actions_rules_create': {'event_type': events},
            'api_v1_actions_rules_partial_update': {'event_type': events},
            'storage_v1_access_grant_create': {
                'subject_type': subjects,
                'resource_type': resources,
                'permission': permissions,
                'effect': effects,
            },
            'storage_v1_access_grant_list': {
                'resource_type': resources,
                'include_effective': ['true', 'false'],
            },
            'api_v1_actions_deliveries_list': {
                'status': statuses,
                'event_type': events,
            },
            'api_v1_actions_event_log_list': {'scope': ['company', 'platform']},
            'api_v1_actions_event_log_retrieve': {'scope': ['company', 'platform']},
            'storage_v1_object_list_create': {},
        }
        query_ops = {
            'storage_v1_access_grant_list',
            'api_v1_actions_deliveries_list',
            'api_v1_actions_event_log_list',
            'api_v1_actions_event_log_retrieve',
        }
        for operation_id, expected in cases.items():
            props = self.by_op[operation_id]['inputSchema']['properties']
            for name, values in expected.items():
                self.assertEqual(_enum_values(props[name]), values, f'{operation_id}.{name}')
                if operation_id in query_ops:
                    openapi_prop = _query(self.openapi, operation_id, name)
                else:
                    openapi_prop = _body_prop(self.openapi, operation_id, name)
                self.assertEqual(_enum_values(openapi_prop), values, f'openapi {operation_id}.{name}')
                self.assertTrue(str(openapi_prop.get('description') or '').strip(), f'openapi {operation_id}.{name}')

        sort_by = self.by_op['storage_v1_object_list_create']['inputSchema']['properties']['sortBy']
        self.assertEqual(_enum_values(sort_by['properties']['column']), ['name', 'updated_at', 'created_at'])
        self.assertEqual(_enum_values(sort_by['properties']['order']), ['asc', 'desc'])
        openapi_sort = _body_prop(self.openapi, 'storage_v1_object_list_create', 'sortBy')
        self.assertEqual(_enum_values(openapi_sort['properties']['column']), ['name', 'updated_at', 'created_at'])
        self.assertEqual(_enum_values(openapi_sort['properties']['order']), ['asc', 'desc'])

        days = self.by_op['storage_v1_stats_retrieve']['inputSchema']['properties']['days']
        self.assertEqual(days['minimum'], 1)
        self.assertEqual(days['maximum'], 90)
        self.assertNotIn('enum', days)
        self.assertIn('1 to 90', days['description'])

        event_type = self.by_op['api_v1_actions_event_log_list']['inputSchema']['properties']['event_type']
        self.assertNotIn('enum', event_type)
        description = event_type['description']
        self.assertIn('separated by commas', description)
        for event in (*company_event_types(), *staff_only_event_types()):
            self.assertIn(event.id, description)

    def test_coerce_splits_flat_arguments_and_keeps_legacy_envelope(self):
        meta = {
            'path': '/storage/v1/object/sign/{bucket_id}',
            'method': 'POST',
            'path_params': ['bucket_id'],
            'query_fields': None,
            'body_fields': ['path', 'expiresIn', 'expires_in'],
            'body_required': None,
        }
        nested = coerce_mcp_call_arguments(
            {'bucket_id': 'company', 'path': 'notes/a.txt', 'expiresIn': 60},
            meta,
        )
        self.assertEqual(nested['path_params'], {'bucket_id': 'company'})
        self.assertEqual(nested['body'], {'path': 'notes/a.txt', 'expiresIn': 60})
        self.assertEqual(nested['query'], {})
        self.assertNotIn('path', nested['query'])

        legacy = {'method': 'POST', 'path': meta['path'], 'body': {'path': 'notes/a.txt'}, 'query': {}}
        self.assertIs(coerce_mcp_call_arguments(legacy, meta), legacy)

        prefix_meta = {
            'path': '/storage/v1/object/prefix/{bucket_id}',
            'method': 'DELETE',
            'path_params': ['bucket_id'],
            'query_fields': ['prefix'],
            'body_fields': ['prefix'],
            'body_required': ['prefix'],
        }
        deleted = coerce_mcp_call_arguments({'bucket_id': 'company', 'prefix': 'trash'}, prefix_meta)
        self.assertEqual(deleted['body'], {'prefix': 'trash'})
        self.assertEqual(deleted['query'], {})

        with self.assertRaises(McpToolArgumentError):
            coerce_mcp_call_arguments({'bucket_id': 'company', 'nope': 1}, prefix_meta)
        with self.assertRaises(McpToolArgumentError):
            coerce_mcp_call_arguments({'bucket_id': 'company'}, prefix_meta)
