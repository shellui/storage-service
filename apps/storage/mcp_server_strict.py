"""Strict MCP HTTP handler: identity-bound approvals, grant checks, and audited call logs."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from datetime import date, datetime
from decimal import Decimal
from uuid import UUID
from collections.abc import Callable
from typing import Any
from django.http import HttpRequest, JsonResponse
from rest_framework.test import APIRequestFactory, force_authenticate

from shellui_django.mcp.masking import redact_mapping
from shellui_django.mcp.openapi_mcp import marker_tree_for_operation_response, marker_tree_for_schema
from shellui_django.mcp.openapi_tools import tools_from_schema
from shellui_django.mcp.rate_limit import check_agent_rate_limit
from shellui_django.mcp.routing import (
    McpToolArgumentError,
    materialize_openapi_path,
    path_parameter_names,
    validate_mcp_tool_arguments,
)
from shellui_django.mcp.write_gate import decide_write, is_destructive_operation

from apps.storage.mcp_assertions import (
    parse_company_binding_version,
    parse_grant_version,
    parse_global_company_id,
)
from apps.storage.mcp_identity import (
    _UUID_RE,
    _registry_operation_for_call_log,
    delegated_live_authority_gate,
    grant_versions_compatible,
    identity_revocation_unavailable,
    identity_token_ok,
)

logger = logging.getLogger(__name__)

_BODYLESS_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS', 'TRACE'})

# MCP downloads return base64. Larger objects should use a signed URL.
_MCP_BINARY_LIMIT_BYTES = 8 * 1024 * 1024

# Share create returns the token once. Webhook signing secrets stay masked in MCP
# results, including on create and rotate. The admin HTTP response still returns
# that secret once.
_REVEAL_ONCE_FIELDS = {
    'storage_v1_share_create': ('token',),
}

_STATS_FILENAME_KEYS = frozenset({'name', 'basename'})

# AI gateway and Shellui Identity error taxonomy (audit ``error.code`` and MCP JSON-RPC layer).
AUDIT_ERROR_CODES = frozenset(
    {
        'bad_request',
        'unauthorized',
        'forbidden',
        'not_found',
        'conflict',
        'rate_limited',
        'timeout',
        'upstream_error',
        'internal_error',
        'denied',
        'expired',
        'out_of_sync',
        'unknown',
        'identity_unavailable',
        'identity_invalid',
        'invalid_json',
        'method_not_allowed',
        'agent_revoked',
        'approval_unavailable',
    }
)

_IDENTITY_RPC_ERRORS = frozenset({'identity_unavailable', 'identity_invalid', 'agent_revoked'})


def _inner_response_failed(*, status_code: int, data: Any) -> bool:
    """True when HTTP status is a success but the body is a storage business error (not success by code alone)."""
    if status_code >= 400:
        return False
    if isinstance(data, dict) and data.get('ok') is False:
        return True
    if isinstance(data, dict) and data.get('error') is not None:
        return True
    if isinstance(data, dict) and data.get('statusCode') is not None:
        return True
    return False


def _inner_response_effective_status(*, status_code: int, data: Any) -> int:
    if _inner_response_failed(status_code=status_code, data=data):
        return max(status_code, 422)
    return status_code


def _inner_http_error_code(status_code: int) -> str | None:
    if status_code >= 400:
        return _http_status_bucket(status_code)
    return None


def _http_status_bucket(status_code: int) -> str:
    if status_code == 400:
        return 'bad_request'
    if status_code == 401:
        return 'unauthorized'
    if status_code == 403:
        return 'forbidden'
    if status_code == 404:
        return 'not_found'
    if status_code == 409:
        return 'conflict'
    if status_code == 422:
        return 'bad_request'
    if status_code == 408:
        return 'timeout'
    if status_code == 429:
        return 'rate_limited'
    if status_code == 503:
        return 'upstream_error'
    if status_code >= 500:
        return 'internal_error'
    return 'unknown'


def public_mcp_tool(tool: dict[str, Any]) -> dict[str, Any]:
    """Tool object returned by ``tools/list`` (no private ``_meta``)."""
    public = {k: v for k, v in tool.items() if not str(k).startswith('_')}
    meta = tool.get('_meta') or {}
    public['annotations'] = {
        'readOnlyHint': bool(meta.get('read_only')),
        'destructiveHint': bool(meta.get('destructive')),
    }
    return public


def _library_validation_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Copy arguments so nested ``object_path`` values pass the shared slash check.

    The shared helper rejects ``/`` in every path parameter. ``object_path`` is a
    catch-all segment on the storage routes, so the real substitution happens in
    ``materialize_storage_mcp_path``.
    """
    cloned = dict(arguments)
    path_params = cloned.get('path_params')
    if isinstance(path_params, dict) and 'object_path' in path_params:
        params = dict(path_params)
        raw = params.get('object_path')
        if isinstance(raw, str):
            params['object_path'] = raw.replace('/', '_')
        cloned['path_params'] = params
    return cloned


def materialize_storage_mcp_path(path_template: str, path_params: dict[str, Any]) -> str:
    """Substitute path parameters. ``object_path`` may contain ``/``."""
    names = path_parameter_names(path_template)
    if not isinstance(path_params, dict):
        raise McpToolArgumentError('path_params must be an object.')
    if set(path_params.keys()) != set(names):
        return materialize_openapi_path(path_template, path_params)
    resolved = path_template
    for name in names:
        raw = path_params[name]
        if raw is None:
            raise McpToolArgumentError(f'Path parameter {name} is required.')
        text = str(raw).strip()
        if not text:
            raise McpToolArgumentError(f'Path parameter {name} is required.')
        if any(ord(ch) < 32 for ch in text) or '{' in text or '}' in text or '?' in text or '#' in text:
            raise McpToolArgumentError(f'Path parameter {name} is invalid.')
        if name == 'object_path':
            if not text.strip('/'):
                raise McpToolArgumentError('Path parameter object_path is required.')
            if '\\' in text:
                raise McpToolArgumentError('Path parameter object_path is invalid.')
        elif '/' in text:
            raise McpToolArgumentError(f'Path parameter {name} is invalid.')
        token = '{' + name + '}'
        if token not in resolved:
            raise McpToolArgumentError('Unresolved path template.')
        resolved = resolved.replace(token, text, 1)
    if path_parameter_names(resolved):
        raise McpToolArgumentError('Unresolved path template.')
    return resolved


def _response_markers(operation: dict[str, Any] | None, schema: dict[str, Any], data: Any) -> tuple[Any, dict[str, Any]]:
    """Return ``(payload, markers)`` for redaction.

    List bodies are wrapped as ``{"result": [...]}`` so item field markers apply.
    """
    if isinstance(data, dict):
        return data, marker_tree_for_operation_response(operation, schema)
    # shellui-django redacts a list item by looking up the parent key inside the
    # item markers. Nest the field markers under that same key so path_url is covered.
    item_markers = _array_item_markers(operation, schema)
    nested = {
        'result': {
            'secret': False,
            'sensitive': False,
            'children': item_markers,
        }
    }
    wrapped_markers = {
        'result': {'secret': False, 'sensitive': False, 'children': nested},
    }
    return {'result': data}, wrapped_markers


def _array_item_markers(operation: dict[str, Any] | None, schema: dict[str, Any]) -> dict[str, Any]:
    responses = (operation or {}).get('responses') or {}
    if not isinstance(responses, dict):
        return {}
    for status_code in ('200', '201', '202', '204'):
        response = responses.get(status_code)
        if not isinstance(response, dict):
            continue
        content = response.get('content') or {}
        if not isinstance(content, dict):
            continue
        json_schema = (content.get('application/json') or {}).get('schema')
        if not isinstance(json_schema, dict):
            continue
        synthetic = {'type': 'object', 'properties': {'result': json_schema}}
        wrapped = marker_tree_for_schema(synthetic, schema)
        node = wrapped.get('result') if isinstance(wrapped, dict) else None
        children = node.get('children') if isinstance(node, dict) else None
        if isinstance(children, dict):
            return children
    return {}


def _redact_stats_filenames(data: Any, *, read_sensitive: bool) -> Any:
    if read_sensitive or not isinstance(data, dict):
        return data
    recent = data.get('recent')
    if not isinstance(recent, list):
        return data
    cleaned = []
    for row in recent:
        if isinstance(row, dict):
            row = dict(row)
            for key in _STATS_FILENAME_KEYS:
                if key in row and row[key] not in (None, ''):
                    row[key] = '[redacted]'
        cleaned.append(row)
    data = dict(data)
    data['recent'] = cleaned
    return data


def _reveal_once_secrets(operation_id: str, original: Any, redacted: dict[str, Any]) -> dict[str, Any]:
    fields = _REVEAL_ONCE_FIELDS.get(operation_id)
    if not fields or not isinstance(original, dict):
        return redacted
    restored = dict(redacted)
    for key in fields:
        value = original.get(key)
        if isinstance(value, str) and value and value != '[redacted]':
            restored[key] = value
    return restored


def _binary_mcp_payload(response: Any) -> dict[str, Any]:
    content_type = str(response.get('Content-Type') or 'application/octet-stream').split(';', 1)[0].strip()
    declared = response.get('Content-Length')
    try:
        declared_len = int(declared) if declared is not None else None
    except (TypeError, ValueError):
        declared_len = None
    if declared_len is not None and declared_len > _MCP_BINARY_LIMIT_BYTES:
        closer = getattr(response, 'close', None)
        if callable(closer):
            closer()
        return {
            'error': 'object_too_large_for_mcp',
            'size': declared_len,
            'content_type': content_type,
        }
    if getattr(response, 'streaming', False):
        raw = b''.join(response.streaming_content)
    else:
        raw = bytes(response.content or b'')
    closer = getattr(response, 'close', None)
    if callable(closer):
        closer()
    if len(raw) > _MCP_BINARY_LIMIT_BYTES:
        return {
            'error': 'object_too_large_for_mcp',
            'size': len(raw),
            'content_type': content_type,
        }
    payload = {
        'content_type': content_type,
        'content_base64': base64.b64encode(raw).decode('ascii'),
        'size': len(raw),
    }
    disposition = response.get('Content-Disposition')
    if disposition:
        payload['content_disposition'] = str(disposition)
    return payload


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f'Object of type {type(value).__name__} is not JSON serializable')


def _tool_operation_summary(tool: dict[str, Any], schema: dict[str, Any]) -> str:
    meta = tool.get('_meta') or {}
    op_id = meta.get('operationId')
    if op_id:
        paths = schema.get('paths') or {}
        for path_item in paths.values():
            if not isinstance(path_item, dict):
                continue
            for op in path_item.values():
                if isinstance(op, dict) and op.get('operationId') == op_id:
                    s = (op.get('summary') or '').strip()
                    if s:
                        return s[:500]
    return f"Operation {tool.get('name') or op_id or 'tool'}"[:500]


def _map_write_gate_outcome(decision: Any, *, granted: bool) -> str:
    if granted:
        return 'allowed'
    if getattr(decision, 'needs_approval', False):
        return 'waiting_approval'
    if not getattr(decision, 'allowed', False):
        return 'denied'
    return 'failed'


class StrictMcpServer:
    """Same contract as ``shellui_django.mcp.server.McpServer`` with stricter identity binding."""

    def __init__(
        self,
        *,
        schema_provider: Callable[[], dict[str, Any]],
        urlconf: str,
        service_name: str,
        identity_revocation_check: Callable[..., bool],
        delegated_authority_gate: Callable[[dict[str, Any], dict[str, Any]], tuple[bool, bool]] | None = None,
        on_call: Callable[[dict[str, Any]], None] | None = None,
        approval_handler: Callable[..., dict[str, Any] | None] | None = None,
        approval_state: Callable[..., str | None] | None = None,
        approval_consume: Callable[..., Any] | None = None,
    ):
        self.schema_provider = schema_provider
        self.urlconf = urlconf
        self.service_name = service_name
        self.identity_revocation_check = identity_revocation_check
        self.delegated_authority_gate = delegated_authority_gate or delegated_live_authority_gate
        self.on_call = on_call
        self.approval_handler = approval_handler
        self.approval_state = approval_state
        self.approval_consume = approval_consume
        self._factory = APIRequestFactory()

    def handle(
        self,
        request: HttpRequest,
        *,
        agent_claims: dict[str, Any] | None,
        mcp_resource_audience: str | None = None,
    ) -> JsonResponse:
        if request.method != 'POST':
            return JsonResponse({'error': 'method_not_allowed'}, status=405)
        if agent_claims is None:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        if agent_claims.get('_mcp_delegated_authority_denied'):
            return JsonResponse({'error': 'forbidden'}, status=403)
        agent_id = str(agent_claims.get('agent_id') or '')
        if not agent_id:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        if check_agent_rate_limit(agent_id):
            return JsonResponse({'error': 'rate_limited'}, status=429)
        token_ok, _reason = identity_token_ok(agent_claims)
        if not token_ok:
            return JsonResponse({'error': 'identity_invalid'}, status=401)
        if parse_grant_version(agent_claims.get('grant_version')) is None:
            return JsonResponse({'error': 'identity_invalid'}, status=401)
        if not str(agent_claims.get('scope') or '').strip():
            return JsonResponse({'error': 'identity_invalid'}, status=401)

        company_id = agent_claims.get('company_id')
        if not isinstance(company_id, int) or isinstance(company_id, bool):
            return JsonResponse({'error': 'identity_invalid'}, status=401)
        company_id_int = company_id

        if identity_revocation_unavailable():
            return JsonResponse({'error': 'identity_unavailable'}, status=503)
        if self.identity_revocation_check(agent_id, company_id_int, agent_claims):
            return JsonResponse({'error': 'agent_revoked'}, status=403)

        gv_ok = grant_versions_compatible(agent_claims)
        if gv_ok is None:
            return JsonResponse({'error': 'identity_unavailable'}, status=503)
        if gv_ok is False:
            return JsonResponse({'error': 'out_of_sync'}, status=409)

        if not self._service_allowed(agent_claims, self.service_name):
            return JsonResponse({'error': 'forbidden'}, status=403)

        expected_res = (mcp_resource_audience if isinstance(mcp_resource_audience, str) else '') or ''
        gate_payload: dict[str, Any] = {
            'mcp_expected_resource': expected_res.strip() or None,
            'agent_id': agent_claims.get('agent_id'),
            'company_id': agent_claims.get('company_id'),
            'service': self.service_name,
        }
        allow_dg, unavail_dg = self.delegated_authority_gate(gate_payload, agent_claims)
        if unavail_dg:
            return JsonResponse({'error': 'identity_unavailable'}, status=503)
        if not allow_dg:
            return JsonResponse({'error': 'forbidden'}, status=403)

        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'invalid_json'}, status=400)
        method = payload.get('method')
        req_id = payload.get('id')
        params = payload.get('params') or {}
        if method == 'initialize':
            return JsonResponse(self._result(req_id, {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}}}))
        if method == 'tools/list':
            schema = self.schema_provider()
            tools = [public_mcp_tool(t) for t in tools_from_schema(schema)]
            return JsonResponse(self._result(req_id, {'tools': tools}))
        if method == 'tools/call':
            return self._tools_call(request, req_id, params, agent_claims, mcp_resource_audience=mcp_resource_audience)
        return JsonResponse(self._error(req_id, -32601, 'Method not found'))

    def _tools_call(
        self,
        request: HttpRequest,
        req_id: Any,
        params: dict[str, Any],
        agent_claims: dict[str, Any],
        *,
        mcp_resource_audience: str | None,
    ) -> JsonResponse:
        started = time.perf_counter()
        tool_name = str(params.get('name') or '')
        arguments = params.get('arguments') or {}
        schema = self.schema_provider()
        tools = tools_from_schema(schema)
        tool = next((t for t in tools if t['name'] == tool_name), None)
        if tool is None:
            return JsonResponse(self._error(req_id, -32602, 'Unknown tool'))
        meta = tool.get('_meta') or {}
        path_template = str(meta.get('path') or '')
        path = str(arguments.get('path') or path_template)
        method = str(arguments.get('method') or meta.get('method') or 'GET').upper()
        if path != path_template or method != meta.get('method'):
            return JsonResponse(self._error(req_id, -32602, 'Tool path mismatch'))
        registry_op_id = str(meta.get('operationId') or tool_name).strip()
        registry_valid = _registry_operation_for_call_log(registry_op_id, path_template, method) is not None
        if not registry_valid:
            return JsonResponse(self._error(req_id, -32602, 'Tool registry mismatch'))
        try:
            raw_arguments = arguments if isinstance(arguments, dict) else {}
            validate_mcp_tool_arguments(_library_validation_arguments(raw_arguments), meta)
            path_params = raw_arguments.get('path_params') if isinstance(raw_arguments.get('path_params'), dict) else {}
            resolved_path = materialize_storage_mcp_path(path_template, path_params)
        except McpToolArgumentError as exc:
            return JsonResponse(self._error(req_id, -32602, str(exc)))

        access = str(agent_claims.get('mcp_access') or 'read_only')
        read_level = str(agent_claims.get('mcp_read') or 'safe')
        operation = self._operation(schema, path_template, method)
        destructive = bool(meta.get('destructive')) or is_destructive_operation(operation)
        tool_read_only = bool(meta.get('read_only'))
        response_markers = marker_tree_for_operation_response(operation, schema)
        decision = decide_write(
            method=method,
            access_mode=access,
            destructive=destructive,
            allow_destructive_without_asking=bool(agent_claims.get('mcp_destructive')),
            tool_read_only=tool_read_only,
        )
        operation_title = _tool_operation_summary(tool, schema)
        audit_inner_path = path_template
        if destructive:
            access_kind = 'destructive'
        elif tool_read_only:
            access_kind = 'read'
        else:
            access_kind = 'write'
        approval_payload: dict[str, Any] = {}

        approval_granted = False
        consumed_approval_id: str | None = None
        approval_flow_state: str | None = None
        if decision.needs_approval:
            args_hash = hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode()).hexdigest()
            expected_res = (mcp_resource_audience if isinstance(mcp_resource_audience, str) else '') or ''
            approval_payload = {
                'agent_id': agent_claims.get('agent_id'),
                'company_id': agent_claims.get('company_id'),
                'service': self.service_name,
                'action': tool_name,
                'arguments_hash': args_hash,
                'resource_path': audit_inner_path,
                'http_method': method,
                'mcp_expected_resource': expected_res.strip() or None,
                'is_destructive': destructive,
            }
            granted = False
            if self.approval_state:
                approval_flow_state = self.approval_state(approval_payload, agent_claims)
                state = approval_flow_state
                if state == 'error':
                    self._emit_audit(
                        request=request,
                        agent_claims=agent_claims,
                        tool_name=tool_name,
                        method='POST',
                        audit_path=audit_inner_path,
                        operation_title=operation_title,
                        access_kind=access_kind,
                        destructive=destructive,
                        read_level=read_level,
                        arguments=arguments,
                        inner_http_method=method,
                        tool_registry_valid=registry_valid,
                        status_code=503,
                        outcome='failed',
                        error_code='upstream_error',
                        approval_id=None,
                        started=started,
                    )
                    return JsonResponse(
                        self._result(
                            req_id,
                            {'content': [{'type': 'text', 'text': 'Identity approval check failed.'}], 'isError': True},
                        )
                    )
                if state == 'expired':
                    self._emit_audit(
                        request=request,
                        agent_claims=agent_claims,
                        tool_name=tool_name,
                        method='POST',
                        audit_path=audit_inner_path,
                        operation_title=operation_title,
                        access_kind=access_kind,
                        destructive=destructive,
                        read_level=read_level,
                        arguments=arguments,
                        inner_http_method=method,
                        tool_registry_valid=registry_valid,
                        status_code=409,
                        outcome='denied',
                        error_code='expired',
                        approval_id=None,
                        started=started,
                    )
                    return JsonResponse(
                        self._result(
                            req_id,
                            {'content': [{'type': 'text', 'text': 'Approval not reusable.'}], 'isError': True},
                        )
                    )
                if state == 'denied':
                    self._emit_audit(
                        request=request,
                        agent_claims=agent_claims,
                        tool_name=tool_name,
                        method='POST',
                        audit_path=audit_inner_path,
                        operation_title=operation_title,
                        access_kind=access_kind,
                        destructive=destructive,
                        read_level=read_level,
                        arguments=arguments,
                        inner_http_method=method,
                        tool_registry_valid=registry_valid,
                        status_code=403,
                        outcome='denied',
                        error_code='denied',
                        approval_id=None,
                        started=started,
                    )
                    return JsonResponse(
                        self._result(
                            req_id,
                            {'content': [{'type': 'text', 'text': 'Approval denied.'}], 'isError': True},
                        )
                    )
                if state == 'approved':
                    approval_id = approval_payload.get('approval_id')
                    if approval_id and self.approval_consume:
                        consume_out = self.approval_consume(str(approval_id), approval_payload, agent_claims)
                        if isinstance(consume_out, tuple) and len(consume_out) == 2:
                            consumed, consume_meta = consume_out[0], consume_out[1]
                        else:
                            consumed, consume_meta = bool(consume_out), {}
                        if not isinstance(consume_meta, dict):
                            consume_meta = {}
                        if consumed:
                            granted = True
                            approval_granted = True
                            consumed_approval_id = str(approval_id)
                        else:
                            oc = str(consume_meta.get('outcome') or 'failed')
                            st = consume_meta.get('status')
                            sc = int(st) if isinstance(st, int) and not isinstance(st, bool) and st >= 0 else 503
                            ec = consume_meta.get('error_code')
                            ec_s = str(ec).strip()[:128] if ec is not None and str(ec).strip() else 'upstream_error'
                            ec_audit = (
                                ec_s
                                if ec_s in AUDIT_ERROR_CODES or ec_s in _IDENTITY_RPC_ERRORS
                                else 'unknown'
                            )
                            aid_log = consume_meta.get('approval_id')
                            aid_final = (
                                str(aid_log).strip()
                                if aid_log is not None and _UUID_RE.match(str(aid_log).strip())
                                else str(approval_id)
                            )
                            self._emit_audit(
                                request=request,
                                agent_claims=agent_claims,
                                tool_name=tool_name,
                                method='POST',
                                audit_path=audit_inner_path,
                                operation_title=operation_title,
                                access_kind=access_kind,
                                destructive=destructive,
                                read_level=read_level,
                                arguments=arguments,
                                inner_http_method=method,
                                tool_registry_valid=registry_valid,
                                status_code=sc,
                                outcome=oc if oc in ('failed', 'denied', 'waiting_approval') else 'failed',
                                error_code=ec_audit,
                                approval_id=aid_final,
                                started=started,
                            )
                            if oc == 'denied' and sc == 409:
                                return JsonResponse(
                                    self._result(
                                        req_id,
                                        {'content': [{'type': 'text', 'text': 'Approval not reusable.'}], 'isError': True},
                                    )
                                )
                            return JsonResponse(
                                self._result(
                                    req_id,
                                    {'content': [{'type': 'text', 'text': 'Approval unavailable.'}], 'isError': True},
                                )
                            )
                    else:
                        self._emit_audit(
                            request=request,
                            agent_claims=agent_claims,
                            tool_name=tool_name,
                            method='POST',
                            audit_path=audit_inner_path,
                            operation_title=operation_title,
                            access_kind=access_kind,
                            destructive=destructive,
                            read_level=read_level,
                            arguments=arguments,
                            inner_http_method=method,
                            tool_registry_valid=registry_valid,
                            status_code=503,
                            outcome='failed',
                            error_code='upstream_error',
                            approval_id=str(approval_id) if approval_id else None,
                            started=started,
                        )
                        return JsonResponse(
                            self._result(
                                req_id,
                                {'content': [{'type': 'text', 'text': 'Approval unavailable.'}], 'isError': True},
                            )
                        )
                if state == 'pending':
                    self._emit_audit(
                        request=request,
                        agent_claims=agent_claims,
                        tool_name=tool_name,
                        method='POST',
                        audit_path=audit_inner_path,
                        operation_title=operation_title,
                        access_kind=access_kind,
                        destructive=destructive,
                        read_level=read_level,
                        arguments=arguments,
                        inner_http_method=method,
                        tool_registry_valid=registry_valid,
                        status_code=202,
                        outcome='waiting_approval',
                        error_code=None,
                        approval_id=str(approval_payload['approval_id'])
                        if approval_payload.get('approval_id')
                        else None,
                        started=started,
                    )
                    return JsonResponse(
                        self._result(
                            req_id,
                            {
                                'content': [{'type': 'text', 'text': 'Approval pending.'}],
                                'isError': True,
                                'meta': {'status': 'pending'},
                            },
                        )
                    )
            if not granted and self.approval_handler and approval_flow_state is None:
                pending = self.approval_handler(approval_payload, agent_claims)
                if pending and pending.get('_approval_error'):
                    ec = str(pending.get('error_code') or 'upstream_error')
                    self._emit_audit(
                        request=request,
                        agent_claims=agent_claims,
                        tool_name=tool_name,
                        method='POST',
                        audit_path=audit_inner_path,
                        operation_title=operation_title,
                        access_kind=access_kind,
                        destructive=destructive,
                        read_level=read_level,
                        arguments=arguments,
                        inner_http_method=method,
                        tool_registry_valid=registry_valid,
                        status_code=503,
                        outcome='failed',
                        error_code=ec if ec in AUDIT_ERROR_CODES else 'upstream_error',
                        approval_id=None,
                        started=started,
                    )
                    msg = str(pending.get('message') or 'Approval unavailable.')
                    return JsonResponse(
                        self._result(
                            req_id,
                            {'content': [{'type': 'text', 'text': msg}], 'isError': True},
                        )
                    )
                if pending:
                    rid = pending.get('id')
                    self._emit_audit(
                        request=request,
                        agent_claims=agent_claims,
                        tool_name=tool_name,
                        method='POST',
                        audit_path=audit_inner_path,
                        operation_title=operation_title,
                        access_kind=access_kind,
                        destructive=destructive,
                        read_level=read_level,
                        arguments=arguments,
                        inner_http_method=method,
                        tool_registry_valid=registry_valid,
                        status_code=202,
                        outcome='waiting_approval',
                        error_code=None,
                        approval_id=str(rid) if rid is not None else None,
                        started=started,
                    )
                    return JsonResponse(
                        self._result(
                            req_id,
                            {
                                'content': [{'type': 'text', 'text': 'Approval required.'}],
                                'isError': True,
                                'meta': {'approval_id': rid, 'status': 'pending'},
                            },
                        )
                    )
            if not granted and not approval_granted:
                oc = _map_write_gate_outcome(decision, granted=False)
                self._emit_audit(
                    request=request,
                    agent_claims=agent_claims,
                    tool_name=tool_name,
                    method='POST',
                    audit_path=audit_inner_path,
                    operation_title=operation_title,
                    access_kind=access_kind,
                    destructive=destructive,
                    read_level=read_level,
                    arguments=arguments,
                    inner_http_method=method,
                    tool_registry_valid=registry_valid,
                    status_code=403,
                    outcome=oc,
                    error_code='denied',
                    approval_id=None,
                    started=started,
                )
                return JsonResponse(
                    self._result(
                        req_id,
                        {'content': [{'type': 'text', 'text': decision.reason or 'Forbidden'}], 'isError': True},
                    )
                )
        if not approval_granted and not decision.allowed:
            oc = _map_write_gate_outcome(decision, granted=False)
            self._emit_audit(
                request=request,
                agent_claims=agent_claims,
                tool_name=tool_name,
                method='POST',
                audit_path=audit_inner_path,
                operation_title=operation_title,
                access_kind=access_kind,
                destructive=destructive,
                read_level=read_level,
                arguments=arguments,
                inner_http_method=method,
                tool_registry_valid=registry_valid,
                status_code=403,
                outcome=oc,
                error_code='denied',
                approval_id=None,
                started=started,
            )
            return JsonResponse(
                self._result(
                    req_id,
                    {'content': [{'type': 'text', 'text': decision.reason or 'Forbidden'}], 'isError': True},
                )
            )

        inner_kwargs: dict[str, Any] = {
            'query_params': arguments.get('query') or {},
            'HTTP_AUTHORIZATION': request.META.get('HTTP_AUTHORIZATION', ''),
        }
        if method not in _BODYLESS_METHODS:
            body = arguments.get('body')
            if body is None:
                body = {}
            if not isinstance(body, dict):
                return JsonResponse(self._error(req_id, -32602, 'body must be an object.'))
            # APIRequestFactory.generic stringifies a dict. Views need JSON bytes.
            inner_kwargs['data'] = json.dumps(body).encode('utf-8')
            inner_kwargs['content_type'] = 'application/json'
        drf_request = self._factory.generic(method, resolved_path, **inner_kwargs)
        self._attach_request_principal(drf_request, request, agent_claims)
        from django.urls import resolve

        match = resolve(resolved_path, urlconf=self.urlconf)
        response = match.func(drf_request, *match.args, **match.kwargs)
        status_code = getattr(response, 'status_code', 500)
        if hasattr(response, 'data'):
            data = response.data  # type: ignore[attr-defined]
        else:
            data = _binary_mcp_payload(response)
        eff_status = _inner_response_effective_status(status_code=status_code, data=data)
        read_sensitive = read_level == 'sensitive'
        if registry_op_id == 'storage_v1_stats_retrieve':
            data = _redact_stats_filenames(data, read_sensitive=read_sensitive)
        payload_for_redact, redact_markers = _response_markers(operation, schema, data)
        if response_markers and isinstance(data, dict):
            redact_markers = response_markers
        redacted = redact_mapping(
            payload_for_redact,
            read_sensitive=read_sensitive,
            markers=redact_markers,
        )
        if eff_status < 400:
            redacted = _reveal_once_secrets(registry_op_id, data if isinstance(data, dict) else None, redacted)
        inner_fail = _inner_response_failed(status_code=status_code, data=data)
        http_outcome = 'failed' if eff_status >= 400 else 'allowed'
        cons_approval_id = consumed_approval_id or (
            str(approval_payload['approval_id']) if approval_payload.get('approval_id') else None
        )
        self._emit_audit(
            request=request,
            agent_claims=agent_claims,
            tool_name=tool_name,
            method='POST',
            audit_path=audit_inner_path,
            operation_title=operation_title,
            access_kind=access_kind,
            destructive=destructive,
            read_level=read_level,
            arguments=arguments,
            inner_http_method=method,
            tool_registry_valid=registry_valid,
            status_code=eff_status,
            outcome=http_outcome,
            error_code=_inner_http_error_code(eff_status),
            approval_id=cons_approval_id,
            started=started,
        )
        return JsonResponse(
            self._result(
                req_id,
                {
                    'content': [{'type': 'text', 'text': json.dumps(redacted, default=_json_default)}],
                    'isError': eff_status >= 400,
                },
            )
        )

    def _emit_audit(
        self,
        *,
        request: HttpRequest,
        agent_claims: dict[str, Any],
        tool_name: str,
        method: str,
        audit_path: str,
        operation_title: str,
        access_kind: str,
        destructive: bool,
        read_level: str,
        arguments: dict[str, Any],
        status_code: int,
        outcome: str,
        error_code: str | None,
        approval_id: str | None,
        started: float,
        inner_http_method: str | None = None,
        tool_registry_valid: bool | None = None,
    ) -> None:
        if not self.on_call:
            return
        duration_ms = int(round((time.perf_counter() - started) * 1000))
        gcid = parse_global_company_id(agent_claims.get('global_company_id'))
        gv = parse_grant_version(agent_claims.get('grant_version'))
        if gv is None:
            return
        cb_raw = agent_claims.get('company_binding_version')
        cbv = parse_company_binding_version(cb_raw) if cb_raw is not None else None
        scope_s = str(agent_claims.get('scope') or '').strip()
        if not scope_s:
            return
        entry: dict[str, Any] = {
            'agent_id': agent_claims.get('agent_id'),
            'company_id': agent_claims.get('company_id'),
            'grant_version': gv,
            'scope': scope_s[:512],
            'service': self.service_name,
            'tool': tool_name,
            'operation_title': operation_title,
            'http_method': inner_http_method if isinstance(inner_http_method, str) and inner_http_method.strip() else method,
            'resource_path': audit_path,
            'access_kind': access_kind,
            'outcome': outcome,
            'status': status_code,
            'duration_ms': duration_ms,
            'approval_id': approval_id,
        }
        if tool_registry_valid is not None:
            entry['tool_registry_valid'] = bool(tool_registry_valid)
        if gcid is not None:
            entry['global_company_id'] = gcid
            if cbv is not None:
                entry['company_binding_version'] = cbv
        if error_code:
            if error_code in AUDIT_ERROR_CODES or error_code in _IDENTITY_RPC_ERRORS:
                entry['error_code'] = error_code
            else:
                entry['error_code'] = 'unknown'
        try:
            self.on_call(entry)
        except Exception:
            logger.debug('MCP on_call hook failed', exc_info=True)

    @staticmethod
    def _attach_request_principal(
        target_request,
        source_request: HttpRequest,
        agent_claims: dict[str, Any],
    ) -> None:
        user = getattr(source_request, 'user', None)
        auth = getattr(source_request, 'auth', None)
        if auth is None and agent_claims:
            auth = agent_claims
        if user is not None or auth is not None:
            force_authenticate(target_request, user=user, token=auth)
        if auth is not None:
            target_request.auth = auth

    @staticmethod
    def _service_allowed(agent_claims: dict[str, Any], service_name: str) -> bool:
        scope = [part for part in str(agent_claims.get('scope') or '').split() if part]
        if not scope:
            return False
        return service_name in scope

    @staticmethod
    def _operation(schema: dict[str, Any], path: str, method: str) -> dict[str, Any] | None:
        item = (schema.get('paths') or {}).get(path) or {}
        return item.get(method.lower())

    @staticmethod
    def _result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {'jsonrpc': '2.0', 'id': req_id, 'result': result}

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {'jsonrpc': '2.0', 'id': req_id, 'error': {'code': code, 'message': message}}
