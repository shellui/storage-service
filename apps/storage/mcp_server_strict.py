"""Strict MCP HTTP handler: identity-bound approvals, grant checks, and audited call logs."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from typing import Any
from django.http import HttpRequest, JsonResponse
from rest_framework.test import APIRequestFactory, force_authenticate

from shellui_django.mcp.masking import redact_mapping
from shellui_django.mcp.openapi_mcp import marker_tree_for_operation_response
from shellui_django.mcp.openapi_tools import tools_from_schema
from shellui_django.mcp.rate_limit import check_agent_rate_limit
from shellui_django.mcp.routing import McpToolArgumentError, materialize_openapi_path, validate_mcp_tool_arguments
from shellui_django.mcp.write_gate import decide_write, is_destructive_operation

from apps.storage.mcp_assertions import (
    parse_company_binding_version,
    parse_grant_version,
    parse_global_company_id,
)
from apps.storage.mcp_identity import (
    _UUID_RE,
    delegated_live_authority_gate,
    grant_versions_compatible,
    identity_revocation_unavailable,
    identity_token_ok,
)

logger = logging.getLogger(__name__)

_BODYLESS_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS', 'TRACE'})

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
            tools = [{k: v for k, v in t.items() if not k.startswith('_')} for t in tools_from_schema(schema)]
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
        try:
            validate_mcp_tool_arguments(arguments if isinstance(arguments, dict) else {}, meta)
            path_params = arguments.get('path_params') if isinstance(arguments.get('path_params'), dict) else {}
            resolved_path = materialize_openapi_path(path_template, path_params)
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
            expected_res = mcp_resource_audience if isinstance(mcp_resource_audience, str) else ''
            approval_payload = {
                'agent_id': agent_claims.get('agent_id'),
                'company_id': agent_claims.get('company_id'),
                'service': self.service_name,
                'action': tool_name,
                'arguments_hash': args_hash,
                'resource_path': audit_inner_path,
                'http_method': method,
                'mcp_expected_resource': expected_res.strip() or None,
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
                if state in ('executed', 'expired'):
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
                        status_code=409,
                        outcome='session_used',
                        error_code='expired',
                        approval_id=None,
                        started=started,
                    )
                    return JsonResponse(
                        self._result(
                            req_id,
                            {'content': [{'type': 'text', 'text': 'Approval already used.'}], 'isError': True},
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
                                status_code=sc,
                                outcome=oc if oc in ('failed', 'session_used', 'waiting_approval') else 'failed',
                                error_code=ec_audit,
                                approval_id=aid_final,
                                started=started,
                            )
                            if oc == 'session_used':
                                return JsonResponse(
                                    self._result(
                                        req_id,
                                        {'content': [{'type': 'text', 'text': 'Approval already used.'}], 'isError': True},
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
                elif state == 'pending':
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
            inner_kwargs['data'] = body if body is not None else {}
        drf_request = self._factory.generic(method, resolved_path, **inner_kwargs)
        self._attach_request_principal(drf_request, request, agent_claims)
        from django.urls import resolve

        match = resolve(resolved_path, urlconf=self.urlconf)
        response = match.func(drf_request, *match.args, **match.kwargs)
        status_code = getattr(response, 'status_code', 500)
        try:
            data = response.data  # type: ignore[attr-defined]
        except AttributeError:
            data = {'detail': 'ok'}
        eff_status = _inner_response_effective_status(status_code=status_code, data=data)
        read_sensitive = read_level == 'sensitive'
        redacted = redact_mapping(
            data if isinstance(data, dict) else {'result': data},
            read_sensitive=read_sensitive,
            markers=response_markers,
        )
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
                    'content': [{'type': 'text', 'text': json.dumps(redacted)}],
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
            'http_method': method,
            'resource_path': audit_path,
            'access_kind': access_kind,
            'outcome': outcome,
            'status': status_code,
            'duration_ms': duration_ms,
            'approval_id': approval_id,
        }
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
