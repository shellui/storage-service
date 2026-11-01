"""Streamable HTTP MCP endpoint handler (JSON-RPC over POST /mcp)."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Callable

from django.http import HttpRequest, JsonResponse
from rest_framework.test import APIRequestFactory, force_authenticate

from shellui_mcp.masking import redact_mapping
from shellui_mcp.openapi_mcp import marker_tree_for_operation_request, marker_tree_for_operation_response
from shellui_mcp.openapi_tools import tools_from_schema
from shellui_mcp.rate_limit import check_agent_rate_limit
from shellui_mcp.routing import McpToolArgumentError, materialize_openapi_path, validate_mcp_tool_arguments
from shellui_mcp.write_gate import decide_write, is_destructive_operation

logger = logging.getLogger(__name__)


class McpServer:
    def __init__(
        self,
        *,
        schema_provider: Callable[[], dict[str, Any]],
        urlconf: str,
        service_name: str,
        identity_revocation_check: Callable[[str], bool] | None = None,
        on_call: Callable[[dict[str, Any]], None] | None = None,
        approval_handler: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
        approval_state: Callable[[dict[str, Any]], str | None] | None = None,
        approval_consume: Callable[..., bool] | None = None,
    ):
        self.schema_provider = schema_provider
        self.urlconf = urlconf
        self.service_name = service_name
        self.identity_revocation_check = identity_revocation_check
        self.on_call = on_call
        self.approval_handler = approval_handler
        self.approval_state = approval_state
        self.approval_consume = approval_consume
        self._factory = APIRequestFactory()

    def handle(self, request: HttpRequest, *, agent_claims: dict[str, Any] | None) -> JsonResponse:
        if request.method != 'POST':
            return JsonResponse({'error': 'method_not_allowed'}, status=405)
        if agent_claims is None:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        agent_id = str(agent_claims.get('agent_id') or '')
        if not agent_id:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        if check_agent_rate_limit(agent_id):
            return JsonResponse({'error': 'rate_limited'}, status=429)
        if self.identity_revocation_check and self.identity_revocation_check(agent_id):
            return JsonResponse({'error': 'agent_revoked'}, status=403)
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
            return self._tools_call(request, req_id, params, agent_claims)
        return JsonResponse(self._error(req_id, -32601, 'Method not found'))

    def _tools_call(
        self,
        request: HttpRequest,
        req_id: Any,
        params: dict[str, Any],
        agent_claims: dict[str, Any],
    ) -> JsonResponse:
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
        request_markers = marker_tree_for_operation_request(operation, schema)
        response_markers = marker_tree_for_operation_response(operation, schema)
        decision = decide_write(
            method=method,
            access_mode=access,
            destructive=destructive,
            allow_destructive_without_asking=bool(agent_claims.get('mcp_destructive')),
            tool_read_only=tool_read_only,
        )
        if decision.needs_approval:
            args_hash = hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode()).hexdigest()
            approval_payload = {
                'agent_id': agent_claims.get('agent_id'),
                'company_id': agent_claims.get('company_id'),
                'service': self.service_name,
                'action': tool_name,
                'arguments': arguments,
                'arguments_hash': args_hash,
                'path': resolved_path,
                'method': method,
            }
            granted = False
            if self.approval_state:
                state = self.approval_state(approval_payload)
                if state == 'executed':
                    return JsonResponse(
                        self._result(
                            req_id,
                            {'content': [{'type': 'text', 'text': 'Approval already used.'}], 'isError': True},
                        )
                    )
                if state == 'approved':
                    approval_id = approval_payload.get('approval_id')
                    if approval_id and self.approval_consume:
                        consumed = self.approval_consume(str(approval_id), approval_payload)
                        if consumed:
                            granted = True
                    else:
                        return JsonResponse(
                            self._result(
                                req_id,
                                {'content': [{'type': 'text', 'text': 'Approval unavailable.'}], 'isError': True},
                            )
                        )
                elif state == 'pending':
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
            if not granted and self.approval_handler:
                pending = self.approval_handler(approval_payload)
                if pending:
                    return JsonResponse(
                        self._result(
                            req_id,
                            {
                                'content': [{'type': 'text', 'text': 'Approval required.'}],
                                'isError': True,
                                'meta': {'approval_id': pending.get('id'), 'status': 'pending'},
                            },
                        )
                    )
            if not granted:
                return JsonResponse(
                    self._result(
                        req_id,
                        {'content': [{'type': 'text', 'text': decision.reason or 'Forbidden'}], 'isError': True},
                    )
                )
        if not decision.allowed:
            return JsonResponse(
                self._result(
                    req_id,
                    {'content': [{'type': 'text', 'text': decision.reason or 'Forbidden'}], 'isError': True},
                )
            )

        drf_request = self._factory.generic(
            method,
            resolved_path,
            data=arguments.get('body') or {},
            query_params=arguments.get('query') or {},
            HTTP_AUTHORIZATION=request.META.get('HTTP_AUTHORIZATION', ''),
        )
        self._attach_request_principal(drf_request, request, agent_claims)
        from django.urls import resolve

        match = resolve(resolved_path, urlconf=self.urlconf)
        response = match.func(drf_request, *match.args, **match.kwargs)
        status_code = getattr(response, 'status_code', 500)
        try:
            data = response.data  # type: ignore[attr-defined]
        except AttributeError:
            data = {'detail': 'ok'}
        read_sensitive = read_level == 'sensitive'
        redacted = redact_mapping(
            data if isinstance(data, dict) else {'result': data},
            read_sensitive=read_sensitive,
            markers=response_markers,
        )
        if self.on_call:
            self.on_call(
                {
                    'agent_id': agent_claims.get('agent_id'),
                    'company_id': agent_claims.get('company_id'),
                    'service': self.service_name,
                    'tool': tool_name,
                    'method': method,
                    'path': resolved_path,
                    'status': status_code,
                    'arguments': redact_mapping(arguments, read_sensitive=False, markers=request_markers),
                }
            )
        return JsonResponse(
            self._result(
                req_id,
                {
                    'content': [{'type': 'text', 'text': json.dumps(redacted)}],
                    'isError': status_code >= 400,
                },
            )
        )

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
