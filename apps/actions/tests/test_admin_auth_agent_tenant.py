"""Agent principals must not override company scope via query or body."""

from __future__ import annotations

from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory

from apps.actions.admin_auth import AgentCompanyIdMismatchError, require_staff_or_company_owner
from apps.authapi.agent_tokens import principal_from_agent_claims


class AdminAuthAgentTenantTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def _agent_request(self, *, company_id: int, query_company: str | None = None):
        claims = {
            'sub': 'agent:00000000-0000-0000-0000-000000000001',
            'token_type': 'access',
            'agent_id': '00000000-0000-0000-0000-000000000001',
            'company_id': company_id,
            'scope': 'storage',
            'aud': 'http://127.0.0.1/mcp',
        }
        user = principal_from_agent_claims(claims)
        path = '/api/v1/actions/rules'
        if query_company is not None:
            path = f'{path}?company_id={query_company}'
        request = self.factory.get(path)
        request.user = user
        return request

    def test_agent_is_not_treated_as_company_owner(self):
        request = self._agent_request(company_id=10, query_company='10')
        user = request.user
        self.assertFalse(user.is_company_owner)
        self.assertFalse(user.is_staff)
        _user, company_id, err = require_staff_or_company_owner(request)
        self.assertIsNone(company_id)
        self.assertEqual(err.status_code, 403)
        self.assertEqual(err.data['error'], 'Forbidden')

    def test_agent_rejects_mismatched_query_company_id(self):
        request = self._agent_request(company_id=10, query_company='20')
        _user, company_id, err = require_staff_or_company_owner(request)
        self.assertIsNone(company_id)
        self.assertEqual(err.status_code, 403)
