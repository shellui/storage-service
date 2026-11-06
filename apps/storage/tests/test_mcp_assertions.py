"""Tests for strict MCP agent claim parsing."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.storage.mcp_assertions import parse_trusted_agent_claims

_GLOBAL = '18e20f88-286e-46ea-858e-1d75bca615ff'
_GAGENT = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'


def _base(**kwargs) -> dict:
    claims = {
        'company_id': 10,
        'mcp_access': 'read_only',
        'scope': 'storage',
    }
    claims.update(kwargs)
    return claims


class ParseTrustedAgentClaimsTests(SimpleTestCase):
    def test_personal_allows_omitted_grant_version(self):
        ok, reason, norm = parse_trusted_agent_claims(_base())
        self.assertTrue(ok, reason)
        assert norm is not None
        self.assertIsNone(norm['grant_version'])
        self.assertIsNone(norm['global_company_id'])

    def test_delegated_requires_full_triplet_including_zero(self):
        ok, _, norm = parse_trusted_agent_claims(
            _base(
                global_company_id=_GLOBAL,
                global_agent_id=_GAGENT,
                company_binding_version=0,
                grant_version=0,
                mcp_authority='delegated',
            )
        )
        self.assertTrue(ok)
        assert norm is not None
        self.assertEqual(norm['company_binding_version'], 0)
        self.assertEqual(norm['grant_version'], 0)

    def test_global_agent_id_without_global_company_id_rejected(self):
        ok, reason, _ = parse_trusted_agent_claims(_base(global_agent_id=_GAGENT))
        self.assertFalse(ok)
        self.assertEqual(reason, 'missing_global_company_id')

    def test_global_agent_id_with_partial_triplet_rejected(self):
        ok, reason, _ = parse_trusted_agent_claims(
            _base(global_agent_id=_GAGENT, global_company_id=_GLOBAL, company_binding_version=0)
        )
        self.assertFalse(ok)
        self.assertEqual(reason, 'missing_grant_version')

    def test_malformed_global_company_id_not_personal(self):
        ok, reason, _ = parse_trusted_agent_claims(_base(global_company_id='not-a-uuid'))
        self.assertFalse(ok)
        self.assertEqual(reason, 'invalid_global_company_id')

    def test_numeric_global_company_id_rejected(self):
        ok, reason, _ = parse_trusted_agent_claims(_base(global_company_id=10))
        self.assertFalse(ok)
        self.assertEqual(reason, 'invalid_global_company_id')

    def test_partial_global_only_binding_rejected(self):
        ok, reason, _ = parse_trusted_agent_claims(_base(global_company_id=_GLOBAL))
        self.assertFalse(ok)
        self.assertEqual(reason, 'missing_global_agent_id')

    def test_partial_binding_without_global_rejected(self):
        ok, reason, _ = parse_trusted_agent_claims(_base(company_binding_version=0))
        self.assertFalse(ok)
        self.assertEqual(reason, 'unexpected_company_binding_version')

    def test_invalid_personal_token_id_rejected(self):
        ok, reason, _ = parse_trusted_agent_claims(_base(personal_token_id='nope'))
        self.assertFalse(ok)
        self.assertEqual(reason, 'invalid_personal_token_id')

    def test_valid_personal_token_id_ok(self):
        tok = 'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22'
        ok, _, norm = parse_trusted_agent_claims(_base(personal_token_id=tok))
        self.assertTrue(ok)
        assert norm is not None
        self.assertEqual(norm['personal_token_id'], tok)

    def test_grant_version_rejects_digit_strings(self):
        from apps.storage.mcp_assertions import parse_grant_version

        self.assertIsNone(parse_grant_version('0'))
        self.assertIsNone(parse_grant_version('12'))
        self.assertIsNone(parse_grant_version(''))
        self.assertIsNone(parse_grant_version('-1'))
