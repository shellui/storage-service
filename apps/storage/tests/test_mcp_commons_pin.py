"""Guardrails for the pinned shellui-django (django-commons) MCP revision."""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

# Merge commit of shellui/django-commons PR #14 (strict revocation iat/exp handling).
_EXPECTED_COMMONS_REV = '1f0754b421688ed26b7eb2e76b25b6fa3eea2a37'
_PRE_MERGE_CANDIDATE_REV = '5f0fdf44bb140848fb1440cf04da6ada7996711d'


class McpCommonsPinTests(SimpleTestCase):
    def test_pyproject_pins_expected_git_sha(self) -> None:
        root = Path(__file__).resolve().parents[3]
        text = (root / 'pyproject.toml').read_text(encoding='utf-8')
        dep_line = next(
            (line for line in text.splitlines() if 'shellui-django[mcp]' in line.strip()),
            '',
        )
        self.assertIn(
            _EXPECTED_COMMONS_REV,
            dep_line,
            msg='Update pyproject.toml so shellui-django[mcp] pins the merged django-commons SHA.',
        )
        self.assertNotIn(
            _PRE_MERGE_CANDIDATE_REV,
            dep_line,
            msg='Replace the pre-merge django-commons pin (5f0f…) with the merged head SHA.',
        )
