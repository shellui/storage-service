"""Guardrail: shellui-django[mcp] is the published PyPI release."""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase


class McpCommonsPinTests(SimpleTestCase):
    def test_pyproject_pins_published_pypi_release(self) -> None:
        root = Path(__file__).resolve().parents[3]
        text = (root / 'pyproject.toml').read_text(encoding='utf-8')
        dep_line = next(
            (line for line in text.splitlines() if 'shellui-django[mcp]' in line.strip()),
            '',
        )
        normalized = ''.join(dep_line.split())
        self.assertIn(
            'shellui-django[mcp]==0.5.0',
            normalized,
            msg='Pin shellui-django[mcp] to the published PyPI release 0.5.0.',
        )
        self.assertNotIn('git+', dep_line)
        self.assertNotIn('django-commons', dep_line)
