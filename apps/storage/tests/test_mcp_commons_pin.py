"""Guardrail: shellui-django is the published PyPI release, with MCP and OpenTelemetry."""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase


class McpCommonsPinTests(SimpleTestCase):
    def test_pyproject_pins_published_pypi_release(self) -> None:
        root = Path(__file__).resolve().parents[3]
        text = (root / 'pyproject.toml').read_text(encoding='utf-8')
        dep_line = next(
            (line for line in text.splitlines() if 'shellui-django[' in line.strip()),
            '',
        )
        normalized = ''.join(dep_line.split())
        self.assertIn(
            'shellui-django[mcp,otel]==0.7.2',
            normalized,
            msg='Pin shellui-django[mcp,otel] to the published PyPI release 0.7.2.',
        )
        self.assertNotIn('git+', dep_line)
        self.assertNotIn('django-commons', dep_line)
