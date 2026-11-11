"""Serializer fields with ``x-mcp`` property markers in OpenAPI."""

from __future__ import annotations

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers


@extend_schema_field({'type': 'string', 'x-mcp-secret': True})
class McpSecretCharField(serializers.CharField):
    pass


@extend_schema_field({'type': 'string', 'x-mcp-sensitive': True})
class McpSensitiveCharField(serializers.CharField):
    pass
