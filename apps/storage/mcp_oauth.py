"""OAuth protected resource metadata for storage-service ``POST /mcp``."""

from __future__ import annotations

from django.conf import settings
from django.http import JsonResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework.views import APIView


class OAuthProtectedResourceMetadataView(APIView):
    authentication_classes = []
    permission_classes = []

    @extend_schema(
        tags=['.well-known'],
        summary='OAuth protected resource metadata for MCP',
        responses={200: OpenApiTypes.OBJECT},
        exclude=True,
    )
    def get(self, request):
        resource_base = (getattr(settings, 'STORAGE_PUBLIC_URL', '') or '').rstrip('/') or request.build_absolute_uri('/').rstrip('/')
        auth_server = (getattr(settings, 'IDENTITY_ISSUER', '') or getattr(settings, 'IDENTITY_SERVICE_URL', '') or '').rstrip('/')
        if not auth_server:
            auth_server = resource_base
        return JsonResponse(
            {
                'resource': f'{resource_base}/mcp',
                'authorization_servers': [auth_server],
                'bearer_methods_supported': ['header'],
            }
        )
