"""OpenTelemetry storage gauges, and the removed Prometheus routes."""

from __future__ import annotations

import os
from unittest.mock import patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from shellui_django.telemetry import _reset_for_tests

from apps.storage.access import COMPANY_BUCKET_NAME
from apps.storage.metrics import clear_storage_metric_cache
from apps.storage.tests.test_storage import make_token
from config.telemetry import setup_telemetry

_CLEARED_ENV = (
    'OTEL_EXPORTER_OTLP_ENDPOINT',
    'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT',
    'OTEL_EXPORTER_OTLP_METRICS_ENDPOINT',
    'OTEL_EXPORTER_OTLP_PROTOCOL',
    'OTEL_SDK_DISABLED',
    'OTEL_TRACES_EXPORTER',
    'OTEL_METRICS_EXPORTER',
    'OTEL_SERVICE_NAME',
    'OTEL_RESOURCE_ATTRIBUTES',
)


def _metric_points(reader, name):
    data = reader.get_metrics_data()
    points = []
    if data is None:
        return points
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                if metric.name == name:
                    points.extend(metric.data.data_points)
    return points


def _values_by_company(points) -> dict[str, float]:
    found = {}
    for point in points:
        company_id = (point.attributes or {}).get('company_id')
        found[str(company_id)] = point.value
    return found


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class StorageMetricsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.jwks_patch = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = self.jwks_patch.start()
        mock_client.return_value.get_signing_key.return_value = None
        self.addCleanup(self.jwks_patch.stop)
        self._saved_env = {key: os.environ.get(key) for key in _CLEARED_ENV}
        for key in _CLEARED_ENV:
            os.environ.pop(key, None)
        _reset_for_tests()
        self.addCleanup(self._restore_telemetry)

    def _restore_telemetry(self):
        clear_storage_metric_cache()
        _reset_for_tests()
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _auth(self, **kwargs):
        return {'HTTP_AUTHORIZATION': f'Bearer {make_token(**kwargs)}'}

    def _upload(self, *, company_id: int, user_id: int, path: str, body: bytes, content_type: str):
        auth = self._auth(user_id=user_id, company_id=company_id, is_company_owner=True)
        response = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/{path}',
            data=body,
            content_type=content_type,
            **auth,
        )
        self.assertEqual(response.status_code, 200, response.content)

    def test_metrics_routes_are_gone(self):
        self.assertEqual(self.client.get('/storage/v1/metrics').status_code, 404)
        self.assertEqual(self.client.get('/storage/v1/metrics/all').status_code, 404)
        self.assertEqual(
            self.client.get('/storage/v1/metrics', **self._auth(is_staff=True)).status_code,
            404,
        )
        self.assertEqual(
            self.client.get('/storage/v1/metrics/all', **self._auth(is_company_owner=True)).status_code,
            404,
        )

    def test_storage_gauges_keep_company_id(self):
        from opentelemetry.sdk.metrics.export import InMemoryMetricReader
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        self._upload(company_id=10, user_id=1, path='a.md', body=b'# a', content_type='text/markdown')
        self._upload(company_id=11, user_id=2, path='b.png', body=b'\x89PNG', content_type='image/png')
        reader = InMemoryMetricReader()
        self.assertTrue(
            setup_telemetry(span_exporter=InMemorySpanExporter(), metric_reader=reader),
        )
        clear_storage_metric_cache()
        objects = _values_by_company(_metric_points(reader, 'shellui.storage.objects'))
        self.assertEqual(objects.get('10'), 1)
        self.assertEqual(objects.get('11'), 1)
        documents = _values_by_company(_metric_points(reader, 'shellui.storage.documents'))
        self.assertEqual(documents.get('10'), 1)
        self.assertEqual(documents.get('11'), 0)
        byte_points = _metric_points(reader, 'shellui.storage.bytes')
        self.assertTrue(byte_points)
        self.assertTrue(all((point.attributes or {}).get('company_id') for point in byte_points))
