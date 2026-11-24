"""Request spans, log correlation, and S3 spans that omit object keys."""

from __future__ import annotations

import logging
import os
from unittest.mock import patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from shellui_django.telemetry import _reset_for_tests

from apps.actions.email_service import RedactEmailServiceApiKeyFormatter
from apps.storage.tests.test_storage import make_token
from config.request_context import RequestIdFilter, request_id_var
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


@override_settings(
    STORAGE_BACKEND='filesystem',
    AWS_S3_REGION_NAME='eu-central-1',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
)
class TelemetryTests(TestCase):
    def setUp(self):
        self._saved_env = {key: os.environ.get(key) for key in _CLEARED_ENV}
        for key in _CLEARED_ENV:
            os.environ.pop(key, None)
        _reset_for_tests()
        self.addCleanup(self._restore)

    def _restore(self):
        _reset_for_tests()
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _enable(self):
        from opentelemetry.sdk.metrics.export import InMemoryMetricReader
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        exporter = InMemorySpanExporter()
        reader = InMemoryMetricReader()
        self.assertTrue(setup_telemetry(span_exporter=exporter, metric_reader=reader))
        return exporter, reader

    def test_formatter_defaults_trace_ids_when_telemetry_is_off(self):
        record = logging.LogRecord('apps.storage', logging.INFO, __file__, 1, 'hello', (), None)
        token = request_id_var.set('req-123')
        try:
            self.assertTrue(RequestIdFilter().filter(record))
            formatted = RedactEmailServiceApiKeyFormatter(
                '{asctime} {levelname} [{name}] [req={request_id}] trace_id={trace_id} span_id={span_id} {message}',
                style='{',
            ).format(record)
        finally:
            request_id_var.reset(token)
        self.assertIn('[req=req-123]', formatted)
        self.assertIn('trace_id=0', formatted)
        self.assertIn('span_id=0', formatted)
        self.assertIn('hello', formatted)

    def test_request_span_carries_shellui_ids_and_logs(self):
        from apps.storage.views import StatsView

        exporter, _reader = self._enable()
        jwks = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = jwks.start()
        mock_client.return_value.get_signing_key.return_value = None
        self.addCleanup(jwks.stop)

        captured: list[logging.LogRecord] = []

        class _Handler(logging.Handler):
            def emit(self, record):
                captured.append(record)

        log = logging.getLogger('apps.telemetry.test')
        handler = _Handler()
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        original = StatsView.get

        def _logged(self, request, *args, **kwargs):
            log.info('during stats')
            return original(self, request, *args, **kwargs)

        try:
            client = APIClient()
            token = make_token(user_id=7, company_id=10, is_company_owner=True)
            with self.settings(STORAGE_BACKEND='s3', AWS_S3_REGION_NAME='eu-central-1'), patch.object(
                StatsView, 'get', _logged
            ):
                response = client.get(
                    '/storage/v1/stats',
                    HTTP_AUTHORIZATION=f'Bearer {token}',
                )
        finally:
            log.removeHandler(handler)
        self.assertEqual(response.status_code, 200, response.content)
        spans = [span for span in exporter.get_finished_spans() if (span.attributes or {}).get('shellui.company_id')]
        self.assertTrue(spans, exporter.get_finished_spans())
        server = spans[-1]
        attributes = dict(server.attributes or {})
        self.assertEqual(attributes.get('shellui.company_id'), '10')
        self.assertEqual(attributes.get('shellui.user_id'), '7')
        self.assertEqual(attributes.get('shellui.region'), 'eu-central-1')
        self.assertNotIn('user@example.com', str(attributes))
        self.assertTrue(captured)
        record = captured[-1]
        self.assertEqual(record.trace_id, format(server.context.trace_id, '032x'))
        self.assertEqual(record.span_id, format(server.context.span_id, '016x'))
        self.assertNotEqual(record.trace_id, '0')

    def test_s3_span_records_bucket_and_operation_not_the_key(self):
        import boto3
        from botocore.stub import Stubber

        exporter, _reader = self._enable()
        client = boto3.client(
            's3',
            region_name='eu-central-1',
            aws_access_key_id='testing',
            aws_secret_access_key='testing',
        )
        key = 'shellui/10/company/11111111-1111-1111-1111-111111111111/report.pdf'
        stubber = Stubber(client)
        stubber.add_response(
            'head_object',
            {'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': 'req-1'}},
            {'Bucket': 'company-bucket', 'Key': key},
        )
        stubber.activate()
        client.head_object(Bucket='company-bucket', Key=key)
        spans = [span for span in exporter.get_finished_spans() if span.name == 's3.HeadObject']
        self.assertEqual(len(spans), 1)
        attributes = dict(spans[0].attributes or {})
        blob = str(attributes)
        self.assertEqual(attributes.get('aws.s3.bucket'), 'company-bucket')
        self.assertEqual(attributes.get('rpc.method'), 'HeadObject')
        self.assertEqual(attributes.get('aws.region'), 'eu-central-1')
        self.assertNotIn(key, blob)
        self.assertNotIn('report.pdf', blob)
        self.assertNotIn('Key', attributes)


class TelemetryStartupTests(TestCase):
    def test_setup_before_django_loads_apps(self):
        """manage.py calls setup_telemetry before django.setup(); metrics must not import models too early."""
        import subprocess
        import sys
        from pathlib import Path

        env = {**os.environ, 'OTEL_EXPORTER_OTLP_ENDPOINT': 'http://127.0.0.1:9', 'OTEL_METRIC_EXPORT_INTERVAL': '600000'}
        env.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
        code = 'from config.telemetry import setup_telemetry; import sys; sys.exit(0 if setup_telemetry() else 1)'
        result = subprocess.run(
            [sys.executable, '-c', code],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
