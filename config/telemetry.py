"""OpenTelemetry setup for storage-service.

Call :func:`setup_telemetry` from each process entry point. With no
``OTEL_EXPORTER_OTLP_ENDPOINT`` (and no signal-specific endpoint), the call
returns immediately and does not load the OpenTelemetry SDK.
"""

from __future__ import annotations

import logging
import os
import sys
import tomllib
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SERVICE_NAME = 'storage-service'
_s3_wrapped = False
_metrics_token: tuple[Any, ...] | None = None


def _package_version() -> str:
    pyproject = Path(__file__).resolve().parent.parent / 'pyproject.toml'
    with pyproject.open('rb') as handle:
        version = str(tomllib.load(handle).get('project', {}).get('version', '')).strip()
    if not version:
        raise RuntimeError(f'project.version is missing in {pyproject}')
    return version


def setup_telemetry(
    *,
    span_exporter: Any = None,
    metric_reader: Any = None,
) -> bool:
    """Enable traces, metrics, and log correlation. False when telemetry stays off.

    Safe to call more than once. Gunicorn ``gthread`` workers and the Celery
    thread pool each call this in their own process. A second call does not
    build another provider.

    ``span_exporter`` and ``metric_reader`` are for tests.
    """
    # The SDK reads these. The names are referenced so generate_env lists them.
    # Header values can be credentials: do not log them.
    os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', '')
    os.getenv('OTEL_EXPORTER_OTLP_HEADERS', '')
    os.getenv('OTEL_RESOURCE_ATTRIBUTES', '')
    service_name = os.getenv('OTEL_SERVICE_NAME', '').strip() or SERVICE_NAME

    from shellui_django.telemetry import setup_telemetry as _setup

    enabled = _setup(
        service_name,
        service_version=_package_version(),
        span_exporter=span_exporter,
        metric_reader=metric_reader,
    )
    if not enabled:
        return False
    _instrument_s3()
    if _in_celery_worker():
        return True
    _ensure_apps_ready()
    _register_metrics()
    return True


def _in_celery_worker() -> bool:
    # The Celery thread pool shares one Django DB connection across threads, so the
    # metric reader thread must not query there. Gunicorn publishes the gauges.
    return bool(sys.argv) and os.path.basename(sys.argv[0]) == 'celery'


def _ensure_apps_ready() -> None:
    # manage.py calls setup before Django loads apps; the metric callbacks import models.
    import django
    from django.apps import apps

    if not apps.ready:
        django.setup()


def _active() -> bool:
    from shellui_django.telemetry._state import state

    return bool(state.active)


def _bucket_name(api_params: Any) -> str | None:
    """Physical bucket only. Object keys are never copied onto the span."""
    if not isinstance(api_params, dict):
        return None
    bucket = api_params.get('Bucket')
    if not isinstance(bucket, str):
        return None
    bucket = bucket.strip()
    if not bucket or len(bucket) > 255 or '/' in bucket or '\\' in bucket or ' ' in bucket:
        return None
    return bucket


def _instrument_s3() -> None:
    """Span each S3 API call with the bucket and operation, never the object key.

    ``botocore`` is already installed via django-storages. The OpenTelemetry
    botocore package is not a dependency, so this is a small hook on
    ``BaseClient._make_api_call`` instead of that instrumentor.
    """
    global _s3_wrapped
    if _s3_wrapped:
        return
    try:
        from botocore.client import BaseClient
    except ImportError:
        logger.info('storage telemetry: botocore is not installed, S3 spans are off')
        return

    original = BaseClient._make_api_call

    def _call(self, operation_name, api_params, *args, **kwargs):
        meta = getattr(self, 'meta', None)
        model = getattr(meta, 'service_model', None)
        service = getattr(model, 'service_name', '') or ''
        if service != 's3' or not _active():
            return original(self, operation_name, api_params, *args, **kwargs)

        from opentelemetry import trace
        from opentelemetry.trace import Status, StatusCode

        tracer = trace.get_tracer(SERVICE_NAME)
        with tracer.start_as_current_span(f's3.{operation_name}') as span:
            if span.is_recording():
                span.set_attribute('rpc.system', 'aws-api')
                span.set_attribute('rpc.service', 's3')
                span.set_attribute('rpc.method', str(operation_name))
                bucket = _bucket_name(api_params)
                if bucket:
                    span.set_attribute('aws.s3.bucket', bucket)
                region = getattr(meta, 'region_name', None)
                if isinstance(region, str) and region and '/' not in region and len(region) <= 64:
                    span.set_attribute('aws.region', region)
            try:
                result = original(self, operation_name, api_params, *args, **kwargs)
            except Exception:
                if span.is_recording():
                    span.set_status(Status(StatusCode.ERROR))
                raise
            if span.is_recording() and isinstance(result, dict):
                code = (result.get('ResponseMetadata') or {}).get('HTTPStatusCode')
                if isinstance(code, int):
                    span.set_attribute('http.response.status_code', code)
            return result

    BaseClient._make_api_call = _call
    _s3_wrapped = True


def _register_metrics() -> None:
    global _metrics_token
    from shellui_django.telemetry._state import state

    token = (state.generation, id(state.meter_provider))
    if _metrics_token == token:
        return
    from shellui_django.telemetry import get_meter

    meter = get_meter(SERVICE_NAME)
    from apps.actions.scheduled_job_metrics import register_scheduled_job_metrics
    from apps.storage.metrics import register_storage_metrics

    register_storage_metrics(meter)
    register_scheduled_job_metrics(meter)
    _metrics_token = token


class ShelluiSpanMiddleware:
    """Set opaque Shellui ids on the active server span after DRF authenticates.

    Django REST framework sets ``request.user`` inside the view, so this runs
    after ``get_response`` and before the OpenTelemetry middleware ends the span.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        _annotate_request(request)
        return response


def _annotate_request(request) -> None:
    if not _active():
        return
    user = getattr(request, 'user', None)
    if user is None or not getattr(user, 'is_authenticated', False):
        return
    from django.conf import settings
    from shellui_django.telemetry import set_shellui_attributes

    company_id = getattr(user, 'company_id', None)
    user_id = getattr(user, 'user_id', None)
    extra: dict[str, str | int] = {}
    claims = getattr(user, 'claims', None)
    if isinstance(claims, dict):
        agent_id = claims.get('agent_id')
        if agent_id not in (None, ''):
            extra['agent_id'] = agent_id
            if user_id == 0:
                user_id = None
    if getattr(settings, 'STORAGE_BACKEND', '') == 's3':
        region = getattr(settings, 'AWS_S3_REGION_NAME', '') or ''
        if region:
            extra['region'] = region
    set_shellui_attributes(
        company_id=company_id,
        user_id=user_id,
        attributes=extra or None,
    )
