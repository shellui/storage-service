"""Company admin REST API for the event log (``/api/v1/actions/event-log``)."""

from __future__ import annotations

from django.db.models import QuerySet
from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.admin_auth import require_staff_or_company_owner
from apps.actions.models import EventLog
from apps.actions.registry import (
    company_event_types,
    get_event_type,
    is_registered_event,
    staff_only_event_types,
)
from apps.actions.retention import retention_status
from apps.actions.serializers import OpenAPISerializer
from apps.authapi.permissions import IsAuthenticatedPrincipal, IsStaffOrCompanyOwner

_MAX_PAGE_SIZE = 100


def _bad_request(message: str) -> Response:
    return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)


def _event_label(event_type: str) -> str:
    return get_event_type(event_type).label if is_registered_event(event_type) else event_type


def _event_payload(row: EventLog) -> dict:
    data = row.data or {}
    return {
        'id': row.id,
        'company_id': row.company_id,
        'created_at': row.created_at,
        'event_type': row.event_type,
        'label': _event_label(row.event_type),
        'user_id': row.user_id,
        'user_email': data.get('actor_email'),
        'data': data,
    }


def _platform_events() -> QuerySet:
    """Staff-only platform events (scheduled job runs). They never have a company."""
    types = [e.id for e in staff_only_event_types()]
    return EventLog.objects.filter(company_id__isnull=True, event_type__in=types)


def _scope(request) -> str:
    return (request.GET.get('scope') or 'company').strip().lower()


def _filtered_events(request, company_id: int) -> tuple[QuerySet | None, Response | None]:
    """``user_id``, ``user`` (email substring), ``event_type`` (comma list) and the date range."""
    qs = EventLog.objects.filter(company_id=company_id)
    uid = (request.GET.get('user_id') or '').strip()
    if uid:
        try:
            qs = qs.filter(user_id=int(uid))
        except ValueError:
            return None, _bad_request('Invalid user_id.')
    email = (request.GET.get('user') or '').strip()
    if email:
        qs = qs.filter(data__actor_email__icontains=email)
    types = [t.strip() for t in (request.GET.get('event_type') or '').split(',') if t.strip()]
    if types:
        if not all(is_registered_event(t) for t in types):
            return None, _bad_request('Invalid event_type.')
        qs = qs.filter(event_type__in=types)
    for param, lookup in (('created_after', 'created_at__gte'), ('created_before', 'created_at__lt')):
        raw = (request.GET.get(param) or '').strip()
        if raw:
            dt = parse_datetime(raw)
            if dt is None:
                return None, _bad_request(f'Invalid {param}.')
            qs = qs.filter(**{lookup: dt})
    return qs, None


class _EventLogBase(APIView):
    permission_classes = [IsAuthenticatedPrincipal, IsStaffOrCompanyOwner]
    serializer_class = OpenAPISerializer


@extend_schema_view(
    get=extend_schema(
        tags=['event-log'],
        summary='List event log (staff or company owner)',
        description=(
            'Every catalog event recorded for the company, newest first, whether or not a webhook rule '
            'matched. Rows are kept for `EVENT_LOG_RETENTION_DAYS` (`GET /api/v1/actions/event-log/retention`).'
        ),
        operation_id='api_v1_actions_event_log_list',
        parameters=[
            OpenApiParameter(
                name='scope',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                enum=['company', 'platform'],
                description=(
                    '`company` (default): events of the company in the token. `platform`: staff-only platform '
                    'events without a company (`storage.scheduled_job.succeeded`, `storage.scheduled_job.failed`). '
                    'Non-staff callers get 403.'
                ),
            ),
            OpenApiParameter(name='user_id', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(
                name='user',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Case-insensitive substring of the actor email.',
            ),
            OpenApiParameter(
                name='event_type',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Catalog event type; comma-separate several types.',
            ),
            OpenApiParameter(
                name='created_after',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='ISO 8601 datetime (inclusive lower bound).',
            ),
            OpenApiParameter(
                name='created_before',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='ISO 8601 datetime (exclusive upper bound).',
            ),
            OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, required=False),
        ],
        responses={200: OpenApiResponse(description='Paginated event log rows')},
    ),
)
class ShellUIAdminEventLogListView(_EventLogBase):
    def get(self, request):
        actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        scope = _scope(request)
        if scope not in {'company', 'platform'}:
            return _bad_request('Invalid scope.')
        if scope == 'platform' and not getattr(actor, 'is_staff', False):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        try:
            page = max(1, int(request.GET.get('page') or 1))
            page_size = min(_MAX_PAGE_SIZE, max(1, int(request.GET.get('page_size') or 20)))
        except (TypeError, ValueError):
            return _bad_request('Invalid page or page_size.')
        if scope == 'platform':
            qs = _platform_events()
        else:
            qs, err = _filtered_events(request, company_id)
            if err:
                return err
        total = qs.count()
        start = (page - 1) * page_size
        return Response(
            {
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': [_event_payload(row) for row in qs[start : start + page_size]],
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['event-log'],
        summary='Retrieve event log row (staff or company owner)',
        operation_id='api_v1_actions_event_log_retrieve',
        parameters=[
            OpenApiParameter(
                name='scope',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                enum=['company', 'platform'],
            ),
        ],
        responses={200: OpenApiResponse(description='Event log row')},
    ),
)
class ShellUIAdminEventLogDetailView(_EventLogBase):
    def get(self, request, pk):
        actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        scope = _scope(request)
        if scope not in {'company', 'platform'}:
            return _bad_request('Invalid scope.')
        if scope == 'platform':
            if not getattr(actor, 'is_staff', False):
                return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
            row = _platform_events().filter(pk=pk).first()
        else:
            row = EventLog.objects.filter(company_id=company_id, pk=pk).first()
        if row is None:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_event_payload(row))


@extend_schema_view(
    get=extend_schema(
        tags=['event-log'],
        summary='List event types recorded in the event log (staff or company owner)',
        operation_id='api_v1_actions_event_log_types_list',
    ),
)
class ShellUIAdminEventLogTypesView(_EventLogBase):
    def get(self, request):
        _actor, _company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        return Response(
            {
                'results': [
                    {'type': e.id, 'label': e.label, 'description': e.description, 'webhook': e.webhook}
                    for e in company_event_types()
                    if e.emit_by_default
                ]
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['event-log'],
        summary='Event log retention status (staff or company owner)',
        description=(
            '`data_retention_days` comes from the `EVENT_LOG_RETENTION_DAYS` setting. `stale_events` is true '
            'when the oldest event is more than one day past retention, which means the '
            '`purge_expired_data` scheduled job is not running.'
        ),
        operation_id='api_v1_actions_event_log_retention_retrieve',
    ),
)
class ShellUIAdminEventLogRetentionView(_EventLogBase):
    def get(self, request):
        _actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        return Response(retention_status(company_id))
