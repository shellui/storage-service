from __future__ import annotations

from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.admin_auth import require_staff_or_company_owner
from apps.actions.company import company_context_from_id
from apps.actions.envelope import build_envelope
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
from apps.actions.registry import event_field_doc_dict, get_event_type, webhook_event_types
from apps.actions.sample_data import payload_data_from_event
from apps.actions.rule_config import build_webhook_config, mask_config_for_response
from apps.actions.serializers import ActionRuleCreateSerializer, ActionRuleUpdateSerializer, OpenAPISerializer
from apps.actions.webhook_signing import generate_webhook_signing_secret
from apps.actions.webhook_test_send import send_webhook_test_for_rule
from apps.authapi.permissions import IsAuthenticatedPrincipal, IsStaffOrCompanyOwner

SUPPORTED_ACTION_KINDS = [ActionRule.ACTION_WEBHOOK]


def _action_rule_payload(rule: ActionRule, *, reveal_secret: bool = False) -> dict:
    data = {
        'id': rule.pk,
        'company_id': rule.company_id,
        'name': rule.name,
        'description': rule.description,
        'event_type': rule.event_type,
        'enabled': rule.enabled,
        'action_kind': rule.action_kind,
        'config': mask_config_for_response(rule.config or {}, rule.action_kind),
        'created_at': rule.created_at.isoformat(),
        'updated_at': rule.updated_at.isoformat(),
    }
    if reveal_secret:
        secret = ((rule.config or {}).get('secret') or '').strip()
        if secret:
            data['secret'] = secret
    return data


def _delivery_attempt_payload(row: DeliveryAttempt, *, staff: bool = False) -> dict:
    data = {
        'id': row.pk,
        'status': row.status,
        'http_status': row.http_status,
        'error_message': row.error_message,
        'attempt_number': row.attempt_number,
        'duration_ms': row.duration_ms,
        'trigger': row.trigger or None,
        'created_at': row.created_at.isoformat(),
    }
    if staff:
        data['scheduled_job_run_id'] = row.scheduled_job_run_id
    return data


def _delivery_payload(row: ActionOutbox, *, include_attempts: bool = False, staff: bool = False) -> dict:
    data = {
        'id': str(row.pk),
        'company_id': row.company_id,
        'action_rule_id': row.action_rule_id,
        'action_rule_name': row.action_rule.name,
        'action_kind': row.action_rule.action_kind,
        'event_type': row.event_type,
        'status': row.status,
        'attempt_count': row.attempt_count,
        'next_attempt_at': row.next_attempt_at.isoformat() if row.next_attempt_at else None,
        'last_error': row.last_error,
        'created_at': row.created_at.isoformat(),
        'updated_at': row.updated_at.isoformat(),
        'delivered_at': row.delivered_at.isoformat() if row.delivered_at else None,
    }
    if include_attempts:
        attempts = row.delivery_attempts.order_by('-created_at')
        data['attempts'] = [_delivery_attempt_payload(a, staff=staff) for a in attempts]
        data['envelope'] = row.envelope
    return data


def _validation_error_response(exc: DjangoValidationError) -> Response:
    if hasattr(exc, 'message_dict'):
        return Response(exc.message_dict, status=status.HTTP_400_BAD_REQUEST)
    messages = exc.messages if hasattr(exc, 'messages') else [str(exc)]
    return Response({'error': ' '.join(messages)}, status=status.HTTP_400_BAD_REQUEST)


def _apply_rule_config(
    rule: ActionRule,
    data: dict,
    *,
    actor,
    partial: bool,
) -> Response | None:
    existing = dict(rule.config or {})
    is_superuser = bool(getattr(actor, 'is_staff', False))
    try:
        rule.config = build_webhook_config(
            existing=existing,
            url=data.get('url') if 'url' in data else (None if partial else existing.get('url')),
            secret=data.get('secret') if 'secret' in data else None,
            authorization_header=data.get('authorization_header')
            if 'authorization_header' in data
            else None,
            allow_private_urls=data.get('allow_private_urls')
            if 'allow_private_urls' in data
            else None,
            is_superuser=is_superuser,
            partial=partial,
        )
    except DjangoValidationError as exc:
        return _validation_error_response(exc)
    return None


def _sample_payload(event_type: str, company_id: int) -> dict:
    event = get_event_type(event_type)
    data = payload_data_from_event(event, unique_values=False)
    return build_envelope(
        event_type=event_type,
        company=company_context_from_id(company_id),
        data=data,
    )


class _ActionsAdminBase(APIView):
    permission_classes = [IsAuthenticatedPrincipal, IsStaffOrCompanyOwner]
    serializer_class = OpenAPISerializer


@extend_schema_view(
    get=extend_schema(
        tags=['actions-admin'],
        summary='List registered Shellui Actions event types (staff or company owner)',
        operation_id='api_v1_actions_events_list',
    ),
)
class ShellUIAdminActionEventsView(_ActionsAdminBase):
    def get(self, request):
        _actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        results = []
        for event in webhook_event_types():
            results.append(
                {
                    'type': event.id,
                    'label': event.label,
                    'description': event.description,
                    'emit_by_default': event.emit_by_default,
                    'supported_action_kinds': list(SUPPORTED_ACTION_KINDS),
                    'payload_fields': [event_field_doc_dict(f) for f in event.payload_fields],
                    'sample_envelope': _sample_payload(event.id, company_id),
                }
            )
        return Response({'results': results})


@extend_schema_view(
    get=extend_schema(
        tags=['actions-admin'],
        summary='List company Shellui Actions rules (staff or company owner)',
        operation_id='api_v1_actions_rules_list',
    ),
    post=extend_schema(
        tags=['actions-admin'],
        summary='Create company Shellui Actions rule (staff or company owner)',
        request=ActionRuleCreateSerializer,
        operation_id='api_v1_actions_rules_create',
    ),
)
class ShellUIAdminActionRuleListCreateView(_ActionsAdminBase):
    def get(self, request):
        _actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        qs = ActionRule.objects.filter(company_id=company_id).order_by('event_type', 'name')
        return Response({'results': [_action_rule_payload(r) for r in qs]})

    def post(self, request):
        actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        serializer = ActionRuleCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        rule = ActionRule(
            company_id=company_id,
            name=data['name'],
            description=data.get('description') or '',
            event_type=data['event_type'],
            enabled=data.get('enabled', True),
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={},
        )
        cfg_err = _apply_rule_config(rule, data, actor=actor, partial=False)
        if cfg_err:
            return cfg_err
        rule.save()
        return Response(_action_rule_payload(rule, reveal_secret=True), status=status.HTTP_201_CREATED)


@extend_schema_view(
    get=extend_schema(
        tags=['actions-admin'],
        summary='Retrieve company Shellui Actions rule (staff or company owner)',
        operation_id='api_v1_actions_rules_retrieve',
    ),
    patch=extend_schema(
        tags=['actions-admin'],
        summary='Update company Shellui Actions rule (staff or company owner)',
        request=ActionRuleUpdateSerializer,
        operation_id='api_v1_actions_rules_partial_update',
    ),
    delete=extend_schema(
        tags=['actions-admin'],
        summary='Delete company Shellui Actions rule (staff or company owner)',
        operation_id='api_v1_actions_rules_destroy',
    ),
)
class ShellUIAdminActionRuleDetailView(_ActionsAdminBase):
    def _get_rule(self, request, pk):
        actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return None, None, err
        try:
            rule = ActionRule.objects.get(pk=pk, company_id=company_id)
        except ActionRule.DoesNotExist:
            return None, None, Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return actor, rule, None

    def get(self, request, pk):
        _actor, rule, err = self._get_rule(request, pk)
        if err:
            return err
        return Response(_action_rule_payload(rule))

    def patch(self, request, pk):
        actor, rule, err = self._get_rule(request, pk)
        if err:
            return err
        serializer = ActionRuleUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        for field in ('name', 'description', 'event_type', 'enabled'):
            if field in data:
                setattr(rule, field, data[field])
        cfg_err = _apply_rule_config(rule, data, actor=actor, partial=True)
        if cfg_err:
            return cfg_err
        rule.action_kind = ActionRule.ACTION_WEBHOOK
        rule.save()
        return Response(_action_rule_payload(rule))

    def delete(self, request, pk):
        _actor, rule, err = self._get_rule(request, pk)
        if err:
            return err
        rule.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    post=extend_schema(
        tags=['actions-admin'],
        summary='Rotate webhook signing secret (staff or company owner)',
        operation_id='api_v1_actions_rules_rotate_secret',
        responses={
            200: OpenApiResponse(description='New secret returned once in `secret` field'),
        },
    ),
)
class ShellUIAdminActionRuleRotateSecretView(_ActionsAdminBase):
    def post(self, request, pk):
        _actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        try:
            rule = ActionRule.objects.get(pk=pk, company_id=company_id)
        except ActionRule.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        cfg = dict(rule.config or {})
        cfg['secret'] = generate_webhook_signing_secret()
        rule.config = cfg
        rule.save(update_fields=['config', 'updated_at'])
        return Response(_action_rule_payload(rule, reveal_secret=True))


@extend_schema_view(
    post=extend_schema(
        tags=['actions-admin'],
        summary='Send a sample webhook for a Shellui Actions rule (staff or company owner)',
        operation_id='api_v1_actions_rules_send_test',
        responses={
            200: OpenApiResponse(description='Sample webhook accepted by the endpoint'),
            400: OpenApiResponse(description='Delivery failed'),
        },
    ),
)
class ShellUIAdminActionRuleSendTestView(_ActionsAdminBase):
    def post(self, request, pk):
        _actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        try:
            rule = ActionRule.objects.get(pk=pk, company_id=company_id)
        except ActionRule.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        if not rule.enabled:
            return Response({'error': 'Rule is disabled.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            result = send_webhook_test_for_rule(rule=rule, company_id=company_id)
        except Exception as exc:  # noqa: BLE001
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_200_OK)


@extend_schema_view(
    get=extend_schema(
        tags=['actions-admin'],
        summary='List Shellui Actions delivery log (staff or company owner)',
        parameters=[
            OpenApiParameter(name='company_id', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='status', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='event_type', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='action_rule_id', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(
                name='scheduled_job_run_id',
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    'Staff only (403 otherwise): deliveries with an attempt made by this scheduled job run '
                    '(`GET /api/v1/scheduled-jobs/runs/<id>`).'
                ),
            ),
            OpenApiParameter(name='created_after', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='created_before', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, required=False),
        ],
        responses={200: OpenApiResponse(description='Paginated delivery log')},
        operation_id='api_v1_actions_deliveries_list',
    ),
)
class ShellUIAdminActionDeliveryListView(_ActionsAdminBase):
    def get(self, request):
        actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        try:
            page = max(1, int(request.GET.get('page') or 1))
            page_size = min(100, max(1, int(request.GET.get('page_size') or 20)))
        except (TypeError, ValueError):
            return Response({'error': 'Invalid page or page_size.'}, status=status.HTTP_400_BAD_REQUEST)

        qs = (
            ActionOutbox.objects.filter(company_id=company_id)
            .select_related('action_rule')
            .order_by('-created_at', '-id')
        )

        st = (request.GET.get('status') or '').strip().lower()
        if st:
            valid = {c[0] for c in ActionOutbox.STATUS_CHOICES}
            if st not in valid:
                return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(status=st)

        event_type = (request.GET.get('event_type') or '').strip()
        if event_type:
            qs = qs.filter(event_type=event_type)

        rule_raw = request.GET.get('action_rule_id')
        if rule_raw is not None and str(rule_raw).strip():
            try:
                qs = qs.filter(action_rule_id=int(rule_raw))
            except (TypeError, ValueError):
                return Response({'error': 'Invalid action_rule_id.'}, status=status.HTTP_400_BAD_REQUEST)

        run_raw = (request.GET.get('scheduled_job_run_id') or '').strip()
        if run_raw:
            if not getattr(actor, 'is_staff', False):
                return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
            try:
                run_id = int(run_raw)
            except ValueError:
                return Response({'error': 'Invalid scheduled_job_run_id.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(
                pk__in=DeliveryAttempt.objects.filter(scheduled_job_run_id=run_id).values('outbox_id')
            )

        created_after = (request.GET.get('created_after') or '').strip()
        if created_after:
            dt = parse_datetime(created_after)
            if dt is None:
                return Response({'error': 'Invalid created_after.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(created_at__gte=dt)

        created_before = (request.GET.get('created_before') or '').strip()
        if created_before:
            dt = parse_datetime(created_before)
            if dt is None:
                return Response({'error': 'Invalid created_before.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(created_at__lte=dt)

        total = qs.count()
        start = (page - 1) * page_size
        rows = [_delivery_payload(r) for r in qs[start : start + page_size]]
        return Response(
            {
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': rows,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['actions-admin'],
        summary='Retrieve Shellui Actions delivery with attempts (staff or company owner)',
        description=(
            'Each attempt has `trigger`: `dispatch` (right after the event) or `automatic_retry` '
            '(the `retry_webhooks` scheduled job). Staff also get `scheduled_job_run_id`.'
        ),
        operation_id='api_v1_actions_deliveries_retrieve',
    ),
)
class ShellUIAdminActionDeliveryDetailView(_ActionsAdminBase):
    def get(self, request, delivery_id):
        actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = ActionOutbox.objects.select_related('action_rule').get(pk=delivery_id, company_id=company_id)
        except ActionOutbox.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_delivery_payload(row, include_attempts=True, staff=bool(getattr(actor, 'is_staff', False))))


@extend_schema_view(
    post=extend_schema(
        tags=['actions-admin'],
        summary='Re-queue Shellui Actions delivery (staff or company owner)',
        operation_id='api_v1_actions_deliveries_requeue',
    ),
)
class ShellUIAdminActionDeliveryRequeueView(_ActionsAdminBase):
    def post(self, request, delivery_id):
        _actor, company_id, err = require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = ActionOutbox.objects.select_related('action_rule').get(pk=delivery_id, company_id=company_id)
        except ActionOutbox.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        ActionOutbox.objects.filter(pk=row.pk).update(
            status=ActionOutbox.STATUS_PENDING,
            next_attempt_at=None,
            last_error='',
            locked_until=None,
        )
        row.refresh_from_db()
        return Response(_delivery_payload(row))
