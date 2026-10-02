from django.urls import path

from apps.actions.admin_api_views import (
    ShellUIAdminActionDeliveryDetailView,
    ShellUIAdminActionDeliveryListView,
    ShellUIAdminActionDeliveryRequeueView,
    ShellUIAdminActionEventsView,
    ShellUIAdminActionRuleDetailView,
    ShellUIAdminActionRuleListCreateView,
    ShellUIAdminActionRuleRotateSecretView,
    ShellUIAdminActionRuleSendTestView,
)
from apps.actions.event_log_views import (
    ShellUIAdminEventLogDetailView,
    ShellUIAdminEventLogListView,
    ShellUIAdminEventLogRetentionView,
    ShellUIAdminEventLogTypesView,
)

urlpatterns = [
    path('event-log', ShellUIAdminEventLogListView.as_view(), name='shellui-admin-event-log'),
    path('event-log/types', ShellUIAdminEventLogTypesView.as_view(), name='shellui-admin-event-log-types'),
    path(
        'event-log/retention',
        ShellUIAdminEventLogRetentionView.as_view(),
        name='shellui-admin-event-log-retention',
    ),
    path('event-log/<int:pk>', ShellUIAdminEventLogDetailView.as_view(), name='shellui-admin-event-log-detail'),
    path('events', ShellUIAdminActionEventsView.as_view(), name='shellui-admin-actions-events'),
    path('rules', ShellUIAdminActionRuleListCreateView.as_view(), name='shellui-admin-actions-rules'),
    path(
        'rules/<int:pk>',
        ShellUIAdminActionRuleDetailView.as_view(),
        name='shellui-admin-actions-rule-detail',
    ),
    path(
        'rules/<int:pk>/send-test',
        ShellUIAdminActionRuleSendTestView.as_view(),
        name='shellui-admin-actions-rule-send-test',
    ),
    path(
        'rules/<int:pk>/rotate-secret',
        ShellUIAdminActionRuleRotateSecretView.as_view(),
        name='shellui-admin-actions-rule-rotate-secret',
    ),
    path('deliveries', ShellUIAdminActionDeliveryListView.as_view(), name='shellui-admin-actions-deliveries'),
    path(
        'deliveries/<uuid:delivery_id>',
        ShellUIAdminActionDeliveryDetailView.as_view(),
        name='shellui-admin-actions-delivery-detail',
    ),
    path(
        'deliveries/<uuid:delivery_id>/requeue',
        ShellUIAdminActionDeliveryRequeueView.as_view(),
        name='shellui-admin-actions-delivery-requeue',
    ),
]
