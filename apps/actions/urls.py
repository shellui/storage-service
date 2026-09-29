from django.urls import path

from apps.actions.admin_api_views import (
    ShellUIAdminActionDeliveryDetailView,
    ShellUIAdminActionDeliveryListView,
    ShellUIAdminActionDeliveryRequeueView,
    ShellUIAdminActionEventsView,
    ShellUIAdminActionRuleDetailView,
    ShellUIAdminActionRuleListCreateView,
    ShellUIAdminActionRuleSendTestView,
)

urlpatterns = [
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
