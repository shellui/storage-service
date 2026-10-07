import json

from django.contrib import admin
from django.utils.html import format_html

from apps.actions.models import ScheduledJobRun
from apps.storage.admin import storage_admin_site


@admin.register(ScheduledJobRun, site=storage_admin_site)
class ScheduledJobRunAdmin(admin.ModelAdmin):
    list_display = ('id', 'job', 'trigger', 'status', 'started_at', 'duration_ms', 'error_key', 'host')
    list_filter = ('job', 'status', 'trigger')
    search_fields = ('=id', 'error_class')
    ordering = ('-started_at', '-id')
    show_full_result_count = False
    readonly_fields = (
        'job',
        'trigger',
        'status',
        'started_at',
        'finished_at',
        'duration_ms',
        'counts_display',
        'error_key',
        'error_class',
        'error_message',
        'host',
        'event_log_id',
    )
    fields = readonly_fields

    @admin.display(description='Counts')
    def counts_display(self, obj: ScheduledJobRun) -> str:
        text = json.dumps(obj.counts or {}, indent=2, sort_keys=True)
        return format_html('<pre style="margin:0;white-space:pre-wrap">{}</pre>', text)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_view_permission(self, request, obj=None):
        return request.user.is_active and request.user.is_staff
