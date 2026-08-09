from django.contrib import admin
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from .models import (
    Bucket,
    CompanyQuota,
    ObjectShareLink,
    StorageObject,
    StorageAccessGrant,
    UserQuota,
)
from .stats import build_storage_stats, human_bytes


class StorageAdminSite(admin.AdminSite):
    site_header = 'ShellUI Storage'
    site_title = 'Storage admin'
    index_title = 'Storage administration'

    def get_urls(self):
        urls = super().get_urls()
        custom = [
            path(
                'statistics/',
                self.admin_view(self.statistics_view),
                name='storage_statistics',
            ),
        ]
        return custom + urls

    def index(self, request, extra_context=None):
        extra_context = extra_context or {}
        stats = build_storage_stats(recent_limit=8, days=14)
        extra_context.update(
            {
                'storage_stats': stats,
                'statistics_url': reverse('admin:storage_statistics'),
            }
        )
        return super().index(request, extra_context=extra_context)

    def statistics_view(self, request):
        stats = build_storage_stats(recent_limit=50, days=30)
        context = {
            **self.each_context(request),
            'title': 'Upload statistics',
            'storage_stats': stats,
            'opts': StorageObject._meta,
        }
        return TemplateResponse(request, 'admin/storage/statistics.html', context)


# Keep namespace "admin" so reverse('admin:…') and /admin/ login redirects work.
storage_admin_site = StorageAdminSite(name='admin')


class HumanSizeMixin:
    @admin.display(description='Size', ordering='size')
    def size_display(self, obj):
        return human_bytes(obj.size)


@admin.register(Bucket, site=storage_admin_site)
class BucketAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'kind',
        'company_id',
        'connector_provider',
        'owner_id',
        'public',
        'file_count',
        'created_at',
    )
    list_filter = ('kind', 'public', 'company_id', 'connector_provider')
    search_fields = ('name', 'connector_provider')
    readonly_fields = ('id', 'created_at', 'updated_at')
    # Only company + connector kinds remain on the model choices.

    @admin.display(description='Files')
    def file_count(self, obj):
        return obj.files.count()


@admin.register(StorageAccessGrant, site=storage_admin_site)
class StorageAccessGrantAdmin(admin.ModelAdmin):
    list_display = (
        'effect',
        'permission',
        'subject_type',
        'subject_id',
        'bucket_name',
        'resource_type',
        'resource_id',
        'company_id',
        'created_at',
    )
    list_filter = ('effect', 'permission', 'subject_type', 'resource_type', 'company_id')
    search_fields = ('subject_id', 'resource_id', 'bucket_name', 'notes')
    readonly_fields = ('id', 'created_at', 'updated_at')


@admin.register(ObjectShareLink, site=storage_admin_site)
class ObjectShareLinkAdmin(admin.ModelAdmin):
    list_display = (
        'token_short',
        'object',
        'company_id',
        'created_by_id',
        'expires_at',
        'max_downloads',
        'download_count',
        'revoked_at',
        'created_at',
    )
    list_filter = ('company_id',)
    search_fields = ('token', 'notes', 'object__name')
    readonly_fields = ('id', 'token', 'download_count', 'created_at')

    @admin.display(description='Token')
    def token_short(self, obj):
        return f'{obj.token[:10]}…'


@admin.register(StorageObject, site=storage_admin_site)
class StorageObjectAdmin(HumanSizeMixin, admin.ModelAdmin):
    list_display = (
        'basename_display',
        'bucket',
        'company_id',
        'owner_id',
        'mime_type',
        'size_display',
        'created_at',
        'updated_at',
    )
    list_filter = ('mime_type', 'company_id', 'bucket')
    search_fields = ('name', 'etag', 'storage_key')
    readonly_fields = (
        'id',
        'storage_key',
        'etag',
        'version',
        'created_at',
        'updated_at',
        'last_accessed_at',
        'size_display',
    )
    date_hierarchy = 'created_at'
    ordering = ('-created_at',)

    @admin.display(description='File', ordering='name')
    def basename_display(self, obj):
        return format_html('<span title="{}">{}</span>', obj.name, obj.basename)


@admin.register(CompanyQuota, site=storage_admin_site)
class CompanyQuotaAdmin(admin.ModelAdmin):
    list_display = (
        'company_id',
        'used_display',
        'max_display',
        'usage_pct',
        'max_bytes_per_user',
        'updated_at',
    )
    search_fields = ('company_id',)
    readonly_fields = ('used_bytes', 'updated_at')

    @admin.display(description='Used', ordering='used_bytes')
    def used_display(self, obj):
        return human_bytes(obj.used_bytes)

    @admin.display(description='Max', ordering='max_bytes')
    def max_display(self, obj):
        return human_bytes(obj.max_bytes)

    @admin.display(description='Usage')
    def usage_pct(self, obj):
        if not obj.max_bytes:
            return '—'
        pct = min(100.0, 100.0 * obj.used_bytes / obj.max_bytes)
        return f'{pct:.1f}%'


@admin.register(UserQuota, site=storage_admin_site)
class UserQuotaAdmin(admin.ModelAdmin):
    list_display = ('company_id', 'user_id', 'used_display', 'max_display', 'updated_at')
    list_filter = ('company_id',)
    search_fields = ('user_id',)
    readonly_fields = ('used_bytes', 'updated_at')

    @admin.display(description='Used', ordering='used_bytes')
    def used_display(self, obj):
        return human_bytes(obj.used_bytes)

    @admin.display(description='Max', ordering='max_bytes')
    def max_display(self, obj):
        return human_bytes(obj.max_bytes)


# Keep default admin.site registrations empty for storage models — we use storage_admin_site.
# Auth/session models still need the default site for the custom AdminSite to show users.
from django.contrib.auth.models import Group, User
from django.contrib.auth.admin import GroupAdmin, UserAdmin

storage_admin_site.register(User, UserAdmin)
storage_admin_site.register(Group, GroupAdmin)
