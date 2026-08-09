"""Storage metadata models — blobs live in the configured Django storage backend."""

from __future__ import annotations

import secrets
import uuid

from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone


class BucketKind(models.TextChoices):
    """Fixed bucket types. Free-form user-created buckets are not supported."""

    COMPANY = 'company', 'Company'
    CONNECTOR = 'connector', 'External connector'


class Bucket(models.Model):
    """
    Storage namespace scoped to a company.

    Current model: one system ``company`` bucket per company. Access inside that
    bucket is refined with ``StorageAccessGrant`` (folder / object).

    ``connector`` is reserved for future read-only mounts (SharePoint, Dropbox, …).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.SlugField(max_length=100)
    company_id = models.PositiveIntegerField(db_index=True)
    kind = models.CharField(
        max_length=32,
        choices=BucketKind.choices,
        default=BucketKind.COMPANY,
        db_index=True,
    )
    public = models.BooleanField(
        default=False,
        help_text='Always false. Anonymous access uses capability share links, not public buckets.',
    )
    file_size_limit = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        help_text='Optional max object size in bytes for this bucket.',
    )
    allowed_mime_types = models.JSONField(
        default=list,
        blank=True,
        help_text='Empty list = allow all. Otherwise list of MIME types / prefixes (e.g. image/*).',
    )
    # Optional connector owner / contact. Unused for company buckets.
    owner_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    # Future: 'sharepoint', 'dropbox', …
    connector_provider = models.CharField(max_length=64, blank=True, default='')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['company_id', 'name'],
                name='storage_bucket_company_name_uniq',
            ),
        ]
        indexes = [
            models.Index(fields=['company_id', 'name']),
            models.Index(fields=['company_id', 'kind']),
            models.Index(fields=['company_id', 'owner_id']),
        ]
        ordering = ['kind', 'name']

    def __str__(self) -> str:
        return f'{self.company_id}/{self.kind}/{self.name}'


class StorageObject(models.Model):
    """Metadata for an object stored under a bucket path (supports nested folders)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    bucket = models.ForeignKey(Bucket, on_delete=models.CASCADE, related_name='files')
    # Full object path within the bucket, e.g. "docs/readme.md" (no leading slash).
    name = models.CharField(max_length=1024, db_index=True)
    company_id = models.PositiveIntegerField(db_index=True)
    owner_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    size = models.BigIntegerField(default=0, validators=[MinValueValidator(0)])
    etag = models.CharField(max_length=64, blank=True, default='')
    mime_type = models.CharField(max_length=255, default='application/octet-stream')
    metadata = models.JSONField(default=dict, blank=True)
    # Key in the Django/S3 storage backend (opaque; not the public path).
    storage_key = models.CharField(max_length=2048)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    last_accessed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['bucket', 'name'],
                name='storage_object_bucket_name_uniq',
            ),
        ]
        indexes = [
            models.Index(fields=['bucket', 'name']),
            models.Index(fields=['company_id', 'owner_id']),
            models.Index(fields=['bucket', 'name', 'updated_at']),
        ]
        ordering = ['name']

    def __str__(self) -> str:
        return f'{self.bucket.name}/{self.name}'

    @property
    def folder(self) -> str:
        if '/' not in self.name:
            return ''
        return self.name.rsplit('/', 1)[0]

    @property
    def basename(self) -> str:
        return self.name.rsplit('/', 1)[-1]


class CompanyQuota(models.Model):
    """Total storage quota for a company. Optional default per-user cap."""

    company_id = models.PositiveIntegerField(unique=True)
    max_bytes = models.BigIntegerField(validators=[MinValueValidator(0)])
    used_bytes = models.BigIntegerField(default=0, validators=[MinValueValidator(0)])
    max_bytes_per_user = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text='Optional default per-user quota for this company. Null/0 disables.',
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'company quota'
        verbose_name_plural = 'company quotas'

    def __str__(self) -> str:
        return f'company={self.company_id} {self.used_bytes}/{self.max_bytes}'


class UserQuota(models.Model):
    """Optional per-user quota override within a company."""

    company_id = models.PositiveIntegerField(db_index=True)
    user_id = models.PositiveIntegerField(db_index=True)
    max_bytes = models.BigIntegerField(validators=[MinValueValidator(0)])
    used_bytes = models.BigIntegerField(default=0, validators=[MinValueValidator(0)])
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['company_id', 'user_id'],
                name='storage_userquota_company_user_uniq',
            ),
        ]
        verbose_name = 'user quota'
        verbose_name_plural = 'user quotas'

    def __str__(self) -> str:
        return f'company={self.company_id} user={self.user_id} {self.used_bytes}/{self.max_bytes}'


class StorageAccessGrant(models.Model):
    """
    Fine-grained sharing inside a company (invite / provide / block).

    Evaluation order:
    1. effect=deny for matching subject + resource
    2. effect=allow for matching subject + resource
    3. Fall back to bucket-kind defaults

    Subjects ``group`` are stored for future identity-service group claims;
    only ``user`` and ``company`` are evaluated today.
    """

    class SubjectType(models.TextChoices):
        USER = 'user', 'User'
        GROUP = 'group', 'Group'
        COMPANY = 'company', 'Company'

    class ResourceType(models.TextChoices):
        BUCKET = 'bucket', 'Bucket'
        FOLDER = 'folder', 'Folder prefix'
        OBJECT = 'object', 'Object'

    class Permission(models.TextChoices):
        READ = 'read', 'Read'
        WRITE = 'write', 'Write'
        ADMIN = 'admin', 'Admin'

    class Effect(models.TextChoices):
        ALLOW = 'allow', 'Allow'
        DENY = 'deny', 'Deny (block)'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company_id = models.PositiveIntegerField(db_index=True)
    bucket_name = models.SlugField(
        max_length=100,
        blank=True,
        default='',
        help_text='Bucket this grant applies to. Empty means company bucket for folder/object grants.',
    )
    subject_type = models.CharField(max_length=16, choices=SubjectType.choices)
    subject_id = models.CharField(
        max_length=64,
        help_text='User id, group id, or company id depending on subject_type.',
    )
    resource_type = models.CharField(max_length=16, choices=ResourceType.choices)
    resource_id = models.CharField(
        max_length=1024,
        help_text='Bucket name, folder prefix, or object path / UUID.',
    )
    permission = models.CharField(max_length=16, choices=Permission.choices)
    effect = models.CharField(
        max_length=8,
        choices=Effect.choices,
        default=Effect.ALLOW,
    )
    created_by_id = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    notes = models.CharField(max_length=255, blank=True, default='')

    class Meta:
        indexes = [
            models.Index(fields=['company_id', 'resource_type', 'resource_id']),
            models.Index(fields=['company_id', 'subject_type', 'subject_id']),
        ]
        verbose_name = 'storage access grant'
        verbose_name_plural = 'storage access grants'

    def __str__(self) -> str:
        return (
            f'{self.effect} {self.permission} '
            f'{self.subject_type}:{self.subject_id} → '
            f'{self.resource_type}:{self.resource_id}'
        )


def _default_share_token() -> str:
    return secrets.token_urlsafe(32)


class ObjectShareLink(models.Model):
    """
    Capability URL to download one object without signing in.

    Not listed publicly: only the creator (or admins) can list/revoke.
    Anyone who possesses the token may download while the link is valid.

    Validity is ``expires_at`` and/or ``max_downloads`` (at least one required).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.CharField(max_length=64, unique=True, default=_default_share_token, db_index=True)
    object = models.ForeignKey(
        StorageObject,
        on_delete=models.CASCADE,
        related_name='share_links',
    )
    company_id = models.PositiveIntegerField(db_index=True)
    created_by_id = models.PositiveIntegerField(db_index=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Optional absolute expiry. Required if max_downloads is unset.',
    )
    max_downloads = models.PositiveIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        help_text='Optional download cap. Required if expires_at is unset.',
    )
    download_count = models.PositiveIntegerField(default=0)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    notes = models.CharField(max_length=255, blank=True, default='')

    class Meta:
        indexes = [
            models.Index(fields=['company_id', 'object']),
            models.Index(fields=['created_by_id', 'created_at']),
        ]
        verbose_name = 'object share link'
        verbose_name_plural = 'object share links'
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f'share:{self.token[:8]}… → {self.object_id}'

    def is_active(self, *, now=None) -> bool:
        now = now or timezone.now()
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= now:
            return False
        if self.max_downloads is not None and self.download_count >= self.max_downloads:
            return False
        return True
