"""Storage metadata models — blobs live in the configured Django storage backend."""

from __future__ import annotations

import uuid

from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone


class BucketKind(models.TextChoices):
    """Fixed bucket types. Free-form user-created buckets are not supported."""

    COMPANY = 'company', 'Company private'
    USER = 'user', 'User private'
    CONNECTOR = 'connector', 'External connector'


class Bucket(models.Model):
    """
    Storage namespace scoped to a company.

    v1: only system-managed ``company`` and ``user-<id>`` buckets.
    ``connector`` is reserved for future SharePoint / Dropbox / etc.
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
        help_text='v1: always false. Public buckets are disabled.',
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
    # Required for kind=user (the only reader/writer). Optional for connector.
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
    Future fine-grained sharing (invite / provide / block).

    Not enforced in v1 — company and user bucket kinds define access instead.
    Kept in the schema so the product model is explicit.

    Evaluation order when enabled:
    1. effect=deny for matching subject+resource
    2. effect=allow
    3. fall back to bucket kind defaults
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
