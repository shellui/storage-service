"""OpenAPI serializers for storage-service views (schema only — views return dicts)."""

from __future__ import annotations

from rest_framework import serializers

from .models import BucketKind, StorageAccessGrant


class ErrorSerializer(serializers.Serializer):
    statusCode = serializers.CharField()
    error = serializers.CharField()
    message = serializers.CharField()
    request_id = serializers.CharField(required=False)


class HealthSerializer(serializers.Serializer):
    status = serializers.CharField()
    version = serializers.CharField()
    storage_backend = serializers.CharField()
    identity_jwks_source = serializers.CharField()
    identity_jwks_url = serializers.CharField(allow_null=True)


class BucketAccessSerializer(serializers.Serializer):
    writers = serializers.CharField()
    can_write = serializers.BooleanField()


class BucketSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField()
    display_name = serializers.CharField()
    kind = serializers.ChoiceField(choices=BucketKind.choices)
    owner = serializers.CharField(allow_null=True)
    public = serializers.BooleanField()
    file_size_limit = serializers.IntegerField(allow_null=True)
    allowed_mime_types = serializers.ListField(child=serializers.CharField(), allow_null=True)
    connector_provider = serializers.CharField(allow_null=True)
    access = BucketAccessSerializer()
    created_at = serializers.CharField()
    updated_at = serializers.CharField()


class ObjectMetadataSerializer(serializers.Serializer):
    eTag = serializers.CharField(allow_null=True)
    size = serializers.IntegerField()
    mimetype = serializers.CharField()
    cacheControl = serializers.CharField()
    lastModified = serializers.CharField()
    contentLength = serializers.IntegerField()
    httpStatusCode = serializers.IntegerField()


class ObjectSerializer(serializers.Serializer):
    id = serializers.CharField(allow_null=True)
    folder_id = serializers.CharField(required=False, allow_null=True)
    name = serializers.CharField()
    bucket_id = serializers.CharField()
    owner = serializers.CharField(allow_null=True)
    created_at = serializers.CharField(allow_null=True)
    updated_at = serializers.CharField(allow_null=True)
    last_accessed_at = serializers.CharField(allow_null=True)
    metadata = ObjectMetadataSerializer(allow_null=True)
    access = serializers.DictField(required=False)


class ObjectUploadResponseSerializer(serializers.Serializer):
    Id = serializers.CharField()
    Key = serializers.CharField()


class ObjectListRequestSerializer(serializers.Serializer):
    prefix = serializers.CharField(required=False, allow_blank=True)
    limit = serializers.IntegerField(required=False)
    offset = serializers.IntegerField(required=False)
    search = serializers.CharField(required=False, allow_blank=True)
    sortBy = serializers.DictField(required=False)


class ObjectByIdSerializer(serializers.Serializer):
    id = serializers.CharField()
    bucket = serializers.CharField()
    path = serializers.CharField()
    name = serializers.CharField()
    type = serializers.ChoiceField(choices=('file', 'folder'))


class PrefixSummarySerializer(serializers.Serializer):
    prefix = serializers.CharField()
    object_count = serializers.IntegerField()
    file_count = serializers.IntegerField()
    placeholder_count = serializers.IntegerField()
    total_bytes = serializers.IntegerField()


class PrefixRenameRequestSerializer(serializers.Serializer):
    prefix = serializers.CharField(required=False)
    source = serializers.CharField(required=False)
    destination = serializers.CharField(required=False)
    to = serializers.CharField(required=False)


class PrefixRenameResponseSerializer(serializers.Serializer):
    moved = serializers.IntegerField()
    grants_updated = serializers.IntegerField()
    to = serializers.CharField()


class PrefixDeleteRequestSerializer(serializers.Serializer):
    prefix = serializers.CharField()


class PrefixDeleteResponseSerializer(serializers.Serializer):
    prefix = serializers.CharField()
    deleted = serializers.ListField(child=serializers.CharField())
    count = serializers.IntegerField()


class DeletedNameSerializer(serializers.Serializer):
    name = serializers.CharField()


class ObjectDeleteManyRequestSerializer(serializers.Serializer):
    prefixes = serializers.ListField(child=serializers.CharField(), required=False)
    paths = serializers.ListField(child=serializers.CharField(), required=False)


class ObjectMoveRequestSerializer(serializers.Serializer):
    sourceKey = serializers.CharField(required=False)
    destinationKey = serializers.CharField(required=False)
    to = serializers.CharField(required=False)


class ObjectMoveResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class ObjectCopyResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    Key = serializers.CharField()


class SignRequestSerializer(serializers.Serializer):
    path = serializers.CharField(required=False)
    expiresIn = serializers.IntegerField(required=False)
    expires_in = serializers.IntegerField(required=False)


class SignedUrlSerializer(serializers.Serializer):
    signedURL = serializers.CharField()
    signedUrl = serializers.CharField()


class QuotaBytesSerializer(serializers.Serializer):
    max_bytes = serializers.IntegerField(allow_null=True)
    used_bytes = serializers.IntegerField()
    remaining_bytes = serializers.IntegerField(allow_null=True)
    user_id = serializers.IntegerField(required=False)


class QuotaSerializer(serializers.Serializer):
    company_id = serializers.IntegerField()
    company = QuotaBytesSerializer()
    user = QuotaBytesSerializer()


class CompanyQuotaUpdateSerializer(serializers.Serializer):
    max_bytes = serializers.IntegerField(required=False)
    max_bytes_per_user = serializers.IntegerField(required=False, allow_null=True)


class CompanyQuotaSerializer(serializers.Serializer):
    company_id = serializers.IntegerField()
    max_bytes = serializers.IntegerField()
    used_bytes = serializers.IntegerField()
    max_bytes_per_user = serializers.IntegerField(allow_null=True)


class UserQuotaUpdateSerializer(serializers.Serializer):
    max_bytes = serializers.IntegerField()


class UserQuotaSerializer(serializers.Serializer):
    company_id = serializers.IntegerField()
    user_id = serializers.IntegerField()
    max_bytes = serializers.IntegerField()
    used_bytes = serializers.IntegerField()


class AccessGrantSerializer(serializers.Serializer):
    id = serializers.CharField()
    company_id = serializers.IntegerField()
    bucket = serializers.CharField(allow_null=True)
    subject_type = serializers.ChoiceField(choices=StorageAccessGrant.SubjectType.choices)
    subject_id = serializers.CharField()
    resource_type = serializers.ChoiceField(choices=StorageAccessGrant.ResourceType.choices)
    resource_id = serializers.CharField()
    permission = serializers.ChoiceField(choices=StorageAccessGrant.Permission.choices)
    effect = serializers.ChoiceField(choices=StorageAccessGrant.Effect.choices)
    created_by_id = serializers.IntegerField(allow_null=True)
    created_at = serializers.CharField()
    updated_at = serializers.CharField()
    expires_at = serializers.CharField(allow_null=True)
    notes = serializers.CharField()


class AccessGrantCreateSerializer(serializers.Serializer):
    subject_type = serializers.ChoiceField(choices=StorageAccessGrant.SubjectType.choices)
    subject_id = serializers.CharField()
    resource_type = serializers.ChoiceField(choices=StorageAccessGrant.ResourceType.choices)
    resource_id = serializers.CharField()
    bucket = serializers.CharField(required=False)
    permission = serializers.ChoiceField(
        choices=StorageAccessGrant.Permission.choices,
        required=False,
    )
    effect = serializers.ChoiceField(choices=StorageAccessGrant.Effect.choices, required=False)
    expires_at = serializers.CharField(required=False, allow_null=True)
    notes = serializers.CharField(required=False, allow_blank=True)


class AccessGrantEffectiveSerializer(serializers.Serializer):
    grants = AccessGrantSerializer(many=True)
    private_ancestor = serializers.CharField(allow_null=True)


class ShareLinkSerializer(serializers.Serializer):
    id = serializers.CharField()
    object_id = serializers.CharField()
    bucket = serializers.CharField()
    path = serializers.CharField()
    company_id = serializers.IntegerField()
    created_by_id = serializers.IntegerField()
    expires_at = serializers.CharField(allow_null=True)
    max_downloads = serializers.IntegerField(allow_null=True)
    download_count = serializers.IntegerField()
    revoked_at = serializers.CharField(allow_null=True)
    created_at = serializers.CharField()
    notes = serializers.CharField()
    active = serializers.BooleanField()
    path_url = serializers.CharField()
    token = serializers.CharField(required=False)


class ShareLinkCreateSerializer(serializers.Serializer):
    expires_at = serializers.CharField(required=False, allow_null=True)
    expiresAt = serializers.CharField(required=False, allow_null=True)
    max_downloads = serializers.IntegerField(required=False, allow_null=True)
    maxDownloads = serializers.IntegerField(required=False, allow_null=True)
    notes = serializers.CharField(required=False, allow_blank=True)
