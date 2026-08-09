"""Supabase-compatible Storage REST views under /storage/v1/."""

from __future__ import annotations

import base64
import json

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.parsers import BaseParser, FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.authapi.permissions import IsAuthenticatedPrincipal, IsStaffOrCompanyOwner

from .downloads import build_download_response, build_signed_url
from .grants import create_grant, delete_grant, list_grants, list_grants_effective
from .mime import safe_object_path
from .models import StorageObject, UserQuota
from .quotas import get_or_create_company_quota, snapshot
from .shares import (
    create_share_link,
    list_share_links_for_object,
    redeem_share_link,
    revoke_share_link,
    serialize_share_link,
)
from .stats import build_storage_stats
from .access import (
    assert_can_access_path,
    get_accessible_bucket,
    get_accessible_object,
    list_accessible_buckets,
    serialize_grant,
)
from .services import (
    StorageError,
    copy_object,
    delete_object,
    delete_paths,
    delete_under_prefix,
    list_objects,
    move_object,
    rename_folder,
    require_company_id,
    serialize_bucket,
    serialize_object,
    summarize_prefix,
    upload_object,
)


class OctetStreamParser(BaseParser):
    media_type = 'application/octet-stream'

    def parse(self, stream, media_type=None, parser_context=None):
        return stream


class AnyBinaryParser(BaseParser):
    """Accept arbitrary Content-Types as raw upload bodies (Supabase-compatible)."""

    media_type = '*/*'

    def parse(self, stream, media_type=None, parser_context=None):
        return stream


def _error(exc: StorageError) -> Response:
    return Response(
        {'statusCode': str(exc.status), 'error': exc.code, 'message': str(exc)},
        status=exc.status,
    )


def _error_message(message: str, *, status_code: int = 400, code: str = 'Error') -> Response:
    return Response(
        {'statusCode': str(status_code), 'error': code, 'message': message},
        status=status_code,
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class HealthView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(tags=['health'], responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        from django.conf import settings

        return Response(
            {
                'status': 'ok',
                'version': settings.VERSION,
                'storage_backend': settings.STORAGE_BACKEND,
                'download_mode': settings.DOWNLOAD_MODE,
                'identity_jwks_url': settings.IDENTITY_JWKS_URL,
            }
        )


# ---------------------------------------------------------------------------
# Buckets
# ---------------------------------------------------------------------------


@extend_schema_view(
    get=extend_schema(tags=['buckets'], summary='List buckets'),
    post=extend_schema(tags=['buckets'], summary='Create bucket (disabled)'),
)
class BucketListCreateView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    def get(self, request):
        try:
            buckets = list_accessible_buckets(request.user)
        except StorageError as exc:
            return _error(exc)
        return Response([serialize_bucket(b, principal=request.user) for b in buckets])

    def post(self, request):
        return _error_message(
            'Creating custom buckets is disabled. Use the company bucket with access grants.',
            status_code=403,
            code='bucket_create_disabled',
        )


@extend_schema_view(
    get=extend_schema(tags=['buckets'], summary='Get bucket'),
    put=extend_schema(tags=['buckets'], summary='Update bucket (disabled for system buckets)'),
    delete=extend_schema(tags=['buckets'], summary='Delete bucket (disabled)'),
)
class BucketDetailView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    def get(self, request, bucket_id):
        try:
            bucket = get_accessible_bucket(request.user, bucket_id)
        except StorageError as exc:
            return _error(exc)
        return Response(serialize_bucket(bucket, principal=request.user))

    def put(self, request, bucket_id):
        return _error_message(
            'System buckets cannot be modified.',
            status_code=403,
            code='bucket_immutable',
        )

    def delete(self, request, bucket_id):
        return _error_message(
            'System buckets cannot be deleted.',
            status_code=403,
            code='bucket_immutable',
        )


class BucketEmptyView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['buckets'], summary='Empty bucket')
    def post(self, request, bucket_id):
        try:
            bucket = get_accessible_bucket(request.user, bucket_id, write=True)
            for obj in list(bucket.files.all()):
                delete_object(obj, request=request)
        except StorageError as exc:
            return _error(exc)
        return Response(True)


# ---------------------------------------------------------------------------
# Objects
# ---------------------------------------------------------------------------


@method_decorator(csrf_exempt, name='dispatch')
class ObjectResourceView(APIView):
    """
    Supabase-compatible object resource.

    ``GET`` download · ``POST`` create · ``PUT`` upsert · ``DELETE`` remove
    at ``/object/{bucket}/{*path}``.
    """

    permission_classes = [IsAuthenticatedPrincipal]
    parser_classes = [MultiPartParser, FormParser, OctetStreamParser, AnyBinaryParser, JSONParser]

    @extend_schema(
        tags=['objects'],
        summary='Download object',
        parameters=[
            OpenApiParameter('download', str, OpenApiParameter.QUERY, required=False),
        ],
        responses={200: OpenApiResponse(description='File bytes')},
    )
    def get(self, request, bucket_id, object_path):
        try:
            _bucket, obj = get_accessible_object(request.user, bucket_id, object_path)
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))

        download = request.query_params.get('download')
        as_attachment = download is not None
        filename = None if download in (None, '', 'true', '1') else download
        return build_download_response(obj, as_attachment=as_attachment, filename=filename)

    @extend_schema(
        tags=['objects'],
        summary='Upload object (POST)',
        parameters=[
            OpenApiParameter('x-upsert', str, OpenApiParameter.HEADER, required=False),
        ],
    )
    def post(self, request, bucket_id, object_path):
        return self._upload(request, bucket_id, object_path)

    @extend_schema(tags=['objects'], summary='Upload object (PUT / upsert)')
    def put(self, request, bucket_id, object_path):
        return self._upload(request, bucket_id, object_path, default_upsert=True)

    @extend_schema(tags=['objects'], summary='Delete single object')
    def delete(self, request, bucket_id, object_path):
        try:
            _bucket, obj = get_accessible_object(
                request.user, bucket_id, object_path, write=True
            )
            delete_object(obj, request=request)
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))
        return Response(True)

    def _upload(self, request, bucket_id, object_path, default_upsert=False):
        try:
            bucket = get_accessible_bucket(request.user, bucket_id, write=True)
            name = safe_object_path(object_path)
            assert_can_access_path(request.user, bucket, name, write=True)
            upsert_header = request.headers.get('x-upsert', '').lower()
            upsert = default_upsert or upsert_header in {'true', '1', 'yes'}

            content_type = request.content_type
            metadata = None
            cache_control = None
            fileobj = None

            if hasattr(request.data, 'get') and request.FILES:
                fileobj = request.FILES.get('file') or next(iter(request.FILES.values()), None)
                cache_control = request.data.get('cacheControl') or request.data.get('cache_control')

            if fileobj is None:
                if hasattr(request.data, 'read'):
                    fileobj = request.data
                else:
                    from io import BytesIO

                    fileobj = BytesIO(request.body)

            raw_meta = request.headers.get('x-metadata')
            if raw_meta:
                try:
                    metadata = json.loads(base64.b64decode(raw_meta))
                except Exception:
                    try:
                        metadata = json.loads(raw_meta)
                    except Exception:
                        metadata = None

            if content_type and content_type.startswith('multipart/'):
                content_type = getattr(fileobj, 'content_type', None)

            obj = upload_object(
                bucket=bucket,
                path=object_path,
                fileobj=fileobj,
                owner_id=request.user.user_id,
                content_type=content_type,
                upsert=upsert,
                metadata=metadata,
                cache_control=cache_control,
                request=request,
            )
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))

        return Response(
            {
                'Id': str(obj.id),
                'Key': f'{bucket_id}/{obj.name}',
            }
        )


# Alias used by /object/authenticated/... routes
ObjectDownloadView = ObjectResourceView


class ObjectPublicDownloadView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        tags=['objects'],
        summary='Download public object (disabled — use share links)',
        auth=[],
    )
    def get(self, request, bucket_id, object_path):
        # Public buckets stay disabled. Anonymous access uses /share/link/{token}.
        return _error_message(
            'Public object downloads are disabled. Use a share link instead.',
            status_code=403,
            code='public_download_disabled',
        )


class ObjectInfoView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['objects'], summary='Object metadata')
    def get(self, request, bucket_id, object_path):
        try:
            _bucket, obj = get_accessible_object(request.user, bucket_id, object_path)
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))
        return Response(serialize_object(obj))


class ObjectListView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['objects'], summary='List objects (folders + files)')
    def post(self, request, bucket_id):
        try:
            bucket = get_accessible_bucket(request.user, bucket_id)
            body = request.data if isinstance(request.data, dict) else {}
            sort_by = body.get('sortBy') or {}
            entries = list_objects(
                bucket,
                prefix=body.get('prefix') or '',
                limit=int(body.get('limit') or 100),
                offset=int(body.get('offset') or 0),
                search=body.get('search') or '',
                sort_column=(sort_by.get('column') if isinstance(sort_by, dict) else None) or 'name',
                sort_order=(sort_by.get('order') if isinstance(sort_by, dict) else None) or 'asc',
                principal=request.user,
            )
        except StorageError as exc:
            return _error(exc)
        return Response(entries)


class ObjectDeleteManyView(APIView):
    """DELETE /object/{bucket} with JSON body of paths (Supabase shape)."""

    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['objects'], summary='Delete multiple objects')
    def delete(self, request, bucket_id):
        try:
            bucket = get_accessible_bucket(request.user, bucket_id, write=True)
            paths = request.data
            if isinstance(paths, dict):
                paths = paths.get('prefixes') or paths.get('paths') or []
            if not isinstance(paths, list):
                return _error_message('Expected a JSON array of object paths')
            deleted = delete_paths(bucket, [str(p) for p in paths], request=request)
        except StorageError as exc:
            return _error(exc)
        return Response([{'name': name} for name in deleted])


class ObjectPrefixView(APIView):
    """Folder prefix stats (GET), rename (POST), and recursive delete (DELETE)."""

    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['objects'], summary='Count objects under a folder prefix')
    def get(self, request, bucket_id):
        try:
            bucket = get_accessible_bucket(request.user, bucket_id)
            prefix = request.query_params.get('prefix') or ''
            if prefix:
                safe_object_path(prefix)
            return Response(summarize_prefix(bucket, prefix))
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))

    @extend_schema(tags=['objects'], summary='Rename a folder prefix')
    def post(self, request, bucket_id):
        try:
            bucket = get_accessible_bucket(request.user, bucket_id, write=True)
            body = request.data if isinstance(request.data, dict) else {}
            source = body.get('from') or body.get('prefix') or body.get('source') or ''
            dest = body.get('to') or body.get('destination') or ''
            source = str(source).strip('/')
            dest = str(dest).strip('/')
            if not source or not dest:
                return _error_message('from and to folder paths are required')
            safe_object_path(source)
            safe_object_path(dest)
            assert_can_access_path(request.user, bucket, source, write=True)
            assert_can_access_path(request.user, bucket, dest, write=True)
            result = rename_folder(bucket=bucket, source_path=source, dest_path=dest)
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))
        return Response(result)

    @extend_schema(tags=['objects'], summary='Delete all objects under a folder prefix')
    def delete(self, request, bucket_id):
        try:
            bucket = get_accessible_bucket(request.user, bucket_id, write=True)
            body = request.data if isinstance(request.data, dict) else {}
            prefix = body.get('prefix') or request.query_params.get('prefix') or ''
            if not str(prefix).strip('/'):
                return _error_message('prefix is required (refusing to delete the whole bucket)')
            safe_object_path(prefix)
            deleted = delete_under_prefix(bucket, prefix, request=request)
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))
        return Response({'prefix': str(prefix).strip('/'), 'deleted': deleted, 'count': len(deleted)})


class ObjectMoveView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['objects'], summary='Move object')
    def post(self, request):
        try:
            company_id = require_company_id(request.user)
            data = request.data if isinstance(request.data, dict) else {}
            from_path = data.get('sourceKey') or data.get('from') or ''
            to_path = data.get('destinationKey') or data.get('to') or ''
            # Paths are bucket/object...
            src_bucket_name, _, src_obj = from_path.partition('/')
            dst_bucket_name, _, dst_obj = to_path.partition('/')
            if not src_bucket_name or not src_obj or not dst_bucket_name or not dst_obj:
                return _error_message('sourceKey and destinationKey must be bucket/path')
            src_bucket = get_accessible_bucket(request.user, src_bucket_name, write=True)
            dst_bucket = get_accessible_bucket(request.user, dst_bucket_name, write=True)
            assert_can_access_path(request.user, src_bucket, src_obj, write=True)
            assert_can_access_path(request.user, dst_bucket, dst_obj, write=True)
            obj = move_object(
                bucket=src_bucket,
                source_path=src_obj,
                dest_bucket=dst_bucket,
                dest_path=dst_obj,
                request=request,
            )
        except StorageError as exc:
            return _error(exc)
        return Response({'message': 'Successfully moved'})


class ObjectCopyView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['objects'], summary='Copy object')
    def post(self, request):
        try:
            company_id = require_company_id(request.user)
            data = request.data if isinstance(request.data, dict) else {}
            from_path = data.get('sourceKey') or data.get('from') or ''
            to_path = data.get('destinationKey') or data.get('to') or ''
            src_bucket_name, _, src_obj = from_path.partition('/')
            dst_bucket_name, _, dst_obj = to_path.partition('/')
            if not src_bucket_name or not src_obj or not dst_bucket_name or not dst_obj:
                return _error_message('sourceKey and destinationKey must be bucket/path')
            src_bucket = get_accessible_bucket(request.user, src_bucket_name)
            dst_bucket = get_accessible_bucket(request.user, dst_bucket_name, write=True)
            assert_can_access_path(request.user, src_bucket, src_obj)
            assert_can_access_path(request.user, dst_bucket, dst_obj, write=True)
            obj = copy_object(
                bucket=src_bucket,
                source_path=src_obj,
                dest_bucket=dst_bucket,
                dest_path=dst_obj,
                owner_id=request.user.user_id,
                request=request,
            )
        except StorageError as exc:
            return _error(exc)
        return Response({'message': 'Successfully copied', 'Key': f'{dst_bucket_name}/{obj.name}'})


class ObjectSignView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['objects'], summary='Create signed URL')
    def post(self, request, bucket_id, object_path=''):
        try:
            data = request.data if isinstance(request.data, dict) else {}
            # Supabase also supports batch sign with path in body
            path = object_path or data.get('path') or ''
            expires = int(data.get('expiresIn') or data.get('expires_in') or 3600)
            _bucket, obj = get_accessible_object(request.user, bucket_id, path)
            url = build_signed_url(obj, expires_in=expires)
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))
        return Response({'signedURL': url, 'signedUrl': url})


# ---------------------------------------------------------------------------
# Quotas & statistics
# ---------------------------------------------------------------------------


class StatsView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['quotas'], summary='Upload / storage statistics')
    def get(self, request):
        # Staff see global stats; others are scoped to their company.
        company_id = None
        if not getattr(request.user, 'is_staff', False):
            try:
                company_id = require_company_id(request.user)
            except StorageError as exc:
                return _error(exc)
        days = int(request.query_params.get('days') or 14)
        days = max(1, min(days, 90))
        stats = build_storage_stats(
            recent_limit=25,
            days=days,
            company_id=company_id,
        )
        return Response(stats)


class QuotaView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['quotas'], summary='Current company / user quota usage')
    def get(self, request):
        try:
            company_id = require_company_id(request.user)
        except StorageError as exc:
            return _error(exc)
        snap = snapshot(company_id, request.user.user_id)
        return Response(
            {
                'company_id': snap.company_id,
                'company': {
                    'max_bytes': snap.company_max,
                    'used_bytes': snap.company_used,
                    'remaining_bytes': max(0, snap.company_max - snap.company_used),
                },
                'user': {
                    'user_id': snap.user_id,
                    'max_bytes': snap.user_max,
                    'used_bytes': snap.user_used,
                    'remaining_bytes': (
                        max(0, snap.user_max - snap.user_used) if snap.user_max is not None else None
                    ),
                },
            }
        )


class CompanyQuotaAdminView(APIView):
    permission_classes = [IsAuthenticatedPrincipal, IsStaffOrCompanyOwner]

    @extend_schema(tags=['quotas'], summary='Set company quota')
    def put(self, request, company_id: int):
        # Staff can manage any company; owners only their own.
        if not request.user.is_staff and int(company_id) != int(request.user.company_id or -1):
            return _error_message('Forbidden', status_code=403, code='forbidden')
        data = request.data if isinstance(request.data, dict) else {}
        quota = get_or_create_company_quota(company_id)
        if 'max_bytes' in data:
            quota.max_bytes = int(data['max_bytes'])
        if 'max_bytes_per_user' in data:
            value = data['max_bytes_per_user']
            quota.max_bytes_per_user = int(value) if value not in (None, '') else None
        quota.save()
        return Response(
            {
                'company_id': quota.company_id,
                'max_bytes': quota.max_bytes,
                'used_bytes': quota.used_bytes,
                'max_bytes_per_user': quota.max_bytes_per_user,
            }
        )


class UserQuotaAdminView(APIView):
    permission_classes = [IsAuthenticatedPrincipal, IsStaffOrCompanyOwner]

    @extend_schema(tags=['quotas'], summary='Set per-user quota override')
    def put(self, request, company_id: int, user_id: int):
        if not request.user.is_staff and int(company_id) != int(request.user.company_id or -1):
            return _error_message('Forbidden', status_code=403, code='forbidden')
        data = request.data if isinstance(request.data, dict) else {}
        if 'max_bytes' not in data:
            return _error_message('max_bytes is required')
        quota, _ = UserQuota.objects.update_or_create(
            company_id=company_id,
            user_id=user_id,
            defaults={'max_bytes': int(data['max_bytes'])},
        )
        return Response(
            {
                'company_id': quota.company_id,
                'user_id': quota.user_id,
                'max_bytes': quota.max_bytes,
                'used_bytes': quota.used_bytes,
            }
        )


# ---------------------------------------------------------------------------
# Access grants
# ---------------------------------------------------------------------------


@extend_schema_view(
    get=extend_schema(tags=['access'], summary='List access grants'),
    post=extend_schema(tags=['access'], summary='Create access grant'),
)
class AccessGrantListCreateView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    def get(self, request):
        try:
            resource_type = request.query_params.get('resource_type') or None
            resource_id = request.query_params.get('resource_id') or None
            bucket = request.query_params.get('bucket') or None
            include_effective = str(
                request.query_params.get('include_effective') or ''
            ).lower() in {'1', 'true', 'yes'}
            if include_effective:
                payload = list_grants_effective(
                    principal=request.user,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    bucket=bucket,
                )
                return Response(payload)
            grants = list_grants(
                principal=request.user,
                resource_type=resource_type,
                resource_id=resource_id,
                bucket=bucket,
            )
        except StorageError as exc:
            return _error(exc)
        return Response(grants)

    def post(self, request):
        try:
            data = request.data if isinstance(request.data, dict) else {}
            grant = create_grant(principal=request.user, data=data)
        except StorageError as exc:
            return _error(exc)
        return Response(serialize_grant(grant), status=status.HTTP_201_CREATED)


class AccessGrantDetailView(APIView):
    permission_classes = [IsAuthenticatedPrincipal]

    @extend_schema(tags=['access'], summary='Delete access grant')
    def delete(self, request, grant_id):
        try:
            delete_grant(principal=request.user, grant_id=grant_id)
        except StorageError as exc:
            return _error(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Capability share links (anonymous download by secret token)
# ---------------------------------------------------------------------------


@extend_schema_view(
    get=extend_schema(tags=['share'], summary='List share links for an object'),
    post=extend_schema(tags=['share'], summary='Create a share link for an object'),
)
class ObjectShareView(APIView):
    """
    Authenticated create/list of share links for one object.

    Links are never published in a public directory — only returned to the
    creator (token once on create) or listed to creators/admins for that object.
    """

    permission_classes = [IsAuthenticatedPrincipal]

    def get(self, request, bucket_id, object_path):
        try:
            links = list_share_links_for_object(
                principal=request.user,
                bucket_name=bucket_id,
                path=object_path,
            )
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))
        return Response([serialize_share_link(link) for link in links])

    def post(self, request, bucket_id, object_path):
        try:
            data = request.data if isinstance(request.data, dict) else {}
            max_downloads = data.get('max_downloads', data.get('maxDownloads'))
            if max_downloads in ('', None):
                max_downloads = None
            link = create_share_link(
                principal=request.user,
                bucket_name=bucket_id,
                path=object_path,
                expires_at=data.get('expires_at') or data.get('expiresAt'),
                max_downloads=max_downloads,
                notes=str(data.get('notes') or ''),
            )
        except StorageError as exc:
            return _error(exc)
        except ValueError as exc:
            return _error_message(str(exc))
        return Response(
            serialize_share_link(link, include_token=True),
            status=status.HTTP_201_CREATED,
        )


class ShareLinkView(APIView):
    """
    ``GET`` — anonymous redeem (no registration).
    ``DELETE`` — authenticated revoke by creator or company owner/staff.
    """

    def get_permissions(self):
        # Schema generation may call this before request is bound.
        if getattr(self, 'request', None) is not None and self.request.method == 'DELETE':
            return [IsAuthenticatedPrincipal()]
        return [AllowAny()]

    def get_authenticators(self):
        if getattr(self, 'request', None) is not None and self.request.method == 'DELETE':
            return super().get_authenticators()
        return []

    @extend_schema(tags=['share'], summary='Download via share link token', auth=[])
    def get(self, request, token):
        try:
            _link, obj = redeem_share_link(token)
        except StorageError as exc:
            return _error(exc)

        download = request.query_params.get('download')
        as_attachment = download is not None
        filename = None if download in (None, '', 'true', '1') else download
        response = build_download_response(obj, as_attachment=as_attachment, filename=filename)
        response['Cache-Control'] = 'private, no-store'
        return response

    @extend_schema(tags=['share'], summary='Revoke a share link')
    def delete(self, request, token):
        try:
            link = revoke_share_link(principal=request.user, token=token)
        except StorageError as exc:
            return _error(exc)
        return Response(serialize_share_link(link))
