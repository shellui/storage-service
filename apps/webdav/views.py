"""
Minimal WebDAV surface for third-party file clients.

Authenticate with:
  * ``Authorization: Bearer <jwt>``
  * or HTTP Basic where the password is the JWT (username ignored / can be email)

URL layout: ``/dav/{bucket}/…path…``

Connect any WebDAV-capable app to path ``/dav`` with the JWT as password
(see docs/clients.md). Direct S3 access (when ``STORAGE_BACKEND=s3``) bypasses
quotas/signals; WebDAV goes through them.
"""

from __future__ import annotations

import base64
import re
from io import BytesIO
from xml.etree import ElementTree as ET

from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework.exceptions import AuthenticationFailed

from apps.authapi.authentication import IdentityJWKSAuthentication
from apps.storage.access import get_accessible_bucket, list_accessible_buckets
from apps.storage.downloads import build_download_response
from apps.storage.mime import safe_object_path
from apps.storage.models import StorageObject
from apps.storage.services import (
    StorageError,
    copy_object,
    delete_object,
    move_object,
    require_company_id,
    upload_object,
)

DAV_NS = 'DAV:'
NSMAP = {'d': DAV_NS}


def _dav_response(status: int = 200, body: bytes | str | None = None, content_type: str = 'text/xml; charset=utf-8'):
    if isinstance(body, str):
        body = body.encode('utf-8')
    response = HttpResponse(body or b'', status=status, content_type=content_type)
    response['DAV'] = '1, 2'
    response['Allow'] = 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, MOVE, COPY'
    response['MS-Author-Via'] = 'DAV'
    return response


def _authenticate(request):
    auth = IdentityJWKSAuthentication()
    result = auth.authenticate(request)
    if result:
        return result[0]

    header = request.META.get('HTTP_AUTHORIZATION', '')
    if header.lower().startswith('basic '):
        try:
            decoded = base64.b64decode(header.split(' ', 1)[1]).decode('utf-8')
            _username, _, password = decoded.partition(':')
            if password:
                return auth.authenticate_credentials(password.strip())
        except AuthenticationFailed:
            raise
        except Exception as exc:
            raise AuthenticationFailed('Invalid Basic credentials.') from exc

    raise AuthenticationFailed('Authentication credentials were not provided.')


def _parse_path(path: str) -> tuple[str | None, str]:
    """Return (bucket_name|None, object_path) from leftover URL path."""
    cleaned = path.strip('/')
    if not cleaned:
        return None, ''
    bucket, _, rest = cleaned.partition('/')
    return bucket or None, rest.strip('/')


def _href(bucket: str | None = None, object_path: str = '', collection: bool = False) -> str:
    parts = ['/dav']
    if bucket:
        parts.append(bucket)
    if object_path:
        parts.append(object_path)
    href = '/'.join(parts)
    if collection and not href.endswith('/'):
        href += '/'
    return href


def _prop_xml_for_collection(href: str, displayname: str) -> ET.Element:
    response = ET.Element(f'{{{DAV_NS}}}response')
    href_el = ET.SubElement(response, f'{{{DAV_NS}}}href')
    href_el.text = href
    propstat = ET.SubElement(response, f'{{{DAV_NS}}}propstat')
    prop = ET.SubElement(propstat, f'{{{DAV_NS}}}prop')
    ET.SubElement(prop, f'{{{DAV_NS}}}displayname').text = displayname
    ET.SubElement(prop, f'{{{DAV_NS}}}resourcetype').append(ET.Element(f'{{{DAV_NS}}}collection'))
    ET.SubElement(propstat, f'{{{DAV_NS}}}status').text = 'HTTP/1.1 200 OK'
    return response


def _prop_xml_for_object(href: str, obj: StorageObject) -> ET.Element:
    response = ET.Element(f'{{{DAV_NS}}}response')
    href_el = ET.SubElement(response, f'{{{DAV_NS}}}href')
    href_el.text = href
    propstat = ET.SubElement(response, f'{{{DAV_NS}}}propstat')
    prop = ET.SubElement(propstat, f'{{{DAV_NS}}}prop')
    ET.SubElement(prop, f'{{{DAV_NS}}}displayname').text = obj.basename
    ET.SubElement(prop, f'{{{DAV_NS}}}getcontentlength').text = str(obj.size)
    ET.SubElement(prop, f'{{{DAV_NS}}}getcontenttype').text = obj.mime_type
    if obj.etag:
        ET.SubElement(prop, f'{{{DAV_NS}}}getetag').text = f'"{obj.etag}"'
    ET.SubElement(prop, f'{{{DAV_NS}}}getlastmodified').text = obj.updated_at.strftime(
        '%a, %d %b %Y %H:%M:%S GMT'
    )
    ET.SubElement(prop, f'{{{DAV_NS}}}resourcetype')
    ET.SubElement(propstat, f'{{{DAV_NS}}}status').text = 'HTTP/1.1 200 OK'
    return response


@method_decorator(csrf_exempt, name='dispatch')
class WebDAVView(View):
    http_method_names = [
        'get',
        'head',
        'put',
        'delete',
        'options',
        'propfind',
        'mkcol',
        'move',
        'copy',
    ]

    def dispatch(self, request, path=''):
        if request.method.upper() == 'OPTIONS':
            return self.options(request, path)
        try:
            request.webdav_user = _authenticate(request)
        except AuthenticationFailed as exc:
            response = _dav_response(401, str(exc))
            response['WWW-Authenticate'] = 'Bearer, Basic realm="ShellUI Storage"'
            return response
        try:
            return super().dispatch(request, path)
        except StorageError as exc:
            return _dav_response(exc.status, str(exc), content_type='text/plain')
        except ValueError as exc:
            return _dav_response(400, str(exc), content_type='text/plain')

    def options(self, request, path=''):
        return _dav_response(200)

    def propfind(self, request, path=''):
        principal = request.webdav_user
        company_id = require_company_id(principal)
        depth = request.headers.get('Depth', '1')
        bucket_name, object_path = _parse_path(path)

        multistatus = ET.Element(f'{{{DAV_NS}}}multistatus')

        if bucket_name is None:
            # Root: list buckets as collections
            multistatus.append(_prop_xml_for_collection(_href(collection=True), 'dav'))
            if depth != '0':
                for bucket in list_accessible_buckets(principal):
                    multistatus.append(
                        _prop_xml_for_collection(_href(bucket.name, collection=True), bucket.name)
                    )
        else:
            bucket = get_accessible_bucket(principal, bucket_name)
            if object_path:
                # Exact object or folder prefix
                obj = StorageObject.objects.filter(bucket=bucket, name=object_path).first()
                if obj:
                    multistatus.append(
                        _prop_xml_for_object(_href(bucket.name, obj.name), obj)
                    )
                else:
                    # Treat as folder
                    prefix = object_path.rstrip('/') + '/'
                    multistatus.append(
                        _prop_xml_for_collection(
                            _href(bucket.name, object_path, collection=True),
                            object_path.rsplit('/', 1)[-1],
                        )
                    )
                    if depth != '0':
                        self._append_children(multistatus, bucket, prefix)
            else:
                multistatus.append(
                    _prop_xml_for_collection(_href(bucket.name, collection=True), bucket.name)
                )
                if depth != '0':
                    self._append_children(multistatus, bucket, '')

        body = ET.tostring(multistatus, encoding='utf-8', xml_declaration=True)
        return _dav_response(207, body)

    def _append_children(self, multistatus, bucket, prefix: str):
        folders: set[str] = set()
        files: list[StorageObject] = []
        qs = StorageObject.objects.filter(bucket=bucket, name__startswith=prefix)
        for obj in qs.iterator(chunk_size=500):
            rest = obj.name[len(prefix) :]
            if not rest:
                continue
            if '/' in rest:
                folders.add(rest.split('/', 1)[0])
            else:
                files.append(obj)
        for name in sorted(folders):
            folder_path = f'{prefix}{name}'.strip('/')
            multistatus.append(
                _prop_xml_for_collection(_href(bucket.name, folder_path, collection=True), name)
            )
        for obj in files:
            multistatus.append(_prop_xml_for_object(_href(bucket.name, obj.name), obj))

    def get(self, request, path=''):
        return self._get_or_head(request, path, head=False)

    def head(self, request, path=''):
        return self._get_or_head(request, path, head=True)

    def _get_or_head(self, request, path, head=False):
        principal = request.webdav_user
        company_id = require_company_id(principal)
        bucket_name, object_path = _parse_path(path)
        if not bucket_name or not object_path:
            return _dav_response(404, 'Not found', content_type='text/plain')
        bucket = get_accessible_bucket(principal, bucket_name)
        name = safe_object_path(object_path)
        obj = StorageObject.objects.filter(bucket=bucket, name=name).first()
        if not obj:
            return _dav_response(404, 'Not found', content_type='text/plain')
        if head:
            response = HttpResponse(status=200, content_type=obj.mime_type)
            response['Content-Length'] = str(obj.size)
            if obj.etag:
                response['ETag'] = f'"{obj.etag}"'
            response['DAV'] = '1, 2'
            return response
        return build_download_response(obj)

    def put(self, request, path=''):
        principal = request.webdav_user
        company_id = require_company_id(principal)
        bucket_name, object_path = _parse_path(path)
        if not bucket_name or not object_path:
            return _dav_response(400, 'Bucket and path required', content_type='text/plain')
        bucket = get_accessible_bucket(principal, bucket_name, write=True)
        content_type = request.headers.get('Content-Type')
        body = BytesIO(request.body)
        created = not StorageObject.objects.filter(
            bucket=bucket, name=safe_object_path(object_path)
        ).exists()
        upload_object(
            bucket=bucket,
            path=object_path,
            fileobj=body,
            owner_id=principal.user_id,
            content_type=content_type,
            upsert=True,
            request=request,
        )
        return _dav_response(201 if created else 204)

    def delete(self, request, path=''):
        principal = request.webdav_user
        company_id = require_company_id(principal)
        bucket_name, object_path = _parse_path(path)
        if not bucket_name or not object_path:
            return _dav_response(400, 'Bucket and path required', content_type='text/plain')
        bucket = get_accessible_bucket(principal, bucket_name, write=True)
        name = safe_object_path(object_path)
        obj = StorageObject.objects.filter(bucket=bucket, name=name).first()
        if not obj:
            # Delete folder: all objects with prefix
            prefix = name.rstrip('/') + '/'
            objs = list(StorageObject.objects.filter(bucket=bucket, name__startswith=prefix))
            if not objs:
                return _dav_response(404, 'Not found', content_type='text/plain')
            for item in objs:
                delete_object(item, request=request)
            return _dav_response(204)
        delete_object(obj, request=request)
        return _dav_response(204)

    def mkcol(self, request, path=''):
        # Folders are virtual (prefix-based). Accept MKCOL as no-op success so
        # clients can create directory hierarchies before uploading files.
        principal = request.webdav_user
        require_company_id(principal)
        bucket_name, object_path = _parse_path(path)
        if not bucket_name:
            return _dav_response(403, 'Cannot create bucket via MKCOL', content_type='text/plain')
        get_accessible_bucket(principal, bucket_name, write=True)
        if object_path:
            safe_object_path(object_path)
        return _dav_response(201)

    def move(self, request, path=''):
        return self._move_or_copy(request, path, copy=False)

    def copy(self, request, path=''):
        return self._move_or_copy(request, path, copy=True)

    def _move_or_copy(self, request, path, copy: bool):
        principal = request.webdav_user
        company_id = require_company_id(principal)
        dest = request.headers.get('Destination', '')
        match = re.search(r'/dav/(.+)$', dest)
        if not match:
            return _dav_response(400, 'Invalid Destination', content_type='text/plain')
        dest_bucket_name, dest_path = _parse_path(match.group(1))
        src_bucket_name, src_path = _parse_path(path)
        if not all([dest_bucket_name, dest_path, src_bucket_name, src_path]):
            return _dav_response(400, 'Invalid paths', content_type='text/plain')
        src_bucket = get_accessible_bucket(principal, src_bucket_name)
        dest_bucket = get_accessible_bucket(principal, dest_bucket_name)
        if copy:
            copy_object(
                bucket=src_bucket,
                source_path=src_path,
                dest_bucket=dest_bucket,
                dest_path=dest_path,
                owner_id=principal.user_id,
                request=request,
            )
        else:
            move_object(
                bucket=src_bucket,
                source_path=src_path,
                dest_bucket=dest_bucket,
                dest_path=dest_path,
                request=request,
            )
        return _dav_response(201)
