"""Stored-file responses must not execute on the storage origin."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import jwt
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from apps.storage.access import COMPANY_BUCKET_NAME
from apps.storage.downloads import (
    build_signed_url,
    content_disposition_value,
    resolve_stored_file_response,
)

SANDBOX_CSP = "sandbox; default-src 'none'"


def make_token(*, user_id: int = 1, company_id: int = 10) -> str:
    payload = {
        'sub': str(user_id),
        'token_type': 'access',
        'user_id': user_id,
        'company_id': company_id,
        'email': 'user@example.com',
        'user_metadata': {
            'is_staff': False,
            'is_company_owner': False,
        },
        'exp': 2**31 - 1,
    }
    return jwt.encode(payload, 'test-secret', algorithm='HS256')


class StoredFilePolicyTests(SimpleTestCase):
    def test_active_and_unknown_types_are_attachments(self):
        cases = {
            'text/html': 'text/plain; charset=utf-8',
            'text/html; charset=utf-8': 'text/plain; charset=utf-8',
            'TEXT/HTML': 'text/plain; charset=utf-8',
            'application/xhtml+xml': 'text/plain; charset=utf-8',
            'image/svg+xml': 'text/plain; charset=utf-8',
            'text/xml': 'text/plain; charset=utf-8',
            'application/xml': 'text/plain; charset=utf-8',
            'application/javascript': 'text/plain; charset=utf-8',
            'text/javascript': 'text/plain; charset=utf-8',
            'application/zip': 'application/octet-stream',
            'application/wasm': 'application/octet-stream',
            'text/markdown': 'text/plain; charset=utf-8',
            'application/json': 'text/plain; charset=utf-8',
            'video/example+xml': 'text/plain; charset=utf-8',
        }
        for mime, expected_type in cases.items():
            content_type, disposition = resolve_stored_file_response(
                mime,
                filename='file.bin',
                object_name='file.bin',
            )
            self.assertEqual(content_type, expected_type, mime)
            self.assertTrue(disposition.startswith('attachment;'), mime)
            self.assertNotIn(mime.split(';', 1)[0].lower(), content_type)

    def test_allowlisted_types_stay_inline_until_download_is_set(self):
        for mime, served in (
            ('image/png', 'image/png'),
            ('image/jpeg', 'image/jpeg'),
            ('image/jpg', 'image/jpeg'),
            ('application/pdf', 'application/pdf'),
            ('text/plain', 'text/plain'),
            ('audio/mpeg', 'audio/mpeg'),
            ('video/mp4', 'video/mp4'),
        ):
            content_type, disposition = resolve_stored_file_response(
                mime,
                filename='file.bin',
                object_name='file.bin',
            )
            self.assertEqual(content_type, served, mime)
            self.assertTrue(disposition.startswith('inline;'), mime)

        forced_type, forced_disposition = resolve_stored_file_response(
            'image/png',
            filename='photo.png',
            as_attachment=True,
            object_name='photo.png',
        )
        self.assertEqual(forced_type, 'image/png')
        self.assertTrue(forced_disposition.startswith('attachment;'))

    def test_content_type_parameters_cannot_inject_headers(self):
        content_type, disposition = resolve_stored_file_response(
            'image/png;\r\nX-Evil: 1',
            filename='photo.png',
            object_name='photo.png',
        )
        self.assertEqual(content_type, 'image/png')
        self.assertNotIn('\r', content_type)
        self.assertNotIn('\n', content_type)
        self.assertNotIn('\r', disposition)
        self.assertNotIn('\n', disposition)
        self.assertTrue(disposition.startswith('inline;'))

        broken, broken_disposition = resolve_stored_file_response(
            'image/png\r\nX-Evil: 1',
            filename='photo.png',
            object_name='photo.png',
        )
        self.assertEqual(broken, 'application/octet-stream')
        self.assertTrue(broken_disposition.startswith('attachment;'))
        self.assertNotIn('\r', broken_disposition)
        self.assertNotIn('\n', broken_disposition)

    def test_download_name_does_not_change_a_safe_type(self):
        content_type, disposition = resolve_stored_file_response(
            'image/png',
            filename='evil.html',
            object_name='photo.png',
        )
        self.assertEqual(content_type, 'image/png')
        self.assertIn('filename="evil.html"', disposition)

    def test_filename_quotes_newlines_backslash_and_unicode(self):
        quoted = content_disposition_value('attachment', 'say "hi"\r\n.txt')
        self.assertEqual(
            quoted,
            'attachment; filename="say \\"hi\\"__.txt"; '
            "filename*=UTF-8''say%20%22hi%22%0D%0A.txt",
        )
        self.assertTrue(quoted.isascii())
        self.assertNotIn('\r', quoted)
        self.assertNotIn('\n', quoted)

        slashed = content_disposition_value('inline', 'a\\b"c.txt')
        self.assertEqual(
            slashed,
            'inline; filename="a\\\\b\\"c.txt"; '
            "filename*=UTF-8''a%5Cb%22c.txt",
        )

        unicode_name = content_disposition_value('inline', 'café.png')
        self.assertEqual(
            unicode_name,
            'inline; filename="caf_.png"; '
            "filename*=UTF-8''caf%C3%A9.png",
        )
        self.assertTrue(unicode_name.isascii())

    def test_empty_filename_uses_download(self):
        header = content_disposition_value('inline', ' \r\n ')
        self.assertIn('filename="download"', header)
        self.assertIn("filename*=UTF-8''", header)


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class StoredFileResponseTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.auth = {'HTTP_AUTHORIZATION': f'Bearer {make_token()}'}
        from unittest.mock import patch

        self.jwks_patch = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = self.jwks_patch.start()
        mock_client.return_value.get_signing_key.return_value = None
        self.addCleanup(self.jwks_patch.stop)

    def _upload(self, path: str, body: bytes, content_type: str):
        response = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/{quote(path)}',
            data=body,
            content_type=content_type,
            **self.auth,
        )
        self.assertEqual(response.status_code, 200, response.content)
        return body

    def _share(self, path: str) -> str:
        created = self.client.post(
            f'/storage/v1/share/{COMPANY_BUCKET_NAME}/{quote(path)}',
            {'max_downloads': 5},
            format='json',
            **self.auth,
        )
        self.assertEqual(created.status_code, 201, created.content)
        return created.json()['token']

    def _assert_attachment(self, response, body: bytes, *, content_type: str, filename: str):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b''.join(response.streaming_content), body)
        disposition = response['Content-Disposition']
        self.assertTrue(disposition.startswith('attachment;'))
        self.assertIn(f'filename="{filename}"', disposition)
        self.assertIn(f"filename*=UTF-8''{filename}", disposition)
        self.assertEqual(response['Content-Type'], content_type)
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response['Content-Security-Policy'], SANDBOX_CSP)
        self.assertNotIn('\r', disposition)
        self.assertNotIn('\n', disposition)

    def test_html_and_svg_are_attachments_on_download_and_share(self):
        html = b'<html><script>alert(1)</script></html>'
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>'
        self._upload('page.html', html, 'text/html')
        self._upload('icon.svg', svg, 'image/svg+xml')
        html_token = self._share('page.html')
        svg_token = self._share('icon.svg')

        html_requests = (
            (f'/storage/v1/object/{COMPANY_BUCKET_NAME}/page.html', self.auth),
            (f'/storage/v1/object/authenticated/{COMPANY_BUCKET_NAME}/page.html', self.auth),
            (f'/storage/v1/share/link/{html_token}', {}),
        )
        for url, extra in html_requests:
            response = self.client.get(url, **extra)
            self._assert_attachment(
                response,
                html,
                content_type='text/plain; charset=utf-8',
                filename='page.html',
            )
            self.assertNotIn('html', response['Content-Type'])

        svg_requests = (
            (f'/storage/v1/object/{COMPANY_BUCKET_NAME}/icon.svg', self.auth),
            (f'/storage/v1/share/link/{svg_token}', {}),
        )
        for url, extra in svg_requests:
            response = self.client.get(url, **extra)
            self._assert_attachment(
                response,
                svg,
                content_type='text/plain; charset=utf-8',
                filename='icon.svg',
            )
            self.assertNotIn('svg', response['Content-Type'])

    def test_png_stays_inline_on_download_and_share(self):
        body = b'\x89PNG\r\n\x1a\nfake'
        self._upload('photo.png', body, 'image/png')
        token = self._share('photo.png')
        urls = (
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/photo.png',
            f'/storage/v1/share/link/{token}',
        )
        for url in urls:
            extra = self.auth if 'share/link' not in url else {}
            response = self.client.get(url, **extra)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(b''.join(response.streaming_content), body)
            disposition = response['Content-Disposition']
            self.assertTrue(disposition.startswith('inline;'))
            self.assertIn('filename="photo.png"', disposition)
            self.assertIn("filename*=UTF-8''photo.png", disposition)
            self.assertEqual(response['Content-Type'], 'image/png')
            self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
            self.assertEqual(response['Content-Security-Policy'], SANDBOX_CSP)

        forced = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/photo.png',
            {'download': 'true'},
            **self.auth,
        )
        self.assertTrue(forced['Content-Disposition'].startswith('attachment;'))
        self.assertEqual(forced['Content-Type'], 'image/png')
        self.assertEqual(forced['Content-Security-Policy'], SANDBOX_CSP)

    def test_filename_with_quotes_or_newlines_is_encoded(self):
        body = b'hello'
        self._upload('quote"file.txt', body, 'text/plain')
        named = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/{quote("quote\"file.txt")}',
            **self.auth,
        )
        self.assertEqual(named.status_code, 200)
        self.assertEqual(
            named['Content-Disposition'],
            'inline; filename="quote\\"file.txt"; '
            "filename*=UTF-8''quote%22file.txt",
        )
        self.assertNotIn('\r', named['Content-Disposition'])
        self.assertNotIn('\n', named['Content-Disposition'])

        injected = 'say "hi"\r\nX-Evil: 1.txt'
        self._upload('plain.txt', body, 'text/plain')
        response = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/plain.txt',
            {'download': injected},
            **self.auth,
        )
        self.assertEqual(response.status_code, 200)
        disposition = response['Content-Disposition']
        self.assertEqual(
            disposition,
            'attachment; filename="say \\"hi\\"__X-Evil: 1.txt"; '
            "filename*=UTF-8''say%20%22hi%22%0D%0AX-Evil%3A%201.txt",
        )
        self.assertTrue(disposition.isascii())
        self.assertNotIn('\r', disposition)
        self.assertNotIn('\n', disposition)
        self.assertIsNone(response.headers.get('X-Evil'))

    def test_webdav_get_and_head_follow_the_same_policy(self):
        html = b'<html><script>alert(1)</script></html>'
        self._upload('web.html', html, 'text/html')
        path = f'/dav/{COMPANY_BUCKET_NAME}/web.html'
        got = self.client.get(path, **self.auth)
        self._assert_attachment(
            got,
            html,
            content_type='text/plain; charset=utf-8',
            filename='web.html',
        )
        head = self.client.head(path, **self.auth)
        self.assertEqual(head.status_code, 200)
        self.assertEqual(head['Content-Type'], 'text/plain; charset=utf-8')
        self.assertTrue(head['Content-Disposition'].startswith('attachment;'))
        self.assertEqual(head['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(head['Content-Security-Policy'], SANDBOX_CSP)
        self.assertNotIn('html', head['Content-Type'])


@override_settings(SIGNED_URL_EXPIRES=3600, STORAGE_BACKEND='s3')
class SignedUrlDispositionTests(SimpleTestCase):
    def _url(self, mime: str, name: str) -> dict:
        obj = SimpleNamespace(
            storage_key='company/1/obj/' + name,
            mime_type=mime,
            basename=name,
            name=name,
        )
        with patch('apps.storage.downloads.default_storage') as storage:
            storage._normalize_name = lambda key: key
            storage.bucket.name = 'bucket'
            client = storage.connection.meta.client
            client.generate_presigned_url = MagicMock(return_value='https://signed.example/object')
            url = build_signed_url(obj, expires_in=60)
        self.assertEqual(url, 'https://signed.example/object')
        call = client.generate_presigned_url.call_args
        params = dict(call.kwargs['Params'])
        return {
            'expire': call.kwargs['ExpiresIn'],
            'parameters': {k: v for k, v in params.items() if k.startswith('Response')},
        }

    def test_html_and_svg_are_attachments_with_a_safe_type(self):
        for mime, name in (
            ('text/html', 'page.html'),
            ('image/svg+xml', 'icon.svg'),
            ('application/xml', 'data.xml'),
            ('text/xml', 'data.xml'),
            ('application/javascript', 'app.js'),
        ):
            kwargs = self._url(mime, name)
            params = kwargs['parameters']
            self.assertEqual(kwargs['expire'], 60, mime)
            self.assertTrue(params['ResponseContentDisposition'].startswith('attachment;'), mime)
            self.assertNotIn('html', params['ResponseContentType'])
            self.assertNotIn('svg', params['ResponseContentType'])
            self.assertNotIn('xml', params['ResponseContentType'])
            self.assertNotIn('javascript', params['ResponseContentType'])
            self.assertIn(
                params['ResponseContentType'],
                {'text/plain; charset=utf-8', 'application/octet-stream'},
                mime,
            )

    def test_allowlisted_types_stay_inline(self):
        for mime, served in (
            ('image/png', 'image/png'),
            ('image/jpeg', 'image/jpeg'),
            ('application/pdf', 'application/pdf'),
            ('text/plain', 'text/plain'),
            ('audio/mpeg', 'audio/mpeg'),
            ('video/mp4', 'video/mp4'),
        ):
            params = self._url(mime, 'file.bin')['parameters']
            self.assertEqual(params['ResponseContentType'], served, mime)
            self.assertTrue(params['ResponseContentDisposition'].startswith('inline;'), mime)


@override_settings(SIGNED_URL_EXPIRES=3600, STORAGE_BACKEND='s3')
class SignedUrlCustomDomainTests(SimpleTestCase):
    """A CDN domain must never replace the signed S3 URL for a private object."""

    def _real_storage(self, **options):
        from storages.backends.s3 import S3Storage

        return S3Storage(
            bucket_name='private-bucket',
            region_name='us-east-1',
            access_key='AKIATESTKEY000000000',  # gitleaks:allow
            secret_key='test-secret-key-not-real-0000000000000000',  # gitleaks:allow
            endpoint_url='https://s3.example.test',
            addressing_style='path',
            querystring_auth=True,
            file_overwrite=True,
            signature_version='s3v4',
            **options,
        )

    def _signed(self, mime: str, name: str, **options) -> 'urllib.parse.SplitResult':
        from urllib.parse import urlsplit

        obj = SimpleNamespace(storage_key='shellui/c1/' + name, mime_type=mime, basename=name, name=name)
        storage = self._real_storage(**options)
        with patch('apps.storage.downloads.default_storage', storage):
            return urlsplit(build_signed_url(obj, expires_in=60))

    def test_custom_domain_still_yields_a_signed_expiring_url_on_the_endpoint(self):
        from urllib.parse import parse_qs

        url = self._signed('text/html', 'evil.html', custom_domain='cdn.example.com')
        self.assertEqual(url.netloc, 's3.example.test')
        self.assertNotIn('cdn.example.com', url.geturl())
        query = parse_qs(url.query)
        self.assertIn('X-Amz-Signature', query)
        self.assertEqual(query['X-Amz-Expires'], ['60'])
        self.assertIn('response-content-type', query)
        self.assertIn('response-content-disposition', query)
        self.assertEqual(query['response-content-type'], ['text/plain; charset=utf-8'])
        self.assertTrue(query['response-content-disposition'][0].startswith('attachment;'))

    def test_url_is_identical_in_shape_without_a_custom_domain(self):
        from urllib.parse import parse_qs

        with_cdn = parse_qs(self._signed('image/png', 'a.png', custom_domain='cdn.example.com').query)
        without = parse_qs(self._signed('image/png', 'a.png').query)
        self.assertEqual(set(with_cdn), set(without))
        self.assertEqual(with_cdn['response-content-type'], ['image/png'])
        self.assertTrue(with_cdn['response-content-disposition'][0].startswith('inline;'))

    def test_the_expiry_never_exceeds_the_setting(self):
        from urllib.parse import parse_qs, urlsplit

        obj = SimpleNamespace(storage_key='k/a.png', mime_type='image/png', basename='a.png', name='a.png')
        with patch('apps.storage.downloads.default_storage', self._real_storage(custom_domain='cdn.example.com')):
            url = urlsplit(build_signed_url(obj, expires_in=10**9))
        self.assertEqual(parse_qs(url.query)['X-Amz-Expires'], ['3600'])
