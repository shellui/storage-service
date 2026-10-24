"""Django admin sign-in with host-only session and CSRF cookies."""

from __future__ import annotations

import re

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

_HOST_COOKIES = dict(
    SESSION_COOKIE_SECURE=True,
    CSRF_COOKIE_SECURE=True,
    SESSION_COOKIE_NAME='__Host-sessionid',
    CSRF_COOKIE_NAME='__Host-csrftoken',
    CSRF_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_DOMAIN=None,
    CSRF_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH='/',
    CSRF_COOKIE_PATH='/',
)


def _csrf_token(html: str) -> str:
    match = re.search(
        r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']',
        html,
    )
    if match is None:
        raise AssertionError('login form did not include csrfmiddlewaretoken')
    return match.group(1)


def _assert_host_only(test, morsel, *, secure: bool, httponly: bool | None = None):
    test.assertEqual(morsel['path'], '/')
    test.assertEqual(morsel['domain'], '')
    test.assertEqual(bool(morsel['secure']), secure)
    if httponly is not None:
        test.assertEqual(bool(morsel['httponly']), httponly)


class AdminLoginTests(TestCase):
    password = 'admin-pass-12345'

    def setUp(self):
        get_user_model().objects.create_superuser('ops', 'ops@example.com', self.password)
        self.client = Client(enforce_csrf_checks=True)

    def _login(self, *, next_path: str = '/admin/'):
        login_url = reverse('admin:login')
        page = self.client.get(login_url)
        self.assertEqual(page.status_code, 200)
        posted = self.client.post(
            login_url,
            {
                'username': 'ops',
                'password': self.password,
                'csrfmiddlewaretoken': _csrf_token(page.content.decode()),
                'next': next_path,
            },
        )
        return page, posted

    def test_admin_login_and_logout_use_process_cookie_names(self):
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)
        self.assertIsNone(settings.SESSION_COOKIE_DOMAIN)
        self.assertIsNone(settings.CSRF_COOKIE_DOMAIN)
        self.assertEqual(settings.SESSION_COOKIE_PATH, '/')
        self.assertEqual(settings.CSRF_COOKIE_PATH, '/')

        page, posted = self._login()
        self.assertEqual(posted.status_code, 302)
        self.assertEqual(posted.url, '/admin/')

        csrf_cookie = page.cookies[settings.CSRF_COOKIE_NAME]
        _assert_host_only(
            self,
            csrf_cookie,
            secure=settings.CSRF_COOKIE_SECURE,
            httponly=True,
        )
        session_cookie = posted.cookies[settings.SESSION_COOKIE_NAME]
        _assert_host_only(self, session_cookie, secure=settings.SESSION_COOKIE_SECURE)
        if settings.SESSION_COOKIE_NAME != 'sessionid':
            self.assertNotIn('sessionid', posted.cookies)
        if settings.CSRF_COOKIE_NAME != 'csrftoken':
            self.assertNotIn('csrftoken', page.cookies)

        index = self.client.get(reverse('admin:index'))
        self.assertEqual(index.status_code, 200)
        self.assertContains(index, 'Log out')

        logged_out = self.client.post(
            reverse('admin:logout'),
            {'csrfmiddlewaretoken': _csrf_token(index.content.decode())},
        )
        self.assertIn(logged_out.status_code, (200, 302))
        again = self.client.get(reverse('admin:index'))
        self.assertEqual(again.status_code, 302)
        self.assertIn('/admin/login/', again.url)

    @override_settings(**_HOST_COOKIES)
    def test_admin_login_with_host_prefix_cookies(self):
        self.assertEqual(settings.SESSION_COOKIE_NAME, '__Host-sessionid')
        self.assertEqual(settings.CSRF_COOKIE_NAME, '__Host-csrftoken')
        page, posted = self._login()
        self.assertEqual(posted.status_code, 302, posted.content.decode())

        _assert_host_only(
            self,
            page.cookies['__Host-csrftoken'],
            secure=True,
            httponly=True,
        )
        _assert_host_only(self, posted.cookies['__Host-sessionid'], secure=True)
        self.assertNotIn('sessionid', posted.cookies)
        self.assertNotIn('csrftoken', page.cookies)

        index = self.client.get(reverse('admin:index'))
        self.assertEqual(index.status_code, 200)
        self.assertContains(index, 'Storage overview')
