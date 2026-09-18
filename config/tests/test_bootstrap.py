"""Tests for first-run superuser bootstrap gating at GET/POST /."""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

User = get_user_model()

VALID_POST = {
    'username': 'admin',
    'email': 'admin@example.com',
    'password': 'long-enough-passphrase',
    'password_confirm': 'long-enough-passphrase',
}


@override_settings(ALLOWED_HOSTS=['testserver'])
class BootstrapDebugTests(TestCase):
    """DEBUG=true allows public bootstrap (local dev / CI default)."""

    def setUp(self):
        self.client = Client()

    @override_settings(DEBUG=True, SETUP_TOKEN='')
    def test_get_shows_form_when_no_users(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create superuser')

    @override_settings(DEBUG=True, SETUP_TOKEN='')
    def test_post_creates_superuser_and_locks_form(self):
        response = self.client.post('/', VALID_POST)
        self.assertRedirects(response, '/?setup=done', fetch_redirect_response=False)
        user = User.objects.get(username='admin')
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

        response = self.client.get('/')
        self.assertNotContains(response, 'Create superuser')

    @override_settings(DEBUG=True, SETUP_TOKEN='')
    def test_post_with_existing_user_redirects_without_creating(self):
        User.objects.create_superuser(username='existing', email='', password='long-enough-passphrase')
        before = User.objects.count()
        response = self.client.post('/', VALID_POST)
        self.assertRedirects(response, '/', fetch_redirect_response=False)
        self.assertEqual(User.objects.count(), before)

    @override_settings(DEBUG=True, SETUP_TOKEN='')
    def test_password_mismatch_shows_error(self):
        data = {**VALID_POST, 'password_confirm': 'different-passphrase'}
        response = self.client.post('/', data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Passwords do not match.')
        self.assertFalse(User.objects.exists())


@override_settings(ALLOWED_HOSTS=['testserver'], DEBUG=False, SETUP_TOKEN='')
class BootstrapProductionBlockedTests(TestCase):
    """Production-like settings block public bootstrap without a token."""

    def setUp(self):
        self.client = Client()

    def test_get_hides_form_when_no_users(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Create superuser')
        self.assertContains(response, 'createsuperuser')

    def test_post_returns_403_without_token(self):
        response = self.client.post('/', VALID_POST)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.exists())

    def test_get_with_users_shows_docs_only(self):
        User.objects.create_superuser(username='existing', email='', password='long-enough-passphrase')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Create superuser')
        self.assertNotContains(response, 'createsuperuser')


@override_settings(ALLOWED_HOSTS=['testserver'], DEBUG=False, SETUP_TOKEN='secret-setup-token')
class BootstrapSetupTokenTests(TestCase):
    """SETUP_TOKEN enables one-time web bootstrap when DEBUG=false."""

    def setUp(self):
        self.client = Client()

    def test_get_shows_form_with_valid_query_token(self):
        response = self.client.get('/?setup_token=secret-setup-token')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create superuser')

    def test_get_hides_form_with_invalid_query_token(self):
        response = self.client.get('/?setup_token=wrong-token')
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Create superuser')

    def test_post_creates_superuser_with_hidden_token_field(self):
        response = self.client.get('/?setup_token=secret-setup-token')
        self.assertEqual(response.status_code, 200)

        data = {**VALID_POST, 'setup_token': 'secret-setup-token'}
        response = self.client.post('/', data)
        self.assertRedirects(response, '/?setup=done', fetch_redirect_response=False)
        self.assertTrue(User.objects.filter(username='admin', is_superuser=True).exists())

    def test_post_creates_superuser_with_header_token(self):
        response = self.client.post(
            '/',
            VALID_POST,
            HTTP_X_SETUP_TOKEN='secret-setup-token',
        )
        self.assertRedirects(response, '/?setup=done', fetch_redirect_response=False)
        self.assertTrue(User.objects.filter(username='admin', is_superuser=True).exists())

    def test_post_returns_403_with_wrong_token(self):
        data = {**VALID_POST, 'setup_token': 'wrong-token'}
        response = self.client.post('/', data)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.exists())
