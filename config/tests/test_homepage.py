"""Public homepage at GET / (landing page, admin link gating)."""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

User = get_user_model()


@override_settings(ALLOWED_HOSTS=['testserver'], DEBUG=False, SETUP_TOKEN='')
class HomepageTests(TestCase):
    """Homepage when bootstrap is closed and an operator account exists."""

    def setUp(self):
        self.client = Client()
        self.staff = User.objects.create_user(
            username='operator',
            password='long-enough-passphrase',
            is_staff=True,
        )
        User.objects.create_user(
            username='regular',
            password='long-enough-passphrase',
            is_staff=False,
        )

    def test_homepage_returns_200(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Shellui Storage')

    def test_anonymous_visitor_does_not_see_django_admin_link(self):
        response = self.client.get('/')
        self.assertNotContains(response, 'Django admin')

    def test_staff_user_sees_django_admin_link(self):
        self.client.force_login(self.staff)
        response = self.client.get('/')
        self.assertContains(response, 'Django admin')
        self.assertContains(response, '/admin/')

    def test_non_staff_authenticated_user_does_not_see_django_admin_link(self):
        regular = User.objects.get(username='regular')
        self.client.force_login(regular)
        response = self.client.get('/')
        self.assertNotContains(response, 'Django admin')
