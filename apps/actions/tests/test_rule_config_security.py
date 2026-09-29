from django.test import SimpleTestCase

from apps.actions.rule_config import build_webhook_config


class WebhookAllowPrivateUrlSecurityTests(SimpleTestCase):
    def test_non_superuser_url_change_clears_allow_private_urls(self):
        existing = {
            'url': 'http://127.0.0.1:5678/hook',
            'secret': 'whsec_test',
            'allow_private_urls': True,
        }
        cfg = build_webhook_config(
            existing=existing,
            url='http://169.254.169.254/latest/meta-data/',
            is_superuser=False,
            partial=True,
        )
        self.assertEqual(cfg['url'], 'http://169.254.169.254/latest/meta-data/')
        self.assertNotIn('allow_private_urls', cfg)

    def test_superuser_can_keep_allow_private_on_url_change(self):
        existing = {
            'url': 'http://127.0.0.1:5678/hook',
            'secret': 'whsec_test',
            'allow_private_urls': True,
        }
        cfg = build_webhook_config(
            existing=existing,
            url='http://127.0.0.1:5678/other',
            allow_private_urls=True,
            is_superuser=True,
            partial=True,
        )
        self.assertTrue(cfg.get('allow_private_urls'))

    def test_partial_without_url_keeps_existing_allow_private_for_owner(self):
        existing = {
            'url': 'http://127.0.0.1:5678/hook',
            'secret': 'whsec_test',
            'allow_private_urls': True,
        }
        cfg = build_webhook_config(
            existing=existing,
            secret='whsec_test',
            is_superuser=False,
            partial=True,
        )
        self.assertTrue(cfg.get('allow_private_urls'))
