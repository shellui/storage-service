"""SSRF validation for IPv6 forms that embed IPv4 addresses."""

from django.test import TestCase

from apps.actions.ssrf import SSRFError, validate_webhook_url


class SsrfEmbeddedIpv4Tests(TestCase):
    def test_nat64_private_embedded_ipv4_blocked(self):
        with self.assertRaises(SSRFError):
            validate_webhook_url('http://[64:ff9b::10.0.0.1]/hook')

    def test_six2four_private_embedded_ipv4_blocked(self):
        with self.assertRaises(SSRFError):
            validate_webhook_url('http://[2002:0a00:0001::]/hook')

    def test_ipv4_compatible_private_embedded_blocked(self):
        with self.assertRaises(SSRFError):
            validate_webhook_url('http://[::10.0.0.1]/hook')
