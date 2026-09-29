"""Tests for SSRF-safe HTTPS transport (pinned IP, correct SNI)."""

from __future__ import annotations

import datetime
import http.server
import ipaddress
import ssl
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.test import SimpleTestCase

from apps.actions.ssrf import ResolvedWebhookEndpoint
from apps.actions.webhook_transport import (
    PinnedHTTPSConnection,
    WebhookHTTPError,
    post_resolved_webhook,
    post_webhook_url,
)


def _write_self_signed_cert(
    *,
    common_name: str,
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
    )
    alt: list[x509.GeneralName] = []
    for name in san_dns or []:
        alt.append(x509.DNSName(name))
    for ip in san_ips or []:
        alt.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if not alt:
        alt.append(x509.DNSName(common_name))
    builder = builder.add_extension(x509.SubjectAlternativeName(alt), critical=False)
    cert = builder.sign(key, hashes.SHA256())

    cert_path = Path(tempfile.mkstemp(suffix='.pem')[1])
    key_path = Path(tempfile.mkstemp(suffix='.pem')[1])
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, _format, *_args):
        return


def _run_one_shot_https_server(*, cert_path: Path, key_path: Path) -> tuple[int, threading.Thread]:
    httpd = http.server.HTTPServer(('127.0.0.1', 0), _OkHandler)
    port = httpd.server_address[1]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    def _serve():
        httpd.handle_request()
        httpd.server_close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return port, thread


class PinnedHTTPSConnectionTests(SimpleTestCase):
    @patch('apps.actions.webhook_transport.socket.create_connection')
    def test_connect_dials_pinned_ip_with_tls_server_name(self, mock_create):
        mock_sock = MagicMock()
        mock_create.return_value = mock_sock
        context = ssl.create_default_context()
        with patch.object(context, 'wrap_socket', return_value=mock_sock) as mock_wrap:
            conn = PinnedHTTPSConnection(
                'hooks.example.com',
                443,
                pinned_host='203.0.113.10',
                timeout=5.0,
                context=context,
            )
            conn.connect()
        mock_create.assert_called_once()
        dial_host, dial_port = mock_create.call_args[0][0]
        self.assertEqual(dial_host, '203.0.113.10')
        self.assertEqual(dial_port, 443)
        mock_wrap.assert_called_once()
        self.assertEqual(mock_wrap.call_args.kwargs['server_hostname'], 'hooks.example.com')

    @patch('apps.actions.webhook_transport.socket.create_connection')
    def test_connect_supports_ipv6_literal_pin(self, mock_create):
        mock_create.return_value = MagicMock()
        context = ssl.create_default_context()
        with patch.object(context, 'wrap_socket', return_value=MagicMock()):
            conn = PinnedHTTPSConnection(
                'example.com',
                443,
                pinned_host='2001:db8::1',
                timeout=3.0,
                context=context,
            )
            conn.connect()
        dial_host, _ = mock_create.call_args[0][0]
        self.assertEqual(dial_host, '2001:db8::1')


def _context_trusting_cert(cert_path: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=str(cert_path))
    return ctx


class HttpsWebhookIntegrationTests(SimpleTestCase):
    def test_localhost_self_signed_roundtrip(self):
        cert_path, key_path = _write_self_signed_cert(common_name='127.0.0.1', san_ips=['127.0.0.1'])
        try:
            port, thread = _run_one_shot_https_server(cert_path=cert_path, key_path=key_path)
            endpoint = ResolvedWebhookEndpoint(
                original_url=f'https://127.0.0.1:{port}/hook',
                scheme='https',
                connect_host='127.0.0.1',
                port=port,
                host_header='127.0.0.1',
                path='/hook',
            )
            with patch(
                'apps.actions.webhook_transport.ssl.create_default_context',
                return_value=_context_trusting_cert(cert_path),
            ):
                result = post_resolved_webhook(
                    endpoint,
                    body=b'{}',
                    headers={'Content-Type': 'application/json'},
                    timeout=5.0,
                )
            self.assertEqual(result.status, 200)
            thread.join(timeout=5)
        finally:
            cert_path.unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)

    def test_hostname_mismatch_fails_verification(self):
        cert_path, key_path = _write_self_signed_cert(
            common_name='wrong-host.invalid',
            san_dns=['wrong-host.invalid'],
        )
        try:
            port, thread = _run_one_shot_https_server(cert_path=cert_path, key_path=key_path)
            endpoint = ResolvedWebhookEndpoint(
                original_url=f'https://localhost:{port}/hook',
                scheme='https',
                connect_host='127.0.0.1',
                port=port,
                host_header='localhost',
                path='/hook',
            )
            with patch(
                'apps.actions.webhook_transport.ssl.create_default_context',
                return_value=_context_trusting_cert(cert_path),
            ):
                with self.assertRaises(ssl.SSLCertVerificationError):
                    post_resolved_webhook(
                        endpoint,
                        body=b'{}',
                        headers={'Content-Type': 'application/json'},
                        timeout=5.0,
                    )
            thread.join(timeout=5)
        finally:
            cert_path.unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)

    def test_post_webhook_url_private_localhost(self):
        cert_path, key_path = _write_self_signed_cert(common_name='127.0.0.1', san_ips=['127.0.0.1'])
        try:
            port, thread = _run_one_shot_https_server(cert_path=cert_path, key_path=key_path)
            url = f'https://127.0.0.1:{port}/hook'
            with patch(
                'apps.actions.webhook_transport.ssl.create_default_context',
                return_value=_context_trusting_cert(cert_path),
            ):
                result = post_webhook_url(
                    url,
                    body=b'{"ok":true}',
                    headers={'Content-Type': 'application/json'},
                    timeout=5.0,
                    allow_private=True,
                )
            self.assertEqual(result.status, 200)
            thread.join(timeout=5)
        finally:
            cert_path.unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)

    def test_private_url_blocked_without_allow_private(self):
        with self.assertRaises(WebhookHTTPError):
            post_webhook_url(
                'https://127.0.0.1/hook',
                body=b'{}',
                headers={},
                timeout=2.0,
                allow_private=False,
            )
