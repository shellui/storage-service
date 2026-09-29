"""Tests for SSRF-pinned webhook HTTP transport (real connection behavior)."""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import TestCase
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from apps.actions.ssrf import ResolvedWebhookEndpoint
from apps.actions.webhook_transport import (
    PinnedHTTPSConnection,
    WebhookHTTPError,
    _tls_server_name,
    post_resolved_webhook,
    post_webhook_url,
)


def _self_signed_localhost_cert() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost')]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])


class TlsServerNameTests(TestCase):
    def _endpoint(self, host_header: str) -> ResolvedWebhookEndpoint:
        return ResolvedWebhookEndpoint(
            original_url='https://example/hook',
            scheme='https',
            connect_host='127.0.0.1',
            port=443,
            host_header=host_header,
            path='/hook',
        )

    def test_plain_hostname(self) -> None:
        self.assertEqual(_tls_server_name(self._endpoint('example.com')), 'example.com')

    def test_hostname_with_port(self) -> None:
        self.assertEqual(_tls_server_name(self._endpoint('example.com:8443')), 'example.com')

    def test_ipv6_literal_with_port(self) -> None:
        self.assertEqual(_tls_server_name(self._endpoint('[::1]:8443')), '::1')

    def test_ipv6_literal_without_port(self) -> None:
        self.assertEqual(_tls_server_name(self._endpoint('[2001:db8::1]')), '2001:db8::1')


class PinnedHTTPSConnectionUnitTests(TestCase):
    def test_connect_dials_pinned_ip_and_wraps_with_hostname(self) -> None:
        context = ssl.create_default_context()
        conn = PinnedHTTPSConnection(
            'webhook.example.com',
            443,
            connect_host='203.0.113.10',
            timeout=5.0,
            context=context,
        )
        mock_sock = MagicMock()
        with patch('apps.actions.webhook_transport.socket.create_connection', return_value=mock_sock) as create_conn:
            with patch.object(context, 'wrap_socket', return_value=MagicMock()) as wrap:
                conn.connect()
        create_conn.assert_called_once_with(('203.0.113.10', 443), 5.0, None)
        wrap.assert_called_once_with(mock_sock, server_hostname='webhook.example.com')

    def test_connect_normalizes_ipv6_literal(self) -> None:
        context = ssl.create_default_context()
        conn = PinnedHTTPSConnection(
            'webhook.example.com',
            443,
            connect_host='2001:db8::1',
            timeout=3.0,
            context=context,
        )
        expected = ipaddress.ip_address('2001:db8::1').compressed
        mock_sock = MagicMock()
        with patch('apps.actions.webhook_transport.socket.create_connection', return_value=mock_sock) as create_conn:
            with patch.object(context, 'wrap_socket', return_value=MagicMock()):
                conn.connect()
        create_conn.assert_called_once_with((expected, 443), 3.0, None)


class WebhookTransportIntegrationTests(TestCase):
    def test_https_post_round_trip_with_pinned_connect(self) -> None:
        port = _free_port()
        received: dict[str, bytes | str] = {}
        body_event = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get('Content-Length', '0'))
                received['host'] = self.headers.get('Host', '')
                received['body'] = self.rfile.read(length)
                self.send_response(204)
                self.end_headers()
                body_event.set()

            def log_message(self, format: str, *args: object) -> None:
                return

        cert_pem, key_pem = _self_signed_localhost_cert()
        httpd = HTTPServer(('127.0.0.1', port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=_pem_temp(cert_pem), keyfile=_pem_temp(key_pem))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        client_context = ssl.create_default_context()
        client_context.load_verify_locations(cadata=cert_pem.decode('ascii'))
        try:
            endpoint = ResolvedWebhookEndpoint(
                original_url=f'https://localhost:{port}/hook',
                scheme='https',
                connect_host='127.0.0.1',
                port=port,
                host_header='localhost',
                path='/hook',
            )
            payload = b'{"ok":true}'
            with patch(
                'apps.actions.webhook_transport.ssl.create_default_context',
                return_value=client_context,
            ):
                result = post_resolved_webhook(
                    endpoint,
                    body=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=5.0,
                )
            self.assertTrue(body_event.wait(timeout=5.0))
            self.assertEqual(result.status, 204)
            self.assertEqual(received['host'], 'localhost')
            self.assertEqual(received['body'], payload)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_https_cert_hostname_mismatch_fails(self) -> None:
        port = _free_port()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(500)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        cert_pem, key_pem = _self_signed_localhost_cert()
        httpd = HTTPServer(('127.0.0.1', port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=_pem_temp(cert_pem), keyfile=_pem_temp(key_pem))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = ResolvedWebhookEndpoint(
                original_url=f'https://wrong.example:{port}/hook',
                scheme='https',
                connect_host='127.0.0.1',
                port=port,
                host_header='wrong.example',
                path='/hook',
            )
            with self.assertRaises(ssl.SSLCertVerificationError):
                post_resolved_webhook(
                    endpoint,
                    body=b'{}',
                    headers={},
                    timeout=5.0,
                )
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_http_post_round_trip_to_pinned_ip(self) -> None:
        port = _free_port()
        received: dict[str, bytes | str] = {}
        body_event = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get('Content-Length', '0'))
                received['host'] = self.headers.get('Host', '')
                received['body'] = self.rfile.read(length)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ok')
                body_event.set()

            def log_message(self, format: str, *args: object) -> None:
                return

        httpd = HTTPServer(('127.0.0.1', port), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{port}/notify'
            result = post_webhook_url(
                url,
                body=b'ping',
                headers={'Content-Type': 'text/plain'},
                timeout=5.0,
                allow_private=True,
            )
            self.assertTrue(body_event.wait(timeout=5.0))
            self.assertEqual(result.status, 200)
            self.assertEqual(received['host'], f'127.0.0.1:{port}')
            self.assertEqual(received['body'], b'ping')
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_private_url_blocked_without_allow_private(self) -> None:
        with self.assertRaises(WebhookHTTPError):
            post_webhook_url(
                'https://127.0.0.1/hook',
                body=b'{}',
                headers={},
                timeout=2.0,
                allow_private=False,
            )


def _pem_temp(pem: bytes) -> str:
    import tempfile

    handle = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
    handle.write(pem)
    handle.flush()
    handle.close()
    return handle.name
