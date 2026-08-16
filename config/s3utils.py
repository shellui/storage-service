"""Normalize S3 env so boto3 talks to MinIO / OVH / AWS with the right origin and region."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_DEFAULT_REGION = 'us-east-1'
_OVH_S3_HOST = re.compile(
    r'^s3\.([a-z0-9-]+)\.(?:io\.cloud\.ovh\.net|perf\.cloud\.ovh\.net|cloud\.ovh\.net)$',
    re.IGNORECASE,
)


def normalize_s3_endpoint(url: str | None, bucket_name: str | None = None) -> str | None:
    """boto3 ``endpoint_url`` must be scheme+host, no path, and must not include the bucket subdomain."""
    raw = (url or '').strip()
    if not raw:
        return None
    if '://' not in raw:
        raw = f'https://{raw}'
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        return None
    bucket = (bucket_name or '').strip().lower()
    # People often paste the virtual-host URL: {bucket}.s3.region.example.com
    if bucket and host.startswith(f'{bucket}.'):
        rest = host[len(bucket) + 1 :]
        if rest.startswith('s3.'):
            host = rest
    netloc = host
    if parsed.port:
        netloc = f'{host}:{parsed.port}'
    return f'{parsed.scheme}://{netloc}'


def infer_s3_region(endpoint: str | None, configured: str) -> str:
    region = (configured or '').strip() or _DEFAULT_REGION
    host = (urlparse(endpoint).hostname or '') if endpoint else ''
    match = _OVH_S3_HOST.match(host)
    if match and region == _DEFAULT_REGION:
        return match.group(1)
    return region


def infer_addressing_style(endpoint: str | None, explicit: str) -> str:
    style = (explicit or '').strip().lower()
    if style in {'path', 'virtual', 'auto'}:
        return style
    if not endpoint:
        return 'virtual'
    host = (urlparse(endpoint).hostname or '').lower()
    if host in {'localhost', '127.0.0.1', '::1'} or host.endswith('.local'):
        return 'path'
    if host == 'minio' or host.startswith('minio.') or '.minio.' in host:
        return 'path'
    try:
        ipaddress.ip_address(host)
        return 'path'
    except ValueError:
        pass
    # OVH / AWS-style hosts: bucket.s3.region.…
    if host.startswith('s3.') or '.s3.' in host:
        return 'virtual'
    return 'path'


def normalize_custom_domain(custom: str | None, endpoint: str | None) -> str | None:
    """Ignore custom_domain when it is just the S3 API host (not a CDN)."""
    raw = (custom or '').strip()
    if not raw:
        return None
    custom_host = urlparse(raw if '://' in raw else f'https://{raw}').hostname or raw
    endpoint_host = urlparse(endpoint).hostname if endpoint else None
    if endpoint_host and custom_host == endpoint_host:
        return None
    return raw
