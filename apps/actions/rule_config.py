"""Build and validate ActionRule.config for admin UI and REST API."""

from __future__ import annotations

from django.core.exceptions import ValidationError

from apps.actions.models import ActionRule
from apps.actions.webhook_signing import generate_webhook_signing_secret


def build_webhook_config(
    *,
    existing: dict,
    url: str | None = None,
    secret: str | None = None,
    authorization_header: str | None = None,
    allow_private_urls: bool | None = None,
    is_superuser: bool,
    partial: bool,
) -> dict:
    cfg = dict(existing or {})
    if url is not None or not partial:
        cfg['url'] = (url if url is not None else cfg.get('url') or '').strip()
    if not cfg.get('url'):
        raise ValidationError('Webhook url is required.')

    if secret is not None:
        secret_s = (secret or '').strip()
        if secret_s:
            cfg['secret'] = secret_s
        elif existing.get('secret'):
            cfg['secret'] = existing['secret']
        elif not partial:
            cfg['secret'] = generate_webhook_signing_secret()
    elif not partial and not cfg.get('secret'):
        cfg['secret'] = generate_webhook_signing_secret()
    elif existing.get('secret'):
        cfg['secret'] = existing['secret']

    if authorization_header is not None:
        auth_s = (authorization_header or '').strip()
        if auth_s:
            cfg['authorization_header'] = auth_s
        else:
            cfg.pop('authorization_header', None)
    elif existing.get('authorization_header'):
        cfg['authorization_header'] = existing['authorization_header']

    if is_superuser:
        if allow_private_urls is True:
            cfg['allow_private_urls'] = True
        elif allow_private_urls is False:
            cfg.pop('allow_private_urls', None)
    elif not partial:
        if existing.get('allow_private_urls'):
            cfg['allow_private_urls'] = True
    return cfg


def mask_config_for_response(config: dict, action_kind: str) -> dict:
    cfg = dict(config or {})
    if action_kind == ActionRule.ACTION_WEBHOOK:
        cfg.pop('secret', None)
        cfg.pop('authorization_header', None)
        cfg['secret_set'] = bool((config or {}).get('secret'))
        cfg['authorization_header_set'] = bool((config or {}).get('authorization_header'))
    return cfg
