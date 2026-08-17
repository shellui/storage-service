from django.apps import AppConfig


class AuthapiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.authapi'
    label = 'authapi'
    verbose_name = 'Identity JWKS auth'

    def ready(self):
        from . import openapi  # noqa: F401
        self._log_jwks_config()

    def _log_jwks_config(self):
        import logging

        from django.conf import settings

        logger = logging.getLogger(__name__)
        document = getattr(settings, 'IDENTITY_JWKS_DOCUMENT', None)
        keys = (document or {}).get('keys') or []
        kids = [entry.get('kid') for entry in keys if isinstance(entry, dict)]
        logger.info(
            'Identity JWKS auth ready: source=%s url=%s file=%s key_count=%s kids=%s '
            'algorithms=%s issuer=%s audience=%s hs256_fallback=%s',
            getattr(settings, 'IDENTITY_JWKS_SOURCE', None) or 'url',
            getattr(settings, 'IDENTITY_JWKS_URL', None),
            getattr(settings, 'IDENTITY_JWKS_FILE', None),
            len(keys) if document is not None else 'fetch-on-demand',
            kids if document is not None else 'fetch-on-demand',
            list(getattr(settings, 'JWT_ALGORITHMS', ('RS256',))),
            getattr(settings, 'IDENTITY_ISSUER', None),
            getattr(settings, 'IDENTITY_AUDIENCE', None),
            bool(getattr(settings, 'JWT_HS256_FALLBACK_SECRET', None))
            and (
                settings.DEBUG or getattr(settings, 'ALLOW_JWT_HS256_FALLBACK', False)
            ),
        )
