from django.apps import AppConfig


class AuthapiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.authapi'
    label = 'authapi'
    verbose_name = 'Identity JWKS auth'

    def ready(self):
        from . import openapi  # noqa: F401
