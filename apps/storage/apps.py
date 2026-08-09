from django.apps import AppConfig


class StorageConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.storage'
    label = 'storage'
    verbose_name = 'Object storage'

    def ready(self):
        from . import signals  # noqa: F401
