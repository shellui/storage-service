from django.apps import AppConfig


class ActionsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.actions'
    verbose_name = 'Shellui Actions'

    def ready(self) -> None:
        from apps.actions import storage_events  # noqa: F401
        from apps.actions import storage_hooks  # noqa: F401
        from apps.actions import admin as actions_admin  # noqa: F401
