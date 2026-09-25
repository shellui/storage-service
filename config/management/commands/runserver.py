from django.contrib.staticfiles.management.commands.runserver import (
    Command as StaticfilesRunserverCommand,
)

from config.tailwind_build import maybe_build_site_css_for_local_dev


class Command(StaticfilesRunserverCommand):
    def handle(self, *args, **options):
        maybe_build_site_css_for_local_dev(log=self.stdout.write)
        super().handle(*args, **options)
