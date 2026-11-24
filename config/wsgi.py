"""
WSGI config for config project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.0/howto/deployment/wsgi/
"""

import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

from config.telemetry import setup_telemetry

setup_telemetry()

from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
