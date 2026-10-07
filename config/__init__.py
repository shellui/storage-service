# Load the Celery app when Django starts so @shared_task binds to it.
from config.celery import app as celery_app

__all__ = ('celery_app',)
