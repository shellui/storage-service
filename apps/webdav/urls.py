from django.urls import re_path

from .views import WebDAVView

urlpatterns = [
    re_path(r'^(?P<path>.*)$', WebDAVView.as_view(), name='webdav'),
]
