"""URL configuration for storage-service."""

from django.conf import settings
from django.urls import include, path
from django.views.decorators.clickjacking import xframe_options_exempt
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from apps.storage.admin import storage_admin_site

from . import views

urlpatterns = [
    path('', views.root, name='root'),
    path('admin/', storage_admin_site.urls),
    path('storage/v1/', include('apps.storage.urls')),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path(
        'api/docs/',
        xframe_options_exempt(SpectacularSwaggerView.as_view(url_name='schema')),
        name='swagger-ui',
    ),
    path(
        'api/docs/redoc/',
        xframe_options_exempt(SpectacularRedocView.as_view(url_name='schema')),
        name='redoc',
    ),
]

if settings.WEBDAV_ENABLED:
    urlpatterns.append(
        path(settings.WEBDAV_PATH_PREFIX.strip('/') + '/', include('apps.webdav.urls')),
    )
