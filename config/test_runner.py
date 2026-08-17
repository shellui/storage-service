"""Test runner that keeps blob writes off the real filesystem and S3 bucket."""

from __future__ import annotations

import tempfile
from pathlib import Path

from django.conf import settings
from django.core.files.storage import default_storage
from django.test.runner import DiscoverRunner
from django.test.utils import override_settings


class IsolatedMediaDiscoverRunner(DiscoverRunner):
    """
    Force a local FileSystemStorage in a temp dir for the whole suite.

    ``override_settings(STORAGE_BACKEND='filesystem')`` does **not** rebuild
    ``STORAGES``, so tests would otherwise keep writing into the S3 bucket
    (or ``data/media``) from ``.env``. The temp dir is deleted when tests end.
    """

    def setup_test_environment(self, **kwargs):
        self._media_tmpdir = tempfile.TemporaryDirectory(prefix='shellui-storage-tests-')
        media_root = Path(self._media_tmpdir.name)
        self._media_override = override_settings(
            STORAGE_BACKEND='filesystem',
            MEDIA_ROOT=str(media_root),
            AWS_STORAGE_BUCKET_NAME='',
            AWS_ACCESS_KEY_ID='',
            AWS_SECRET_ACCESS_KEY='',
            AWS_S3_ENDPOINT_URL=None,
            STORAGES={
                'default': {
                    'BACKEND': 'django.core.files.storage.FileSystemStorage',
                    'OPTIONS': {
                        'location': str(media_root / 'objects'),
                        'base_url': f'{settings.MEDIA_URL}objects/',
                    },
                },
                'staticfiles': settings.STORAGES['staticfiles'],
            },
        )
        self._media_override.enable()
        location = Path(getattr(default_storage, 'location', '') or '').resolve()
        if not str(location).startswith(str(media_root.resolve())):
            raise RuntimeError(
                'Test storage is not isolated to the temp directory; '
                'refusing to run against S3 or the real MEDIA_ROOT.'
            )
        super().setup_test_environment(**kwargs)

    def teardown_test_environment(self, **kwargs):
        try:
            super().teardown_test_environment(**kwargs)
        finally:
            override = getattr(self, '_media_override', None)
            if override is not None:
                override.disable()
            tmpdir = getattr(self, '_media_tmpdir', None)
            if tmpdir is not None:
                tmpdir.cleanup()
