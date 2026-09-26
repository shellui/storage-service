"""Build landing-page Tailwind CSS (npm run build:css)."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)


def project_has_tailwind_build() -> bool:
    return (settings.BASE_DIR / 'package.json').is_file()


def build_site_css(*, log) -> bool:
    """
    Run `npm run build:css` when package.json exists.

    Returns True when CSS was built successfully or skipped intentionally.
    """
    base_dir = settings.BASE_DIR
    package_json = base_dir / 'package.json'
    if not package_json.is_file():
        return True

    npm = shutil.which('npm')
    if not npm:
        log(
            'npm not found — skipping Tailwind build for static/css/site.css. '
            'Install Node.js, run `npm ci && npm run build:css`, or use the prebuilt CSS in git.'
        )
        return False

    node_modules = base_dir / 'node_modules'
    if not node_modules.is_dir():
        log('node_modules missing — running `npm ci` before Tailwind build…')
        install = subprocess.run(
            [npm, 'ci'],
            cwd=base_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if install.returncode != 0:
            log(
                'npm ci failed — landing CSS may be stale. '
                f'Stderr: {install.stderr.strip() or install.stdout.strip()}'
            )
            return False

    log('Building Tailwind CSS (`npm run build:css`)…')
    result = subprocess.run(
        [npm, 'run', 'build:css'],
        cwd=base_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        log(
            'Tailwind build failed — landing CSS may be stale. '
            f'Stderr: {result.stderr.strip() or result.stdout.strip()}'
        )
        return False

    log('Tailwind CSS written to static/css/site.css')
    return True


def maybe_build_site_css_for_local_dev(*, log) -> None:
    """Build CSS once when DEBUG is on (local runserver)."""
    if not settings.DEBUG:
        return
    if not project_has_tailwind_build():
        return
    build_site_css(log=log)
