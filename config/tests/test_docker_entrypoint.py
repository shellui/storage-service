"""
tools/docker-entrypoint.sh modes and process supervision.

The real gunicorn, celery, python and setpriv are replaced by stubs on PATH that log
their arguments, so the script runs without Docker, root or Redis.
"""

import os
import shutil
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

ENTRYPOINT = Path(settings.BASE_DIR) / 'tools' / 'docker-entrypoint.sh'

# Long-running stub: logs its arguments, then waits for SIGTERM unless STUB_<NAME>_EXIT
# asks it to exit on its own with that status.
_SERVICE_STUB = textwrap.dedent(
    '''\
    #!/usr/bin/env bash
    name="$(basename "$0")"
    echo "${name} $*" >> "${STUB_LOG}"
    var="STUB_$(echo "${name}" | tr '[:lower:]' '[:upper:]')_EXIT"
    if [ -n "${!var:-}" ]; then
      sleep 0.2
      exit "${!var}"
    fi
    # The sleep must not keep the test's stdout/stderr pipes open after we exit.
    sleep 30 >/dev/null 2>&1 &
    sleeper=$!
    trap 'echo "${name} TERM" >> "${STUB_LOG}"; kill "${sleeper}"; exit 0' TERM
    wait
    '''
)

_ONESHOT_STUB = textwrap.dedent(
    '''\
    #!/usr/bin/env bash
    echo "$(basename "$0") $*" >> "${STUB_LOG}"
    '''
)

# Drops the privilege options and runs the command, like the real setpriv.
# The first line records the invocation so tests can see the uid drop.
_SETPRIV_STUB = textwrap.dedent(
    '''\
    #!/usr/bin/env bash
    echo "setpriv $*" >> "${STUB_LOG}"
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
    shift
    exec "$@"
    '''
)


@unittest.skipUnless(shutil.which('bash'), 'bash is required')
class DockerEntrypointTests(SimpleTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='entrypoint-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        stubs = {
            'gunicorn': _SERVICE_STUB,
            'celery': _SERVICE_STUB,
            'python': _ONESHOT_STUB,
            'chown': _ONESHOT_STUB,
            'setpriv': _SETPRIV_STUB,
        }
        for name, body in stubs.items():
            path = bin_dir / name
            path.write_text(body)
            path.chmod(0o755)
        self.log = self.tmp / 'calls.log'
        self.log.touch()
        self.base_env = {
            'PATH': f'{bin_dir}{os.pathsep}{os.environ.get("PATH", "")}',
            'STUB_LOG': str(self.log),
            'SQLITE_PATH': str(self.tmp / 'data' / 'db.sqlite3'),
            'MEDIA_ROOT': str(self.tmp / 'media'),
            'APP_USER': 'appuser',
            'HOME': str(self.tmp),
        }

    def _env(self, **extra):
        env = dict(self.base_env)
        env.update(extra)
        return env

    def run_entrypoint(self, *args, timeout=15, **env):
        return subprocess.run(
            ['bash', str(ENTRYPOINT), *args],
            env=self._env(**env),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def calls(self):
        return self.log.read_text().splitlines()

    def started(self, name):
        return [line for line in self.calls() if line.startswith(f'{name} ') and line != f'{name} TERM']

    def assert_dropped_privileges(self, command):
        matches = [
            line
            for line in self.calls()
            if line.startswith('setpriv ')
            and '--reuid=appuser' in line
            and '--regid=appuser' in line
            and command in line
        ]
        self.assertTrue(matches, self.calls())

    def assert_access_log_omits_query_and_referer(self):
        gunicorn = self.started('gunicorn')[0]
        self.assertIn('%(U)s', gunicorn)
        self.assertNotIn('%(r)s', gunicorn)
        self.assertNotIn('%(f)s', gunicorn)
        self.assertIn('"-"', gunicorn)

    def wait_for(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def test_web_starts_gunicorn_and_scheduler_and_forwards_sigterm(self):
        proc = subprocess.Popen(
            ['bash', str(ENTRYPOINT)],
            env=self._env(REDIS_URL='redis://redis:6379/0'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertTrue(
                self.wait_for(lambda: self.started('gunicorn') and self.started('celery')),
                self.calls(),
            )
            # Let the stubs install their TERM traps.
            time.sleep(0.3)
            proc.send_signal(signal.SIGTERM)
            _, stderr = proc.communicate(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

        self.assertEqual(proc.returncode, 0, stderr)
        calls = self.calls()
        self.assertIn('python manage.py migrate --noinput', calls)
        self.assertIn('python manage.py check --deploy', calls)
        self.assertIn('gunicorn TERM', calls)
        self.assertIn('celery TERM', calls)
        celery_args = self.started('celery')[0]
        self.assertIn('-A config --quiet worker --beat', celery_args)
        self.assertIn('--schedule /tmp/celerybeat-schedule', celery_args)
        self.assertIn('--pool threads --concurrency 2', celery_args)
        self.assertIn('--hostname storage-service@%h', celery_args)
        self.assertIn('config.wsgi:application', self.started('gunicorn')[0])
        self.assertIn('--timeout 120', self.started('gunicorn')[0])
        self.assertIn('--workers 2', self.started('gunicorn')[0])
        self.assert_dropped_privileges('gunicorn')
        self.assert_dropped_privileges('celery')
        self.assert_access_log_omits_query_and_referer()

    def test_web_exits_when_the_scheduler_dies(self):
        result = self.run_entrypoint(REDIS_URL='redis://redis:6379/0', STUB_CELERY_EXIT='3')
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('gunicorn TERM', self.calls())
        self.assertIn('a process exited with status 3', result.stderr)

    def test_web_exits_non_zero_when_gunicorn_exits(self):
        result = self.run_entrypoint(REDIS_URL='redis://redis:6379/0', STUB_GUNICORN_EXIT='0')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('celery TERM', self.calls())

    def assert_refused_without_redis(self, result):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            'ERROR: REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0)',
            result.stderr,
        )
        # Exits before migrations, checks and any server process.
        self.assertEqual(self.calls(), [])

    def test_web_in_production_without_redis_refuses_to_start(self):
        # DEBUG unset means false, like settings.py and the image default.
        self.assert_refused_without_redis(self.run_entrypoint('web', STUB_GUNICORN_EXIT='0'))

    def test_web_with_debug_false_without_redis_refuses_to_start(self):
        self.assert_refused_without_redis(self.run_entrypoint(DEBUG='false', STUB_GUNICORN_EXIT='0'))

    def test_blank_redis_url_counts_as_unset(self):
        self.assert_refused_without_redis(
            self.run_entrypoint(DEBUG='false', REDIS_URL='  ', STUB_GUNICORN_EXIT='0')
        )

    def test_scheduler_disabled_still_requires_redis_in_production(self):
        result = self.run_entrypoint(DEBUG='false', SCHEDULER_ENABLED='false', STUB_GUNICORN_EXIT='0')
        self.assert_refused_without_redis(result)

    def test_celery_broker_url_does_not_replace_redis_url_in_production(self):
        result = self.run_entrypoint(
            DEBUG='false', CELERY_BROKER_URL='redis://broker:6379/1', STUB_GUNICORN_EXIT='0'
        )
        self.assert_refused_without_redis(result)

    def test_web_in_debug_without_redis_warns_and_runs_gunicorn_only(self):
        result = self.run_entrypoint('web', DEBUG='True', STUB_GUNICORN_EXIT='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('WARNING: REDIS_URL is not set', result.stderr)
        self.assertNotIn('ERROR', result.stderr)
        self.assertIn('python manage.py check --deploy', self.calls())
        self.assertTrue(self.started('gunicorn'))
        self.assertFalse(self.started('celery'))

    def test_web_in_production_with_redis_starts(self):
        result = self.run_entrypoint(
            DEBUG='false', REDIS_URL='redis://redis:6379/0', STUB_GUNICORN_EXIT='0'
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn('REDIS_URL is required', result.stderr)
        self.assertTrue(self.started('gunicorn'))
        self.assertTrue(self.started('celery'))

    def test_scheduler_disabled(self):
        result = self.run_entrypoint(
            REDIS_URL='redis://redis:6379/0', SCHEDULER_ENABLED='false', STUB_GUNICORN_EXIT='0'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SCHEDULER_ENABLED=false', result.stderr)
        self.assertFalse(self.started('celery'))

    def test_celery_broker_url_alone_starts_the_scheduler_in_debug(self):
        result = self.run_entrypoint(
            DEBUG='true',
            CELERY_BROKER_URL='redis://broker:6379/1',
            CELERY_WORKER_CONCURRENCY='4',
            STUB_CELERY_EXIT='0',
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('--concurrency 4', self.started('celery')[0])

    def test_worker_mode_runs_only_the_scheduler(self):
        result = self.run_entrypoint('worker', REDIS_URL='redis://redis:6379/0', STUB_CELERY_EXIT='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.started('celery'))
        self.assertFalse(self.started('gunicorn'))
        self.assertFalse(self.started('python'), 'worker mode leaves migrations to the web container')
        self.assert_dropped_privileges('celery')

    def test_worker_mode_in_production_without_redis_refuses_to_start(self):
        self.assert_refused_without_redis(self.run_entrypoint('worker', STUB_CELERY_EXIT='0'))

    def test_worker_mode_in_debug_without_broker_fails(self):
        result = self.run_entrypoint('worker', DEBUG='true')
        self.assertEqual(result.returncode, 1)
        self.assertIn('worker mode needs REDIS_URL', result.stderr)
        self.assertFalse(self.started('celery'))

    def test_other_command_runs_as_given(self):
        # Not gated on REDIS_URL, so an operator can still run check --deploy or
        # createsuperuser in a misconfigured production container.
        result = self.run_entrypoint('python', 'manage.py', 'purge_expired_data', '--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.started('python'), ['python manage.py purge_expired_data --dry-run'])
        self.assertFalse(self.started('gunicorn'))
        self.assert_dropped_privileges('python')
