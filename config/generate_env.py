"""``manage.py generate_env``: print a production env block with a fresh SECRET_KEY.

Runs before Django settings load (see manage.py), so it works with zero env,
no database and no Redis. Secrets go to stdout only. Nothing is logged or written.
"""

from __future__ import annotations

import argparse
import secrets
import sys

from config import env_registry as reg

SECRET_KEY_BYTES = 64  # token_urlsafe(64) is about 86 characters


def _values(host: str) -> dict[str, str]:
    origin = f'https://{host}'
    ph = reg.PLACEHOLDER
    return {
        'SECRET_KEY': secrets.token_urlsafe(SECRET_KEY_BYTES),
        'DEBUG': 'false',
        'ALLOWED_HOSTS': host,
        'CSRF_TRUSTED_ORIGINS': origin,
        'IDENTITY_SERVICE_URL': f'https://{ph}',
        'IDENTITY_ISSUER': f'https://{ph}',
        'IDENTITY_AUDIENCE': 'shellui',
        'REDIS_URL': 'redis://redis:6379/0',
        'POSTGRES_DATABASE_URL': f'postgres://{ph}:{ph}@postgres:5432/storage',
    }


def render(*, host: str, optional: bool) -> str:
    values = _values(host)
    lines = [f'# storage-service. Replace every {reg.PLACEHOLDER}.']
    for var in reg.REQUIRED:
        lines.append(f'# {var.comment}')
        lines.append(f'{var.name}={values[var.name]}')
    if optional:
        lines.extend(['', '# Optional (defaults shown)'])
        lines.extend(reg.optional_lines(skip=frozenset(v.name for v in reg.REQUIRED)))
    return '\n'.join(lines) + '\n'


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog='manage.py generate_env',
        description='Print the required production settings with a fresh SECRET_KEY.',
    )
    parser.add_argument('--host', default=f'{reg.PLACEHOLDER}.example.com', help='Public host, for example storage.example.com.')
    parser.add_argument('--optional', action='store_true', help='Also print optional settings with their defaults.')
    parser.add_argument('--example', action='store_true', help='Print .env.example (local development, no secrets).')
    args = parser.parse_args(argv)
    if args.example:
        sys.stdout.write(reg.render_example())
        return 0
    host = args.host.strip().lower().removeprefix('https://').removeprefix('http://').rstrip('/')
    sys.stdout.write(render(host=host, optional=args.optional))
    sys.stderr.write('generate_env: this output holds secrets. Store it in a secret manager and do not commit it.\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
