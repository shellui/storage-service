"""Ensure ``shellui_mcp/`` stays byte-identical to identity-service (ref fa19556)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from django.test import SimpleTestCase

# SHA-256 of each file under identity-service shellui_mcp at fa1955640cf08bd4d6ea324c4105cb0125792871
IDENTITY_SHELLUI_MCP_SHA256: dict[str, str] = {
    'README.md': '0a69e89c47d056d55b4f7f44ba06cccb2c3d07761426d6c16853aa50bc47e6b4',
    '__init__.py': 'efadf5fc6912f02370dbcbe98aed96b2135a4a23f451fd2e167af010e80d1cae',
    'decorators.py': '41b1d42c6cd3b16458c55c8e5f7bb3a40b3590fb425dffb736609da8c75e43dd',
    'internal.py': '8d53c1e1130a761e0d29c60515dd13de2c51cfc76d4c52534d03a2f2182d8783',
    'masking.py': '86588d60a1da6f2fd1b19e7a1d58dc417076e6d4411786a66245fd3f981ac734',
    'openapi_mcp.py': '7ef643dc6c26e4c8e74b9bc87f5f57647b816cde9b44b8dd35124e97ed0cfa52',
    'openapi_tools.py': 'd89095025f5d98d57b9712068b51e6b31500bffb69f9f555c4b522a690ee72bd',
    'rate_limit.py': '5a6abfc62ed9109087f69528e560f8c913cc5d527984f4eca9e6e41a19d87b95',
    'resources.py': '20310ae111b415edf3b24a1790e8b6e310461c1019ca607bb68437c15b72a324',
    'routing.py': 'f34b3427a8d8001fde11cfa4f9cb322951cf279dc22c1d0e01278db64392a0de',
    'server.py': '422ff89b8a35067421bc2708fd4f416aff817ceb21e24adff424648d78172993',
    'write_gate.py': '6efb96273a358e1fc83fa95d1ce0abc417dba5cbbc6b89fb5f415526ce8755c1',
    'tests/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'tests/mcp_routing_urlconf.py': '88faf6d6f39ebdf75648c59a1cc12b8912bea28fa63914f9b2122d9203863277',
    'tests/test_internal_revocation.py': 'ed8263d90e67ca13829953a534bb873822c3011639656b166374783650114e0a',
    'tests/test_masking.py': '5979fd676ad726f087bd0acffba2b38798786b518287a9b8a483329d32449aee',
    'tests/test_openapi_tools.py': 'ea096f5f8d0ff26395907d3852bf14715dd44cf950d603e55216595e0352d404',
    'tests/test_package.py': '571def9ad72310d4bce34f3372129435b969a090668ec40e010c968c75d6d1f4',
    'tests/test_resources.py': '20839c30dc322a5bdf38179e25cbfac5fe4ad987f03cded50b03cbb357ff534c',
    'tests/test_routing.py': '677589a3258744fe24dc31ede95796ddb380eb578e0aed9c8c14a08e91469d79',
    'tests/test_server_routing.py': '4e7523e2d77744cb2edfc7eb4e42230ae67b045fc7cd6df5524dfb2bd7bc0745',
    'tests/test_write_gate_mcp.py': '599e61f117b0f3cba1c0ec2a7d6d617156fbc7ce2aad176bbcbc3f7de37a8cf8',
}

PACKAGE_ROOT = Path(__file__).resolve().parents[3] / 'shellui_mcp'


class ShelluiMcpIdentitySyncTests(SimpleTestCase):
    def test_shellui_mcp_byte_identical_to_identity_fa19556(self):
        missing = []
        drift = []
        for rel, expected in sorted(IDENTITY_SHELLUI_MCP_SHA256.items()):
            path = PACKAGE_ROOT / rel
            if not path.is_file():
                missing.append(rel)
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != expected:
                drift.append(f'{rel} (got {digest})')
        if missing:
            self.fail(f'shellui_mcp missing files: {missing}')
        if drift:
            self.fail(f'shellui_mcp drift from identity fa19556: {drift}')

        extra = []
        for path in PACKAGE_ROOT.rglob('*'):
            if path.is_dir() or '__pycache__' in path.parts:
                continue
            rel = str(path.relative_to(PACKAGE_ROOT)).replace('\\', '/')
            if rel not in IDENTITY_SHELLUI_MCP_SHA256:
                extra.append(rel)
        if extra:
            self.fail(f'shellui_mcp has unexpected files vs identity fa19556: {sorted(extra)}')
