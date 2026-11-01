"""Ensure ``shellui_mcp/`` stays byte-identical to identity-service (ref 09ea226)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from django.test import SimpleTestCase

# SHA-256 of each file under identity-service shellui_mcp at 09ea226a484de514cd955c5e46fc7a5b2a4475af
IDENTITY_SHELLUI_MCP_SHA256: dict[str, str] = {
    'README.md': '2f6f3b77db549fa5cc7dc2558a47f881e7ff1878b2babc5417dba7aef6b1c25b',
    '__init__.py': '043bd137a7401e93e158f3974bc5f7fad828cfac12ffb36d17d211f54f8b9e10',
    'decorators.py': '41b1d42c6cd3b16458c55c8e5f7bb3a40b3590fb425dffb736609da8c75e43dd',
    'internal.py': '517e9adc3aaef646fe9d2349bbf22b0af6f085ffc27e133bc9aa3db8e00d98bb',
    'masking.py': '6fd5a7565450b378a408b95722e17f082e633480aca142e802f117833dd416fa',
    'openapi_tools.py': 'dbcaf05cf05e889aafb9554707c70d868a23337770ab6cc74ba631c594dbea1f',
    'rate_limit.py': '5a6abfc62ed9109087f69528e560f8c913cc5d527984f4eca9e6e41a19d87b95',
    'resources.py': '20310ae111b415edf3b24a1790e8b6e310461c1019ca607bb68437c15b72a324',
    'server.py': '43d42f100fa93ec341db8c49ab07a8350338fd845525c4f86370e8c66bab3264',
    'write_gate.py': '72c1aa0b88f876d5d8b670b4387dcbb6e4e6294fd10022ab8ceac3c86c3965df',
    'tests/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'tests/test_package.py': '8626dc22aa30b3cfcfbf4b53594f0229092372cac1195456a478b2062414d841',
    'tests/test_resources.py': '20839c30dc322a5bdf38179e25cbfac5fe4ad987f03cded50b03cbb357ff534c',
}

PACKAGE_ROOT = Path(__file__).resolve().parents[3] / 'shellui_mcp'


class ShelluiMcpIdentitySyncTests(SimpleTestCase):
    def test_shellui_mcp_byte_identical_to_identity_09ea226(self):
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
            self.fail(f'shellui_mcp drift from identity 09ea226: {drift}')

        extra = []
        for path in PACKAGE_ROOT.rglob('*'):
            if path.is_dir() or '__pycache__' in path.parts:
                continue
            rel = str(path.relative_to(PACKAGE_ROOT)).replace('\\', '/')
            if rel not in IDENTITY_SHELLUI_MCP_SHA256:
                extra.append(rel)
        if extra:
            self.fail(f'shellui_mcp has unexpected files vs identity 09ea226: {sorted(extra)}')
