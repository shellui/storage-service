# shellui_mcp tests

Run with the service Django test runner:

```bash
python manage.py test shellui_mcp.tests
```

Portable unit tests (`test_internal_revocation`, `test_routing`, `test_masking`, `test_write_gate_mcp`, `test_openapi_tools`, `test_resources`, `test_package`) do not require Identity-specific settings. Revocation verification tests use inline RS256 JWKS fixtures in `rs256_helpers.py`.

`test_server_routing` needs Django URL resolution only (`ROOT_URLCONF` override) and no database.
