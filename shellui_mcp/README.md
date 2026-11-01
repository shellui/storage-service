# shellui_mcp

Copy this directory into storage-service, hosting-service, email-service, and saas-service unchanged.

## Service wiring

1. Mount `POST /mcp` with `shellui_mcp.server.McpServer`.
2. Tag OpenAPI operations with `mcp-tools` using `@mcp_expose_tool` (never tag staff-only routes).
3. Publish `/.well-known/oauth-protected-resource` pointing at Identity.
4. Poll Identity `GET /api/v1/mcp/internal/mcp-revocations` every 30 seconds.
5. Forward call logs with `POST /api/v1/mcp/internal/mcp-call-logs` and signed assertions (`shellui_mcp.internal`).
6. Create approval requests with `POST /api/v1/mcp/internal/mcp-approval-requests` when writes need confirmation.

See [MCP and agents](../docs/mcp-and-agents.md) in identity-service docs.
