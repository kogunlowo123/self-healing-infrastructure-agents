# ADR-0006: MCP SDK 2.x, stateless streamable HTTP, own host guard

- Status: Accepted
- Date: 2026-10-14

## Context

The portfolio standard calls for the official MCP Python SDK. Version 2
renamed `FastMCP` to `MCPServer`. The service runs several replicas behind a
load balancer, and its host name is deployment configuration.

## Decision

- Use `mcp>=2.3,<3` and `MCPServer`, mounted at `/mcp/` with
  `stateless_http=True` and `json_response=True`; the session manager runs in
  the FastAPI lifespan.
- Authorization happens inside each tool from the request's bearer token,
  through the same resolver as the REST API, so a tool cannot be more
  permissive than the equivalent endpoint.
- The SDK's DNS-rebinding check is replaced by `McpHostGuard`, which reads
  allowed hosts and the public origin from runtime settings.

## Consequences

- No sticky sessions; server-initiated notifications are not used.
- Moving to a later 2.x release is a dependency update covered by the MCP
  end-to-end tests.
