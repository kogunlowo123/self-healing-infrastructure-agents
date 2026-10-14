# MCP integration

The service exposes its tools through the official MCP Python SDK
(`mcp` 2.x, `MCPServer`), mounted in the FastAPI app at `/mcp/` with the
streamable HTTP transport in stateless JSON-response mode, so any replica can
answer any request and no session affinity is needed.

## Tools

| Tool | Annotations | Required scope (agents) | Purpose |
|---|---|---|---|
| `list_incidents` | read-only, idempotent | `incidents:read` | Incidents, newest first, optional status filter |
| `get_incident` | read-only, idempotent | `incidents:read` | One incident with alerts, diagnosis and plans |
| `diagnose_incident` | write | `alerts:diagnose` | Re-run the playbook on fresh read-only evidence |
| `analyze_terraform_plan` | read-only, idempotent | `terraform:analyze` | Risk analysis of `terraform show -json` output |
| `propose_remediation` | write | `remediation:propose` | Policy-validated proposal |
| `list_remediations` | read-only, idempotent | `remediation:read` | Plans, newest first |
| `dry_run_remediation` | write | `remediation:dry-run` | Server-side dry run of a plan |
| `execute_remediation` | destructive | `remediation:execute` | Live execution; refused unless live mode is enabled and approvals are recorded |

Input and output schemas are generated from the same Pydantic models as the
REST API (`ActionSpec`, `RemediationPlan`, `Incident`, `PlanAnalysis`), so
`tools/list` advertises both `inputSchema` and `outputSchema`, and results
carry `structuredContent`.

Approval is not a tool. MCP clients are agents; approvals require a human
operator's OIDC token on `POST /v1/remediations/{id}/decision`.

## Authorization and audit

Each tool reads the `Authorization` header of the HTTP request carrying the
MCP call and resolves the caller through the same `CallerResolver` as the
REST API: identity fabric decision (or the local access policy), or operator
roles for human-driven MCP clients. Failures are returned as tool errors
(`isError: true`) with the error code, never as partial results. Every call,
allowed or refused, writes an audit event `mcp.<tool>` and increments
`heal_agent_tool_calls_total{interface="mcp"}`.

## Transport protection

`McpHostGuard` wraps the MCP ASGI app and rejects requests whose `Host`
header is not one of the configured hosts (`HEAL_MCP_ALLOWED_HOSTS`, default
the host of `HEAL_PUBLIC_URL`) or whose `Origin`, when present, is not the
public URL. This protects against DNS rebinding with deployment
configuration instead of values fixed at build time. The service-wide 16 MiB
body limit applies to MCP requests as well.

## Client configuration

```json
{"mcpServers": {"self-healing": {
  "type": "http",
  "url": "<HEAL_PUBLIC_URL>/mcp/",
  "headers": {"Authorization": "Bearer <agent credential from the identity fabric>"}}}}
```
