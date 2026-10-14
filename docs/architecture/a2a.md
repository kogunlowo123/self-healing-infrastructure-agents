# A2A communication design

Other agents (an SRE triage agent, a change-management agent, a CI pipeline
agent) reach this service through the Agent2Agent protocol.

## Agent card

`GET /.well-known/agent-card.json` (unauthenticated) returns:

| Field | Value |
|---|---|
| `protocolVersion` | `0.3.0` |
| `name`, `description`, `version` | Service identity and package version |
| `url` | `<HEAL_PUBLIC_URL>/a2a` |
| `preferredTransport` | `JSONRPC` |
| `provider` | Organization and repository URL |
| `capabilities` | `streaming: false`, `pushNotifications: false`, `stateTransitionHistory: false` |
| `defaultInputModes`, `defaultOutputModes` | `application/json` |
| `skills` | id, name, description, tags, input and output modes |
| `securitySchemes` | `agentCredential`: HTTP bearer JWT issued by the agent identity fabric |
| `security` | `[{"agentCredential": []}]` |

## Skills

| Skill | Input (data part) | Authorization action |
|---|---|---|
| `get-incident` | `{skill, incident_id}` | `incidents:read` |
| `diagnose-incident` | `{skill, incident_id}` | `alerts:diagnose` |
| `analyze-terraform-plan` | `{skill, plan}` | `terraform:analyze` |
| `propose-remediation` | `{skill, action, incident_id?}` | `remediation:propose` |
| `get-remediation` | `{skill, plan_id}` | `remediation:read` |

Live execution and approval are deliberately not A2A skills: approval is a
human act, and execution of an approved plan is done by operators or the
MCP `execute_remediation` tool under the same controls.

## message/send

`POST /a2a` with a JSON-RPC 2.0 request whose `params.message` carries at
least one `data` part naming a skill. The request is authorized for that
skill exactly as the REST API would authorize it, then answered with a
`Task`:

```json
{"kind": "task", "id": "...", "contextId": "<from the message or new>",
 "status": {"state": "completed", "timestamp": "..."},
 "artifacts": [{"artifactId": "...", "name": "<skill>",
                "parts": [{"kind": "data", "data": {"...": "skill output"}}]}],
 "history": [{"role": "user", "messageId": "...", "parts": ["..."]}]}
```

Domain failures (not found, invalid input, policy refusal) return a task in
state `failed` whose `status.message` carries the error code and text.
Tasks complete synchronously and are not retained, so `tasks/get` is not
offered.

## Errors

| Condition | Response |
|---|---|
| No bearer credential | HTTP 401, OAuth-style body |
| Credential invalid or caller not allowed for the skill | HTTP 401 / 403 |
| Body is not JSON | JSON-RPC `-32700` |
| Not a JSON-RPC 2.0 object or bad `id` | `-32600` |
| Method other than `message/send` | `-32601` |
| Invalid params, unknown skill | `-32602` |
| No data part naming a skill | `-32005` (content type not supported) |

Every skill call increments `heal_agent_tool_calls_total{interface="a2a"}`
and writes an audit event `a2a.<skill>` with its outcome.
