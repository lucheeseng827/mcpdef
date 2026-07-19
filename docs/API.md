# MCPdef API reference

What the gateway exposes to clients, as built. Two downstream surfaces speak
the same MCP JSON-RPC 2.0 envelope: **stdio** (`mcpdef run`) and the **Streamable
HTTP listener** (`mcpdef run --http` / `mcpdef up`). Source of truth: the axum
router in [`crates/mcpdef/src/listener.rs`](../crates/mcpdef/src/listener.rs) and
the method dispatch in [`crates/mcpdef/src/gateway.rs`](../crates/mcpdef/src/gateway.rs);
regenerate this file when they change.

Only the gates that are implemented are documented here (allowlist/profiles,
RBAC, pin/rug-pull, rate limiting, upstream timeout, sandbox traps). The
Phase-3 policy-as-code engine and inline result-content scanning are **not
built** — see [ROADMAP.md](../ROADMAP.md).

## HTTP listener endpoints

Built stateless-first for the 2026-07-28 RC: one JSON-RPC message per `POST`, no
sessions. A client `Mcp-Session-Id` is ignored, never required or issued.
Request bodies are capped at **2 MiB** (`MAX_BODY_BYTES`); over the cap → `413`.

### `POST /mcp`

The single MCP endpoint. Body: one JSON-RPC 2.0 message.

Request-processing order (each step can end the request):

1. **Origin check** — a browser cross-site `Origin` not in
   `[gateway] allowed_origins` → `403 Forbidden` (text body
   `origin "…" not allowed`). No-Origin clients (CLIs, agents) and loopback
   origins always pass.
2. **Load-shedding** — with `[gateway] max_inflight` set and the cap reached →
   `503 Service Unavailable` + `Retry-After: 1`, body
   `gateway overloaded — retry shortly`. Never queued unboundedly.
3. **OAuth 2.1 bearer validation** (only when `[gateway.auth] enabled`) — a
   missing/invalid/expired token, wrong `aud`/`iss`, unknown `kid`, or a
   `none`/HMAC algorithm → `401 Unauthorized` with
   `WWW-Authenticate: Bearer resource_metadata="<PRM url>", error="invalid_token"`
   and body `missing or invalid bearer token`. The validated token's `sub`
   becomes the audit identity (`sub:<subject>`) and its scopes/roles drive RBAC.
4. **Parse** — a body that is not one JSON-RPC message → `400 Bad Request`
   (`invalid JSON-RPC: …`).
5. **Gateway dispatch** (serialized behind a mutex — one request at a time):
   - a *request* → `200 OK`, `content-type: application/json`,
     `mcp-protocol-version: 2025-11-25`, body = the JSON-RPC response;
   - a *notification* → `202 Accepted`, no body;
   - an internal gateway/transport failure → `500` (`gateway error: …`).

Example (auth off, a denied call — note it is HTTP `200` with an MCP
**tool-execution error**, so the model can self-correct):

```sh
$ curl -s -X POST http://127.0.0.1:7878/mcp \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}'
{"jsonrpc":"2.0","id":2,"result":{"content":[{"text":"MCPdef denied: tool 'delete_repo' matches deny pattern 'delete_*' for 'mock'","type":"text"}],"isError":true}}
```

### `GET /mcp`

`405 Method Not Allowed` — MCPdef does not offer a server→client SSE stream in
this phase (spec-allowed: "405 if the server does not offer one").

### `GET /.well-known/oauth-protected-resource`

The RFC 9728 Protected Resource Metadata document, so a `401`'d client can
discover the authorization server. No auth required. `404` when
`[gateway.auth]` is disabled.

```json
{ "resource": "https://mcpdef.acme.internal/mcp",
  "authorization_servers": ["https://auth.example.com"],
  "bearer_methods_supported": ["header"] }
```

## The MCP surface (both transports)

Method dispatch in `Gateway::handle_authed`:

| Method | Handling |
|---|---|
| `initialize` | Answered by the gateway itself (`protocolVersion: "2025-11-25"`, `capabilities: { tools: {} }`, `serverInfo.name: "mcpdef"`). On the stdio gateway the client's `clientInfo.name` becomes the audit identity (`agent:<name>`); on the shared HTTP listener it is deliberately ignored so one client cannot rename another's audit records. |
| `tools/list` | Aggregated across all upstreams from the `tools/list` cached at connect, then filtered: a tool the allowlist denies or whose definition drifted from its pin is **hidden**. |
| `tools/call` | The governed hot path — see the gate order below. |
| `ping` | Answered by the gateway (`{}`). |
| notifications / stray responses | Absorbed; no reply (HTTP: `202`). |
| anything else (`resources/*`, `prompts/*`, …) | Forwarded to the **primary** (first-configured) upstream un-governed but audited (`decision: "allow"`, no `tool`). With no upstream available → JSON-RPC error `-32601 no upstream available`. |

### `tools/call` gate order

Every outcome — allow or deny — appends one record to the audit ledger. A
denial is returned as a `tools/call` **result** with `isError: true` and text
`MCPdef denied: <reason>` (never a protocol error), with one exception noted
below.

| # | Gate | Audit `rule` on deny | Deny reason the client sees |
|---|---|---|---|
| 1 | Routing — is the tool exposed by any governed server? | `unknown-tool` | `no governed server exposes tool '<t>'` |
| 2 | Allowlist / profiles (`Policy::decide_tool`) | `unknown-server`, `deny-glob`, `not-on-allowlist`, `not-in-active-profile` | e.g. `tool '<t>' matches deny pattern '<p>' for '<server>'` |
| 3 | RBAC (authenticated HTTP callers only, and only when `[[role]]` is defined) | `rbac` | `no role grants '<t>' on '<server>'` |
| 4 | Pin / rug-pull (when `[gateway] pins` is set) | `rug-pull` | `tool '<t>' on '<server>' changed since it was pinned (possible rug-pull); re-approve with mcpdef pin` |
| 5 | Rate limit (after authorization, so denied floods can't drain buckets) | `rate-limited` | `global rate limit exceeded …` / `tool rate limit exceeded for '<t>' — retry shortly` |
| 6 | Dispatch + per-call timeout (`[gateway] upstream_timeout_ms`) | `upstream-timeout` | `MCPdef error: upstream '<server>' did not respond to '<t>' within <n>ms` |

Notes:

- Gate 6's client text is prefixed `MCPdef error:` (an upstream failure, not a
  policy denial); non-tool forwarded requests that time out get a JSON-RPC
  error `-32000` instead.
- A sandboxed (`wasm` / `wasm-component`) upstream sits behind the same seam
  and gates 1–6 apply identically. A sandbox **trap** (out of fuel, over the
  memory cap, wall-clock deadline) is a *transport* error, not a policy denial:
  it propagates as HTTP `500` (`gateway error: …`) or a CLI error naming the
  cause (e.g. `all fuel consumed`) — and, honestly stated, such trap-failed
  calls are **not** appended to the audit ledger today (only denials, timeouts,
  and completed calls are). A component's **egress-denied** connect is
  different again: the guest just sees its outbound socket refused (host-side
  `EgressAllow`), and whatever the guest then returns is the tool result.
- Rate-limit denials count the *attempt* — the audited deny is the 429 analog.

## The local CLI as a client

`mcpdef call <tool> --args '{…}'` drives one `tools/call` through gates 1–2 and
4–6 plus the audit ledger. RBAC (gate 3) does **not** apply: it gates
authenticated callers by token, and this local operator path carries no bearer.
On a denial the CLI prints the deny text on stderr and exits non-zero;
`--json` prints the raw JSON-RPC result instead.

## Admin listener (`[gateway.admin]`)

The OSS read-only observability server: Prometheus metrics, a small JSON API,
and an embedded status UI — a self-served view of a running gateway, on a
**separate port** from the MCP data path (`[gateway.admin] listen`, default
`127.0.0.1:7879`). Off by default. Never mutates state and never touches the
MCP wire; carries no auth of its own — see
[CONFIG.md § `[gateway.admin]`](./CONFIG.md#gatewayadmin--oss-read-only-admin--observability-server).
Source of truth: [`crates/mcpdef/src/admin.rs`](../crates/mcpdef/src/admin.rs).

| Endpoint | Returns |
|---|---|
| `GET /` | The built-in status UI (single-file, vanilla JS): status header, fronted-servers table, live audit tail, counters. |
| `GET /metrics` | Prometheus text exposition: `mcpdef_tools_calls_total{server,tool,decision,rule}`, a call-latency histogram, `mcpdef_upstreams`, `mcpdef_uptime_seconds`. Incremented at the single audit chokepoint (`Gateway::audit`) — every governed `tools/call` counted once. |
| `GET /api/v1/status` | `{ version, upstreams, uptime_seconds }`. |
| `GET /api/v1/servers` | The configured upstreams' effective (profile-applied) allow/deny, as `ServerView[]` (`id`, `transport`, `url`, `tools`, `deny`, `profile`). |
| `GET /api/v1/stats` | The metrics registry's JSON snapshot (call counts by allow/deny/rule/server). |
| `GET /api/v1/audit` | The last N audit records, newest first (`?limit=` up to 1000, default 100). Reads the same ledger file as `mcpdef audit tail`. |

## Auditability

Every decision above lands in the hash-linked ledger (`[gateway] audit`) as one
JSON line — schema and verification in
[CONFIG.md § Data formats](./CONFIG.md#data-formats--compatibility) and
[OPERATIONS.md](./OPERATIONS.md#audit-ledger-verification). Export for SIEM
ingestion with `mcpdef audit tail --format json|ocsf|cef|syslog`.
