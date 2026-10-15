# MCPdef API reference

What the gateway exposes to clients, as built. Two downstream surfaces speak
the same MCP JSON-RPC 2.0 envelope: **stdio** (`mcpdef run`) and the **Streamable
HTTP listener** (`mcpdef run --http` / `mcpdef up`). Source of truth: the axum
router in [`crates/mcpdef/src/listener.rs`](../crates/mcpdef/src/listener.rs) and
the method dispatch in [`crates/mcpdef/src/gateway.rs`](../crates/mcpdef/src/gateway.rs);
regenerate this file when they change.

The gate table below itemises the allowlist/profiles, RBAC, pin/rug-pull, rate
limit and upstream gates (a timeout, a downed upstream, a failed call, a
sandbox trap). Two more gates sit on the
same path and are configured in [CONFIG.md](./CONFIG.md): the policy-as-code
rules (`[[policy]]`, evaluated after the allowlist and audited under the rule's
own `name`) and the inline injection / secret-exfil scan (`[gateway.inspect]`,
audited as `injection` / `secret-exfil`). The rules' `transform` pass runs
first, right after the allowlist (gate 2): it rewrites a tool call's arguments,
which the `allow` and `deny` rules then judge and the upstream gets, and a rule
of it that cannot apply denies the call under its own name
([CONFIG.md](./CONFIG.md#transform-rules)). Their `result` edits run once the
upstream answers and before the scan: they edit a final result, a tool call's
or a read's, and one that cannot apply denies the call under its own name
([CONFIG.md](./CONFIG.md#edits-of-a-result)). With `[gateway.inspect] mode =
"redact"`, the scan rewrites the secrets it finds and passes the result, which
is recorded as allowed under `secret-redacted`.

## HTTP listener endpoints

Built stateless-first for the 2026-07-28 RC: one JSON-RPC message per `POST`, no
sessions. A client `Mcp-Session-Id` is ignored, never required or issued.
Request bodies are capped at **2 MiB** (`MAX_BODY_BYTES`); over the cap → `413`.
With `[gateway.tls]` on, the same endpoints are served over HTTPS
(`https://<host>:<port>/mcp`), HTTP/1.1 only, and a plain-HTTP request to the
port gets no answer: see
[CONFIG.md](./CONFIG.md#gatewaytls-and-gatewayadmintls--tls-on-mcpdefs-own-listeners).
The admin listener follows it unless `[gateway.admin.tls]` says otherwise. With
`[gateway.tls.client_auth]` on, the listener asks each client for a certificate
at the handshake, and its identity names the caller: see
[CONFIG.md § mTLS](./CONFIG.md#gatewaytlsclient_auth--mtls-client-certificates-as-identity).
Behind a `[gateway.trusted_proxy]`, the listener may serve plain HTTP, and
takes each client's certificate from the header the proxy forwards it in, on a
request from the proxy alone: see
[CONFIG.md § trusted proxy](./CONFIG.md#gatewaytrusted_proxy--a-proxy-that-terminates-tls-in-front).

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
3. **Client certificate** (only when `[gateway.tls.client_auth]` is on) — the
   certificate the client presented at the handshake, checked again first if a
   reload changed the CAs or CRLs since, and read for its identity. On a
   request from a `[gateway.trusted_proxy]`, the certificate it forwards in its
   header instead, checked whole; the proxy's own is never its client's. `403
   Forbidden`, saying why, for `a client certificate is required` (`mode =
   "required"`, a connection made before it was, or a request the proxy
   forwarded none with), `the client certificate the proxy forwarded does not
   read: <why>`, `the client certificate is refused: <why>` (revoked, not
   covered by `ca`, or expired) and `the client certificate names no identity
   MCPdef accepts: <why>`. Its identity is
   the audit identity (`cert:<identity>`) when no token names the caller, and
   [`[[identity.cert_map]]`](./CONFIG.md#gatewaytlsclient_auth--mtls-client-certificates-as-identity)
   gives it its roles.
4. **Auth** (only when `[gateway.auth] enabled`): what `methods` and `require`
   ask. A missing/invalid/expired token, one not valid yet (`nbf`), one whose
   `exp` or `nbf` is not a number, wrong `aud`/`iss`, unknown `kid`, or a
   `none`/HMAC algorithm → `401 Unauthorized` with
   `WWW-Authenticate: Bearer resource_metadata="<PRM url>", error="invalid_token"`
   and body `missing or invalid bearer token`: when `bearer` is a method and a
   token is needed, and whenever one is presented that does not check out. A
   certificate needed and missing → `403`, `a client certificate is required`.
   The validated token's `sub` becomes the audit identity (`sub:<subject>`),
   over a certificate's, which is then the record's `actor`, and its
   scopes/roles drive RBAC. Where `key` is a method, a bearer token that
   begins `mcpdef_key_` is a client key the gateway issued: one a `[[key]]`
   keeps the SHA-256 of names its caller `key:<name>`, holding that key's
   roles; any other is refused `401`, as is another kind of token where keys
   alone are taken (with `WWW-Authenticate: Bearer`, there being no metadata
   to point at).
5. **Parse** — a body that is not one JSON-RPC message → `400 Bad Request`
   (`invalid JSON-RPC: …`).
6. **Gateway dispatch** (concurrently: a slow upstream holds up only the calls
   sent to it), each record carrying the client's address as `peer`:
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
this phase (spec-allowed: "405 if the server does not offer one"). So an HTTP
client is sent no `notifications/tools/list_changed`, and sees a change to the
tools on its next `tools/list`.

### `GET /.well-known/oauth-protected-resource`

The RFC 9728 Protected Resource Metadata document, so a `401`'d client can
discover the authorization server. No auth required. `404` when
`[gateway.auth]` takes no bearer token: disabled, or `methods = ["mtls"]`.

```json
{ "resource": "https://mcpdef.acme.internal/mcp",
  "authorization_servers": ["https://auth.example.com"],
  "bearer_methods_supported": ["header"] }
```

## The MCP surface (both transports)

Method dispatch in `Gateway::handle_from` (`handle_authed` for a caller a
token alone names):

| Method | Handling |
|---|---|
| `initialize` | Answered by the gateway itself (`protocolVersion: "2025-11-25"`, `capabilities: { tools: {} }`, plus `resources: {}` when some server's `resources` or `resource_templates` exposes any, `prompts: {}` when some server's `prompts` does, and `completions: {}` when there is a prompt or a template to complete, `serverInfo.name: "mcpdef"`). On the stdio gateway the client's `clientInfo.name` becomes the audit identity (`agent:<name>`); on the shared HTTP listener it is deliberately ignored so one client cannot rename another's audit records. Over stdio, `tools` is `{ listChanged: true }`: from the client's `notifications/initialized` on, MCPdef sends it `notifications/tools/list_changed` each time what `tools/list` shows changes ([WIRE.md](./WIRE.md#status)). |
| `tools/list` | Aggregated across all upstreams from each one's `tools/list`, every page of it, taken when it opens and again each time it sends `notifications/tools/list_changed` ([OPERATIONS.md](./OPERATIONS.md#when-an-upstreams-tools-change)), then filtered: a tool the allowlist denies, whose definition drifted from its pin, or whose description tripped the scanner is **hidden**. Each name is listed once: a name more than one server offers is listed from the first in config order whose allowlist takes it, the server a call to it goes to (see [CONFIG.md § Tool names](./CONFIG.md#tool-names)). With `[gateway] tool_namespace = "prefix"` each is listed as `<prefix>__<name>`. Each tool names its server in `_meta["mcpdef/server"]`, over any value the server set there itself; the rest of its `_meta`, and of the tool, is as the server sent it, its `name` aside when prefixed. The pin hashes the server's definition, which this key is not part of. |
| `tools/call` | The governed hot path — see the gate order below. |
| `ping` | Answered by the gateway (`{}`). |
| `resources/list`, `resources/templates/list` | Every server whose `resources` (for URIs) or `resource_templates` (for templates) exposes any is asked at once, its pages followed. What each allowlist takes is answered as **one page**, in config order, each entry naming its server in `_meta["mcpdef/server"]` and each URI in [normal form](./CONFIG.md#resource-uri-patterns). A URI or template two servers show is listed once, from the first. A server that fails to answer adds nothing. A `cursor` from the client gets `-32602`: the gateway never gives one. Not audited, as `tools/list` is not. |
| `resources/read` | The URI is put in normal form, then routed: to the server that listed it, else the one whose tool result linked it (`resource_link`), else the first in config order whose `resources` takes it. It is judged by the gates a `tools/call` meets, in their order: that server's allowlist (`resource-not-allowed`), the `[[policy]]` rules (by `uris`; the rule's name), RBAC for an authenticated caller (`resource_grants`; `rbac`), and the rate limit (`rate-limited`). It is sent upstream in normal form, and what comes back is scanned (`injection`, `secret-exfil`). A refused or denied read gets JSON-RPC error `-32002 MCPdef denied: <reason>`, and a scanned-out one `-32002 MCPdef blocked: <reason>`. An `InputRequiredResult` is passed back to a 2026-07-28 client that can answer it, with no caching hints, and refused otherwise with `-32000 MCPdef denied: <reason>`, both audited under `input-required` ([WIRE.md](./WIRE.md#status)). Every read is audited with its `uri`, allowed or denied (`uri-refused` for a URI refused outright). |
| `resources/subscribe`, `resources/unsubscribe` | `-32601`, audited under `method-not-found`: the gateway has no stream to send updates on, and does not advertise `subscribe`. |
| `prompts/list` | Every server whose `prompts` exposes any is asked at once, its pages followed. What each allowlist takes is answered as **one page**, in config order, each entry naming its server in `_meta["mcpdef/server"]`. A name two servers show is listed once, from the first. A `cursor` from the client gets `-32602`. Not audited. |
| `prompts/get` | Routed by name: to the server that listed it, else the first in config order whose `prompts` takes it. It is judged by the gates a `tools/call` meets, in their order: that server's allowlist (`prompt-not-allowed`), the `[[policy]]` rules (by `prompts` and `args`; the rule's name), RBAC for an authenticated caller (`prompt_grants`; `rbac`), and the rate limit (`rate-limited`). The request is sent upstream as the client wrote it, and what comes back is scanned (`injection`, `secret-exfil`). A denied get gets JSON-RPC error `-32602 MCPdef denied: <reason>`, the error for a prompt name the server does not know, and a scanned-out one `-32602 MCPdef blocked: <reason>`. An `InputRequiredResult` is passed back to a 2026-07-28 client that can answer it, and refused otherwise with `-32000 MCPdef denied: <reason>`, both audited under `input-required`. Every get is audited with the prompt's name in `tool`, allowed or denied. |
| `completion/complete` | Routed by its `ref`: a `ref/prompt` as a `prompts/get` of that name is, a `ref/resource` to the server that listed the template, else the first whose `resource_templates` shows it. A prompt's completion meets a get's gates, its `context.arguments` being what the `[[policy]]` rules judge. A template's meets the template allowlist (`template-not-allowed`), the rules that name no kind, RBAC for an authenticated caller (a role granting any resource on that server; `rbac`), and the server's completions bucket (`rate-limited`). What comes back is scanned. A denied completion gets `-32602 MCPdef denied: <reason>`, a scanned-out one `-32602 MCPdef blocked: <reason>`, and one with no usable `ref` `-32602`. Every routed one is audited with the prompt's name in `tool` or the template in `uri`. |
| notifications / stray responses | Absorbed; no reply (HTTP: `202`). Over stdio, `notifications/initialized` starts the `notifications/tools/list_changed` the client is sent. |
| anything else (`logging/setLevel`, `tasks/*`, `subscriptions/listen`, …) | Refused: JSON-RPC error `-32601 MCPdef denied: method '<name>' is not one MCPdef serves: …`, audited as a deny under `method-not-found` with the method's name, kept to 128 bytes. Nothing is sent upstream. On the modern wire the reply is HTTP `404`, as the revision requires. |

### `tools/call` gate order

Every outcome — allow or deny — appends one record to the audit ledger. A
denial is returned as a `tools/call` **result** with `isError: true` and text
`MCPdef denied: <reason>` (never a protocol error), with one exception noted
below.

| # | Gate | Audit `rule` on deny | Deny reason the client sees |
|---|---|---|---|
| 1 | Routing — is the tool listed by a running server, or named in the `tools` of one that has not started? A name goes to the first server in config order whose allowlist takes it, else the first that lists it. With prefixes, `<prefix>__<name>` goes to that prefix's server, and from here on is `<name>`: each gate, the audit record and the upstream see the tool as its server names it. | `unknown-tool` | `no governed server exposes tool '<t>'` |
| 2 | Allowlist / profiles (`Policy::decide_tool`) | `unknown-server`, `deny-glob`, `not-on-allowlist`, `not-in-active-profile` | e.g. `tool '<t>' matches deny pattern '<p>' for '<server>'` |
| 3 | RBAC (HTTP callers a token or a client certificate names, and only when `[[role]]` is defined) | `rbac` | `no role grants '<t>' on '<server>'` |
| 4 | Pin / rug-pull (when `[gateway] pins` is set) | `rug-pull` | `tool '<t>' on '<server>' changed since it was pinned (possible rug-pull); re-approve with mcpdef pin` |
| 5 | Rate limit (after authorization, so denied floods can't drain buckets), a bucket per server and tool | `rate-limited` | `global rate limit exceeded …` / `tool rate limit exceeded for '<t>' — retry shortly` |
| 6 | Dispatch + per-call timeout (`[gateway] upstream_timeout_ms`) | `upstream-timeout` | `MCPdef error: upstream '<server>' did not respond to '<t>' within <n>ms` |
| 6 | Dispatch to an upstream that is down (it did not start, or went down and is restarting) | `upstream-down` | `MCPdef error: upstream '<server>' is down (<why>); MCPdef is restarting it — retry shortly` |
| 6 | Dispatch the upstream could not take or answer (an HTTP error status with no JSON-RPC body, a sandbox trap) | `upstream-error` | `MCPdef error: upstream '<server>' failed the call: <why>` |
| 6 | Dispatch an HTTP upstream refused with `401`, after its `[server.auth]` secret was read again once, or a fresh `oauth2` token fetched | `upstream-auth-failed` | `MCPdef error: upstream '<server>' refused MCPdef's credentials: <url> answered 401 Unauthorized` |
| 6 | Dispatch with no credentials to send: an `oauth2` token endpoint gave no token, or a `[server.auth]` secret could not be read. Nothing is sent upstream | `credentials-unavailable` | `MCPdef error: no credentials for upstream '<server>': <why>`, e.g. `token endpoint <url> answered 401 Unauthorized: invalid_client` |
| 7 | Result transforms, on a final result: a `transform` rule's `result` edit cannot apply (a `mask` of what is not a string, a `redact` of a secret in a key, an edit the tool's `outputSchema` may not allow) | the rule's `name` | `transform rule '<r>' could not apply to the result of '<t>' on '<server>': <why>` |
| 8 | Inspect (`[gateway.inspect]`): a finding in the result under `enforce`; under `redact`, an injection, a secret in an interim result, or one it cannot redact (a secret it can is rewritten, and the call allowed under `secret-redacted`) | `injection`, `secret-exfil` | `MCPdef blocked: tool '<t>' on '<server>': result matched <secret-exfil\|injection> rule '<id>'`, then, for a secret not redacted, `, which MCPdef could not redact: <why>` |
| 9 | The answer is an `InputRequiredResult` the client cannot answer: it speaks 2025-11-25, or the result asks for what it did not declare, or breaks the revision's rules for one ([WIRE.md](./WIRE.md#status)) | `input-required` | `tool '<t>' on '<server>' asked for input, which MCPdef passes on only to a 2026-07-28 client`, or `… asked for input the client cannot give: <why>` |

Notes:

- Gate 6's client text is prefixed `MCPdef error:` (an upstream failure, not a
  policy denial); a read, a prompt get or a completion whose upstream times
  out, is down or fails gets JSON-RPC error `-32000 MCPdef error: …` instead,
  audited under the same rules.
- A URL in gate 6's text shows none of the secrets it holds: its user name and
  password, a path segment with a known credential's shape, and a query or
  fragment parameter that is a secret by its name or its shape are shown as
  `***`, as in `http://***:***@mcp.internal/mcp?api_key=***`. So does every
  other place MCPdef shows a URL: its log, the error a command exits with,
  `/api/v1/servers`, `servers list`, `egress show` and `validate`.
- A sandboxed (`wasm` / `wasm-component`) upstream sits behind the same seam
  and gates 1–6 apply identically. A sandbox **trap** (out of fuel, over the
  memory cap, wall-clock deadline) fails that one call as `upstream-error`,
  with the cause in the text (e.g. `all fuel consumed`), and the sandbox stays
  up for the next. A component's **egress-denied** connect is
  different again: the guest just sees its outbound socket refused (host-side
  `EgressAllow`), and whatever the guest then returns is the tool result.
- Rate-limit denials count the *attempt* — the audited deny is the 429 analog.
- An `InputRequiredResult` a 2026-07-28 client can answer is passed back as it
  came, and recorded as allowed, with `rule = "input-required"`. The client's
  retry, with its `inputResponses` and the `requestState`, is a `tools/call` of
  its own: it meets every gate again, spends a rate-limit token of its own,
  and gets a record of its own.
- A request to a 2026-07-28 upstream declares the `elicitation`, `sampling`
  and `roots` capabilities of the 2026-07-28 client that sent it, and no
  others. From any other client it declares none.

## The local CLI as a client

`mcpdef call <tool> --args '{…}'` drives one `tools/call` through gates 1–2 and
4–6 plus the audit ledger. RBAC (gate 3) does **not** apply: it gates
authenticated callers by token, and this local operator path carries no bearer.
On a denial the CLI prints the deny text on stderr and exits non-zero;
`--json` prints the raw JSON-RPC result instead.

## Admin listener (`[gateway.admin]`)

The console, its JSON API, and Prometheus metrics, on a **separate port** from
the MCP data path (`[gateway.admin] listen`, default `127.0.0.1:7879`). Off by
default. It never touches the MCP wire. Who may use it, and what each request
passes first — its Host, its origin when it changes something, the caller's
console role — is in
[CONFIG.md § `[gateway.admin]`](./CONFIG.md#gatewayadmin--the-admin-listener-console-api-and-metrics).
Every route but the console's files, `GET /api/v1/session`, `GET /health`
and the sign-in routes needs `console:viewer`. A refusal is an RFC 9457
`application/problem+json` document, `{ type, title, status, detail }`: `401`
for a caller who has not signed in where the console signs people in
([`[gateway.admin.oidc]`](./CONFIG.md#gatewayadminoidc--signing-people-in-to-the-console)),
`detail` saying where to, and for a bearer token refused (`Bearer token
refused`, with `WWW-Authenticate: Bearer error="invalid_token"`); `503` while
the identity provider whose tokens it takes cannot be found; `403` for a
caller without the role a route needs,
or whose client certificate is refused (`detail` says why, as `POST /mcp`
step 3 does), `421` for a Host it does not answer to, `415` for a change that
sends no JSON, `404` for no such route, `405` for a method a route does not
take (its `Allow` header says which it does).
Source of truth: [`crates/mcpdef/src/admin.rs`](../crates/mcpdef/src/admin.rs).

Automation sends a bearer token, `Authorization: Bearer <token>`, where the
admin API takes one: a token the identity provider issued for
`[gateway.admin.oidc] api_audience` (`mcpdef:admin:read` reads,
`mcpdef:admin:write` acts too), or the break-glass token of
`[gateway.admin.break_glass]` (`console:admin`, each request recorded before
it is served, as an `admin` record by actor `break-glass` whose `uri` is the
request's method and path). A request with no browser's headers needs no
origin. See [CONFIG.md § `[gateway.admin]`](./CONFIG.md#gatewayadmin--the-admin-listener-console-api-and-metrics).

| Endpoint | Returns |
|---|---|
| `GET /` | The console's page (`console/`, built into the `mcpdef-console` crate). For anyone: it holds no data, and asks the API below for what it shows. `no-cache`, with an entity tag. A build without the default `console` feature serves the built-in status page instead (vanilla JS: status header, fronted-servers table with each one's health and, for one sent credentials, how they fare, live audit tail, counters), with its styles and script at `GET /ui.css` and `GET /ui.js`. |
| `GET /assets/*` | The console's files: scripts, styles, fonts. Each in the encoding the client accepts of those it has, brotli then gzip, with `Vary: accept-encoding`; with an entity tag, `304` to a client that holds it; and, as each name changes with its content, `Cache-Control: public, max-age=31536000, immutable`. For anyone. |
| `POST /api/v1/reload` | Read the config again and apply it, as `SIGHUP` does ([OPERATIONS.md § Reloading the config](./OPERATIONS.md#reloading-the-config)). Needs `console:operator`. Applied: `200`, `{ outcome: "applied", added, removed, reconnected, failed: [{ server, error }] }`. Refused, the config in effect still serving: `409`, a problem document with `outcome: "refused"`, `rule` (`invalid-config` or `restart-required`) and `reasons`. The reload's record names the caller as its `actor`, and the address it called from as its `peer`. A caller without the role is refused `403`, recorded as an admin action refused under `console-role`. |
| `POST /api/v1/servers/{id}/restart` | Needs `console:operator`. The server's keeper opens it again now, its backoff reset: a stdio server is started as a new process. The connection it holds serves until the new one opens, and keeps serving if that fails. `202` once asked, `{ restarting }`: `/api/v1/servers` shows how it went (`restarts` counts it). `409` for a server the gateway does not keep running, or one opening already; `404` for an id no server has. Recorded as an admin action, `method = "restart"`. |
| `POST /api/v1/servers/{id}/test` | Needs `console:operator`. A `ping` over the server's live connection, given `[gateway] upstream_timeout_ms` (10 s without it) to answer: `{ ok, latency_ms, error }`: `ok: false` with `error` saying why when it answers with an error, does not answer in time, or has no connection yet. Recorded as `method = "test"`. `404` for no such server. |
| `POST /api/v1/servers/{id}/pins` | Needs `console:operator`. Approve drift: `{ tools: { name: hash } }` names each drifted tool approved with the `hash` of the definition looked at, as `GET /api/v1/servers/{id}/tools` gives it. Those definitions are taken as their pins, recorded in the pin store and saved, and the tools are served again from the next call, as `mcpdef pin` and a reload would. When one offers another definition now than its hash names, nothing is approved: what changed since it was looked at is not served unseen. `{ approved }`; one record per tool, `method = "approve-drift"` with the tool. A reload or a restart after it reads the saved store. `400` with no tool named; `409` when pinning is off, the server has no connection yet, a named tool has not drifted, or one offers another definition now than its hash names. |
| `GET /api/v1/session` | Who the caller is: `{ actor, role, roles, open }`. `actor` is `local` (anyone on this machine, when nothing signs callers in), `anonymous` (with `allow_unauthenticated`, or not signed in where the console signs people in), `cert:<identity>`, `user:<subject>` (signed in), `token:<subject>` (a bearer token the identity provider issued for `api_audience`) or `break-glass`; `role` the highest console role it holds, or `null`; `roles` each it holds; `open` whether nothing signs callers in. One who could sign in and has not also has `sign_in`, where to: `/login`. One signed in also has `sign_out`, `/logout`, and `name`, the name their identity provider gave them, or `null`. For anyone, so that a caller with no role can see what it would need. |
| `GET /login` | Sign in: off to the identity provider (`302`), with a state, a nonce and a PKCE challenge, the sign-in sealed in a ten-minute `__Host-mcpdef-login` cookie. `?then=` is the console page to come back to, a path on this listener (anything else comes back to `/`). `503`, a page saying why, while the provider cannot be found; `404` where nothing signs people in. For anyone. |
| `GET /callback` | Where the provider sends people back, as [CONFIG.md § `[gateway.admin.oidc]`](./CONFIG.md#gatewayadminoidc--signing-people-in-to-the-console) says it checks them. Signed in: `303` back to the page they started from, the session in `__Host-mcpdef-session`. Given no console role: `403`, a page of the claims MCPdef received, for them alone. Refused: `400`, a page saying why. Each answer clears the sign-in's cookie, and each is recorded. For anyone. |
| `POST /logout` | Sign out: the session refused from then on, its cookie cleared, and `{ redirect }`, where the browser goes next: the provider's `end_session_endpoint`, with `client_id` and `post_logout_redirect_uri` (`<public_url>/`), or `/`. Recorded as `sign-out`. Only from the console's own origin, as every change is. |
| `GET /metrics` | Prometheus text exposition: `mcpdef_tools_calls_total{server,tool,decision,rule}`, a call-latency histogram, `mcpdef_upstreams`, `mcpdef_uptime_seconds`. Incremented at the single audit chokepoint (`Gateway::audit`) — every governed `tools/call` counted once. Plus each upstream's health when scraped: `mcpdef_upstream_up{server}` (1 while open, 0 while starting or down) and `mcpdef_upstream_restarts_total{server}`. And for each HTTPS upstream that has opened, `mcpdef_upstream_cert_expiry_seconds{server}`: when the certificate its server presented last expires, as a Unix time. It is absent, HELP and TYPE included, while no upstream has shown a certificate. `mcpdef_upstream_auth_failures_total{server}` counts, for every upstream, the times it refused MCPdef's credentials or MCPdef had none to send it: the calls audited as `upstream-auth-failed` and `credentials-unavailable`, and the openings that failed so. `mcpdef_credential_expiry_seconds{server,credential}` is when a credential MCPdef sends an upstream expires, as a Unix time: `credential="token"` for an `oauth2` token, once one is fetched, and `credential="client_cert"` for the certificate an HTTPS upstream's connection presents (`client_cert`). It is absent, HELP and TYPE included, while no credential says when it expires. |
| `GET /health` | `{ status: "ok" }` while the listener answers: for a probe, so for anyone, and it says nothing else. |
| `GET /api/v1/info` | What this gateway is and how it is set up: `{ version, wire, revisions, listen, mcp: { tls, client_auth }, admin: { tls, client_auth }, auth: { enabled, methods, issuer, resource, keys, audiences }, inspect, pins, strict, audit: { records, head }, upstreams, upstreams_up, uptime_seconds }`, and, from `mcpdef run`, `serving: { mcp, admin }`, the addresses it took (`mcp` is `stdio` for a stdio gateway). `wire` is `[gateway] wire`, and `revisions` the MCP revisions it answers for. `admin` is what the admin listener serves: `[gateway.admin.tls]`, or `[gateway.tls]` where it sets none. `issuer` and `resource` are masked as `url` is in `/api/v1/servers`; `keys` says where the token keys come from (`jwks`, `jwks_uri` or `discovery`), never the keys; `audiences` are those a token may carry besides `resource`, masked as it is. `audit` is the ledger's length and head, as this gateway wrote them. |
| `GET /api/v1/metrics` | The calls since the gateway started, for the console: `{ calls, allow, deny, rate_limited, inspect_blocked, deny_by_rule, latency_ms: { p50, p95, p99, mean }, top_tools: [{ server, tool, calls, deny }], trend: [{ minute, allow, deny }], uptime_seconds }`. `inspect_blocked` counts the denials under `injection` and `secret-exfil`. The percentiles are estimated from the latency histogram as Prometheus's `histogram_quantile` does, and are `null` with no calls. `top_tools` are the ten most called; `trend` is the last 60 minutes, oldest first, each `minute` the Unix time in milliseconds it starts. |
| `GET /api/v1/status` | `{ version, upstreams, upstreams_up, uptime_seconds }`. |
| `GET /api/v1/servers` | The configured upstreams' effective (profile-applied) allow/deny (`id`, `transport`, `url`, `tools`, `deny`, `profile`), what each exposes of its resources and prompts (`resources`, `resource_templates`, `prompts`, each absent when it exposes none), how many of its tools are hidden for drifting from their pins (`drifted`) and for tripping the scanner (`poisoned`), `url` with any secret it holds shown as `***` (see the notes on gate 6), and `env`: for each variable its `[server.env]` sets, by name, where the value comes from, `{ scheme, from }`, never the value. `scheme` is `literal`, `env`, `file` or `exec`, and `from` is `(literal)`, `$NAME`, the file's path or `(exec PROGRAM)`. A server with `[server.auth]` also has `auth`: `{ kind, <field>: { scheme, from } }`, where `<field>` is `token`, `value`, `password` or `client_secret`, with a `header` kind's `name` and an `oauth2` kind's `token_url`, masked as `url` is, never the secret, a `basic` kind's user name or an `oauth2` client id. Each with its live `health` (`starting`, `up`, `degraded` or `down`), `restarts`, and `last_error` (`{ message, at_unix_ms }` or `null`). A server with `[server.auth]` also has `credential`, how the credentials MCPdef sends it fare: `last_ok` (`{ at_unix_ms }` or `null`), the last time the upstream answered a request that carried them; `last_error` (`{ message, at_unix_ms }` or `null`), the last time it refused them or MCPdef had none to send, and why; and `expires_at`, when the credentials it is sent now expire, in RFC 3339: an `oauth2` token's, from its `expires_in`, and `null` for another kind, until a token is fetched, and after a fetch failed. A token is fetched when a request needs one, so an upstream no one calls holds one that has expired. An HTTPS upstream that has opened also has `tls`: `{ verify, fingerprint, not_after }`, and `client_not_after` when its connection presents a certificate (`client_cert`): when that certificate expires, in RFC 3339. `verify` is how its certificate was checked: `ca` (its chain, name and dates), `pin` (its key alone, `pin_sha256`) or `disabled` (`insecure_skip_verify`). `fingerprint` is the SHA-256 of the certificate its server presented last, in the colon-separated hex `openssl x509 -fingerprint -sha256` prints, and `not_after` is when that certificate expires, in RFC 3339. A plain-HTTP, stdio or sandboxed upstream has no `tls` key, and nor does one that has not opened. A server that offers a tool name another server offers too also has `tool_collisions`: `[{ tool, servers }]`, the name as `tools/list` gives it and every server that offers it, in config order, the first being the one it is listed from and called on. Each server the gateway runs also has `listing`, what it adds to `tools/list`: `{ offered, listed, bytes }`. `offered` is how many tools its connection lists, none until it opens; `listed` how many of them `tools/list` shows, after the allowlist, the active profile, the pins and the scanner, less a name listed from another server; and `bytes` what those take up in a `tools/list` answer, each entry as it is sent, compact, by the name it is listed by and with its `_meta`, the commas between entries not counted. Every agent that lists the tools reads those bytes into its context; `bytes ÷ 4` estimates the tokens, as `mcpdef tools list --cost` prints. It follows the live list, so a re-list, a reload or a restart changes it. As of the last config reload, like `upstreams` in `/api/v1/status` and `mcpdef_upstreams`. |
| `GET /api/v1/servers/{id}` | One server, as `/api/v1/servers` shows it; `404` for an id no server has. |
| `GET /api/v1/servers/{id}/tools` | Each tool the server's connection offers, in the order it lists them: `[{ name, listed_as, hidden, pin, hash, description }]`. `listed_as` is the name `tools/list` gives it (with the server's prefix under `tool_namespace = "prefix"`). `hidden` is why `tools/list` does not show it, `null` when it does: `allowlist` (the server's allowlist or profile), `drift` (its definition changed since it was pinned), `inspect` (its definition tripped the scanner), `x-mcp-header` or `collision` (another server's tool of that name is listed). `pin` is `off` with no pin store, else `pinned` or `drift`. `hash` is the hex SHA-256 of the definition it offers now, over the fields a pin governs: what approving its drift names. Empty until the connection opens; `404` for an id no server has. |
| `GET /api/v1/policy/rules` | The `[[policy]]` rules, in the order they run: `{ transform, admission }`, the transform rules, which rewrite a call's arguments before the others judge it and a result after, then the allow and deny rules, the first that matches deciding. Each with its `name`, `effect`, the globs it matches (`agents`, `servers`, `tools`, `uris`, `prompts`, `null` for any), `args` (`[{ path, op, value }]`), and a transform's `set_args` (`[{ path, op }]`, a clamp's `min` and `max` too; never a value it sets), `on_error` and `result` (`[{ op, arg }]`). |
| `GET /api/v1/policy/rbac` | `{ roles: [{ name, grants, resource_grants, prompt_grants }], cert_map: [{ identity, roles }] }`: the `[[role]]`s and `[[identity.cert_map]]`. |
| `GET /api/v1/policy/profiles` | `{ active, profiles: [{ name, tools, deny }] }`: `[gateway] profile`, and each `[profile.<name>]`, by name. |
| `GET /api/v1/inspect/config` | `{ mode, injection_phrases, secret_substrings }`: `[gateway.inspect]`, with how many secret substrings it has, never what they are. |
| `GET /api/v1/inspect/findings` | What inspect found lately, newest first, the last 256: `[{ ts_unix_ms, category, rule, surface, server, target, outcome, matched }]`. `category` is `injection` or `secret`; `rule` the pack's rule; `surface` where it was found (`tool-description`, when a connection opens or its tools change, `tool-result`, `resource`, `prompt` or `completion`); `target` the tool, prompt or completion's target, or the resource's URI, masked as `url` is; `outcome` `blocked`, `redacted` or `warned`. A finding keeps no text it was found in: for an injection, `matched` is the words that matched, which are the attack; a secret's has none. Kept in memory: a restart starts the list again. |
| `GET /api/v1/config` | Needs `console:admin`. The config file the gateway was started from, as it is on disk now, so a change no reload has applied yet shows here first: `{ path, text, redacted }`, `redacted` listing where a secret was masked as `***` (`/server/0/env/API_KEY`, say). Masked: each secret written in the file (listener and client keys, `[server.auth]` secrets, `[server.env]` values, a transform's `set` and `default` values, `[gateway.inspect] secret_substrings`), the credentials in its URLs, and anything anywhere in it, comments included, with a credential's shape. A value that says where a secret comes from (`{ env = … }`, `{ file = … }`, `{ exec = … }`) is kept: it is not the secret. A file that does not parse is `500`, saying at which line and nothing of it. |
| `POST /api/v1/config/validate` | Needs `console:admin`. `{ text }`, a config, parsed and checked as `mcpdef validate` checks one, never applied: `{ valid, problems }`. Nothing the config names is read or run, no file and no command, so the warnings `mcpdef validate` prints about files (a key others can read) are not among the problems. |
| `GET /api/v1/tls` | Each listener's TLS as the config sets it: `{ mcp, admin, local_ca, upstreams }`, a listener as `{ mode, hostnames, certificate, client_auth: { mode, identity, trust_domains, ca, crl } }` (`admin` is `null` when the admin listener is off), each certificate as `{ path, subject, names, issuer, not_after, sha256 }` (or `{ path, error }`), read from the file the config names, or for `self-signed` the one in `state_dir`; `local_ca` is the local CA's certificate, when there is one; and `upstreams` each HTTPS upstream's `tls` as `/api/v1/servers` shows it, once its connection has opened. |
| `GET /api/v1/credentials` | How the credentials MCPdef sends each upstream with `[server.auth]` fare: `[{ server, kind, credential, auth_failures }]`, `credential` as `/api/v1/servers` shows it. Never the secret. |
| `GET /api/v1/clients/{client}/snippet` | What `mcpdef connect <client>` prints for this gateway: `{ client, name, url, text, report }`, `text` the entry in the client's own format. `client` is one of `claude-code`, `claude-desktop`, `cursor`, `vscode`, `codex` and `generic`; another is `404`. `?name=` names the entry (`mcpdef`), and `?token_env=` the variable a client that sends its own bearer token reads it from. `422` when the entry cannot be made as asked: a `?token_env=` for Claude Desktop, whose `mcpdef bridge` entry reads its token from a file. |
| `GET /api/v1/ca.pem` | The local CA's certificate (`application/x-pem-file`), for a client to trust: each certificate in the CA's file, written out again from its DER, so nothing else in the file, a key above all, goes out. `404` when there is no local CA. |
| `GET /api/v1/identity` | Needs `console:admin`. Who the gateway takes its callers to be: `{ mcp: { bearer: { enabled, methods, issuer, resource, audiences, discovery }, client_certificates, identity }, console: { signs_in, oidc, break_glass, provider, allow_unauthenticated, public_url, hosts, roles }, model: { subject_claim, roles_claims, role_map }, cert_map, keys, roles }`. `signs_in` lists how the console signs people in: `oidc`, `certificate` where the admin listener requires one, both, or neither. `oidc` is `[gateway.admin.oidc]`, `{ issuer, client_id, client_secret, client_auth, scopes, userinfo, api_audience, redirect_uri }`, or `null`: `client_secret` says whether one is set, never what it is. `break_glass` says whether a break-glass token is set. `provider` says whether the console's identity provider was found, as the gateway last looked for it: `{ found: true, issuer, sends_iss, signs_out, userinfo }`, or `{ found: false, error }`; `null` where nothing signs people in. `model` is how `[identity]` reads a token's claims. `keys` lists the client keys the gateway issued, `{ name, roles }`, never their digests. |
| `GET /api/v1/stats` | The metrics registry's JSON snapshot (call counts by allow/deny/rule/server). |
| `GET /api/v1/audit` | A page of the ledger's records, newest first: `?cursor=` (empty for the first page) and `limit` (1 to 500, default 50), with any of the filters `decision` (`allow` or `deny`), `server`, `tool`, `agent`, `rule`, `kind` (`call` for a governed call, `admin`, `reload`, `upstream`), `since` and `until` (milliseconds since the epoch; `since` inclusive, `until` not), all of which a record must match. Answers `{ records, next_cursor }`: hand `next_cursor` back for the next, older page; `null` when no older record can match. A page reads only its own records, from where the last one stopped; a filtered page reads at most 100,000 looking for matches and, if it finds too few, stops short with a cursor to go on from. `since` stops at the first record older than it, so a record written after the clock was set back can be missed. A cursor from another ledger, or from this one before it was cut short or replaced, is refused `400`. With `limit` alone (up to 1000, default 100), or nothing, the newest records as a bare list, as before. |
| `GET /api/v1/audit/{seq}` | One record, by its `seq`; `404` if the ledger holds none. |
| `GET /api/v1/audit/verify` | The hash chain checked from the first record, as `mcpdef audit verify` does, and against a point the file must still hold: how far this gateway has written, or, given `head` and `count` both, a seal kept elsewhere. `{ ok, records, head, broken_at, ambiguous, against: { kind, records, head }, reason }`: `kind` is `written` or `seal`; `broken_at` the first record broken, or the first known to be missing or changed; `reason` says which, or is `null`. A ledger cut short or replaced since that point fails though its own chain holds, and one that has grown since passes. One verify runs at a time. |
| `GET /api/v1/audit/export` | `?format=json\|ocsf\|cef\|syslog`, with the filters above: every record they take, first to last, one line each as `mcpdef audit tail --format` writes it, streamed as it is read, as an attachment (`application/x-ndjson` for `json` and `ocsf`, `text/plain` for the others). Four exports at a time; a fifth is `503`. |
| `GET /api/v1/audit/stream` | Server-Sent Events: each record as it is appended, its `id` the record's `seq` and its `data` the record. It starts after `Last-Event-ID`, else after `?after=`, else at the end of the ledger, and takes the filters above; a record they pass over still moves the `id` on, in an event with no data, so a browser that comes back resumes after it. The listener ends a stream after 10 minutes, and the browser comes back at once, its caller checked again. 64 streams at a time; one more is `503`. |

## Auditability

Every decision above lands in the hash-linked ledger (`[gateway] audit`) as one
JSON line — schema and verification in
[CONFIG.md § Data formats](./CONFIG.md#data-formats--compatibility) and
[OPERATIONS.md](./OPERATIONS.md#audit-ledger-verification). Export for SIEM
ingestion with `mcpdef audit tail --format json|ocsf|cef|syslog`, or from the
admin API's `GET /api/v1/audit/export`.
