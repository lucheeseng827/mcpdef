# MCPdef configuration reference

Every knob MCPdef reads, in one place. MCPdef is configured by **one TOML file**
(default `mcpdef.toml`, overridable per command with `--config`) plus a handful of
CLI flags. **MCPdef reads no environment variables** — the only env interaction is
the variables *it injects* into stdio upstreams via `[server.env]` (the token
broker). Source of truth: the serde structs in
[`crates/mcpdef/src/config.rs`](../crates/mcpdef/src/config.rs) and the clap derive
in [`crates/mcpdef/src/main.rs`](../crates/mcpdef/src/main.rs); regenerate this file
when they change. A commented, runnable example is
[`mcpdef.example.toml`](../mcpdef.example.toml).

`mcpdef validate --config <file>` checks everything below structurally (unknown
transport, missing `command`/`url`/`wasm`, dead rate-limit buckets, incomplete
`[gateway.auth]`, unknown profile references, malformed egress entries) without
starting the gateway.

## `[gateway]`

Struct: `GatewayConfig` (`config.rs`).

| Key | Type | Default | What it does |
|---|---|---|---|
| `listen` | string `host:port` | `"127.0.0.1:7878"` | Bind address for the downstream Streamable HTTP listener (`mcpdef run --http` / `mcpdef up`). Loopback by default — binding wider is a deliberate act. |
| `audit` | path | `"./mcpdef-audit/audit.log"` | The append-only, hash-linked audit ledger (JSONL, one record per governed call). Parent dirs are created on first run. |
| `policy` | path | unset | **Reserved** for the Phase-3 policy-as-code directory. Parsed but unused today. |
| `pins` | path | unset (pinning off) | Tool-def pin store (TOML). When set, MCPdef pins each upstream tool's definition (trust-on-first-use) and denies + audits a `rug-pull` if a definition later drifts. Managed with `mcpdef pin` / `mcpdef diff-tools`. |
| `profile` | string | unset | The active gateway profile — a `[profile.<name>]` layered over **every** server, scoping the whole tool surface an agent sees. Overridable at launch with `--profile`. |
| `upstream_timeout_ms` | int (ms) | unset / `0` = no timeout | Per-call upstream response bound. A wedged upstream is failed as an audited `upstream-timeout` instead of hanging the gateway; also bounds the connect handshake. |
| `allowed_origins` | array of strings | `[]` | Extra `Origin` values accepted on the HTTP listener beyond loopback (`localhost`/`127.0.0.1`/`::1`, any port, always allowed; requests with no Origin always pass). Anything else → `403` (DNS-rebinding defense). |
| `max_inflight` | int | unset = unlimited | Max concurrent in-flight HTTP requests; excess is shed with `503` + `Retry-After: 1` (fail-fast load-shedding). |

## `[gateway.rate_limit]`

Struct: `RateLimitConfig`. Token buckets on the `tools/call` hot path (checked
**after** the authorization gates, so a flood of denied calls cannot drain the
buckets). Over-limit calls get a tool-error result + a `rate-limited` audit
record — the stdio analog of a 429.

| Key | Type | Default | What it does |
|---|---|---|---|
| `per_tool_per_sec` | float > 0 | unset = per-tool scope off | Refill rate (tokens/sec) for each tool's own bucket. |
| `per_tool_burst` | float ≥ 1 | = `per_tool_per_sec` | Per-tool bucket capacity (max burst). |
| `global_per_sec` | float > 0 | unset = global scope off | Refill rate for the gateway-wide bucket (checked before the per-tool one). |
| `global_burst` | float ≥ 1 | = `global_per_sec` | Gateway-wide bucket capacity. |

Validation rejects non-positive rates, bursts < 1, and a rate < 1 without an
explicit burst (the defaulted sub-1 bucket could never admit a whole token, so
every call would be denied).

## `[gateway.egress]`

Struct: `EgressConfig`. The SSRF guard for **HTTP upstreams**
(`streamable-http` / `sse`) and the `jwks_uri` fetch. Cloud-metadata
(`169.254.169.254`), link-local (`169.254.0.0/16`, `fe80::/10`), and the
unspecified address are **always blocked — there is no knob to allow them**.
Resolved IPs are DNS-pinned to defeat rebinding. Inspect the effective policy
with `mcpdef egress show`.

| Key | Type | Default | What it does |
|---|---|---|---|
| `allow_private` | bool | `true` | Allow private / loopback / unique-local upstream addresses (MCPdef commonly fronts internal or localhost MCP servers). Set `false` to reach only public upstreams. |
| `require_https` | bool | `true` | Require HTTPS for public destinations (private/loopback may be plain HTTP). |

## `[gateway.auth]` — OAuth 2.1 Resource Server

Struct: `AuthConfig`. Applies to the **HTTP listener only**: when `enabled`,
every `POST /mcp` must carry a valid `Authorization: Bearer <JWT>`, validated
per request (signature against the JWKS, `aud == resource`, `iss == issuer`,
`exp`/`nbf`; asymmetric algorithms only — `none`/HMAC are rejected). Running
`mcpdef run` *without* `--http` while auth is enabled prints a warning: stdio has
no per-request transport identity, so auth is not enforced there.

| Key | Type | Default | What it does |
|---|---|---|---|
| `enabled` | bool | `false` | Turn bearer validation on. When `true`, `issuer`, `resource`, and one of `jwks`/`jwks_uri` are required (blank strings count as unset). |
| `issuer` | string (URL) | unset | The authorization server's `iss` claim value. |
| `resource` | string (URL) | unset | This gateway's canonical URI — the audience tokens must carry (RFC 8707/9068). Also the origin used to build the `WWW-Authenticate` metadata URL (never derived from request headers). |
| `jwks` | inline JSON or path | unset | Pinned keys: inline JWKS JSON (a value starting with `{`) or a path to a JWKS file. Preferred for hardened deploys — no startup network dependency. |
| `jwks_uri` | string (URL) | unset | Fetch the JWKS at startup, through the egress/SSRF guard. `jwks` wins if both are set. |

## `[gateway.admin]` — OSS read-only admin / observability server

Struct: `AdminConfig`. Prometheus `/metrics`, a small JSON API, and the
built-in status UI — see [API.md § Admin listener](./API.md#admin-listener-gatewayadmin).
Off by default; runs on a **separate port** from the MCP data path so scraping
it never touches the governed hot path. Carries no auth of its own (that's the
EE control plane's job) — bind it to loopback or keep it behind your own
network policy, same as the audit ledger.

| Key | Type | Default | What it does |
|---|---|---|---|
| `enabled` | bool | `false` | Start the admin server alongside the gateway. |
| `listen` | string `host:port` | `"127.0.0.1:7879"` | Bind address for the admin server. Loopback by default, and a different port than `[gateway] listen`. |

## `[[role]]` — RBAC

Struct: `RoleConfig`. Layered over the allowlist for **authenticated** HTTP
callers; with no `[[role]]` defined the gate is off (the allowlist alone
decides). A caller holds a role when the role's `name` appears among the
token's scopes or `roles` claim.

| Key | Type | What it does |
|---|---|---|
| `name` | string (non-empty) | The role name matched against token scopes/roles. |
| `grants` | array of strings | Grants as `"server-glob:tool-glob"`; a bare `"tool-glob"` (no colon) grants it on any server. |

## `[profile.<name>]`

Struct: `ProfileConfig`. A named, reusable allow/deny set — referenced by a
server (`profile = "<name>"`) or applied gateway-wide (`[gateway] profile`).

| Key | Type | What it does |
|---|---|---|
| `tools` | array of globs | Allowlist (deny-by-default). Unset = allow all, subject to `deny`. |
| `deny` | array of globs | Denies; deny wins over allow. |

Resolution when a server references a profile: inline `tools` **replaces** the
profile's allowlist; inline `deny` is **appended** (denies accumulate).

## `[[server]]` — the governed upstreams

Struct: `ServerConfig`. At least one is required.

| Key | Applies to | Type | Default | What it does |
|---|---|---|---|---|
| `id` | all | string (unique, non-empty) | — | The server's name in policy, audit records, and `servers list`. |
| `transport` | all | `"stdio"` \| `"streamable-http"` \| `"sse"` \| `"wasm"` \| `"wasm-component"` | — | How MCPdef reaches the upstream (`SUPPORTED_TRANSPORTS`). `streamable-http` auto-falls back to the legacy SSE bridge on a 400/404/405; `sse` forces it. |
| `command` | stdio | argv array | — (required) | The child process to spawn. |
| `env` | stdio | table of string→string | `{}` | Env vars injected into the child — the token-broker path: MCPdef holds the upstream's credential and the client's bearer is never passed through. |
| `url` | streamable-http, sse | string (URL) | — (required) | The upstream endpoint. Goes through the egress/SSRF guard. |
| `tools` | all | array of globs | unset = all (subject to `deny`) | Allowlist: only these tools are exposed/callable (deny-by-default once set). |
| `deny` | all | array of globs | `[]` | Glob denies (e.g. `delete_*`); deny wins over allow. |
| `profile` | all | string | unset | Inherit allow/deny from `[profile.<name>]` (see resolution rule above). |
| `resources` | — | array | unset | **Reserved**: resource-URI allowlist. Parsed but not enforced — Phase 1 governs tools. |
| `wasm` | wasm, wasm-component | path | — (required) | The `.wasm` core module / `wasm32-wasip2` component to run in-path under Wasmtime. |
| `wasm_fuel` | wasm, wasm-component | int | `200_000_000` (`SandboxLimits::default`, `mcpdef-sandbox`) | Fuel per call (≈ one unit per instruction); exceeding it traps `out of fuel`. |
| `wasm_max_memory_mb` | wasm, wasm-component | int (MiB) | `64` | Linear-memory ceiling for the module. |
| `wasm_deadline_ms` | wasm, wasm-component | int (ms) | unset / `0` = no bound | Per-call **wall-clock** deadline via epoch interruption (20 ms tick granularity), on top of the fuel (CPU) bound. |
| `wasm_allow_egress` | wasm-component | array of `"ip:port"` | `[]` = **deny all** | Outbound TCP allowlist for the sandboxed component. A connect is permitted only if listed **and** the IP passes the egress classification (metadata/special-use always blocked). Hostnames are not accepted. |

## CLI flags

Clap derive: `Cli`/`Cmd` in [`crates/mcpdef/src/main.rs`](../crates/mcpdef/src/main.rs).
Every subcommand that reads config takes `--config <file>` (default `mcpdef.toml`).

| Command | Flags beyond `--config` | What it does |
|---|---|---|
| `mcpdef run` | `--profile <name>`, `--http` | Run the gateway; serves the client over stdio, or over the Streamable HTTP listener with `--http`. `--profile` overrides `[gateway] profile` for this run. |
| `mcpdef up` | `--profile <name>` | Shorthand for `run --http`. |
| `mcpdef call <tool>` | `--args <json-object>` (default `{}`), `--json`, `--profile` | One-shot governed tool call: allowlist/profile/pin/rate-limit gates + audit apply; RBAC does not (no bearer on this trusted local path). Exits non-zero on a denial or tool error. |
| `mcpdef validate` | — | Structurally validate the config; exit non-zero listing every problem. |
| `mcpdef servers list` | — | Static, config-level view of the governed servers and their *resolved* allow/deny (profiles applied). Does not connect upstreams. |
| `mcpdef audit verify` | `--path <ledger>`, `--head <hash> --count <n>` (together) | Offline hash-chain check; with `--head`/`--count`, also checks against a seal recorded out-of-band (catches tail-truncation). Exit non-zero on a break. |
| `mcpdef audit tail` | `--path <ledger>`, `-n/--lines <n>` (default 20), `--format json\|ocsf\|cef\|syslog` | Print the last N records in a SIEM-ready format, one line per record. |
| `mcpdef egress show` | — | Print the effective SSRF/egress policy. |
| `mcpdef pin` | — | Pin the current tool definitions of all upstreams as approved (writes `[gateway] pins`; overwrites — this is the re-approval command). |
| `mcpdef diff-tools` | — | Diff current tool definitions against the pin store (read-only); exit non-zero if any pinned tool changed (rug-pull). |
| `mcpdef version` | — | Print version, MCP spec target, and phase. |

## Data formats & compatibility

There is no `format_version` field in any of these files yet (pre-1.0); the
shapes below are what `mcpdef 0.1.0` reads and writes.

- **Audit ledger** (`[gateway] audit`): JSON Lines, one `Record` per line
  (`mcpdef-audit::Record`): `seq`, `ts_unix_ms`, `agent`, `server`, `method?`,
  `tool?`, `decision` (`"allow"`/`"deny"`), `rule?`, `latency_ms`, `prev_hash`,
  `hash`. `hash = SHA-256` over a unit-separator-delimited encoding of the
  fields + `prev_hash`; the first record chains to 64 hex zeros (`GENESIS`).
  Append-only; re-opening resumes the chain from the current head. The hash is
  computed over the explicit field encoding, not the JSON text, so field order
  in a line does not matter.
- **Pin store** (`[gateway] pins`): TOML, `[<server-id>]` tables mapping
  `tool = "<hex sha-256>"` (`mcpdef-pin::PinStore`, serde-transparent
  `BTreeMap<String, BTreeMap<String, String>>`). Sorted deterministically so it
  diffs cleanly in version control; written atomically (temp file + rename).
  The hash covers the tool's governed fields only: `name`, `description`,
  `inputSchema`, `outputSchema`, `annotations`, canonicalized with recursively
  sorted keys.
- **JWKS** (`[gateway.auth] jwks`): a standard JWKS JSON document; keys must
  carry `kid` and be RSA or EC (RS256/384/512, PS256, ES256/384).
