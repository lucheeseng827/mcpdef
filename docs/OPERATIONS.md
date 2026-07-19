# MCPdef operations runbook

How to deploy, back up, verify, monitor, and debug a running `mcpdef`. Everything
here describes the shipped OSS binary (`crates/mcpdef`, v0.1.x) — grounded in
[`main.rs`](../crates/mcpdef/src/main.rs) / [`listener.rs`](../crates/mcpdef/src/listener.rs) /
[`gateway.rs`](../crates/mcpdef/src/gateway.rs). Config knobs are in
[CONFIG.md](./CONFIG.md); the wire surface is in [API.md](./API.md).

## Deploy

MCPdef is one binary + one TOML file. No database, no sidecars.

- **From source:** `cargo build -p mcpdef --release` → `target/release/mcpdef`.
- **Container:** [`Dockerfile`](../Dockerfile) builds a distroless
  (`gcr.io/distroless/static-debian12:nonroot`) image from a musl-static build;
  `EXPOSE 7878`. CI releases assemble multi-arch images from prebuilt binaries
  via [`Dockerfile.release`](../Dockerfile.release) — see
  [RELEASING.md](../RELEASING.md) and [docs/DOCKERHUB.md](./DOCKERHUB.md).
  Musl caveat: Wasmtime's Cranelift JIT must be validated on the fully-static
  target (ARCHITECTURE.md §13) — "static-ish", not a blanket promise.
- **Run:** `mcpdef run --config mcpdef.toml` (stdio client) or
  `mcpdef up --config mcpdef.toml` (HTTP listener). Validate first:
  `mcpdef validate --config mcpdef.toml`.
- **Readiness signal:** one stderr line —
  `mcpdef 0.1.0 ready · 1 upstream(s) · audit ./mcpdef-audit/audit.log · listening streamable-http 127.0.0.1:7878`
  (plus `· profile <p>`, `· ⚠ N rug-pulled tool(s) denied`, `· oauth on · N role(s)`
  when applicable). Startup **fails fast** if the config is invalid, an
  upstream's initialize handshake fails (or exceeds `upstream_timeout_ms`), the
  audit ledger can't be opened, or — with auth on — the JWKS is unreadable /
  the `jwks_uri` fetch is egress-blocked.
- **Upgrade / rollback:** stateless swap — stop, replace the binary, start.
  The audit ledger re-opens and resumes its hash chain; the pin store is
  re-read. There is no on-disk migration in 0.1.x.

## State: what to back up

| File | Config key | Format | Loss impact |
|---|---|---|---|
| Audit ledger | `[gateway] audit` (default `./mcpdef-audit/audit.log`) | JSONL hash chain (append-only) | Your tamper-evident record of every governed call. Back up continuously (it is the compliance artifact). Snapshot-friendly: append-only, safe to copy live. |
| Pin store | `[gateway] pins` (optional) | TOML, `server → tool → sha256` | Your approved tool-definition baseline. Losing it means every tool re-pins on next start (trust-on-first-use) — a rug-pull window. Keep it in version control; it is deterministic and diff-clean by design. |
| Config + JWKS | `mcpdef.toml`, `[gateway.auth] jwks` file | TOML / JSON | The policy itself. Version-control both. |

`[server.env]` values (brokered upstream credentials) live in the config file —
protect it like a secret store (file permissions, encrypted at rest, no world
reads).

Durability note (honest guarantee): the ledger append is `write` + userspace
`flush`, **not** `fsync` — a host crash can lose the last unsynced record(s).
The hash chain proves *integrity*, not *durability*.

## Audit-ledger verification

Routine (proves internal consistency — any edit/delete of an interior record):

```sh
$ mcpdef audit verify --config mcpdef.toml
chain OK · 2 record(s) · head=f4bb388a0ba59cef9af31b5732c5f03c4dfb27d24e68fc078abafbe1a40fa17a
```

Exit is non-zero on a break, printing `chain BROKEN at seq=<n>`.

**Plain `verify` cannot detect tail-truncation or wholesale replacement** — a
shortened-but-valid chain still verifies. To close that, periodically **seal**
the `(head, count)` pair somewhere the same attacker cannot edit (a ticket, a
separate WORM store, the `ee/` control plane), then verify against the seal:

```sh
# seal: record the current head hash and record count out-of-band, then later:
mcpdef audit verify --config mcpdef.toml --head <sealed-head-hash> --count <sealed-count>
```

`--head`/`--count` must be given together. A mismatch (fewer records, different
head) fails verification even when the chain is internally consistent.

SIEM streaming from the free binary:

```sh
mcpdef audit tail --format ocsf -n 500 | your-siem-forwarder   # also: json | cef | syslog
```

## Monitoring

The audit ledger is the source of truth, and an optional **read-only admin /
observability server** (`[gateway.admin]`, off by default) exposes it for humans
and scrapers on a separate port: Prometheus `GET /metrics`
(`mcpdef_tools_calls_total{server,tool,decision,rule}`, a call-latency histogram,
`mcpdef_upstreams`, `mcpdef_uptime_seconds`), a small JSON API
(`/api/v1/status|servers|stats|audit`), and a built-in status UI at `/`. It
carries no auth of its own — bind it to loopback or keep it behind your own
network boundary. What to watch:

- **Deny spikes:** `mcpdef audit tail --format json` → `decision:"deny"` grouped
  by `rule`. A burst of `rate-limited` = an agent loop or an undersized bucket;
  `rug-pull` = a server changed a pinned tool; `not-on-allowlist`/`rbac` = an
  agent probing beyond its grants.
- **Latency:** each record carries `latency_ms`; `upstream-timeout` records
  mean a wedged upstream.
- **Drift at startup:** the ready line's `⚠ N rug-pulled tool(s) denied`, or
  `mcpdef diff-tools` in cron/CI (exits non-zero on drift).
- **Chain integrity:** scheduled `mcpdef audit verify` (+ sealed `--head/--count`).
- **Process:** it is one foreground process; supervise with systemd/container
  restart policy. HTTP `503` responses (shed load) are visible to clients, not
  logged by mcpdef.

## Troubleshooting (symptom first)

What the client sees → why → what to do. Full gate semantics in
[API.md](./API.md#toolscall-gate-order).

| Symptom (exact error/status) | Cause | Fix |
|---|---|---|
| Tool result `isError:true`: `MCPdef denied: tool '<t>' is not on the allowlist` | Server has a `tools = […]` allowlist and `<t>` is not on it | Add the tool to `[[server]] tools` (or the profile), restart. Deliberate deny-by-default. |
| `MCPdef denied: tool '<t>' matches deny pattern '<p>' …` | A `deny` glob (server or profile) matched; deny wins over allow | Remove/narrow the glob if the tool is legitimate. |
| `MCPdef denied: tool '<t>' is not in the gateway's active profile` | `[gateway] profile` (or `--profile`) scopes the whole surface | Run without the profile override or extend `[profile.<name>] tools`. |
| `MCPdef denied: no governed server exposes tool '<t>'` | No connected upstream listed that tool at connect time | Check the upstream actually exposes it (`tools/list` is cached at connect — restart mcpdef after an upstream adds tools). |
| `MCPdef denied: server '<s>' is not governed by MCPdef` | Tool routed to a server with no policy entry (fail-closed) | Add a `[[server]]` entry for it. |
| `MCPdef denied: no role grants '<t>' on '<s>'` | RBAC: the token's scopes/roles hold no matching `[[role]]` grant | Grant `"<server-glob>:<tool-glob>"` to a role the token carries, or fix the IdP scopes. |
| `MCPdef denied: tool '<t>' on '<s>' changed since it was pinned (possible rug-pull)` | Pinned definition drifted (description/schema/annotations changed) | Review with `mcpdef diff-tools`; if legitimate, re-approve with `mcpdef pin`. The tool is also hidden from `tools/list` until re-pinned. |
| `MCPdef denied: global/tool rate limit exceeded … — retry shortly` | Token bucket empty (`[gateway.rate_limit]`) | Retry with backoff; raise `*_per_sec`/`*_burst` if the budget is undersized. |
| `MCPdef error: upstream '<s>' did not respond to '<t>' within <n>ms` | `upstream_timeout_ms` fired; upstream wedged or slow | Check the upstream process/endpoint; raise the timeout for legitimately slow tools. |
| HTTP `401` + `WWW-Authenticate: Bearer resource_metadata=…` | Auth on and the bearer is missing/invalid (bad signature, wrong `aud`/`iss`, expired, unknown `kid`, HMAC/`none` alg) | Fetch the PRM document from the challenge URL, get a token from the advertised AS with `aud` = `[gateway.auth] resource`. |
| HTTP `403` `origin "…" not allowed` | Browser cross-site `Origin` (DNS-rebinding defense) | Add the origin to `[gateway] allowed_origins` if it is your web app. |
| HTTP `405` on `GET /mcp` | No server→client SSE stream in this phase | Expected; use `POST`. |
| HTTP `413` | Request body > 2 MiB (`MAX_BODY_BYTES`) | JSON-RPC messages are small by design; oversized tool args need a code change. |
| HTTP `503` + `Retry-After: 1`, `gateway overloaded — retry shortly` | `max_inflight` cap reached (deliberate shed, never an unbounded queue) | Retry; raise `max_inflight` or add replicas if sustained. |
| HTTP `404` on `/.well-known/oauth-protected-resource` | `[gateway.auth]` disabled | Expected when auth is off. |
| Startup: `mcpdef: warning — [gateway.auth] is enabled but applies only to the HTTP listener` | Running stdio with auth configured | Use `--http`; stdio has no per-request identity to authenticate. |
| Startup fails: `upstream '<id>' did not complete its initialize handshake within <n>ms` | Upstream wedged at connect | Fix the upstream; the same `upstream_timeout_ms` bounds connect. |
| Startup fails: `N validation error(s) in mcpdef.toml` | Structural config problem | Run `mcpdef validate` — it lists every error (unknown transport, missing url/command/wasm, dead rate buckets, incomplete auth…). |
| Sandboxed call fails — HTTP `500` `gateway error: …` / CLI error naming e.g. `all fuel consumed` or an epoch deadline | `wasm_fuel` / `wasm_deadline_ms` / `wasm_max_memory_mb` exceeded (a trap) | Raise the specific cap. Note: trap-failed calls are not audited today (denials/timeouts are). |
| Sandboxed component's outbound connect fails (error text depends on the guest) | The destination is not in `wasm_allow_egress` (default deny-all), or is in an always-blocked class | Add the exact `ip:port` to `wasm_allow_egress` (metadata/special-use ranges are rejected even if listed; hostnames not accepted). |
| `mcpdef pin` fails: `` `mcpdef pin` needs a pin store `` | `[gateway] pins` unset | Set `pins = "./mcpdef-pins.toml"`. |
| `mcpdef audit verify` fails: `audit ledger … does not exist` | Fresh install — the ledger is written on first governed call | Expected before first run. |

## Security posture

- **What listens where.** Nothing, by default: `mcpdef run` is stdio-only. With
  `--http`/`up`, exactly one TCP socket — `[gateway] listen`, default
  **loopback** `127.0.0.1:7878`. There is no TLS termination in the binary;
  for non-loopback exposure put a TLS-terminating reverse proxy in front and
  turn on `[gateway.auth]`.
- **Authn/z.** OAuth 2.1 Resource Server per request (JWKS-validated bearer
  JWT, asymmetric-only — algorithm-confusion-safe, `aud`/`iss`/`exp`/`nbf`
  checked), RFC 9728 discovery on 401. RBAC roles layer over the deny-by-default
  allowlist. The stdio path and `mcpdef call` are trusted-operator paths with no
  bearer.
- **Token handling.** The client's bearer is validated and dropped — it is
  **never forwarded** to upstreams. Upstream credentials are brokered from
  config into stdio children via `[server.env]`. Tokens are not written to the
  audit ledger (only the token's `sub` is, as the audit identity).
- **Egress.** HTTP upstream and `jwks_uri` fetches pass the SSRF guard:
  cloud-metadata/link-local always blocked, DNS-pinned, HTTPS required for
  public hosts (`[gateway.egress]`). Verify with `mcpdef egress show`.
- **Sandbox boundaries.** `transport = "wasm"` runs against an empty linker —
  no filesystem, network, or clock (a module importing WASI fails to load).
  `transport = "wasm-component"` gets capability-scoped WASI whose only grant
  is outbound TCP to the explicit `wasm_allow_egress` list (default deny-all).
  Both are fuel-, memory-, and optionally wall-clock-bounded per call.
- **Listener hardening.** Origin validation (DNS-rebinding), 2 MiB body cap
  before auth/parse, optional in-flight cap with explicit `503` shed, no
  sessions (stateless per the 2026-07-28 direction).
- **Deliberately out of scope (0.1.x):** TLS in-binary, policy-as-code,
  inline result-content/injection scanning (roadmap Phase 3), and multi-replica
  coordination (each replica has its own ledger/pin store/metrics registry — see
  [Monitoring](#monitoring) for the `[gateway.admin]` `/metrics` endpoint this no
  longer excludes). Disclosure policy: [SECURITY.md](../SECURITY.md).
