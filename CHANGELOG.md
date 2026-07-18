# Changelog

All notable changes to MCPdef are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because MCPdef tracks a **moving protocol**, every release explicitly records the
MCP spec revision(s) it supports (see ROADMAP.md "Spec-version reality").

## [Unreleased]

_Nothing yet._

## [0.1.0] - 2026-07-19

### Added
- **Policy-as-code rule engine** (`[[policy]]`, in `mcpdef-policy`). A richer gate
  than the static allowlist, evaluated *after* it: where the allowlist decides on
  the tool name alone, a policy rule matches on the **caller** (agent), **server**,
  **tool** (all globs), and the tool-call **arguments** (per-field predicates —
  `equals`/`glob`/`contains`/`exists`, over dotted paths). So a policy can express
  "deny `delete_*` on `github` when `args.name` is a `prod-*` repo" or "only
  `agent:ci-*` may call `deploy`". Rules are **first-match-wins** (a specific
  `allow` can precede a broad `deny`); no match is allow (the allowlist already
  gated). A denial is audited under the rule's own `name`, and a mis-typed effect
  or an argument predicate with no operator fails `mcpdef validate` (no silent
  fail-open). *(A `transform` effect — argument/result mutation — remains a
  follow-up.)*
- **Inline injection / secret-exfil scanning** (`[gateway.inspect]`, new
  `mcpdef-inspect` crate). A curated, dependency-free rule pack scans the two
  untrusted-content surfaces an in-path gateway straddles: tool **descriptions**
  (at connect — a "line-jumping" / tool-poisoning attempt hides the tool from
  `tools/list` and denies its `tools/call`) and tool-call **results** (per call —
  a response that leaks a credential or carries injected instructions is refused
  before it reaches the model). Detects prompt-injection phrasing and secret
  patterns (AWS/Slack/GitHub/Stripe keys, PEM private-key blocks). Three modes:
  `off` (default), `warn` (audit/log findings only), `enforce` (hide/deny); a
  finding is audited under a new `injection` / `secret-exfil` rule. Opt-in and
  high-precision to keep false positives low. Operators can extend the built-in
  pack via `[gateway.inspect]` — `injection_phrases` (case-insensitive) and
  `secret_substrings` (case-sensitive, e.g. an internal token prefix). *(Regex-based
  rule packs remain a follow-up.)*

### Security / hardening
- **JWKS rotation without a restart.** The OAuth 2.1 Resource Server loaded the
  authorization server's signing keys once at startup, so a key rotation rejected
  every bearer until `mcpdef` was restarted. The verifier now holds the JWKS behind
  an `RwLock`, and on a token whose `kid` isn't cached the HTTP listener re-fetches
  the configured `jwks_uri` **once** (through the egress/SSRF guard), swaps in the
  rotated keys, and retries. Fail-closed throughout — a static (inline/file) JWKS,
  a rate-limited attempt, a failed fetch, or a malformed document all leave the
  request denied — and rate-limited to one re-fetch per 60s so a flood of
  bogus-`kid` tokens can't hammer the IdP. Inline/file JWKS stay static.
- **WASM sandbox runtime moved to the Wasmtime 36 LTS line (from 27).** Clears 18
  outstanding RustSec advisories against `wasmtime` / `wasmtime-wasi` 27 — several
  sandbox-relevant, notably a Winch sandbox-escape (RUSTSEC-2026-0095) and a
  shared-linear-memory unsoundness (RUSTSEC-2025-0118) — none of which had an
  in-place v27 patch. The component path is updated for the `wasmtime-wasi` 36 API
  (single-accessor `WasiView` → `WasiCtxView`, `p2::add_to_linker_async`,
  per-function async `bindgen!`); the capability-scoped WASI and the per-destination
  egress allowlist are unchanged, and the committed `wasm32-wasip2` fixture still
  loads. Declared **MSRV rises to 1.88** — the dependency-tree floor (Wasmtime 36
  needs 1.86, but `time` 0.3.x requires 1.88).
- **Core-module WASM sandbox calls run off the async worker.** `WasmUpstream` (the
  `transport = "wasm"` path) previously ran the synchronous `handle` inline on the
  Tokio worker, so a non-yielding, fuel/deadline-bound call could pin an executor
  thread and stall unrelated traffic. Each call now moves the (reused, stateful)
  instance onto the blocking pool and restores it afterward, so guest session state
  still persists across calls (consistent with the component path) while the
  synchronous execution no longer blocks an async worker. Guest memory growth from an
  `alloc`-only ABI remains bounded by the configured memory cap (`wasm_max_memory_mb`)
  — a guest that never reuses its buffer fails its own calls at the cap, never harming
  the host; a guest-side reset/free hook is a documented follow-up.
- **No HTTP-redirect SSRF bypass.** The egress-guarded HTTP clients now use
  `redirect(none)`, so a validated upstream (or a `jwks_uri`) cannot `3xx` to an
  unvalidated host (e.g. `169.254.169.254`) and have it dialed outside the guard.
- **JWT verification is pinned to the key family, not the header `alg`.** The
  verifier now explicitly rejects a token whose header algorithm doesn't match the
  selected JWK's key type (RSA vs EC), so the algorithm-confusion defense no longer
  depends implicitly on the JWT library's internal family check (the `none`/HMAC
  allow-list pre-check already stood).
- **Per-request audit identity.** The gateway computes the audit subject per
  request and threads it through, instead of storing it on the shared, long-lived
  `Gateway` — removing a latent path where one caller's identity could be recorded
  against a later request.
- **Explicit request-body cap** on the HTTP listener (`DefaultBodyLimit`, 2 MiB),
  so an unauthenticated client can't force a large allocation before auth/policy.
- **`servers list` no longer panics** on a multi-byte UTF-8 server/tool id
  (`truncate` now counts/splits by `char`, not byte).
- **SIEM export is injection-safe.** CEF/syslog renderers strip CR/LF from
  caller-controlled fields (e.g. a crafted tool name), so one audit record can't
  forge a second SIEM line (CWE-117).
- **Hardened egress blocks special-use IPs.** Multicast, documentation
  (`192.0.2/24`, `2001:db8::/32`), benchmarking (`198.18/15`), IETF-protocol, and
  reserved (`240/4`, `ff00::/8`) ranges are now always blocked — never valid
  upstreams — closing a gap where `hardened()` could dial them.
- **PRM challenge URL is trusted.** The `WWW-Authenticate` Protected Resource
  Metadata URL is now built from the configured `[gateway.auth] resource` origin,
  not the client-supplied `Host`/`X-Forwarded-Proto`, so a `401` can't advertise
  attacker-chosen metadata.
- **Atomic pin-store writes.** `PinStore::save` writes a temp file and renames
  over the target, so a crash mid-write can't corrupt the trust baseline.
- **`jwks_uri` fetch is time-bounded** (10s), so a silent server can't hang
  startup; the connect handshake honors the upstream timeout too.
- **Stricter config validation.** A sub-1 rate limit with no explicit burst (a
  bucket that admits no calls) and blank/whitespace `[gateway.auth]` fields are
  now rejected instead of silently accepted.
- **Rate limiting runs after authorization.** The `tools/call` rate-limit gate
  now sits after the allowlist/RBAC/rug-pull checks, so a flood of *denied* calls
  can't drain the per-tool/global buckets and starve authorized callers (the
  expensive upstream dispatch is still rate-bounded).
- **Unauthenticated HTTP can't rename audit identity.** On the shared HTTP
  listener, a client's `initialize`-supplied name no longer sets the audit
  identity used for other clients' records (it remains a stdio-only convenience).
- **JWKS fetch is fully bounded** — DNS resolution is now inside the fetch
  deadline, and the response body is read under a 2 MiB cap (no unbounded buffer).
- **Hardened egress blocks more IPv6 special-use ranges** — documentation
  (`3fff::/20`), benchmarking (`2001:2::/48`), SRv6 (`5f00::/16`), discard/dummy
  (`100::/48`), and local-use NAT64 (`64:ff9b:1::/48`); the global NAT64 prefix
  stays reachable.

### Added
- **In-path WASM sandbox** (Phase 4; new `mcpdef-sandbox` crate). An upstream can now
  be an **untrusted `.wasm` MCP server run in-process under Wasmtime** —
  `transport = "wasm"`, `wasm = "./server.wasm"` — behind the same `Transport`
  seam as a stdio or HTTP upstream, so the full governance path (allowlist, RBAC,
  rug-pull pinning, rate limiting, audit) applies unchanged. The module runs with
  **zero ambient capability**: it is instantiated against an **empty linker**, so
  it cannot touch the filesystem, network, or clock — a module that imports
  anything (e.g. WASI) fails to load, by design. Each call is bounded by a **fuel**
  budget (CPU; a runaway module traps `out of fuel` instead of spinning) and a
  **linear-memory ceiling** (`StoreLimits`), plus an **optional per-call wall-clock
  deadline** (Wasmtime **epoch interruption** + a background ticker — a call that
  runs too long traps even with fuel to spare; off by default, defense-in-depth on
  top of the fuel/CPU bound). All three are tunable per server via `wasm_fuel` /
  `wasm_max_memory_mb` / `wasm_deadline_ms`. The module speaks the gateway's normal
  MCP envelope over a deliberately tiny, no-WASI `alloc`/`handle` ABI (documented on
  the crate).
- **WASI component-model sandbox + egress allowlist** (Phase 4, the component path).
  An upstream can now be a **`wasm32-wasip2` component** (`transport = "wasm-component"`)
  that exports the new **`mcpdef:server` WIT world** (`handle(string) -> string`) — a
  typed MCP-over-component interface, so a sandboxed server can be written in any
  language that targets `wasm32-wasip2` (no hand-rolled memory ABI). It runs under a
  **capability-scoped WASI** (`wasmtime-wasi`) that grants **nothing by default**: no
  preopened directories (no filesystem), no inherited stdio. Its only possible host
  capability is **outbound TCP**, gated by a **per-destination egress allowlist**
  (`wasm_allow_egress = ["ip:port", …]`, default **deny-all**): a connection is
  permitted only if its resolved address is explicitly listed **and** passes the same
  IP classification as the HTTP egress guard (cloud-metadata / link-local /
  special-use are **always** blocked, even if mis-listed) — a host-fn networking gate
  via `WasiCtxBuilder::socket_addr_check`, reusing `mcpdef-transport`'s classifier
  (now exported as `check_socket_ip`). The same fuel / memory / epoch caps apply, and
  the full governance path (allowlist, RBAC, pinning, rate-limit, audit) is unchanged.
  *(WASI filesystem/clock grants and hostname egress with DNS-pinning are follow-ups;
  the allowlist is by resolved IP today, with DNS name lookup off.)*
- **CLI ergonomics: `mcpdef up` + `mcpdef call`.** `mcpdef up` is shorthand for
  `mcpdef run --http` (bring the gateway up on the Streamable HTTP listener — the
  shared-gateway shape). `mcpdef call <tool> [--args JSON] [--json]` is a one-shot
  client: it builds the same governed gateway, issues a single `tools/call`
  through it, prints the tool's text content (or the raw result with `--json`),
  and exits non-zero if a governance gate or the upstream returns an error. The
  allowlist/profile/pinning/rate-limit gates apply and the call is audited, so
  the output is what a live client would see — handy for demos and scripts. (RBAC
  is not enforced on this local path: it gates authenticated callers by token
  role, and `mcpdef call` carries no bearer.)
- **OAuth 2.1 termination + token broker + RBAC** (Phase 2; new `mcpdef-auth` crate).
  The HTTP listener can now require auth: with `[gateway.auth] enabled`, every
  `POST /mcp` must carry a valid `Authorization: Bearer <JWT>`, validated **per
  request** as an OAuth 2.1 **Resource Server** (MCP forbids session-based auth) —
  signature against the configured **JWKS** (inline/file `jwks` or an
  egress-guarded `jwks_uri` fetch), `aud == resource` (RFC 8707/9068),
  `iss == issuer`, and `exp`/`nbf`. Only **asymmetric** algorithms are accepted
  (RS/PS/ES); `none` and HMAC are refused to defeat the classic algorithm-confusion
  forgery. A missing/invalid token gets **`401`** with a `WWW-Authenticate`
  challenge pointing at the **RFC 9728 Protected Resource Metadata** document, now
  served at `GET /.well-known/oauth-protected-resource`, so a client can discover
  the authorization server. The validated subject (`sub`) becomes the **audit
  identity**. **RBAC** (`[[role]]`, new `mcpdef_policy::Rbac`) layers over the
  allowlist: a caller "holds" a role when its name is in the token's scopes/`roles`,
  and a `tools/call` is allowed only if a held role grants `"server:tool"` (glob);
  an RBAC denial is a tool-error result audited under rule `rbac`. **Token
  brokering**: a stdio upstream's credential is injected into the child process
  env via `[server.env]` (`StdioChild::spawn_with_env`) — MCPdef holds the upstream
  cred, and the client's bearer is never passed through. Auth applies to the HTTP
  listener only (stdio has no per-request transport identity; enabling it for a
  stdio run warns and is a no-op).
- **Downstream Streamable HTTP listener** (`mcpdef run --http`) — clients now reach
  the gateway over HTTP, not just stdio (the shared-gateway shape: point every
  agent at one endpoint, govern centrally). A `POST` to `/mcp` carries one
  JSON-RPC message; the gateway replies with a single `application/json` response
  or `202 Accepted` for a notification. Built **stateless-first** (no required
  `Mcp-Session-Id`), so it serves both the 2025-11-25 and 2026-07-28 wire models.
  Defenses: **Origin validation** (cross-site `Origin` → `403`, DNS-rebinding
  defense; loopback + no-Origin clients pass; extra origins via
  `[gateway] allowed_origins`), **loopback bind** by default, and an opt-in
  **in-flight load-shedding cap** (`[gateway] max_inflight` → `503` + `Retry-After`,
  the §5b connection-cap piece). `GET /mcp` → `405` (no server→client stream yet).
- **Availability controls** (ARCHITECTURE §5b — the in-path single-point-of-failure
  posture). A **token-bucket rate limiter** (new `mcpdef-ratelimit` crate) caps
  `tools/call` per-tool and gateway-wide; an over-limit call is shed with a
  tool-error result and a `rate-limited` audit event (the stdio analog of a `429`),
  before any policy/dispatch work. A **per-call upstream timeout**
  (`[gateway] upstream_timeout_ms`) fails a wedged upstream — audited as
  `upstream-timeout` — instead of letting it hang the gateway. Configured via
  `[gateway.rate_limit]` (`per_tool_per_sec`/`_burst`, `global_per_sec`/`_burst`).
  *(Connection caps + backpressure arrive with the downstream HTTP listener.)*
- **Signed release pipeline** ([`ops/release.yml`](./ops/release.yml), synced to the
  public mirror's `.github/workflows/release.yml`). A `v*` tag builds static-musl
  (`x86_64`/`aarch64`) + macOS (`x86_64`/`arm64`) `mcpdef` binaries, each with a
  `.sha256`, a **cosign** keyless signature, and a **SLSA build-provenance**
  attestation; generates a **CycloneDX SBOM**; publishes the GitHub release;
  publishes the OSS engine crates to crates.io **in dependency order** (`ee/` never
  published); bumps the Homebrew formula; and pushes a cosign-signed, SLSA-attested
  multi-arch distroless image. Pre-release (`-rc.N`) tags build + sign but skip
  crates.io / brew / `:latest`. Adds `Dockerfile`(.release), `RELEASING.md`,
  `docs/DOCKERHUB.md`, a `Formula/mcpdef.rb` placeholder, and version-pins the
  internal workspace deps so the workspace is crates.io-publishable.
- **Tool-definition pinning + rug-pull detection** (new `mcpdef-pin` crate). On
  connect, MCPdef hashes each tool's governed fields (name, description,
  inputSchema, outputSchema, **annotations** — pinned, not trusted, per spec) and
  compares against a persistent TOML pin store. Trust-on-first-use records unseen
  tools; a tool whose definition **drifts** after approval is hidden from
  `tools/list`, **denied** on `tools/call`, and audited with rule `rug-pull`.
  Enabled by `[gateway] pins = "…"`. New CLI: `mcpdef pin` (approve current defs)
  and `mcpdef diff-tools` (read-only drift report, exits non-zero on a rug-pull).
  The hash is canonical (recursively sorted keys), so benign field-order changes
  don't false-positive.
- **Egress / SSRF guard for HTTP upstreams** (`mcpdef-transport::egress`). Before
  dialing any HTTP upstream — and before POSTing to the URL a legacy HTTP+SSE
  server names in its `endpoint` event (an untrusted, server-controlled value) —
  MCPdef resolves the host and classifies every resolved IP. Cloud-metadata /
  link-local (`169.254/16`, `fe80::/10`) and the unspecified address are
  **always blocked**; private/loopback are allowed by default (MCPdef fronts
  internal servers) but can be blocked via `[gateway.egress] allow_private`;
  public destinations must use HTTPS by default (`require_https`). Validated IPs
  are **DNS-pinned** to defeat TOCTOU rebinding. Closes the standing SSRF TODO.
- `mcpdef egress show` — print the effective egress policy (OSS-ROLLOUT.md §6
  self-verification).
- **Named allowlist profiles** (`[profile.<name>]`). Define a reusable glob
  allow/deny set once and reference it from a server (`profile = "readonly"`;
  inline `tools` replaces, inline `deny` appends), or apply one gateway-wide as
  the **active profile** (`[gateway] profile` / `mcpdef run --profile <name>`) to
  scope the whole tool surface an agent sees — directly cutting the multi-server
  context/token tax. `servers list` now shows the resolved profile + active note.
- **Allowlist entries are now globs** (e.g. `get_*`, `list_*`), not just exact
  names — so a profile can scope a whole tool family in one line. (Exact names
  still match exactly; backward-compatible.)
- `mcpdef audit verify` — offline tamper-evidence check of the hash-linked audit
  ledger. Exits non-zero on a broken chain. With `--head` + `--count` it also
  checks against a seal recorded out-of-band, catching tail-truncation and
  wholesale-replacement that a plain chain check cannot.
- `mcpdef audit tail` — print the last N audit records in a SIEM-ready format:
  `json` (default), `ocsf` (OCSF "API Activity", class 6003), `cef`
  (ArcSight CEF:0), or `syslog` (RFC 5424). Local SIEM export ships in the OSS
  binary — it is never paywalled.
- `mcpdef servers list` — a config-level view of the governed servers and each
  server's configured allowlist / deny globs.
- `mcpdef-audit`: public `read_all` / `tail` read API over the ledger, an
  `ExportFormat` enum, and a `Record::export` formatter; a dependency-free
  RFC 3339 UTC timestamp formatter for the syslog shape.
- Phase-0 release scaffolding: root `LICENSE` (Apache-2.0), `ee/LICENSE`
  (BSL 1.1), `NOTICE`, `CONTRIBUTING.md` (DCO), `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, and SPDX headers on engine sources.

### Spec support
- Built against MCP spec revision **2025-11-25**; forward-planning the stateless
  **2026-07-28** release candidate behind a single transport abstraction.

## [0.1.0-alpha] — Phase 1 + 1.5 (internal pre-release)

### Added
- Transport-multiplexing reverse proxy fronting upstream MCP servers over
  **stdio**, **Streamable HTTP**, and the **legacy 2024-11-05 HTTP+SSE** bridge,
  including the dual-transport probe/fallback and `Last-Event-ID` resumption.
- Initialize / `tools/list` handshake; `tools/list` aggregation + allowlist
  filtering; deny-by-default allowlist enforcement on `tools/call` (a denial
  returns an `isError` tool result so the model can self-correct, and is audited).
- Append-only, hash-linked, tamper-evident **audit ledger** with offline
  `verify` / `verify_against`.
- Single declarative `mcpdef.toml` config; `mcpdef run` / `mcpdef validate` /
  `mcpdef version`.

[Unreleased]: https://github.com/lucheeseng827/mcpdef/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lucheeseng827/mcpdef/releases/tag/v0.1.0
