// SPDX-License-Identifier: Apache-2.0
//! The `mcpdef.toml` config model + structural validation, and the mapping from
//! per-server `tools`/`deny` to the Phase-1 [`Policy`].

use anyhow::Context;
use mcpdef_policy::{ArgMatch, ArgOp, Effect, Policy, PolicyRules, Rbac, Rule, ServerPolicy};
use mcpdef_sandbox::{EgressAllow, SandboxLimits};
use mcpdef_transport::EgressPolicy;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;

/// Transports the config grammar accepts — all of them are served as of Phase
/// 1.5 (stdio, Streamable HTTP, and the legacy HTTP+SSE bridge).
pub const SUPPORTED_TRANSPORTS: &[&str] =
    &["stdio", "streamable-http", "sse", "wasm", "wasm-component"];

/// One rate-limit scope as `(refill_per_sec, burst_capacity)`.
pub type RateScope = (f64, f64);

#[derive(Debug, Deserialize)]
pub struct Config {
    pub gateway: GatewayConfig,
    #[serde(default, rename = "server")]
    pub servers: Vec<ServerConfig>,
    /// Named, reusable allow/deny profiles (`[profile.<name>]`).
    #[serde(default, rename = "profile")]
    pub profiles: HashMap<String, ProfileConfig>,
    /// RBAC roles (`[[role]]`) — each grants tools to authenticated callers.
    #[serde(default, rename = "role")]
    pub roles: Vec<RoleConfig>,
    /// Policy-as-code rules (`[[policy]]`) — per-agent / per-argument allow/deny
    /// evaluated after the allowlist, first-match-wins.
    #[serde(default, rename = "policy")]
    pub policy: Vec<PolicyRuleConfig>,
}

/// `[[policy]]` — one policy-as-code rule. Match conditions (`agents` / `servers`
/// / `tools` globs and `args` predicates) are AND-ed. **Omit** a condition to
/// match anything for that dimension; an explicit empty list (`servers = []`) is
/// rejected by `validate()` — it would otherwise silently match nothing (a
/// fail-open for a `deny`).
#[derive(Debug, Deserialize, Clone)]
pub struct PolicyRuleConfig {
    pub name: String,
    /// `"allow"` or `"deny"` (case-insensitive).
    pub effect: String,
    #[serde(default)]
    pub agents: Option<Vec<String>>,
    #[serde(default)]
    pub servers: Option<Vec<String>>,
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Argument predicates: `{ path = "name", glob = "prod-*" }` etc.
    #[serde(default)]
    pub args: Vec<ArgMatchConfig>,
}

/// One argument predicate in a `[[policy]]` rule. Exactly one of `equals` /
/// `glob` / `contains` / `exists` selects the operator.
#[derive(Debug, Deserialize, Clone)]
pub struct ArgMatchConfig {
    pub path: String,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub exists: Option<bool>,
}

impl ArgMatchConfig {
    /// Resolve the configured operator (precedence equals → glob → contains →
    /// exists). `None` if the predicate names no operator (rejected by `validate`).
    fn to_arg_match(&self) -> Option<ArgMatch> {
        let op = if let Some(v) = &self.equals {
            ArgOp::Equals(v.clone())
        } else if let Some(v) = &self.glob {
            ArgOp::Glob(v.clone())
        } else if let Some(v) = &self.contains {
            ArgOp::Contains(v.clone())
        } else if self.exists == Some(true) {
            ArgOp::Exists
        } else {
            return None;
        };
        Some(ArgMatch {
            path: self.path.clone(),
            op,
        })
    }
}

/// `[[role]]` — an RBAC role: a set of `"server:tool"` glob grants. A caller
/// holds the role when its `name` appears among the token's scopes or `roles`.
#[derive(Debug, Deserialize, Clone)]
pub struct RoleConfig {
    pub name: String,
    /// Grants as `"server-glob:tool-glob"` (a bare `"tool"` means any server).
    #[serde(default)]
    pub grants: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_audit")]
    pub audit: String,
    /// Reserved for the Phase-3 policy directory; unused in Phase 1.
    #[serde(default)]
    pub policy: Option<String>,
    /// Tool-def pin store path. When set, MCPdef pins each upstream tool's
    /// definition (trust-on-first-use) and denies + audits a `rug-pull` if a
    /// later definition drifts. Unset = pinning off.
    #[serde(default)]
    pub pins: Option<String>,
    /// The active named profile (`[profile.<name>]`) layered over every server,
    /// scoping the whole tool surface an agent sees. `None` = no extra filter.
    /// Overridable at launch with `mcpdef run --profile <name>`.
    #[serde(default)]
    pub profile: Option<String>,
    /// The SSRF/egress guard applied to HTTP upstreams (`[gateway.egress]`).
    #[serde(default)]
    pub egress: EgressConfig,
    /// Token-bucket rate limits for `tools/call` (`[gateway.rate_limit]`).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Per-call upstream response timeout (ms). A wedged upstream that does not
    /// reply within this bound is failed (and audited) instead of hanging the
    /// gateway. `0` / unset = no timeout.
    #[serde(default)]
    pub upstream_timeout_ms: Option<u64>,
    /// Extra Origins allowed on the downstream HTTP listener (`mcpdef run --http`)
    /// beyond loopback (`localhost` / `127.0.0.1` / `::1`, any port — always
    /// allowed). A browser cross-site `Origin` not in this set is rejected with
    /// `403` (DNS-rebinding defense).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Max concurrent in-flight HTTP requests on the listener; excess is shed with
    /// `503` + `Retry-After` (load-shedding, ARCHITECTURE §5b). Unset = unlimited.
    #[serde(default)]
    pub max_inflight: Option<usize>,
    /// OAuth 2.1 Resource Server settings (`[gateway.auth]`). When `enabled`, the
    /// HTTP listener requires a valid bearer on every request.
    #[serde(default)]
    pub auth: AuthConfig,
    /// Inline injection / secret-exfil scanning of tool descriptions + results
    /// (`[gateway.inspect]`).
    #[serde(default)]
    pub inspect: InspectConfig,
}

/// `[gateway.inspect]` — inline injection / secret-exfil scanning. `mode` is
/// `off` (default), `warn` (log findings only), or `enforce` (hide poisoned tools
/// and refuse results that leak a secret / carry injected instructions).
#[derive(Debug, Deserialize, Default)]
pub struct InspectConfig {
    #[serde(default)]
    pub mode: Option<String>,
    /// Operator-defined prompt-injection phrases, matched case-insensitively on
    /// top of the built-in pack (e.g. org-specific instruction-override wording).
    #[serde(default)]
    pub injection_phrases: Vec<String>,
    /// Operator-defined secret substrings, matched case-sensitively (e.g. an
    /// internal credential prefix like `acme_sk_` the built-in pack won't know).
    #[serde(default)]
    pub secret_substrings: Vec<String>,
}

/// `[gateway.auth]` — the OAuth 2.1 Resource Server config. When `enabled`, the
/// listener validates a bearer JWT per request against the JWKS (inline `jwks` or
/// fetched `jwks_uri`), checking `aud == resource` and `iss == issuer`.
#[derive(Debug, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The authorization server's `iss`.
    #[serde(default)]
    pub issuer: Option<String>,
    /// This gateway's canonical URI — the audience tokens must carry (RFC 8707).
    #[serde(default)]
    pub resource: Option<String>,
    /// The offline / pinned-keys path: either inline JWKS JSON (a value starting
    /// with `{`) or a path to a JWKS JSON file. Preferred over `jwks_uri` for a
    /// hardened deploy — no startup network dependency, keys are pinned.
    #[serde(default)]
    pub jwks: Option<String>,
    /// A `jwks_uri` to fetch the JWKS from at startup (egress-guarded).
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

impl GatewayConfig {
    /// The effective egress policy for HTTP upstreams.
    pub fn egress_policy(&self) -> EgressPolicy {
        EgressPolicy {
            allow_private_network: self.egress.allow_private,
            require_https_public: self.egress.require_https,
        }
    }

    /// Build the inline-inspection scanner from `[gateway.inspect] mode`, or `None`
    /// when off (the default). An unrecognized mode is rejected by `validate()`, so
    /// here it falls back to off.
    pub fn inspect_scanner(&self) -> Option<mcpdef_inspect::Scanner> {
        let mode = self.inspect.mode.as_deref().unwrap_or("off");
        mcpdef_inspect::Mode::parse(mode)
            .and_then(mcpdef_inspect::Scanner::new)
            .map(|s| {
                s.with_extra_injection(self.inspect.injection_phrases.clone())
                    .with_extra_secrets(self.inspect.secret_substrings.clone())
            })
    }

    /// `(per_tool, global)` rate-limit settings as `(refill_per_sec, burst)`
    /// tuples for the limiter; either is `None` when that scope is unset.
    pub fn rate_limit_settings(&self) -> (Option<RateScope>, Option<RateScope>) {
        let per_tool = self
            .rate_limit
            .per_tool_per_sec
            .map(|r| (r, self.rate_limit.per_tool_burst.unwrap_or(r)));
        let global = self
            .rate_limit
            .global_per_sec
            .map(|r| (r, self.rate_limit.global_burst.unwrap_or(r)));
        (per_tool, global)
    }

    /// The per-call upstream timeout, if configured (> 0).
    pub fn upstream_timeout(&self) -> Option<std::time::Duration> {
        self.upstream_timeout_ms
            .filter(|&ms| ms > 0)
            .map(std::time::Duration::from_millis)
    }
}

/// `[gateway.rate_limit]` — token-bucket caps on `tools/call`. A scope is active
/// only if its `*_per_sec` is set; `*_burst` defaults to the per-sec rate.
#[derive(Debug, Deserialize, Default)]
pub struct RateLimitConfig {
    /// Refill rate (tokens/sec) for each tool's own bucket.
    #[serde(default)]
    pub per_tool_per_sec: Option<f64>,
    /// Per-tool bucket capacity (max burst). Defaults to `per_tool_per_sec`.
    #[serde(default)]
    pub per_tool_burst: Option<f64>,
    /// Refill rate (tokens/sec) for the gateway-wide bucket.
    #[serde(default)]
    pub global_per_sec: Option<f64>,
    /// Gateway-wide bucket capacity (max burst). Defaults to `global_per_sec`.
    #[serde(default)]
    pub global_burst: Option<f64>,
}

/// `[gateway.egress]` — the SSRF guard knobs. Cloud-metadata / link-local
/// (`169.254/16`, `fe80::/10`) is **always** blocked and has no knob.
#[derive(Debug, Deserialize)]
pub struct EgressConfig {
    /// Allow private / loopback / unique-local upstreams. Default `true` — MCPdef
    /// commonly fronts internal or localhost MCP servers. Set `false` to only
    /// reach public upstreams.
    #[serde(default = "default_true")]
    pub allow_private: bool,
    /// Require HTTPS for public destinations (private/loopback may be plain
    /// HTTP). Default `true`.
    #[serde(default = "default_true")]
    pub require_https: bool,
}

impl Default for EgressConfig {
    fn default() -> Self {
        EgressConfig {
            allow_private: true,
            require_https: true,
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:7878".to_string()
}
fn default_audit() -> String {
    "./mcpdef-audit/audit.log".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub id: String,
    pub transport: String,
    /// stdio: the command (argv) to spawn.
    #[serde(default)]
    pub command: Vec<String>,
    /// streamable-http / sse: the upstream endpoint (reserved in Phase 1).
    #[serde(default)]
    pub url: Option<String>,
    /// Allowlist: if present, only these tools are exposed (deny-by-default).
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Glob denies (e.g. `delete_*`), applied after the allowlist.
    #[serde(default)]
    pub deny: Vec<String>,
    /// A named `[profile.<name>]` to inherit allow/deny from. Inline `tools`
    /// replaces the profile's allowlist; inline `deny` is appended to it.
    #[serde(default)]
    pub profile: Option<String>,
    /// Environment variables injected into a **stdio** upstream's child process —
    /// the OSS token-broker path: MCPdef holds the upstream's credentials and hands
    /// them to the server via env (the spec says stdio servers take creds from the
    /// environment), so the client's bearer is never passed through.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Reserved: resource-URI allowlist (Phase 1 governs tools).
    #[serde(default)]
    pub resources: Option<Vec<String>>,
    /// `wasm` transport: path to the `.wasm` module to run in the in-path sandbox
    /// (Phase 4). Required when `transport = "wasm"`.
    #[serde(default)]
    pub wasm: Option<String>,
    /// `wasm`: fuel granted per call (≈ one unit per instruction). Unset = default.
    #[serde(default)]
    pub wasm_fuel: Option<u64>,
    /// `wasm`: max linear memory (MiB) the module may grow to. Unset = default.
    #[serde(default)]
    pub wasm_max_memory_mb: Option<usize>,
    /// `wasm`: per-call **wall-clock** deadline (ms). A module that runs longer than
    /// this traps, even with fuel to spare — defense-in-depth on top of the fuel
    /// (CPU) bound. Unset or `0` = no wall-clock bound.
    #[serde(default)]
    pub wasm_deadline_ms: Option<u64>,
    /// `wasm-component`: outbound TCP **egress allowlist** for the sandboxed
    /// component (`["ip:port", …]`). Default empty = **deny all** network access.
    /// A connection is permitted only if its address is listed *and* passes the
    /// egress IP classification (cloud-metadata/special-use are always blocked).
    #[serde(default)]
    pub wasm_allow_egress: Vec<String>,
}

impl ServerConfig {
    /// The configured `wasm` module/component path, treating an empty or
    /// whitespace-only string as **missing** (so a blank `wasm = ""` is rejected
    /// at `validate()` time rather than blowing up later as a confusing file-not-
    /// found during transport construction).
    pub fn wasm_path(&self) -> Option<&str> {
        self.wasm
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
    }

    /// The sandbox resource caps for a `wasm` upstream — config overrides on top
    /// of [`SandboxLimits::default`].
    pub fn sandbox_limits(&self) -> SandboxLimits {
        let d = SandboxLimits::default();
        SandboxLimits {
            fuel_per_call: self.wasm_fuel.unwrap_or(d.fuel_per_call),
            max_memory_bytes: self
                .wasm_max_memory_mb
                .map(|mb| mb.saturating_mul(1024 * 1024))
                .unwrap_or(d.max_memory_bytes),
            // A `0` deadline means "no wall-clock bound", same as unset.
            deadline: self
                .wasm_deadline_ms
                .filter(|&ms| ms > 0)
                .map(std::time::Duration::from_millis)
                .or(d.deadline),
        }
    }

    /// The outbound-socket egress allowlist for a `wasm-component` upstream. Empty
    /// `wasm_allow_egress` = deny all. Errors if an entry isn't a valid `ip:port`
    /// (also surfaced by [`Config::validate`]).
    pub fn egress_allow(&self) -> Result<EgressAllow, String> {
        let mut addrs = Vec::with_capacity(self.wasm_allow_egress.len());
        for e in &self.wasm_allow_egress {
            let addr: SocketAddr = e.parse().map_err(|_| {
                format!(
                    "server '{}': wasm_allow_egress entry '{e}' is not a valid ip:port",
                    self.id
                )
            })?;
            addrs.push(addr);
        }
        // Private/loopback are allowed when explicitly listed (the allowlist is the
        // grant); only the always-blocked classes (metadata/special-use) are denied.
        Ok(EgressAllow::new(addrs, EgressPolicy::default()))
    }
}

/// A reusable, named allow/deny set (`[profile.<name>]`). Defined once and
/// referenced by one or more servers (DRY), or applied gateway-wide as the
/// active profile to scope the whole tool surface an agent sees.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProfileConfig {
    /// Glob allowlist (deny-by-default). `None` = allow all (subject to `deny`).
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Glob denies, applied before the allowlist.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing TOML {}", path.display()))?;
        Ok(cfg)
    }

    /// Structural validation. Returns the list of problems (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.servers.is_empty() {
            errs.push(
                "no [[server]] entries — the gateway must front at least one upstream".to_string(),
            );
        }
        let mut seen = HashSet::new();
        for s in &self.servers {
            if s.id.trim().is_empty() {
                errs.push("a [[server]] has an empty `id`".to_string());
            } else if !seen.insert(s.id.clone()) {
                errs.push(format!("duplicate server id '{}'", s.id));
            }
            if !SUPPORTED_TRANSPORTS.contains(&s.transport.as_str()) {
                errs.push(format!(
                    "server '{}': unknown transport '{}' (expected one of {:?})",
                    s.id, s.transport, SUPPORTED_TRANSPORTS
                ));
                continue;
            }
            match s.transport.as_str() {
                "stdio" => {
                    if s.command.is_empty() {
                        errs.push(format!(
                            "server '{}': stdio transport needs a non-empty `command`",
                            s.id
                        ));
                    }
                }
                "streamable-http" | "sse" => {
                    if s.url.is_none() {
                        errs.push(format!(
                            "server '{}': '{}' transport needs a `url`",
                            s.id, s.transport
                        ));
                    }
                }
                "wasm" => {
                    if s.wasm_path().is_none() {
                        errs.push(format!(
                            "server '{}': wasm transport needs a `wasm` module path",
                            s.id
                        ));
                    }
                }
                "wasm-component" => {
                    if s.wasm_path().is_none() {
                        errs.push(format!(
                            "server '{}': wasm-component transport needs a `wasm` component path",
                            s.id
                        ));
                    }
                    // Surface a malformed egress allowlist entry at config-load time.
                    if let Err(e) = s.egress_allow() {
                        errs.push(e);
                    }
                }
                _ => {}
            }
            if let Some(p) = &s.profile {
                if !self.profiles.contains_key(p) {
                    errs.push(format!(
                        "server '{}': references unknown profile '{}'",
                        s.id, p
                    ));
                }
            }
        }
        if let Some(p) = &self.gateway.profile {
            if !self.profiles.contains_key(p) {
                errs.push(format!(
                    "[gateway] profile '{p}' is not defined as a [profile.{p}]"
                ));
            }
        }
        // Rate-limit sanity: a set rate must be positive and a set burst >= 1
        // (a sub-1 bucket can never hold a whole token, so it would deny every call).
        let rl = &self.gateway.rate_limit;
        for (name, rate) in [
            ("per_tool_per_sec", rl.per_tool_per_sec),
            ("global_per_sec", rl.global_per_sec),
        ] {
            if let Some(r) = rate {
                if !r.is_finite() || r <= 0.0 {
                    errs.push(format!(
                        "[gateway.rate_limit] {name} must be a finite number > 0"
                    ));
                }
            }
        }
        for (name, burst) in [
            ("per_tool_burst", rl.per_tool_burst),
            ("global_burst", rl.global_burst),
        ] {
            if let Some(b) = burst {
                if !b.is_finite() || b < 1.0 {
                    errs.push(format!(
                        "[gateway.rate_limit] {name} must be a finite number >= 1"
                    ));
                }
            }
        }
        // When the burst is omitted it DEFAULTS to the rate (see `rate_limit_settings`),
        // so a sub-1 rate without an explicit burst yields a bucket that can never
        // admit a whole token — every call would be denied. Reject that combination.
        for (rate_name, rate, burst_name, burst) in [
            (
                "per_tool_per_sec",
                rl.per_tool_per_sec,
                "per_tool_burst",
                rl.per_tool_burst,
            ),
            (
                "global_per_sec",
                rl.global_per_sec,
                "global_burst",
                rl.global_burst,
            ),
        ] {
            if burst.is_none() {
                if let Some(r) = rate {
                    if r.is_finite() && r < 1.0 {
                        errs.push(format!(
                            "[gateway.rate_limit] {rate_name} < 1 requires an explicit `{burst_name}` >= 1 (a sub-1 bucket admits no calls)"
                        ));
                    }
                }
            }
        }
        // Auth: when enabled, the RS needs an issuer, an audience (resource), and a
        // key source (inline JWKS or a jwks_uri). Treat blank/whitespace strings as
        // missing — an empty `issuer = ""` is no more usable than an unset one.
        let auth = &self.gateway.auth;
        let blank = |o: &Option<String>| match o.as_deref() {
            None => true,
            Some(s) => s.trim().is_empty(),
        };
        if auth.enabled {
            if blank(&auth.issuer) {
                errs.push("[gateway.auth] enabled but `issuer` is not set".to_string());
            }
            if blank(&auth.resource) {
                errs.push(
                    "[gateway.auth] enabled but `resource` (audience) is not set".to_string(),
                );
            }
            if blank(&auth.jwks) && blank(&auth.jwks_uri) {
                errs.push(
                    "[gateway.auth] enabled but neither `jwks` nor `jwks_uri` is set".to_string(),
                );
            }
        }
        for role in &self.roles {
            if role.name.trim().is_empty() {
                errs.push("a [[role]] has an empty `name`".to_string());
            }
        }
        // Inspect mode, if set, must be a recognized value — a typo silently
        // disabling scanning would be a dangerous fail-open.
        if let Some(mode) = &self.gateway.inspect.mode {
            if mcpdef_inspect::Mode::parse(mode).is_none() {
                errs.push(format!(
                    "[gateway.inspect] `mode` must be off/warn/enforce, got '{mode}'"
                ));
            }
        }
        // Policy rules: a recognized effect, a name, and each arg predicate must
        // name exactly one operator (a mis-typed predicate that matched nothing
        // would silently weaken a deny).
        for r in &self.policy {
            if r.name.trim().is_empty() {
                errs.push("a [[policy]] rule has an empty `name`".to_string());
            }
            if !r.effect.eq_ignore_ascii_case("allow") && !r.effect.eq_ignore_ascii_case("deny") {
                errs.push(format!(
                    "[[policy]] rule '{}' has `effect` '{}' (must be allow/deny)",
                    r.name, r.effect
                ));
            }
            // An explicit empty condition list matches nothing at runtime, so a
            // `deny` with `servers = []` / `tools = []` / `agents = []` would never
            // fire (a silent fail-open). Require the field be omitted (= any) or
            // non-empty.
            for (dim, list) in [
                ("agents", &r.agents),
                ("servers", &r.servers),
                ("tools", &r.tools),
            ] {
                if matches!(list, Some(v) if v.is_empty()) {
                    errs.push(format!(
                        "[[policy]] rule '{}' has an empty `{dim}` list — omit it to match any, or list entries",
                        r.name
                    ));
                }
            }
            for a in &r.args {
                let ops = [
                    a.equals.is_some(),
                    a.glob.is_some(),
                    a.contains.is_some(),
                    a.exists == Some(true),
                ]
                .iter()
                .filter(|b| **b)
                .count();
                if ops != 1 {
                    errs.push(format!(
                        "[[policy]] rule '{}' arg '{}' must name exactly one of equals/glob/contains/exists (found {ops})",
                        r.name, a.path
                    ));
                }
            }
        }
        errs
    }

    /// Resolve a server's effective allow/deny, applying its referenced profile.
    /// Inline `tools` **replaces** the profile's allowlist (a server-specific
    /// allowlist wins); inline `deny` is **appended** to the profile's deny
    /// (denies accumulate — deny-by-default safety).
    pub fn resolve_server(&self, s: &ServerConfig) -> ServerPolicy {
        let prof = s.profile.as_ref().and_then(|n| self.profiles.get(n));
        let allow_tools = s
            .tools
            .clone()
            .or_else(|| prof.and_then(|p| p.tools.clone()));
        let mut deny = prof.map(|p| p.deny.clone()).unwrap_or_default();
        deny.extend(s.deny.iter().cloned());
        ServerPolicy { allow_tools, deny }
    }

    /// The gateway's active profile as a [`ServerPolicy`], if set and defined.
    pub fn active_profile(&self) -> Option<ServerPolicy> {
        let name = self.gateway.profile.as_ref()?;
        let p = self.profiles.get(name)?;
        Some(ServerPolicy {
            allow_tools: p.tools.clone(),
            deny: p.deny.clone(),
        })
    }

    /// Build the allowlist policy: per-server rules (with profiles resolved) plus
    /// the gateway-wide active profile.
    pub fn to_policy(&self) -> Policy {
        let mut map = HashMap::new();
        for s in &self.servers {
            map.insert(s.id.clone(), self.resolve_server(s));
        }
        Policy::from_map(map).with_active(self.active_profile())
    }

    /// Build the RBAC model from `[[role]]`. Each grant `"server:tool"` becomes a
    /// `(server-glob, tool-glob)`; a bare `"tool"` (no colon) grants it on any
    /// server. Empty when no roles are defined (the RBAC gate stays off).
    pub fn rbac(&self) -> Rbac {
        let mut rbac = Rbac::new();
        for role in &self.roles {
            let grants = role
                .grants
                .iter()
                .map(|g| match g.split_once(':') {
                    Some((server, tool)) => (server.to_string(), tool.to_string()),
                    None => ("*".to_string(), g.to_string()),
                })
                .collect();
            rbac.insert_role(role.name.clone(), grants);
        }
        rbac
    }

    /// Build the policy-as-code rule set from `[[policy]]`, preserving config order
    /// (first-match-wins). Empty when no rules are defined (the engine stays off).
    pub fn policy_rules(&self) -> PolicyRules {
        let rules = self
            .policy
            .iter()
            .map(|r| Rule {
                name: r.name.clone(),
                effect: if r.effect.eq_ignore_ascii_case("deny") {
                    Effect::Deny
                } else {
                    Effect::Allow
                },
                agents: r.agents.clone(),
                servers: r.servers.clone(),
                tools: r.tools.clone(),
                args: r
                    .args
                    .iter()
                    .filter_map(ArgMatchConfig::to_arg_match)
                    .collect(),
            })
            .collect();
        PolicyRules::new(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpdef_core::Decision;

    const GOOD: &str = r#"
        [gateway]
        listen = "127.0.0.1:7878"
        audit  = "./audit/mcpdef.log"

        [[server]]
        id = "github"
        transport = "stdio"
        command = ["mcp-server-github"]
        tools = ["list_issues"]
        deny = ["delete_*"]
    "#;

    #[test]
    fn parses_and_validates_good_config() {
        let cfg: Config = toml::from_str(GOOD).unwrap();
        assert!(cfg.validate().is_empty());
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.gateway.listen, "127.0.0.1:7878");
        let pol = cfg.to_policy();
        assert!(pol.is_governed("github"));
        assert!(pol.decide_tool("github", "delete_repo").as_str() == "deny");
        assert!(pol.decide_tool("github", "list_issues").is_allow());
    }

    #[test]
    fn defaults_fill_in() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert_eq!(cfg.gateway.listen, "127.0.0.1:7878");
        assert_eq!(cfg.gateway.audit, "./mcpdef-audit/audit.log");
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn flags_missing_command_and_unknown_transport() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "a"
            transport = "stdio"
            [[server]]
            id = "b"
            transport = "carrier-pigeon"
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("non-empty `command`")));
        assert!(errs.iter().any(|e| e.contains("unknown transport")));
    }

    #[test]
    fn wasm_transport_requires_a_module_path_and_carries_sandbox_limits() {
        // Missing `wasm` path is a validation error.
        let missing: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "sandboxed"
            transport = "wasm"
        "#,
        )
        .unwrap();
        assert!(missing
            .validate()
            .iter()
            .any(|e| e.contains("wasm transport needs a `wasm` module path")));

        // A blank / whitespace-only path is treated the same as missing (it would
        // otherwise fail later as a confusing file-not-found at load time).
        let blank: Config = toml::from_str(
            "[gateway]\n[[server]]\nid = \"sandboxed\"\ntransport = \"wasm\"\nwasm = \"   \"\n",
        )
        .unwrap();
        assert!(blank
            .validate()
            .iter()
            .any(|e| e.contains("wasm transport needs a `wasm` module path")));
        assert!(blank.servers[0].wasm_path().is_none());

        // With a module path it validates, and the per-server fuel/memory
        // overrides flow into the sandbox limits (others fall back to defaults).
        let ok: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "sandboxed"
            transport = "wasm"
            wasm = "./echo.wasm"
            wasm_fuel = 5000000
            wasm_max_memory_mb = 16
            wasm_deadline_ms = 250
        "#,
        )
        .unwrap();
        assert!(ok.validate().is_empty());
        let limits = ok.servers[0].sandbox_limits();
        assert_eq!(limits.fuel_per_call, 5_000_000);
        assert_eq!(limits.max_memory_bytes, 16 * 1024 * 1024);
        assert_eq!(limits.deadline, Some(std::time::Duration::from_millis(250)));
    }

    #[test]
    fn wasm_component_requires_path_and_validates_egress_allowlist() {
        // Missing component path → error.
        let missing: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "comp"
            transport = "wasm-component"
        "#,
        )
        .unwrap();
        assert!(missing
            .validate()
            .iter()
            .any(|e| e.contains("wasm-component transport needs a `wasm` component path")));

        // A malformed egress entry is rejected at config-load time.
        let bad_egress: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "comp"
            transport = "wasm-component"
            wasm = "./server.wasm"
            wasm_allow_egress = ["not-an-addr"]
        "#,
        )
        .unwrap();
        assert!(bad_egress
            .validate()
            .iter()
            .any(|e| e.contains("is not a valid ip:port")));

        // A well-formed component server with an ip:port allowlist validates, and
        // the allowlist parses.
        let ok: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "comp"
            transport = "wasm-component"
            wasm = "./server.wasm"
            wasm_allow_egress = ["10.1.2.3:5432", "203.0.113.9:443"]
        "#,
        )
        .unwrap();
        assert!(ok.validate().is_empty());
        assert!(ok.servers[0].egress_allow().is_ok());
    }

    #[test]
    fn flags_empty_server_list_and_duplicates() {
        let empty: Config = toml::from_str("[gateway]\n").unwrap();
        assert!(empty
            .validate()
            .iter()
            .any(|e| e.contains("at least one upstream")));

        let dup: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert!(dup
            .validate()
            .iter()
            .any(|e| e.contains("duplicate server id")));
    }

    const PROFILES: &str = r#"
        [gateway]
        profile = "readonly"

        [profile.readonly]
        tools = ["get_*", "list_*"]
        deny  = ["*_secret"]

        [[server]]
        id = "github"
        transport = "stdio"
        command = ["mcp-server-github"]
        profile = "readonly"
        deny = ["delete_*"]          # appended to the profile's deny

        [[server]]
        id = "db"
        transport = "stdio"
        command = ["mcp-db"]
        profile = "readonly"
        tools = ["query"]            # replaces the profile's allowlist
    "#;

    #[test]
    fn profile_resolution_merges_allow_and_deny() {
        let cfg: Config = toml::from_str(PROFILES).unwrap();
        assert!(cfg.validate().is_empty());

        // github: inherits the profile allowlist (get_*/list_*), deny is the
        // union of the profile's *_secret and the server's delete_*.
        let gh = cfg.resolve_server(&cfg.servers[0]);
        assert_eq!(gh.allow_tools.as_ref().unwrap(), &["get_*", "list_*"]);
        assert!(gh.deny.contains(&"*_secret".to_string()));
        assert!(gh.deny.contains(&"delete_*".to_string()));

        // db: inline tools REPLACE the profile allowlist; profile deny still applies.
        let db = cfg.resolve_server(&cfg.servers[1]);
        assert_eq!(db.allow_tools.as_ref().unwrap(), &["query"]);
        assert!(db.deny.contains(&"*_secret".to_string()));
    }

    #[test]
    fn active_profile_scopes_the_gateway() {
        let cfg: Config = toml::from_str(PROFILES).unwrap();
        let pol = cfg.to_policy();
        // github would expose get_*/list_* per its (profile) allowlist…
        assert!(pol.decide_tool("github", "get_file").is_allow());
        assert!(pol.decide_tool("github", "list_issues").is_allow());
        // …and the deny union still bites.
        assert_eq!(pol.decide_tool("github", "delete_repo").as_str(), "deny");
        assert_eq!(pol.decide_tool("github", "api_secret").as_str(), "deny");
        // db's inline allowlist is [query]; the active readonly profile excludes
        // it (query is neither get_* nor list_*), so it is denied gateway-wide.
        match pol.decide_tool("db", "query") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "not-in-active-profile"),
            other => panic!("expected active-profile deny, got {other:?}"),
        }
    }

    #[test]
    fn validate_flags_unknown_profile_references() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            profile = "ghost"
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
            profile = "nope"
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("unknown profile 'nope'")));
        assert!(errs.iter().any(|e| e.contains("profile 'ghost'")));
    }

    #[test]
    fn rate_limit_settings_default_burst_and_timeout() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            upstream_timeout_ms = 2000
            [gateway.rate_limit]
            per_tool_per_sec = 5
            global_per_sec = 100
            global_burst = 200
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert!(cfg.validate().is_empty());
        let (per_tool, global) = cfg.gateway.rate_limit_settings();
        assert_eq!(per_tool, Some((5.0, 5.0))); // burst defaults to the rate
        assert_eq!(global, Some((100.0, 200.0))); // explicit burst kept
        assert_eq!(
            cfg.gateway.upstream_timeout(),
            Some(std::time::Duration::from_millis(2000))
        );
    }

    #[test]
    fn validate_rejects_nonpositive_rate() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.rate_limit]
            per_tool_per_sec = 0
            global_burst = 0.5
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("per_tool_per_sec")));
        assert!(errs.iter().any(|e| e.contains("global_burst")));
    }

    #[test]
    fn validate_rejects_sub1_rate_without_explicit_burst() {
        // rate < 1 with no burst → burst defaults to the rate → a dead bucket.
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.rate_limit]
            per_tool_per_sec = 0.5
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(
            errs.iter()
                .any(|e| e.contains("per_tool_per_sec") && e.contains("per_tool_burst")),
            "got: {errs:?}"
        );

        // …but the same rate WITH an explicit burst >= 1 is fine.
        let ok: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.rate_limit]
            per_tool_per_sec = 0.5
            per_tool_burst = 5
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert!(ok.validate().is_empty(), "got: {:?}", ok.validate());
    }

    #[test]
    fn validate_treats_blank_auth_fields_as_missing() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.auth]
            enabled = true
            issuer = ""
            resource = "   "
            jwks = ""
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("`issuer`")), "got: {errs:?}");
        assert!(errs.iter().any(|e| e.contains("`resource`")));
        assert!(errs.iter().any(|e| e.contains("`jwks`")));
    }

    #[test]
    fn validate_flags_incomplete_auth() {
        // enabled but no issuer / resource / key source.
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.auth]
            enabled = true
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("`issuer`")));
        assert!(errs.iter().any(|e| e.contains("`resource`")));
        assert!(errs.iter().any(|e| e.contains("`jwks`")));
    }

    #[test]
    fn complete_auth_validates_and_rbac_builds() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.auth]
            enabled  = true
            issuer   = "https://auth.example.com"
            resource = "https://mcpdef.acme.internal/mcp"
            jwks     = "./jwks.json"

            [[role]]
            name   = "reader"
            grants = ["github:get_*", "list_*"]

            [[server]]
            id = "github"
            transport = "stdio"
            command = ["mcp-server-github"]
        "#,
        )
        .unwrap();
        assert!(cfg.validate().is_empty());

        let rbac = cfg.rbac();
        assert!(!rbac.is_empty());
        // "github:get_*" → (github, get_*) matches; "list_*" (no colon) → (*, list_*).
        assert!(rbac
            .decide(["reader"].into_iter(), "github", "get_file")
            .is_allow());
        assert!(rbac
            .decide(["reader"].into_iter(), "files", "list_dir")
            .is_allow());
        // not granted: write on github, and a caller who doesn't hold the role.
        assert!(!rbac
            .decide(["reader"].into_iter(), "github", "delete_repo")
            .is_allow());
        assert!(!rbac
            .decide(["viewer"].into_iter(), "github", "get_file")
            .is_allow());
    }

    #[test]
    fn flags_empty_role_name() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[role]]
            name = ""
            grants = ["x:y"]
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert!(cfg.validate().iter().any(|e| e.contains("empty `name`")));
    }

    #[test]
    fn parses_policy_rules_and_builds_the_engine() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "github"
            transport = "stdio"
            command = ["mcp-server-github"]
            [[policy]]
            name = "no-delete-prod"
            effect = "deny"
            servers = ["github"]
            tools = ["delete_*"]
            args = [ { path = "name", glob = "prod-*" } ]
        "#,
        )
        .unwrap();
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
        let rules = cfg.policy_rules();
        assert!(!rules.is_empty());
        // The rule denies delete_repo on github when name is prod-*, and allows it
        // otherwise — proving the config→engine conversion carries every field.
        use mcpdef_policy::PolicyContext;
        let prod = serde_json::json!({ "name": "prod-secrets" });
        let dev = serde_json::json!({ "name": "dev-box" });
        assert!(!rules
            .evaluate(&PolicyContext {
                agent: "a",
                server: "github",
                tool: "delete_repo",
                args: &prod,
            })
            .is_allow());
        assert!(rules
            .evaluate(&PolicyContext {
                agent: "a",
                server: "github",
                tool: "delete_repo",
                args: &dev,
            })
            .is_allow());
    }

    #[test]
    fn validate_rejects_bad_effect_and_malformed_arg() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[policy]]
            name = "bad"
            effect = "maybe"
            servers = []
            args = [ { path = "x" } ]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("effect")), "{errs:?}");
        assert!(
            errs.iter().any(|e| e.contains("empty `servers`")),
            "an explicit empty condition list must be rejected: {errs:?}"
        );
        assert!(
            errs.iter().any(|e| e.contains("exactly one")),
            "a predicate with no operator must be rejected: {errs:?}"
        );
    }
}
