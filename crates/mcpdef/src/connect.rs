// SPDX-License-Identifier: Apache-2.0
//! From a config to a running gateway: the gateway it describes, the transport
//! each `[[server]]` entry names, and how the gateway keeps each one running.

use crate::config::{Config, ServerConfig, UpstreamAuth};
use crate::gateway::{Connect, Gateway, Startup, Supervised, UpstreamOptions};
use crate::listener::Fetching;
use anyhow::{Context, Result};
use mcpdef_audit::Ledger;
use mcpdef_pin::PinStore;
use mcpdef_sandbox::{WasmComponentUpstream, WasmUpstream};
use mcpdef_secrets::SecretString;
use mcpdef_transport::{
    read_secret, HttpClient, StaticAuth, StdioChild, TlsSettings, TokenAuth, Transport,
};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Build the governed gateway from a (validated) config: open the audit ledger,
/// apply pinning / rate-limit / per-call timeout / RBAC, connect every upstream,
/// and persist any trust-on-first-use pins. Shared by `run`/`up` (then served)
/// and `call` (then issues one request). Does not enforce OAuth — that is the
/// HTTP listener's per-request job; the local CLI caller is trusted.
pub async fn build_gateway(cfg: &Config) -> Result<Gateway> {
    warn(cfg);
    if let Some(parent) = Path::new(&cfg.gateway.audit).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let ledger = Ledger::open(&cfg.gateway.audit)
        .with_context(|| format!("opening audit ledger {}", cfg.gateway.audit))?;
    let mut gw = assemble(cfg, ledger, None)?;
    // Every upstream opens at once. One that does not start is logged, audited
    // and retried in the background while the gateway serves the rest; under
    // `[gateway] strict`, it fails the start.
    let startup = match cfg.gateway.strict {
        true => Startup::FailFast,
        false => Startup::Degraded,
    };
    gw.start_supervised(servers(cfg), startup).await?;
    // What the upstreams offer is known only now: a name two of them offer,
    // listed once from the first, or with prefixes a name too long for some
    // clients. Each is a warning, and under `strict` the start fails.
    let findings = tool_findings(cfg, &gw);
    if cfg.gateway.strict && !findings.is_empty() {
        let refused: Vec<String> = findings.iter().map(|f| format!("strict: {f}")).collect();
        anyhow::bail!("{}", refused.join("\n"));
    }
    for finding in &findings {
        eprintln!("mcpdef: warning — {finding}");
    }
    // Persist any trust-on-first-use pin additions made during connect.
    gw.persist_pins().context("saving pin store")?;
    Ok(gw)
}

/// The gateway `mcpdef doctor` looks at: the one [`build_gateway`] builds,
/// with every upstream opened as it opens them, keeping nothing a running
/// gateway keeps. What it would keep goes in `scratch`, a directory the
/// caller throws away.
///
/// - Its ledger is there, so an upstream that will not open goes in no audit
///   trail.
/// - The pin store is read from where the config says, and saved, if at all,
///   only there: a tool seen for the first time is not pinned by a diagnosis.
/// - An upstream that does not open is reported, not fatal, `strict` or not.
/// - An opening may take `upstream_timeout_ms`, or `wait` where that is unset,
///   so that one wedged upstream cannot keep the report from finishing.
pub async fn examine(cfg: &Config, scratch: &Path, wait: Duration) -> Result<Gateway> {
    let audit = scratch.join("audit.log");
    let ledger = Ledger::open(&audit)
        .with_context(|| format!("opening a scratch ledger {}", audit.display()))?;
    let wait = cfg.gateway.upstream_timeout().unwrap_or(wait);
    let gw =
        assemble(cfg, ledger, Some(&scratch.join("pins.toml")))?.with_upstream_timeout(Some(wait));
    gw.start_supervised(servers(cfg), Startup::Degraded).await?;
    Ok(gw)
}

/// The gateway a config describes before any upstream opens: its policy and
/// pins, and all that judges a call, writing to `ledger`. The pins are saved
/// to `pins_to`, or where they were read from.
fn assemble(cfg: &Config, ledger: Ledger, pins_to: Option<&Path>) -> Result<Gateway> {
    let mut gw = Gateway::new(cfg.to_policy(), ledger, "agent:unknown");
    if let Some(pins_path) = &cfg.gateway.pins {
        let store =
            PinStore::load(pins_path).with_context(|| format!("loading pin store {pins_path}"))?;
        let saved = pins_to.map_or_else(|| Path::new(pins_path).to_path_buf(), Path::to_path_buf);
        gw = gw.with_pins(store, saved);
    }
    let (rl_per_tool, rl_global) = cfg.gateway.rate_limit_settings();
    Ok(gw
        .with_rate_limit(rl_per_tool, rl_global)
        .with_upstream_timeout(cfg.gateway.upstream_timeout())
        // RBAC over the allowlist for authenticated callers (a no-op when no
        // `[[role]]` is defined). The HTTP listener supplies the principal.
        .with_rbac(Some(cfg.rbac()))
        // The client keys it issued, which a listener that takes them reads.
        .with_keys(cfg.issued_keys())
        // Policy-as-code rules (per-agent / per-argument) over the allowlist; a
        // no-op when no `[[policy]]` rules are defined.
        .with_policy_rules(cfg.policy_rules())
        // Inline injection / secret-exfil scanning (a no-op when mode is off).
        .with_inspect(cfg.gateway.inspect_scanner())
        // Which MCP revisions to answer for. Only `server/discover` reads this
        // on the gateway itself; the listener does its own per-request era
        // check, because that one needs the HTTP headers.
        .with_wire(cfg.gateway.wire)
        // How `tools/list` names each tool: as served, or with each server's
        // prefix.
        .with_tool_prefixes(cfg.tool_prefixes()))
}

/// Each `[[server]]`, in config order, as the gateway supervises it.
fn servers(cfg: &Config) -> Vec<Supervised> {
    cfg.servers.iter().map(|s| supervised(cfg, s)).collect()
}

/// Print what a config does that it should not have to (see
/// [`Config::warnings`]).
pub fn warn(cfg: &Config) {
    for warning in cfg.warnings() {
        eprintln!("mcpdef: warning — {warning}");
    }
}

/// What the gateway found in the tools its upstreams offer
/// ([`Gateway::tool_warnings`]) that [`warn`] has not already said from the
/// config alone.
pub fn tool_findings(cfg: &Config, gw: &Gateway) -> Vec<String> {
    let said: HashSet<String> = cfg.warnings().into_iter().collect();
    let mut findings = gw.tool_warnings();
    findings.retain(|finding| !said.contains(finding));
    findings
}

/// Build the upstream transport for one server (shared by `run` / `pin` /
/// `diff-tools`). HTTP transports carry the egress/SSRF policy `fetching`
/// gives, and an HTTPS one the TLS profile `tls` gives, its files read now.
/// An `oauth2` `[server.auth]` fetches its tokens as `fetching` says. A stdio
/// server gets its brokered credentials injected into the child env (the
/// token-broker path — the client's bearer is never passed through), each
/// read now from where its `[server.env]` says, and none of the variables in
/// `withheld`, which MCPdef reads secrets from
/// ([`Config::secret_vars`](crate::config::Config::secret_vars)).
pub async fn build_transport(
    s: &ServerConfig,
    fetching: &Fetching,
    tls: &TlsSettings,
    withheld: &[String],
) -> Result<Box<dyn Transport>> {
    Ok(match s.transport.as_str() {
        "stdio" => {
            let env = read_env(s).await?;
            Box::new(
                StdioChild::spawn_withholding(&s.command, &env, withheld)
                    .with_context(|| format!("spawning upstream '{}'", s.id))?,
            )
        }
        "streamable-http" => {
            let url = s
                .url
                .clone()
                .with_context(|| format!("server '{}': streamable-http needs a `url`", s.id))?;
            Box::new(http(s, HttpClient::streamable(url)?, fetching, tls).await?)
        }
        "sse" => {
            let url = s
                .url
                .clone()
                .with_context(|| format!("server '{}': sse needs a `url`", s.id))?;
            Box::new(http(s, HttpClient::legacy_sse(url)?, fetching, tls).await?)
        }
        "wasm" => {
            // In-path WASM sandbox: run an untrusted module with fuel + memory caps
            // and zero ambient capabilities (no fs/net/clock). No egress policy
            // applies — a sandboxed module has no network.
            let path = s
                .wasm_path()
                .with_context(|| format!("server '{}': wasm needs a `wasm` module path", s.id))?;
            Box::new(
                WasmUpstream::from_file(path, s.sandbox_limits())
                    .with_context(|| format!("loading wasm upstream '{}' from {path}", s.id))?,
            )
        }
        "wasm-component" => {
            // Component-model sandbox: run a `wasm32-wasip2` component under a
            // capability-scoped WASI. The only host capability is outbound TCP,
            // gated by the per-destination egress allowlist (default deny-all).
            let path = s.wasm_path().with_context(|| {
                format!(
                    "server '{}': wasm-component needs a `wasm` component path",
                    s.id
                )
            })?;
            let allow = s
                .egress_allow()
                .map_err(|e| anyhow::anyhow!(e))
                .with_context(|| format!("server '{}': invalid egress allowlist", s.id))?;
            Box::new(
                WasmComponentUpstream::from_file(path, s.sandbox_limits(), allow)
                    .await
                    .with_context(|| {
                        format!("loading wasm component upstream '{}' from {path}", s.id)
                    })?,
            )
        }
        other => anyhow::bail!("server '{}': unknown transport '{other}'", s.id),
    })
}

/// What `s`'s `[server.env]` sets, each value read now from where it says, for
/// a spawn. Each is read off the async workers ([`read_secret`]): a value a
/// command writes can take seconds, and a file can sit on a slow mount. An
/// error names the variable and where its value comes from, never a value.
async fn read_env(s: &ServerConfig) -> Result<Vec<(String, SecretString)>> {
    let mut env = Vec::with_capacity(s.env.len());
    for (name, value) in &s.env {
        match read_secret(value).await {
            Ok(value) => env.push((name.clone(), value)),
            Err(e) => anyhow::bail!("server '{}': [server.env] {name}: {e}", s.id),
        }
    }
    Ok(env)
}

/// An HTTP upstream's client, with its egress policy, its `[server.auth]`
/// credentials, and for HTTPS its TLS profile and any `connect_to`. The
/// credentials and the profile are read off the async workers: a secret a
/// command writes can take seconds. An `oauth2` token is fetched when the
/// first request needs it, through the egress guard with the gateway's own
/// TLS profile, as `fetching` says.
async fn http(
    s: &ServerConfig,
    client: HttpClient,
    fetching: &Fetching,
    tls: &TlsSettings,
) -> Result<HttpClient> {
    let mut client = client.with_egress(fetching.egress);
    match s.credentials() {
        None => {}
        Some(Err(e)) => anyhow::bail!("server '{}': [server.auth] {e}", s.id),
        Some(Ok(UpstreamAuth::Static(credential))) => {
            let auth = StaticAuth::read(credential)
                .await
                .with_context(|| format!("server '{}': [server.auth]", s.id))?;
            client = client.with_auth(Arc::new(auth));
        }
        Some(Ok(UpstreamAuth::OAuth2(grant))) => {
            let tokens = TokenAuth::new(grant, fetching.egress, fetching.tls.clone());
            client = client.with_auth(Arc::new(tokens));
        }
    }
    if !s.is_https() {
        return Ok(client);
    }
    // The default profile is the one the client already has: Mozilla's roots
    // alone, with nothing to read.
    if *tls != TlsSettings::default() {
        let profile = tls
            .load_async()
            .await
            .with_context(|| format!("server '{}': reading its TLS profile", s.id))?;
        client = client.with_tls(profile)?;
    }
    if let Some(ip) = s.connect_to().map_err(anyhow::Error::msg)? {
        client = client.with_connect_to(ip);
    }
    Ok(client)
}

/// The upstream `s` names in `cfg`, as the gateway keeps it running: opened
/// afresh from the entry for its first start and for every restart, so a
/// stdio server is spawned again and its environment read again, and an
/// HTTPS server's TLS files are read again.
pub fn supervised(cfg: &Config, s: &ServerConfig) -> Supervised {
    let tls = cfg.upstream_tls(s);
    Supervised {
        id: s.id.clone(),
        options: UpstreamOptions {
            spec: s.spec,
            max_inflight: s.max_inflight(),
            trip_after: s.trip_after(),
            tls_verify_disabled: s.is_https() && tls.insecure_skip_verify,
            credentials: s.auth.is_some(),
        },
        connect: opener(cfg, s),
    }
}

/// How to open `s` afresh, as `cfg` describes it: for its first start and
/// for every restart, and for the commands that list its tools. Each builds a
/// new transport from the config, so a stdio server is spawned again and its
/// environment read again.
pub fn opener(cfg: &Config, s: &ServerConfig) -> Connect {
    let (s, fetching, tls, withheld) = (
        Arc::new(s.clone()),
        Arc::new(Fetching::of(cfg)),
        Arc::new(cfg.upstream_tls(s)),
        Arc::new(cfg.secret_vars()),
    );
    Arc::new(move || {
        let (s, fetching, tls, withheld) = (
            Arc::clone(&s),
            Arc::clone(&fetching),
            Arc::clone(&tls),
            Arc::clone(&withheld),
        );
        Box::pin(async move { build_transport(&s, &fetching, &tls, &withheld).await })
    })
}
