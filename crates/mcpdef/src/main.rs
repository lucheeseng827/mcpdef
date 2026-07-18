// SPDX-License-Identifier: Apache-2.0
//! The `mcpdef` binary — a thin CLI over the `mcpdef` library.
//!
//! Subcommands (Phase 1 / 1.5):
//!   mcpdef run          --config mcpdef.toml   front the configured upstreams (stdio downstream)
//!   mcpdef validate     --config mcpdef.toml   structurally validate a config
//!   mcpdef servers list --config mcpdef.toml   show governed servers + exposed/denied tools
//!   mcpdef audit verify [--path F] [--head H --count N]   offline hash-chain check
//!   mcpdef audit tail   [--path F] [-n N] [--format json|ocsf|cef|syslog]
//!   mcpdef version                           print version + MCP spec target

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mcpdef::config::ServerConfig;
use mcpdef::listener::{AuthState, JwksRefresher};
use mcpdef::{handshake_list, serve_http, serve_stdio, Config, Gateway, HttpConfig};
use mcpdef_audit::{tail, verify, verify_against, ExportFormat, Ledger};
use mcpdef_auth::Verifier;
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::{tool_hash, DiffKind, PinStore};
use mcpdef_sandbox::{WasmComponentUpstream, WasmUpstream};
use mcpdef_transport::{EgressPolicy, HttpClient, StdioChild, Transport};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "mcpdef",
    version,
    about = "MCP gateway & governance plane (Phase 1.5)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the gateway: front the configured upstreams. Serves the client over
    /// stdio by default, or over Streamable HTTP with `--http`.
    Run {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Override the active gateway profile (`[profile.<name>]`) for this run,
        /// scoping the tool surface the agent sees (e.g. `--profile readonly`).
        #[arg(long)]
        profile: Option<String>,
        /// Serve clients over the downstream Streamable HTTP listener (bound to
        /// `[gateway] listen`) instead of stdio.
        #[arg(long)]
        http: bool,
    },
    /// Bring the gateway up on the Streamable HTTP listener — shorthand for
    /// `mcpdef run --http` (the shared-gateway shape: one endpoint, govern centrally).
    Up {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Override the active gateway profile for this run (e.g. `--profile readonly`).
        #[arg(long)]
        profile: Option<String>,
    },
    /// Invoke a single governed tool through the gateway, print the result, and
    /// exit — a one-shot client for demos and scripts. The allowlist, profiles,
    /// tool-def pinning, and rate limit all apply and the call is audited. (RBAC
    /// is not enforced here: it gates *authenticated* callers by token role, and
    /// this local CLI path carries no bearer — it is a trusted operator tool.)
    Call {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Override the active gateway profile for this call.
        #[arg(long)]
        profile: Option<String>,
        /// The tool to invoke (a name from `mcpdef servers list` / `tools/list`).
        tool: String,
        /// Tool arguments as a JSON object (default `{}`).
        #[arg(long, default_value = "{}")]
        args: String,
        /// Print the raw JSON-RPC result instead of just the text content.
        #[arg(long)]
        json: bool,
    },
    /// Validate a config file without starting the gateway.
    Validate {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
    /// Inspect the governed servers and the tools each exposes.
    Servers {
        #[command(subcommand)]
        cmd: ServersCmd,
    },
    /// Inspect the tamper-evident audit ledger.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Inspect the egress (SSRF) policy for HTTP upstreams.
    Egress {
        #[command(subcommand)]
        cmd: EgressCmd,
    },
    /// Pin the current tool definitions of all upstreams as approved (writes the
    /// pin store). Re-run after a legitimate tool change to re-approve.
    Pin {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
    /// Diff each upstream's current tool definitions against the pin store
    /// (read-only); exits non-zero if any pinned tool changed (a rug-pull).
    DiffTools {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
    /// Print version and the MCP spec target.
    Version,
}

#[derive(Subcommand)]
enum EgressCmd {
    /// Print the effective egress policy (the SSRF guard for HTTP upstreams).
    Show {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ServersCmd {
    /// List the governed servers and their configured allowlist / denies.
    List {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify the ledger's hash chain offline (exit non-zero on a break). With
    /// both --head and --count, also checks against a seal recorded out-of-band
    /// (catches tail-truncation / wholesale replacement that a plain chain check
    /// cannot).
    Verify {
        /// Ledger file. Overrides the audit path from --config.
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Expected head hash sealed out-of-band (use with --count).
        #[arg(long)]
        head: Option<String>,
        /// Expected record count sealed out-of-band (use with --head).
        #[arg(long)]
        count: Option<u64>,
    },
    /// Print the last N audit records in a SIEM-ready format.
    Tail {
        /// Ledger file. Overrides the audit path from --config.
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// How many trailing records to print.
        #[arg(short = 'n', long = "lines", default_value_t = 20)]
        lines: usize,
        /// Output format: json (default), ocsf, cef, or syslog.
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Version => {
            print_version();
            Ok(())
        }
        Cmd::Validate { config } => cmd_validate(&config),
        Cmd::Run {
            config,
            profile,
            http,
        } => cmd_run(&config, profile, http).await,
        Cmd::Up { config, profile } => cmd_run(&config, profile, true).await,
        Cmd::Call {
            config,
            profile,
            tool,
            args,
            json,
        } => cmd_call(&config, profile, &tool, &args, json).await,
        Cmd::Servers {
            cmd: ServersCmd::List { config },
        } => cmd_servers_list(&config),
        Cmd::Audit { cmd } => cmd_audit(cmd),
        Cmd::Egress {
            cmd: EgressCmd::Show { config },
        } => cmd_egress_show(&config),
        Cmd::Pin { config } => cmd_pin(&config).await,
        Cmd::DiffTools { config } => cmd_diff_tools(&config).await,
    }
}

/// Build the upstream transport for one server (shared by `run` / `pin` /
/// `diff-tools`). HTTP transports carry the egress/SSRF policy; a stdio server
/// gets its brokered credentials injected into the child env (the token-broker
/// path — the client's bearer is never passed through).
async fn build_transport(s: &ServerConfig, egress: EgressPolicy) -> Result<Box<dyn Transport>> {
    Ok(match s.transport.as_str() {
        "stdio" => {
            let env: Vec<(String, String)> =
                s.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            Box::new(
                StdioChild::spawn_with_env(&s.command, &env)
                    .with_context(|| format!("spawning upstream '{}'", s.id))?,
            )
        }
        "streamable-http" => {
            let url = s
                .url
                .clone()
                .with_context(|| format!("server '{}': streamable-http needs a `url`", s.id))?;
            Box::new(HttpClient::streamable(url)?.with_egress(egress))
        }
        "sse" => {
            let url = s
                .url
                .clone()
                .with_context(|| format!("server '{}': sse needs a `url`", s.id))?;
            Box::new(HttpClient::legacy_sse(url)?.with_egress(egress))
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

/// Connect every upstream, collecting each server's `tool name → hash` map.
async fn collect_tool_hashes(cfg: &Config) -> Result<Vec<(String, BTreeMap<String, String>)>> {
    let egress = cfg.gateway.egress_policy();
    let mut out = Vec::new();
    for s in &cfg.servers {
        let mut transport = build_transport(s, egress).await?;
        let tools = handshake_list(&mut *transport)
            .await
            .with_context(|| format!("listing tools for upstream '{}'", s.id))?;
        let mut map = BTreeMap::new();
        for t in &tools {
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                map.insert(name.to_string(), tool_hash(t));
            }
        }
        let _ = transport.close().await;
        out.push((s.id.clone(), map));
    }
    Ok(out)
}

/// `mcpdef pin` — record the current tool definitions of every upstream as the
/// approved baseline. Overwrites existing pins (re-approval after a change).
async fn cmd_pin(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let pins_path =
        cfg.gateway.pins.clone().context(
            "`mcpdef pin` needs a pin store: set `[gateway] pins = \"./mcpdef-pins.toml\"`",
        )?;
    let mut store = PinStore::load(&pins_path).with_context(|| format!("loading {pins_path}"))?;
    let mut recorded = 0usize;
    for (server, tools) in collect_tool_hashes(&cfg).await? {
        for (tool, hash) in tools {
            store.record(&server, &tool, hash);
            recorded += 1;
        }
    }
    store
        .save(&pins_path)
        .with_context(|| format!("writing {pins_path}"))?;
    println!(
        "pinned {recorded} tool definition(s) across {} server(s) → {pins_path}",
        cfg.servers.len()
    );
    Ok(())
}

/// `mcpdef diff-tools` — compare current tool definitions against the pins; exit
/// non-zero if any pinned tool's definition changed (a suspected rug-pull).
async fn cmd_diff_tools(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let pins_path = cfg.gateway.pins.clone().context(
        "`mcpdef diff-tools` needs a pin store: set `[gateway] pins = \"…\"` (run `mcpdef pin` first)",
    )?;
    let store = PinStore::load(&pins_path).with_context(|| format!("loading {pins_path}"))?;
    let mut rug_pull = false;
    for (server, current) in collect_tool_hashes(&cfg).await? {
        let diff = store.diff(&server, &current);
        if diff.is_empty() {
            println!("{server}: ok · {} tool(s) match pins", current.len());
            continue;
        }
        for d in &diff {
            let mark = match d.kind {
                DiffKind::Added => "+ added   (new, unpinned)",
                DiffKind::Removed => "- removed (was pinned)",
                DiffKind::Changed => "~ CHANGED (rug-pull!)",
            };
            if matches!(d.kind, DiffKind::Changed) {
                rug_pull = true;
            }
            println!("{server}: {mark}  {}", d.tool);
        }
    }
    if rug_pull {
        anyhow::bail!(
            "a pinned tool definition changed (possible rug-pull); review above, then `mcpdef pin` to re-approve"
        );
    }
    Ok(())
}

/// `mcpdef egress show` — print the effective SSRF guard for HTTP upstreams so an
/// operator can confirm the gateway's outbound posture (OSS-ROLLOUT.md §6).
fn cmd_egress_show(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let e = &cfg.gateway.egress;
    println!("egress policy (SSRF guard for HTTP upstreams):");
    println!(
        "  allow_private  : {:<5}  private / loopback / unique-local upstreams",
        e.allow_private
    );
    println!(
        "  require_https  : {:<5}  public destinations must use HTTPS",
        e.require_https
    );
    println!("  always blocked : 169.254.0.0/16 (incl. 169.254.169.254 metadata), fe80::/10, 0.0.0.0, ::");
    println!("  dns pinning    : on     resolved IPs are pinned to defeat DNS rebinding");
    println!("\n(stdio upstreams have no network egress; this governs streamable-http / sse only)");
    Ok(())
}

fn print_version() {
    println!(
        "mcpdef {}  ·  MCP gateway & governance plane",
        env!("CARGO_PKG_VERSION")
    );
    println!("  spec target : 2025-11-25 (planning the stateless 2026-07-28 RC)");
    println!(
        "  phase       : 1.5 — transport-mux proxy (stdio · Streamable HTTP · legacy SSE) + allowlist + audit"
    );
}

fn cmd_validate(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let errs = cfg.validate();
    if errs.is_empty() {
        println!(
            "ok: {} — {} upstream(s), config valid",
            path.display(),
            cfg.servers.len()
        );
        Ok(())
    } else {
        for e in &errs {
            eprintln!("  ✗ {e}");
        }
        anyhow::bail!("{} validation error(s) in {}", errs.len(), path.display());
    }
}

/// `mcpdef servers list` — a config-level view of what the gateway would govern.
/// This reads the declared allowlist/denies; it does not connect upstreams (run
/// `mcpdef run` for the live `tools/list`), so it is honest about being static.
fn cmd_servers_list(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let errs = cfg.validate();
    if !errs.is_empty() {
        for e in &errs {
            eprintln!("  ✗ {e}");
        }
        anyhow::bail!(
            "invalid config; run `mcpdef validate --config {}`",
            path.display()
        );
    }

    println!(
        "{:<12} {:<16} {:<10} {:<30} DENY",
        "ID", "TRANSPORT", "PROFILE", "ALLOWLISTED TOOLS"
    );
    for s in &cfg.servers {
        // Show the *resolved* policy (after applying the server's profile), so
        // the listing reflects what the gateway will actually enforce.
        let sp = cfg.resolve_server(s);
        let allow = match &sp.allow_tools {
            Some(t) if !t.is_empty() => t.join(", "),
            _ => "(all)".to_string(),
        };
        let deny = if sp.deny.is_empty() {
            "-".to_string()
        } else {
            sp.deny.join(", ")
        };
        println!(
            "{:<12} {:<16} {:<10} {:<30} {}",
            truncate(&s.id, 12),
            truncate(&s.transport, 16),
            truncate(s.profile.as_deref().unwrap_or("-"), 10),
            truncate(&allow, 30),
            deny
        );
    }
    if let Some(active) = &cfg.gateway.profile {
        println!("\nactive gateway profile: {active} (tools are additionally filtered through it)");
    }
    if !cfg.profiles.is_empty() {
        let mut names: Vec<&String> = cfg.profiles.keys().collect();
        names.sort();
        let names: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        println!("defined profiles: {}", names.join(", "));
    }
    println!(
        "{} server(s) governed · allowlist deny-by-default · `mcpdef run` for the live tool list",
        cfg.servers.len()
    );
    Ok(())
}

fn cmd_audit(cmd: AuditCmd) -> Result<()> {
    match cmd {
        AuditCmd::Verify {
            path,
            config,
            head,
            count,
        } => {
            let ledger = resolve_audit_path(path, &config)?;
            if !ledger.exists() {
                anyhow::bail!(
                    "audit ledger {} does not exist — nothing to verify (a gateway writes it on first run)",
                    ledger.display()
                );
            }
            let report = match (head, count) {
                (Some(h), Some(c)) => verify_against(&ledger, &h, c)
                    .with_context(|| format!("verifying {} against seal", ledger.display()))?,
                (None, None) => {
                    verify(&ledger).with_context(|| format!("verifying {}", ledger.display()))?
                }
                _ => anyhow::bail!("--head and --count must be given together (or neither)"),
            };
            if report.ok() {
                println!(
                    "chain OK · {} record(s) · head={}",
                    report.records, report.head
                );
                Ok(())
            } else {
                eprintln!(
                    "chain BROKEN at seq={} · {} record(s) · head={}",
                    report.broken_at.unwrap_or(0),
                    report.records,
                    report.head
                );
                anyhow::bail!("audit ledger {} failed verification", ledger.display());
            }
        }
        AuditCmd::Tail {
            path,
            config,
            lines,
            format,
        } => {
            let ledger = resolve_audit_path(path, &config)?;
            let fmt = ExportFormat::parse(&format).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown --format '{format}' (expected one of {:?})",
                    ExportFormat::NAMES
                )
            })?;
            let records =
                tail(&ledger, lines).with_context(|| format!("reading {}", ledger.display()))?;
            for rec in &records {
                println!("{}", rec.export(fmt));
            }
            Ok(())
        }
    }
}

/// Resolve the ledger path: an explicit `--path` wins; otherwise take the audit
/// path from the config file.
fn resolve_audit_path(path: Option<PathBuf>, config: &Path) -> Result<PathBuf> {
    if let Some(p) = path {
        return Ok(p);
    }
    let cfg = Config::load(config).with_context(|| {
        format!(
            "no --path given and could not load config {} for its audit path",
            config.display()
        )
    })?;
    Ok(PathBuf::from(cfg.gateway.audit))
}

/// Truncate `s` to `width` characters (not bytes) for the `servers list` columns,
/// appending an ellipsis when shortened. Counts/splits by `char` so a multi-byte
/// UTF-8 id never panics on a byte-boundary slice.
fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else if width <= 1 {
        "…".to_string()
    } else {
        let kept: String = s.chars().take(width - 1).collect();
        format!("{kept}…")
    }
}

/// Build the governed gateway from a (validated) config: open the audit ledger,
/// apply pinning / rate-limit / per-call timeout / RBAC, connect every upstream,
/// and persist any trust-on-first-use pins. Shared by `run`/`up` (then served)
/// and `call` (then issues one request). Does not enforce OAuth — that is the
/// HTTP listener's per-request job; the local CLI caller is trusted.
async fn build_gateway(cfg: &Config) -> Result<Gateway> {
    if let Some(parent) = Path::new(&cfg.gateway.audit).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let ledger = Ledger::open(&cfg.gateway.audit)
        .with_context(|| format!("opening audit ledger {}", cfg.gateway.audit))?;
    let mut gw = Gateway::new(cfg.to_policy(), ledger, "agent:unknown");
    if let Some(pins_path) = &cfg.gateway.pins {
        let store =
            PinStore::load(pins_path).with_context(|| format!("loading pin store {pins_path}"))?;
        gw = gw.with_pins(store, pins_path.clone());
    }
    let (rl_per_tool, rl_global) = cfg.gateway.rate_limit_settings();
    gw = gw
        .with_rate_limit(rl_per_tool, rl_global)
        .with_upstream_timeout(cfg.gateway.upstream_timeout())
        // RBAC over the allowlist for authenticated callers (a no-op when no
        // `[[role]]` is defined). The HTTP listener supplies the principal.
        .with_rbac(Some(cfg.rbac()))
        // Policy-as-code rules (per-agent / per-argument) over the allowlist; a
        // no-op when no `[[policy]]` rules are defined.
        .with_policy_rules(cfg.policy_rules())
        // Inline injection / secret-exfil scanning (a no-op when mode is off).
        .with_inspect(cfg.gateway.inspect_scanner());
    let egress = cfg.gateway.egress_policy();

    for s in &cfg.servers {
        let transport = build_transport(s, egress).await?;
        gw.add_upstream(s.id.clone(), transport)
            .await
            .with_context(|| format!("initializing upstream '{}'", s.id))?;
    }
    // Persist any trust-on-first-use pin additions made during connect.
    gw.persist_pins().context("saving pin store")?;
    Ok(gw)
}

/// Load + validate a config, applying a `--profile` override. The shared front
/// half of `run`/`up`/`call`.
fn load_validated(path: &Path, profile_override: Option<String>) -> Result<Config> {
    let mut cfg = Config::load(path)?;
    // A `--profile` flag overrides the config's active gateway profile; validate
    // afterwards so an unknown override is reported like any bad config.
    if profile_override.is_some() {
        cfg.gateway.profile = profile_override;
    }
    let errs = cfg.validate();
    if !errs.is_empty() {
        for e in &errs {
            eprintln!("  ✗ {e}");
        }
        anyhow::bail!(
            "invalid config; run `mcpdef validate --config {}`",
            path.display()
        );
    }
    Ok(cfg)
}

/// `mcpdef call <tool>` — invoke one governed tool through the gateway and print
/// the result. The allowlist/profile/pinning/rate-limit gates and the audit
/// ledger apply (RBAC does not — it gates authenticated callers, and this local
/// path has no principal). Exits non-zero if the tool (or a gate) returns an error.
async fn cmd_call(
    path: &Path,
    profile_override: Option<String>,
    tool: &str,
    args: &str,
    json: bool,
) -> Result<()> {
    let cfg = load_validated(path, profile_override)?;

    let arguments: serde_json::Value = serde_json::from_str(args)
        .with_context(|| format!("--args must be valid JSON (got: {args})"))?;
    if !arguments.is_object() {
        anyhow::bail!("--args must be a JSON object, e.g. --args '{{\"path\":\"/etc\"}}'");
    }

    let mut gw = build_gateway(&cfg).await?;
    let params = serde_json::json!({ "name": tool, "arguments": arguments });
    let resp = gw
        .handle(Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(params),
        ))
        .await?
        .context("gateway returned no response to tools/call")?;

    // A `tools/call` denial or upstream error comes back as a result with
    // `isError: true` (or, for an unexpected failure, a JSON-RPC `error`).
    let is_error = resp.error.is_some()
        || resp
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false);

    if json {
        let payload = resp
            .result
            .clone()
            .or_else(|| resp.error.clone())
            .unwrap_or(serde_json::Value::Null);
        println!("{}", serde_json::to_string_pretty(&payload)?);
        if is_error {
            anyhow::bail!("tool '{tool}' returned an error");
        }
    } else {
        let text = tool_result_text(&resp);
        if is_error {
            // The denial/error reason is the message; anyhow prints it once.
            anyhow::bail!("{text}");
        }
        println!("{text}");
    }
    Ok(())
}

/// The human-readable text of a `tools/call` response: the joined `content[].text`
/// blocks, falling back to the raw result JSON or the JSON-RPC error message.
fn tool_result_text(resp: &Message) -> String {
    if let Some(result) = &resp.result {
        if let Some(items) = result.get("content").and_then(|c| c.as_array()) {
            let texts: Vec<&str> = items
                .iter()
                .filter_map(|it| it.get("text").and_then(|t| t.as_str()))
                .collect();
            if !texts.is_empty() {
                return texts.join("\n");
            }
        }
        return result.to_string();
    }
    if let Some(err) = &resp.error {
        return err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("(unknown error)")
            .to_string();
    }
    String::new()
}

async fn cmd_run(path: &Path, profile_override: Option<String>, http: bool) -> Result<()> {
    let cfg = load_validated(path, profile_override)?;
    let mut gw = build_gateway(&cfg).await?;

    let profile_note = cfg
        .gateway
        .profile
        .as_deref()
        .map(|p| format!(" · profile {p}"))
        .unwrap_or_default();
    let drift = gw.drift_count();
    let drift_note = if drift > 0 {
        format!(" · ⚠ {drift} rug-pulled tool(s) denied")
    } else {
        String::new()
    };
    // Build the OAuth 2.1 verifier (HTTP listener only). Done before printing the
    // ready line so a bad JWKS / blocked jwks_uri fails fast.
    let auth = if http {
        build_verifier(&cfg).await?
    } else {
        if cfg.gateway.auth.enabled {
            eprintln!(
                "mcpdef: warning — [gateway.auth] is enabled but applies only to the HTTP listener; \
                 stdio has no per-request transport identity, so auth is not enforced over stdio"
            );
        }
        None
    };
    let auth_note = match (&auth, cfg.roles.len()) {
        (Some(_), 0) => " · oauth on".to_string(),
        (Some(_), n) => format!(" · oauth on · {n} role(s)"),
        (None, _) => String::new(),
    };
    let transport_note = if http {
        format!("streamable-http {}", cfg.gateway.listen)
    } else {
        "stdio".to_string()
    };
    eprintln!(
        "mcpdef {} ready · {} upstream(s) · audit {}{}{}{} · listening {}",
        env!("CARGO_PKG_VERSION"),
        gw.upstream_count(),
        cfg.gateway.audit,
        profile_note,
        drift_note,
        auth_note,
        transport_note
    );

    if http {
        let http_cfg = HttpConfig {
            listen: cfg.gateway.listen.clone(),
            allowed_origins: cfg.gateway.allowed_origins.clone(),
            max_inflight: cfg.gateway.max_inflight,
        };
        serve_http(gw, http_cfg, auth).await
    } else {
        serve_stdio(&mut gw).await
    }
}

/// Build the OAuth 2.1 [`Verifier`] from `[gateway.auth]`, or `None` when auth is
/// disabled. The JWKS comes from inline JSON / a file (`jwks`) or is fetched from
/// `jwks_uri` through the egress/SSRF guard.
async fn build_verifier(cfg: &Config) -> Result<Option<AuthState>> {
    let auth = &cfg.gateway.auth;
    if !auth.enabled {
        return Ok(None);
    }
    // validate() already guaranteed these are present when enabled.
    let issuer = auth
        .issuer
        .clone()
        .context("[gateway.auth] enabled but `issuer` is unset")?;
    let resource = auth
        .resource
        .clone()
        .context("[gateway.auth] enabled but `resource` is unset")?;

    // Keys come from a static inline/file JWKS, or a `jwks_uri` we can re-fetch to
    // pick up an authorization-server signing-key rotation at runtime.
    let (jwks_json, refresher) = if let Some(j) = &auth.jwks {
        // Inline JSON (starts with `{`) or a path to a JWKS file.
        let json = if j.trim_start().starts_with('{') {
            j.clone()
        } else {
            std::fs::read_to_string(j).with_context(|| format!("reading JWKS file {j}"))?
        };
        (json, None)
    } else if let Some(uri) = &auth.jwks_uri {
        let json = mcpdef_transport::fetch_text(uri, &cfg.gateway.egress_policy())
            .await
            .with_context(|| format!("fetching jwks_uri {uri}"))?;
        (
            json,
            Some(JwksRefresher::new(uri.clone(), cfg.gateway.egress_policy())),
        )
    } else {
        anyhow::bail!("[gateway.auth] enabled but neither `jwks` nor `jwks_uri` is set");
    };

    let verifier = Verifier::from_jwks_json(&jwks_json, issuer, resource)
        .map_err(|e| anyhow::anyhow!("building OAuth verifier: {e}"))?;
    let state = match refresher {
        Some(r) => AuthState::with_refresher(verifier, r),
        None => AuthState::new(verifier),
    };
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncate_counts_chars_and_never_panics_on_utf8() {
        // ASCII: shortened with an ellipsis, kept under the width.
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc"); // already short
                                               // Multi-byte UTF-8 must not panic on a byte-boundary slice.
        assert_eq!(truncate("héllo-wörld", 4), "hél…");
        assert_eq!(truncate("日本語サーバ", 3), "日本…");
        // Degenerate widths.
        assert_eq!(truncate("abc", 1), "…");
    }
}
