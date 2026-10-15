// SPDX-License-Identifier: Apache-2.0
//! The `mcpdef` binary — a thin CLI over the `mcpdef` library.
//!
//! Subcommands:
//!   mcpdef run          --config mcpdef.toml   front the configured upstreams (stdio downstream)
//!   mcpdef up           --config mcpdef.toml   the same over Streamable HTTP (`run --http`)
//!   mcpdef bridge <url> [--ca F] [--cert F --key F] [--token-file F]   stdio to a remote gateway
//!   mcpdef connect <client> [--write]   the entry a client needs: claude-code, cursor, vscode, …
//!   mcpdef call <tool>  --config mcpdef.toml [--args JSON]   one governed, audited tool call
//!   mcpdef validate     --config mcpdef.toml   structurally validate a config
//!   mcpdef doctor       --config mcpdef.toml   what is wrong, or soon will be, end to end
//!   mcpdef servers list --config mcpdef.toml   show governed servers + exposed/denied tools
//!   mcpdef tools list   --config mcpdef.toml [--cost]   the tools the gateway lists, or their cost
//!   mcpdef audit verify [--path F] [--head H --count N]   offline hash-chain check
//!   mcpdef audit tail   [--path F] [-n N] [--format json|ocsf|cef|syslog]
//!   mcpdef egress show  --config mcpdef.toml   the egress (SSRF) policy for HTTP upstreams
//!   mcpdef pin          --config mcpdef.toml   approve the upstreams' current tool definitions
//!   mcpdef diff-tools   --config mcpdef.toml   compare them to the pins; non-zero on a change
//!   mcpdef tls init     --config mcpdef.toml [--new-ca]   the local CA, and how clients trust it
//!   mcpdef tls show     --config mcpdef.toml   each listener's TLS, the local CA, upstream profiles
//!   mcpdef tls export-ca --config mcpdef.toml [--out F]   the local CA's certificate
//!   mcpdef tls issue    --client NAME [--spiffe-id ID] [--days N] [--out DIR]   a client's certificate
//!   mcpdef tls revoke   <serial | certificate file>   revoke one, in the local CA's CRL
//!   mcpdef tls pin      <url>                  an HTTPS server's SPKI pin
//!   mcpdef version                           print the version and the MCP revisions it speaks

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use mcpdef::bridge::Bridge;
use mcpdef::clients::{self, Ask, Client, Target, Wrote};
use mcpdef::config::{
    AuthConfig, AuthMethod, AuthRequire, CertIdentity, ClientAuthConfig, ListenerTlsConfig,
    ListenerTlsMode,
};
use mcpdef::connect::{build_gateway, examine, opener, tool_findings, warn};
use mcpdef::doctor::{self, Finding, Mark, Section};
use mcpdef::listener::{
    serve_http_on, serve_https_on, serve_proxied_on, AuthState, Fetching, JwksRefresher,
};
use mcpdef::redact::{redact_url, redact_urls};
use mcpdef::reload::{Reloader, Snapshot, WATCH_INTERVAL};
use mcpdef::tls::issued::{self, Revoked};
use mcpdef::tls::{self, local_ca, ListenerTls, Serving};
use mcpdef::{
    list_tools_speaking, serve_admin_on, serve_stdio, AdminState, Config, HealthState, HttpConfig,
    Metrics, ToolCost,
};
use mcpdef_audit::{tail, verify, verify_against, ExportFormat};
use mcpdef_auth::Verifier;
use mcpdef_core::wire::{WireMode, KNOWN_SPEC_VERSIONS};
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::{tool_hash, DiffKind, PinStore};
use mcpdef_transport::{
    rfc3339, CertificateNames, MinVersion, PeerCertificate, Roots, TlsSettings, Verification,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[derive(Parser)]
#[command(name = "mcpdef", version, about = "MCP gateway & governance plane")]
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
    /// Bridge a stdio MCP client to a remote MCPdef, or to any Streamable-HTTP
    /// MCP endpoint, with a private CA, a client certificate and a token file
    /// for a client that cannot use them itself. It is the gateway with that
    /// one upstream, and governance passes through: the remote end decides.
    Bridge {
        /// The remote end's MCP endpoint, e.g. `https://mcpdef.example.com/mcp`.
        url: String,
        /// A CA to trust for it (PEM), in place of the system's. Repeatable.
        #[arg(long)]
        ca: Vec<PathBuf>,
        /// A client certificate to present (PEM, with its chain). Needs `--key`.
        #[arg(long, requires = "key")]
        cert: Option<PathBuf>,
        /// The client certificate's private key (PEM). Needs `--cert`.
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
        /// A file holding the bearer token to send. Read when needed, never printed.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// The MCP revision the remote end speaks: `auto`, `2025-11-25` or `2026-07-28`.
        #[arg(long, default_value = "auto")]
        spec: String,
        /// The bridge's own ledger [default: ~/.mcpdef/bridge/audit.log].
        #[arg(long)]
        audit: Option<PathBuf>,
        /// Where the bridge keeps its state [default: ~/.mcpdef/bridge/state].
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Print the config the bridge runs, and exit. It is a gateway config:
        /// save it as a file to run it with `mcpdef run` instead.
        #[arg(long)]
        print_config: bool,
    },
    /// Print the entry an MCP client needs to reach this gateway, in that
    /// client's own format, or merge it into the client's config file.
    /// Claude Desktop, and any client given a certificate, gets a `bridge` entry.
    Connect {
        /// claude-code, claude-desktop, cursor, vscode, codex or generic.
        client: String,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// The gateway's URL, when clients reach it at another: a load balancer's, say.
        #[arg(long)]
        url: Option<String>,
        /// The entry's name in the client.
        #[arg(long, default_value = "mcpdef")]
        name: String,
        /// An environment variable holding a bearer token, for a client that sends it.
        /// The entry names the variable, never its value.
        #[arg(long)]
        token_env: Option<String>,
        /// A file holding a bearer token, for a `bridge` entry.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// A client certificate to present (PEM): the entry becomes a `bridge` one.
        #[arg(long, requires = "key")]
        cert: Option<PathBuf>,
        /// The client certificate's private key (PEM).
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
        /// Merge the entry into the client's config file, keeping a `.bak` of it.
        #[arg(long)]
        write: bool,
        /// The file to merge into, in place of the client's usual one.
        #[arg(long, requires = "write")]
        file: Option<PathBuf>,
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
        /// Refuse what would otherwise be a warning, as `[gateway] strict =
        /// true` does: a secret written in the config, a secret file others
        /// can read, a certificate not checked, credentials sent in the clear.
        #[arg(long)]
        strict: bool,
    },
    /// Check a gateway end to end and say what is wrong, or soon will be: the
    /// config, the TLS of its listeners, the identity provider's keys and
    /// clock, the admin listener's exposure, and each upstream as `run` opens
    /// it. Keeps nothing a running gateway keeps: no audit record, no pin.
    /// Exits non-zero if anything is broken.
    Doctor {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// How long an upstream may take to open, in seconds, where
        /// `[gateway] upstream_timeout_ms` does not say.
        #[arg(long, default_value_t = 30)]
        wait: u64,
    },
    /// Inspect the governed servers and the tools each exposes.
    Servers {
        #[command(subcommand)]
        cmd: ServersCmd,
    },
    /// Inspect the tools the gateway lists to its clients.
    Tools {
        #[command(subcommand)]
        cmd: ToolsCmd,
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
    /// TLS: on the gateway's own listeners, and towards upstreams.
    Tls {
        #[command(subcommand)]
        cmd: TlsCmd,
    },
    /// Authentication: what the gateway makes of a caller's token.
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
    /// Client keys the gateway issues, for callers of the MCP listener.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// The admin listener: its console and API.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Signing people in to the console at an identity provider.
    Sso {
        #[command(subcommand)]
        cmd: SsoCmd,
    },
    /// Print the version and the MCP revisions this build speaks.
    Version,
}

#[derive(Subcommand)]
enum AuthCmd {
    /// Verify a bearer token as the MCP listener does, and say whom it names:
    /// the subject and roles `[identity]` reads from it, its scopes, and on
    /// each server what those roles grant. Exits non-zero for a token the
    /// listener would refuse, saying why.
    Test {
        /// The token; `-` reads it from stdin, which keeps it out of the
        /// shell's history.
        #[arg(long, conflicts_with = "token_file")]
        token: Option<String>,
        /// A file holding the token.
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Make a client key: printed this once, with the `[[key]]` that keeps
    /// its SHA-256 and the roles it holds. A reload takes it, and one removed
    /// and reloaded opens nothing from then on. Its caller is `key:<name>`.
    Create {
        /// Its caller's name: the ledger records `key:<name>`.
        #[arg(long)]
        name: String,
        /// A `[[role]]` it holds; give it again for each.
        #[arg(long = "role", required = true)]
        roles: Vec<String>,
    },
}

#[derive(Subcommand)]
enum SsoCmd {
    /// The config that signs people in to the console at a provider, and what
    /// to set there: the redirect URIs, the scopes, and which claim carries
    /// roles or groups. Printed as TOML, its prose in comments; `--write`
    /// merges it into the config file instead, keeping a `.bak`.
    Init {
        /// keycloak, entra, okta, google, authentik, generic or saml-broker.
        #[arg(long)]
        provider: String,
        /// The provider's issuer, exactly as its tokens write it. Without it,
        /// an example of the provider's is shown.
        #[arg(long)]
        issuer: Option<String>,
        /// The client registered with the provider.
        #[arg(long, default_value = "mcpdef-console")]
        client_id: String,
        /// The console's origin, as its users reach it; the config's
        /// `[gateway.admin] public_url` without it.
        #[arg(long)]
        public_url: Option<String>,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Merge it into the config file, keeping a `.bak` of the file.
        #[arg(long)]
        write: bool,
    },
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Make a break-glass token: one that holds `console:admin` on the admin
    /// API, for when the identity provider signs no one in. It is printed
    /// this once, with the SHA-256 that `[gateway.admin.break_glass]` keeps;
    /// the config never holds the token.
    Token,
}

#[derive(Subcommand)]
enum TlsCmd {
    /// Make the local CA and the certificate it issues the listeners, as
    /// `[gateway.tls] mode = "self-signed"` serves them, and print how each
    /// client comes to trust the CA. A CA already there is kept, and so is a
    /// certificate that still does.
    Init {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Make a new CA in place of the one there: one that vouches for a
        /// name the old one does not. Every client has to trust it instead.
        #[arg(long)]
        new_ca: bool,
    },
    /// Show the TLS of the gateway's listeners (each one's certificate, its
    /// names and when it expires, and the local CA), each HTTPS upstream's
    /// profile, and what to fix.
    Show {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
    /// Print the local CA's certificate, for a client to trust. Its key
    /// stays where it is.
    ExportCa {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Write it to this file instead.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Issue a client certificate from the local CA, for a workload to
    /// present where `[gateway.tls.client_auth]` asks for one: its name as
    /// the subject's common name, and its SPIFFE ID in a URI name if given.
    /// Writes `<client>.crt` and `<client>.key` in `--out`, the key readable
    /// by its owner alone, and prints the serial that revokes it. Makes the
    /// local CA if there is none, and writes its CRL, so that
    /// `[gateway.tls.client_auth] crl` can name it at once.
    Issue {
        /// Who it is for: the common name `identity = "subject-cn"` reads,
        /// and the files' name.
        #[arg(long)]
        client: String,
        /// Its SPIFFE ID, which `identity = "spiffe"` reads.
        #[arg(long)]
        spiffe_id: Option<String>,
        /// How many days it is valid for.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3650))]
        days: u64,
        /// The directory to write it in.
        #[arg(long, default_value = ".")]
        out: PathBuf,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
    /// Revoke a client certificate the local CA issued: put it in the CA's
    /// CRL. A gateway whose `[gateway.tls.client_auth] crl` names the CRL
    /// refuses it from its next reload, on connections already open too.
    Revoke {
        /// Its serial, as `tls issue` printed it, or its certificate's file.
        certificate: String,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
    /// Print the SPKI pin of the certificate an HTTPS server presents, as a
    /// `pin_sha256` line for its `[server.tls]`. The connection goes through
    /// the egress guard and is not verified: check the fingerprint it prints
    /// against the server's own before trusting the pin.
    Pin {
        /// The server's URL, as its `[[server]]` gives it.
        url: String,
        /// Dial this address rather than what the URL's host resolves to, as
        /// `connect_to` does.
        #[arg(long)]
        connect_to: Option<std::net::IpAddr>,
        /// Take `[gateway.egress]` from this config. Without one, the guard's
        /// defaults apply.
        #[arg(long)]
        config: Option<PathBuf>,
    },
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
enum ToolsCmd {
    /// List the tools a client is listed: every upstream opened, and the
    /// allowlist, the profile, the pins and the scanner applied, as `mcpdef
    /// run` applies them. New tools are pinned on first use, as there.
    List {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Override the active gateway profile, as `mcpdef run --profile`
        /// does.
        #[arg(long)]
        profile: Option<String>,
        /// Instead, what each server's tools add to every agent's context:
        /// how many are listed of those it offers, the bytes they take up in
        /// `tools/list`, and bytes ÷ 4, an estimate of the tokens.
        #[arg(long)]
        cost: bool,
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
async fn main() -> ExitCode {
    // Before anything can build a TLS configuration: every TLS connection this
    // process makes runs on ring.
    mcpdef_transport::install_crypto_provider();
    match run(Cli::parse().cmd).await {
        Ok(()) => ExitCode::SUCCESS,
        // As `main` returning it prints it, less any secret a URL in it holds.
        Err(e) => {
            eprintln!("Error: {}", redact_urls(&format!("{e:?}")));
            ExitCode::FAILURE
        }
    }
}

/// Run the command the command line names.
async fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Auth {
            cmd:
                AuthCmd::Test {
                    token,
                    token_file,
                    config,
                },
        } => cmd_auth_test(&config, token, token_file.as_deref()).await,
        Cmd::Admin {
            cmd: AdminCmd::Token,
        } => cmd_admin_token(),
        Cmd::Keys {
            cmd: KeysCmd::Create { name, roles },
        } => cmd_keys_create(&name, &roles),
        Cmd::Sso {
            cmd:
                SsoCmd::Init {
                    provider,
                    issuer,
                    client_id,
                    public_url,
                    config,
                    write,
                },
        } => cmd_sso_init(&provider, issuer, client_id, public_url, &config, write),
        Cmd::Version => {
            print_version();
            Ok(())
        }
        Cmd::Validate { config, strict } => cmd_validate(&config, strict),
        Cmd::Doctor { config, wait } => cmd_doctor(&config, Duration::from_secs(wait)).await,
        Cmd::Run {
            config,
            profile,
            http,
        } => cmd_run(&config, profile, http).await,
        Cmd::Up { config, profile } => cmd_run(&config, profile, true).await,
        Cmd::Bridge {
            url,
            ca,
            cert,
            key,
            token_file,
            spec,
            audit,
            state_dir,
            print_config,
        } => {
            // Only a default needs a home directory: flags that name both
            // places make the bridge independent of one.
            let home = match (&audit, &state_dir) {
                (Some(_), Some(_)) => None,
                _ => Some(mcpdef::bridge::default_home()?),
            };
            let bridge = Bridge {
                url,
                ca,
                cert,
                key,
                token_file,
                spec,
                audit: audit.unwrap_or_else(|| home.as_ref().unwrap().join("audit.log")),
                state_dir: state_dir.unwrap_or_else(|| home.as_ref().unwrap().join("state")),
            };
            cmd_bridge(bridge, print_config).await
        }
        Cmd::Connect {
            client,
            config,
            url,
            name,
            token_env,
            token_file,
            cert,
            key,
            write,
            file,
        } => cmd_connect(
            &client,
            &config,
            url,
            Ask {
                name,
                token_env,
                token_file,
                cert,
                key,
                mcpdef: std::env::current_exe().context("finding this binary's path")?,
            },
            write,
            file,
        ),
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
        Cmd::Tools {
            cmd:
                ToolsCmd::List {
                    config,
                    profile,
                    cost,
                },
        } => cmd_tools_list(&config, profile, cost).await,
        Cmd::Audit { cmd } => cmd_audit(cmd),
        Cmd::Egress {
            cmd: EgressCmd::Show { config },
        } => cmd_egress_show(&config),
        Cmd::Pin { config } => cmd_pin(&config).await,
        Cmd::DiffTools { config } => cmd_diff_tools(&config).await,
        Cmd::Tls { cmd } => match cmd {
            TlsCmd::Init { config, new_ca } => cmd_tls_init(&config, new_ca),
            TlsCmd::Show { config } => cmd_tls_show(&config),
            TlsCmd::ExportCa { config, out } => cmd_tls_export_ca(&config, out.as_deref()),
            TlsCmd::Issue {
                client,
                spiffe_id,
                days,
                out,
                config,
            } => cmd_tls_issue(&config, &client, spiffe_id.as_deref(), days, &out),
            TlsCmd::Revoke {
                certificate,
                config,
            } => cmd_tls_revoke(&config, &certificate),
            TlsCmd::Pin {
                url,
                connect_to,
                config,
            } => cmd_tls_pin(&url, connect_to, config.as_deref()).await,
        },
    }
}

/// Connect every upstream, collecting each server's `tool name → hash` map.
async fn collect_tool_hashes(cfg: &Config) -> Result<Vec<(String, BTreeMap<String, String>)>> {
    warn(cfg);
    let mut out = Vec::new();
    for s in &cfg.servers {
        let mut transport = opener(cfg, s)().await?;
        let tools = list_tools_speaking(&s.id, &mut *transport, s.spec)
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

/// `mcpdef tls pin <url>` — print the SPKI pin of the certificate an HTTPS
/// server presents, as a `pin_sha256` line to paste into its `[server.tls]`.
/// Every other line is a TOML comment, so the whole output pastes as it is.
/// The connection is not verified, which is what the pin will be for: check
/// the fingerprint against the server's own out of band first.
async fn cmd_tls_pin(
    url: &str,
    connect_to: Option<std::net::IpAddr>,
    config: Option<&Path>,
) -> Result<()> {
    let policy = match config {
        Some(path) => Config::load(path)?.gateway.egress_policy(),
        None => mcpdef_transport::EgressPolicy::default(),
    };
    let presented = mcpdef_transport::presented_certificate(url, &policy, connect_to)
        .await
        .with_context(|| format!("reading the certificate {url} presents"))?;
    let names = presented.names();
    let names = match names.is_empty() {
        true => "no DNS name or URI".to_string(),
        false => names.join(", "),
    };
    println!(
        "# {url}: {} presented a certificate for {names}",
        presented.addr
    );
    println!("# sha256 fingerprint {}", presented.fingerprint());
    println!(
        "# Not verified: check the fingerprint against the server's own before trusting \
         this pin."
    );
    println!("pin_sha256 = [\"{}\"]", presented.pin);
    Ok(())
}

/// `mcpdef tls issue` — a client's certificate from the local CA, and what
/// `[gateway.tls.client_auth]` needs to take it.
fn cmd_tls_issue(
    path: &Path,
    client: &str,
    spiffe_id: Option<&str>,
    days: u64,
    out: &Path,
) -> Result<()> {
    let cfg = Config::load(path)?;
    let g = &cfg.gateway;
    let paths = local_ca::Paths::under(&g.state_dir);
    let who = issued::Client {
        name: client,
        spiffe_id,
    };
    let lifetime = Duration::from_secs(days * 86_400);
    let done = issued::issue(
        &paths,
        &self_signed_names(&cfg),
        &who,
        lifetime,
        out,
        SystemTime::now(),
    )
    .map_err(anyhow::Error::msg)?;
    for note in &done.notes {
        println!("mcpdef: {note}");
    }
    let absolute = |path: &Path| std::fs::canonicalize(path).unwrap_or(path.to_path_buf());
    let spiffe = spiffe_id.map_or(String::new(), |id| format!(", spiffe {id}"));
    println!("certificate  : {}", absolute(&done.cert).display());
    println!(
        "key          : {}, its owner's alone",
        absolute(&done.key).display()
    );
    println!("serial       : {}", done.serial);
    println!("until        : {}", rfc3339(done.not_after));
    println!("identity     : subject-cn {client}{spiffe}");
    println!();

    let (ca, crl) = (absolute(&paths.ca_cert()), absolute(&paths.crl()));
    let client_auth = &g.tls.client_auth;
    let names =
        |files: &[String], file: &Path| files.iter().any(|f| absolute(Path::new(f)) == file);
    if client_auth.mode.is_on() && names(&client_auth.ca, &ca) && names(&client_auth.crl, &crl) {
        println!(
            "[gateway.tls.client_auth] in {} takes it: its `ca` and `crl` name the local CA's.",
            path.display()
        );
    } else {
        let toml = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
        println!("For the gateway to take it, its [gateway.tls.client_auth] names the local CA and its CRL:");
        println!();
        println!("[gateway.tls.client_auth]");
        println!("mode = \"required\"");
        println!("ca = [{}]", toml(&ca));
        println!("crl = [{}]", toml(&crl));
        match spiffe_id.map(issued::trust_domain) {
            Some(domain) => {
                println!("identity = \"spiffe\"");
                println!(
                    "trust_domains = [{}]",
                    toml::Value::String(domain.to_string())
                );
            }
            None => println!("identity = \"subject-cn\""),
        }
        if g.tls.mode == ListenerTlsMode::Off {
            println!();
            println!(
                "and [gateway.tls] on: a certificate is asked for at the TLS handshake, and the \
                 listener in {} serves plain HTTP.",
                path.display()
            );
        }
    }
    println!();
    println!("`mcpdef tls revoke {}` revokes it.", done.serial);
    Ok(())
}

/// `mcpdef tls revoke` — put a certificate the local CA issued in its CRL.
fn cmd_tls_revoke(path: &Path, certificate: &str) -> Result<()> {
    let cfg = Config::load(path)?;
    let paths = local_ca::Paths::under(&cfg.gateway.state_dir);
    let file = Path::new(certificate);
    let serial = if file.is_file() {
        let der = CertificateDer::from_pem_file(file)
            .with_context(|| format!("reading the certificate {}", file.display()))?;
        mcpdef_transport::certificate_serial(&der)
            .with_context(|| format!("{} holds no serial that reads", file.display()))?
    } else {
        issued::parse_serial(certificate)
            .map_err(|e| anyhow::anyhow!("{e}, nor a file that holds a certificate"))?
    };
    let hex = issued::serial_hex(&serial);
    let revoked = issued::revoke(&paths, &serial, SystemTime::now()).map_err(anyhow::Error::msg)?;
    let crl = std::fs::canonicalize(paths.crl()).unwrap_or(paths.crl());
    match revoked {
        Revoked::Now { listed } => println!(
            "revoked {hex}: {} revokes {listed} certificate(s)",
            crl.display()
        ),
        Revoked::Already { at } => println!(
            "{hex} was revoked already, at {}: {} is as it was",
            rfc3339(at),
            crl.display()
        ),
    }
    println!(
        "A gateway whose [gateway.tls.client_auth] crl names it refuses the certificate from its \
         next reload, on connections already open too: send it SIGHUP, or set [gateway] \
         watch_config = true for it to see the CRL change."
    );
    Ok(())
}

/// The names a local CA is made for: the listeners', as self-signed mode
/// serves them, the admin listener's too if it takes the MCP listener's TLS
/// or has self-signed of its own.
fn self_signed_names(cfg: &Config) -> local_ca::Names {
    let g = &cfg.gateway;
    let admin = g.admin.enabled
        && g.admin
            .tls
            .as_ref()
            .is_none_or(|tls| tls.mode == ListenerTlsMode::SelfSigned);
    tls::self_signed_names(cfg, true, admin)
}

/// `mcpdef tls init` — make the local CA and the certificate it issues the
/// listeners, as `[gateway.tls] mode = "self-signed"` serves them, and print
/// how each client comes to trust the CA.
fn cmd_tls_init(path: &Path, new_ca: bool) -> Result<()> {
    let cfg = Config::load(path)?;
    let g = &cfg.gateway;
    if g.tls.mode == ListenerTlsMode::Files {
        anyhow::bail!(
            "[gateway.tls] mode is \"files\" in {}: the listener serves the certificate its \
             files hold, and needs no local CA. For one, set mode = \"self-signed\"",
            path.display()
        );
    }
    let names = self_signed_names(&cfg);
    let paths = local_ca::Paths::under(&g.state_dir);
    let now = SystemTime::now();
    if new_ca {
        let ca = local_ca::LocalCa::new(&names, now).map_err(anyhow::Error::msg)?;
        ca.write(&paths).map_err(anyhow::Error::msg)?;
        println!(
            "mcpdef: made a new local CA, {}, for {names}: a client that trusted the one before \
             has to trust this one instead",
            paths.ca_cert().display()
        );
        if issued::refresh_crl(&paths, now).map_err(anyhow::Error::msg)? {
            println!(
                "mcpdef: wrote the new CA's CRL, {}: from the next reload, a client \
                 certificate the old CA issued is refused. `mcpdef tls issue` issues each \
                 client a new one",
                paths.crl().display()
            );
        }
    }
    let ensured = local_ca::ensure(&paths, &names, now, true).map_err(anyhow::Error::msg)?;
    for note in &ensured.notes {
        println!("mcpdef: {note}");
    }
    let ca = local_ca::LocalCa::load(&paths)
        .map_err(anyhow::Error::msg)?
        .context("the local CA is gone")?;
    let absolute = |path: PathBuf| std::fs::canonicalize(&path).unwrap_or(path);
    let ca_path = absolute(paths.ca_cert());
    let ca_names = CertificateNames::read(ca.cert_der());
    println!();
    println!("local CA     : {}", ca_path.display());
    println!(
        "               {}, until {}",
        ca_names.subject.unwrap_or_default(),
        rfc3339(ca.not_after().unwrap_or_default())
    );
    println!(
        "               sha256 {}",
        PeerCertificate::read(ca.cert_der()).fingerprint
    );
    println!(
        "certificate  : {}, for {names}",
        absolute(paths.cert()).display()
    );
    println!(
        "               until {}: the gateway issues it again before then",
        rfc3339(ensured.not_after)
    );
    println!();
    println!("Each client that connects over TLS has to trust the CA:");
    let ca = ca_path.display();
    println!("  Claude Code  : export NODE_EXTRA_CA_CERTS={ca}");
    println!("  Codex        : export CODEX_CA_CERTIFICATE={ca}");
    println!(
        "  curl         : curl --cacert {ca} {}",
        clients::listener_url(&g.listen, true)
    );
    println!("  VS Code, Cursor and the rest trust the system's store:");
    for line in clients::system_store(&ca_path) {
        println!("                 {line}");
    }
    if g.tls.mode == ListenerTlsMode::Off {
        println!();
        println!(
            "Then set [gateway.tls] mode = \"self-signed\" in {}: until then the listener \
             serves plain HTTP.",
            path.display()
        );
    }
    println!();
    println!(
        "`mcpdef connect <client>` prints the entry each client needs, this CA included: \
         claude-code, claude-desktop, cursor, vscode, codex or generic."
    );
    Ok(())
}

/// `mcpdef tls export-ca` — the local CA's certificate, for a client to
/// trust: printed, or written to `out`.
fn cmd_tls_export_ca(path: &Path, out: Option<&Path>) -> Result<()> {
    let cfg = Config::load(path)?;
    let paths = local_ca::Paths::under(&cfg.gateway.state_dir);
    let pem = local_ca::ca_cert_pem(&paths)
        .map_err(anyhow::Error::msg)?
        .with_context(|| {
            format!(
                "there is no local CA in {}: make one with `mcpdef tls init`",
                paths.dir().display()
            )
        })?;
    match out {
        Some(out) => {
            std::fs::write(out, &pem).with_context(|| format!("writing {}", out.display()))?;
            eprintln!(
                "mcpdef: wrote the local CA's certificate to {}",
                out.display()
            );
        }
        None => print!("{pem}"),
    }
    Ok(())
}

/// `mcpdef tls show` — the TLS of the gateway's listeners, the local CA,
/// each HTTPS upstream's profile, and what to fix. It reads certificates,
/// never keys: `mcpdef validate` checks that each key is its certificate's.
fn cmd_tls_show(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let mut stdout = std::io::stdout().lock();
    let warnings = tls_report(&cfg, &mut stdout)?;
    print_upstream_profiles(&cfg);
    if !warnings.is_empty() {
        writeln!(stdout, "\nwarnings:")?;
        for warning in &warnings {
            writeln!(stdout, "  ⚠ {warning}")?;
        }
    }
    Ok(())
}

/// What `mcpdef tls show` reports of the gateway's own listeners and its
/// local CA, written to `out`, and what it warns of. `mcpdef doctor` runs the
/// same checks with `out` thrown away, so the two cannot disagree.
fn tls_report(cfg: &Config, out: &mut dyn Write) -> std::io::Result<Vec<String>> {
    let g = &cfg.gateway;
    let paths = local_ca::Paths::under(&g.state_dir);
    let now = SystemTime::now();
    let mut warnings = Vec::new();
    writeln!(out, "listener (streamable-http {}):", g.listen)?;
    show_listener(out, &g.tls, "[gateway.tls]", &paths, now, &mut warnings)?;
    if let Some(proxy) = &g.trusted_proxy {
        // With no TLS of its own, `show_listener` stopped at its mode.
        if !g.tls.mode.is_on() {
            show_client_auth(out, &g.tls.client_auth)?;
        }
        writeln!(
            out,
            "    trusted proxy: {} from {}",
            proxy.client_cert_header.as_str(),
            proxy.cidrs.join(", ")
        )?;
    }
    writeln!(out, "admin listener ({}):", g.admin.listen)?;
    if !g.admin.enabled {
        writeln!(out, "    not enabled")?;
    } else if g.admin.tls.is_none() {
        writeln!(out, "    tls          : the listener's")?;
    } else {
        show_listener(
            out,
            g.admin_tls(),
            "[gateway.admin.tls]",
            &paths,
            now,
            &mut warnings,
        )?;
    }
    let self_signed = |tls: &ListenerTlsConfig| tls.mode == ListenerTlsMode::SelfSigned;
    if self_signed(&g.tls) || (g.admin.enabled && self_signed(g.admin_tls())) {
        show_local_ca(out, &paths, now, &mut warnings)?;
    }
    // What the config itself says of TLS.
    warnings.extend(cfg.warnings().into_iter().filter(|w| {
        w.starts_with("[gateway] listen")
            || w.starts_with("[gateway.tls]")
            || w.starts_with("[gateway.admin.tls]")
            || w.starts_with("[gateway.trusted_proxy]")
            || w.contains("insecure_skip_verify")
    }));
    Ok(warnings)
}

/// Days from `now` to `secs` since the Unix epoch, rounded down.
fn days_until(secs: i64, now: SystemTime) -> i64 {
    let now = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    (secs - now).div_euclid(86_400)
}

/// The lines `mcpdef tls show` prints for one listener's TLS, and what it
/// warns of: a certificate that does not read, or that is near its end.
fn show_listener(
    out: &mut dyn Write,
    tls: &ListenerTlsConfig,
    table: &str,
    paths: &local_ca::Paths,
    now: SystemTime,
    warnings: &mut Vec<String>,
) -> std::io::Result<()> {
    writeln!(out, "    tls          : {}", tls.mode.as_str())?;
    let cert = match tls.mode {
        ListenerTlsMode::Off => return Ok(()),
        ListenerTlsMode::Files => PathBuf::from(tls.cert.as_deref().unwrap_or_default()),
        ListenerTlsMode::SelfSigned => paths.cert(),
    };
    writeln!(out, "    certificate  : {}", cert.display())?;
    let leaf = match CertificateDer::pem_file_iter(&cert).map(|mut certs| certs.next()) {
        Ok(Some(Ok(leaf))) => leaf,
        _ if tls.mode == ListenerTlsMode::SelfSigned && !cert.exists() => {
            writeln!(out, "                   not issued yet: `mcpdef tls init` issues it, and so does the gateway as it starts")?;
            return Ok(());
        }
        Ok(Some(Err(e))) => {
            warnings.push(format!("{table} {}: {e}", cert.display()));
            return Ok(());
        }
        Ok(None) => {
            warnings.push(format!("{table} {} holds no certificate", cert.display()));
            return Ok(());
        }
        Err(e) => {
            warnings.push(format!("{table} {}: {e}", cert.display()));
            return Ok(());
        }
    };
    let names = CertificateNames::read(&leaf);
    let read = PeerCertificate::read(&leaf);
    let none = || "(none)".to_string();
    writeln!(
        out,
        "    subject      : {}",
        names.subject.unwrap_or_else(none)
    )?;
    let alt_names = match names.alt_names.is_empty() {
        true => none(),
        false => names.alt_names.join(", "),
    };
    writeln!(out, "    names        : {alt_names}")?;
    writeln!(
        out,
        "    issuer       : {}",
        names.issuer.unwrap_or_else(none)
    )?;
    if let Some(until) = read.not_after {
        let days = days_until(until, now);
        writeln!(out, "    expires      : {} ({days} days)", rfc3339(until))?;
        let renew_before = (local_ca::RENEW_BEFORE.as_secs() / 86_400) as i64;
        match tls.mode {
            _ if days < 0 => warnings.push(format!(
                "{table} the certificate {} expired at {}",
                cert.display(),
                rfc3339(until)
            )),
            ListenerTlsMode::Files if days < doctor::EXPIRY_WARN_DAYS => warnings.push(format!(
                "{table} the certificate {} expires in {days} days, at {}: renew it, and the \
                 gateway serves the renewed one from its next reload",
                cert.display(),
                rfc3339(until)
            )),
            ListenerTlsMode::SelfSigned if days < renew_before => warnings.push(format!(
                "{table} the certificate {} expires in {days} days, at {}: a running gateway \
                 issues it again with {renew_before} days left, and one that starts does so at once",
                cert.display(),
                rfc3339(until)
            )),
            _ => {}
        }
    }
    writeln!(out, "    sha256       : {}", read.fingerprint)?;
    show_client_auth(out, &tls.client_auth)?;
    Ok(())
}

/// The lines `mcpdef tls show` prints for what a listener asks of a client's
/// certificate.
fn show_client_auth(out: &mut dyn Write, client_auth: &ClientAuthConfig) -> std::io::Result<()> {
    if !client_auth.mode.is_on() {
        writeln!(out, "    client certs : not asked for")?;
        return Ok(());
    }
    let identity = client_auth.identity.map_or("(unset)", CertIdentity::as_str);
    writeln!(
        out,
        "    client certs : {}, identity {identity}",
        client_auth.mode.as_str()
    )?;
    if !client_auth.trust_domains.is_empty() {
        writeln!(
            out,
            "    trust domains: {}",
            client_auth.trust_domains.join(", ")
        )?;
    }
    writeln!(out, "    client CAs   : {}", client_auth.ca.join(", "))?;
    if !client_auth.crl.is_empty() {
        writeln!(out, "    client CRLs  : {}", client_auth.crl.join(", "))?;
    }
    Ok(())
}

/// The lines `mcpdef tls show` prints for the local CA.
fn show_local_ca(
    out: &mut dyn Write,
    paths: &local_ca::Paths,
    now: SystemTime,
    warnings: &mut Vec<String>,
) -> std::io::Result<()> {
    writeln!(out, "local CA ({}):", paths.ca_cert().display())?;
    let pem = match local_ca::ca_cert_pem(paths) {
        Ok(Some(pem)) => pem,
        Ok(None) => {
            writeln!(
                out,
                "    none yet: `mcpdef tls init` makes it, and so does the gateway as it starts"
            )?;
            return Ok(());
        }
        Err(e) => {
            warnings.push(e);
            return Ok(());
        }
    };
    let Ok(der) = CertificateDer::from_pem_slice(pem.as_bytes()) else {
        return Ok(());
    };
    let names = CertificateNames::read(&der);
    let read = PeerCertificate::read(&der);
    writeln!(
        out,
        "    subject      : {}",
        names.subject.unwrap_or_else(|| "(none)".to_string())
    )?;
    if let Some(until) = read.not_after {
        let days = days_until(until, now);
        writeln!(out, "    expires      : {} ({days} days)", rfc3339(until))?;
        if days < (local_ca::LEAF_LIFETIME.as_secs() / 86_400) as i64 {
            warnings.push(format!(
                "the local CA {} expires in {days} days, at {}: make a new one with `mcpdef tls \
                 init --new-ca`, and have every client trust it in place of this one",
                paths.ca_cert().display(),
                rfc3339(until)
            ));
        }
    }
    writeln!(out, "    sha256       : {}", read.fingerprint)?;
    Ok(())
}

/// `mcpdef egress show` — print the effective SSRF guard for HTTP upstreams so an
/// operator can confirm the gateway's outbound posture (OSS-ROLLOUT.md §6), and
/// the TLS profile each HTTPS upstream is verified with.
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

    print_upstream_profiles(&cfg);
    Ok(())
}

/// The TLS profile of each HTTPS upstream, and of the gateway's own fetches,
/// as `mcpdef egress show` and `mcpdef tls show` print them.
fn print_upstream_profiles(cfg: &Config) {
    println!("\ntls profiles (HTTPS upstreams; plain-HTTP and stdio ones have none):");
    println!("  [gateway.upstream_tls], for the jwks_uri fetch and under every [server.tls]:");
    print_tls_profile(&cfg.gateway.fetch_tls(), None);
    for s in cfg.servers.iter().filter(|s| s.is_https()) {
        println!(
            "  server '{}' ({}):",
            s.id,
            redact_url(s.url.as_deref().unwrap_or_default())
        );
        let connect_to = s.tls.as_ref().and_then(|tls| tls.connect_to.as_deref());
        print_tls_profile(&cfg.upstream_tls(s), connect_to);
    }
}

/// The lines `mcpdef egress show` prints for one TLS profile: what verifies
/// a server, then what the profile speaks and presents. Roots, CAs and CRLs
/// only count when a certificate is checked by its chain, so only then are
/// they shown.
fn print_tls_profile(tls: &TlsSettings, connect_to: Option<&str>) {
    let paths = |paths: &[PathBuf]| match paths.is_empty() {
        true => "none".to_string(),
        false => paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    };
    let verification = tls.verification();
    let how = match verification {
        Verification::Ca => "its chain to a trusted root, its name and its dates are checked",
        Verification::Pin => "its key alone is checked: not its issuer, names or dates",
        Verification::Disabled => "nothing is checked (insecure_skip_verify)",
    };
    println!("    verify       : {:<8}  {how}", verification.as_str());
    match verification {
        Verification::Ca => {
            let roots = match tls.roots {
                Roots::Bundled => "bundled",
                Roots::System => "system",
                Roots::Both => "both",
            };
            println!("    roots        : {roots}");
            println!("    ca           : {}", paths(&tls.ca));
            println!("    crl          : {}", paths(&tls.crl));
        }
        Verification::Pin => println!("    pin_sha256   : {}", tls.pin_sha256.join(", ")),
        Verification::Disabled => {}
    }
    let min_version = match tls.min_version {
        MinVersion::Tls12 => "1.2",
        MinVersion::Tls13 => "1.3",
    };
    println!("    min_version  : {min_version}");
    let client_cert = tls.identity.as_ref().map(|i| i.cert.clone());
    println!("    client_cert  : {}", paths(client_cert.as_slice()));
    if let Some(ip) = connect_to {
        println!("    connect_to   : {ip}");
    }
}

fn print_version() {
    // `mcpdef-bench` records this first line as the measured binary's identity,
    // so its shape is load-bearing beyond this function.
    println!(
        "mcpdef {}  ·  MCP gateway & governance plane",
        env!("CARGO_PKG_VERSION")
    );
    println!("  spec target : {}", spec_target());
}

/// The MCP revisions this build speaks, as `mcpdef version` reports them.
///
/// Read from the wire module rather than written out. This line was prose once,
/// and went stale: it went on calling 2026-07-28 "planned" after that revision
/// had shipped, because it restated facts the binary already held. Built from
/// [`KNOWN_SPEC_VERSIONS`] and the default listener's [`WireMode`], a revision
/// added there reaches this line without anyone remembering to edit it.
///
/// "Stateless" is likewise not a word typed next to a date: it is whatever
/// [`WireMode::Modern`] serves.
///
/// One default is printed because a listener and an upstream default to the
/// same revision. `the_listener_and_upstream_defaults_agree` holds that, so if
/// one ever moves, the line is rewritten to say which is which rather than
/// going quietly wrong.
fn spec_target() -> String {
    let default = WireMode::default().served();
    let stateless = WireMode::Modern.served();
    let others: Vec<String> = KNOWN_SPEC_VERSIONS
        .iter()
        .filter(|v| !default.contains(v))
        .map(|v| {
            if stateless.contains(v) {
                format!("stateless {v}")
            } else {
                (*v).to_string()
            }
        })
        .collect();

    let mut line = format!("{} default", default.join(", "));
    if !others.is_empty() {
        line.push_str(&format!(
            "; {} via `[gateway] wire` / `[[server]] spec`",
            others.join(", ")
        ));
    }
    line
}

/// `mcpdef bridge` — the gateway with one Streamable-HTTP upstream, served
/// over stdio. See [`mcpdef::bridge`].
async fn cmd_bridge(bridge: Bridge, print_config: bool) -> Result<()> {
    if print_config {
        print!("{}", bridge.config_text()?);
        return Ok(());
    }
    let cfg = bridge.config()?;
    warn(&cfg);
    let gw = build_gateway(&cfg).await?;
    // From here on stdout is the client's JSON-RPC channel, and nothing else
    // may be written to it: what the bridge has to say goes to stderr.
    eprintln!(
        "mcpdef {} bridge ready · {} · spec {} · audit {}",
        env!("CARGO_PKG_VERSION"),
        redact_url(&bridge.url),
        bridge.spec,
        cfg.gateway.audit,
    );
    serve_stdio(&gw).await
}

/// `mcpdef connect` — see [`mcpdef::clients`].
fn cmd_connect(
    client: &str,
    config: &Path,
    url: Option<String>,
    ask: Ask,
    write: bool,
    file: Option<PathBuf>,
) -> Result<()> {
    let client: Client = client.parse()?;
    let cfg = Config::load(config)?;
    let mut target = Target::of(&cfg);
    if let Some(url) = url {
        target.url = url;
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from);
    let entry = clients::entry(client, &target, &ask, home.as_deref())?;
    if !write {
        print!("{}", entry.report());
        return Ok(());
    }
    let file = file.or_else(|| entry.file.clone()).with_context(|| {
        format!(
            "{} has no config file of its own to write: give --file, or leave out --write",
            client.name()
        )
    })?;
    match clients::write(&entry, &file)? {
        Wrote::Created => println!("wrote {} with the '{}' entry", file.display(), entry.name),
        Wrote::Updated { backup } => println!(
            "updated '{}' in {}; what it held before is in {}",
            entry.name,
            file.display(),
            backup.display()
        ),
        Wrote::Unchanged => println!(
            "{} already has this '{}' entry: nothing written",
            file.display(),
            entry.name
        ),
    }
    // What the entry cannot carry still has to be done: trusting the CA,
    // signing in.
    for note in &entry.notes {
        println!("{note}");
    }
    Ok(())
}

fn cmd_validate(path: &Path, strict: bool) -> Result<()> {
    let cfg = Config::load(path)?;
    let checked = cfg.check(strict);
    if checked.errors.is_empty() {
        for warning in &checked.warnings {
            eprintln!("  ⚠ {warning}");
        }
        let strictly = if strict || cfg.gateway.strict {
            ", strictly"
        } else {
            ""
        };
        println!(
            "ok: {} — {} upstream(s), config valid{strictly}",
            path.display(),
            cfg.servers.len()
        );
        Ok(())
    } else {
        for e in &checked.errors {
            eprintln!("  ✗ {e}");
        }
        anyhow::bail!(
            "{} validation error(s) in {}",
            checked.errors.len(),
            path.display()
        );
    }
}

/// `mcpdef doctor` — each part of the report as soon as it is checked, then
/// the count; an error, and so a non-zero exit, if anything is broken.
async fn cmd_doctor(path: &Path, wait: Duration) -> Result<()> {
    println!("mcpdef doctor: {}\n", path.display());
    let mut tally = Tally::default();

    let mut config = Section::new("config");
    let cfg = match Config::load(path) {
        Ok(cfg) => cfg,
        Err(e) => {
            config.push(Finding::fail(redact_urls(&format!("{e:#}"))));
            tally.show(&config)?;
            return tally.verdict();
        }
    };
    let checked = cfg.check(false);
    if !checked.errors.is_empty() {
        for error in checked.errors {
            config.push(Finding::fail(error));
        }
        config.push(Finding::note("the rest is checked once these are fixed"));
        tally.show(&config)?;
        return tally.verdict();
    }
    let tls_warnings = tls_report(&cfg, &mut std::io::sink())?;
    config.push(Finding::ok(format!(
        "valid, {} server(s)",
        cfg.servers.len()
    )));
    for warning in checked.warnings {
        if !tls_warnings.contains(&warning) {
            config.push(Finding::warn(warning));
        }
    }
    tally.show(&config)?;

    let mut tls = Section::new("tls");
    let g = &cfg.gateway;
    tls.push(match g.tls.mode {
        ListenerTlsMode::Off => Finding::note(format!("listener {}: TLS off", g.listen)),
        mode => Finding::ok(format!(
            "listener {}: TLS {} (`mcpdef tls show` prints its certificate)",
            g.listen,
            mode.as_str()
        )),
    });
    for warning in tls_warnings {
        tls.push(Finding::warn(warning));
    }
    tally.show(&tls)?;

    let mut sign_in = Section::new("sign-in");
    sign_in.findings = sign_in_findings(&cfg).await;
    tally.show(&sign_in)?;

    let mut admin = Section::new("admin");
    admin.push(doctor::admin(g));
    tally.show(&admin)?;

    let mut servers = Section::new("servers");
    if cfg.servers.is_empty() {
        servers.push(Finding::note("none configured"));
    } else {
        let scratch = tempfile::tempdir().context("making a scratch directory")?;
        match examine(&cfg, scratch.path(), wait).await {
            Ok(gw) => {
                let costs = gw.tool_costs();
                let now = SystemTime::now();
                for status in gw.upstream_status() {
                    let Some(server) = cfg.servers.iter().find(|s| s.id == status.id) else {
                        continue;
                    };
                    let cost = costs.iter().find(|c| c.id == status.id);
                    servers
                        .findings
                        .extend(doctor::upstream(server, &status, cost, now));
                }
                for finding in tool_findings(&cfg, &gw) {
                    servers.push(Finding::warn(finding));
                }
            }
            Err(e) => servers.push(Finding::fail(redact_urls(&format!("{e:#}")))),
        }
    }
    tally.show(&servers)?;
    tally.verdict()
}

/// What `mcpdef doctor` has found so far.
#[derive(Default)]
struct Tally {
    problems: usize,
    warnings: usize,
}

impl Tally {
    /// Print `section`, and count what it found.
    fn show(&mut self, section: &Section) -> Result<()> {
        section.render(&mut std::io::stdout().lock())?;
        self.problems += section.count(Mark::Fail);
        self.warnings += section.count(Mark::Warn);
        Ok(())
    }

    /// The last line, and an error if anything is broken.
    fn verdict(&self) -> Result<()> {
        let count = |n: usize, what: &str| match n {
            1 => format!("1 {what}"),
            n => format!("{n} {what}s"),
        };
        println!(
            "{}, {}",
            count(self.problems, "problem"),
            count(self.warnings, "warning")
        );
        if self.problems > 0 {
            anyhow::bail!("{} found", count(self.problems, "problem"));
        }
        Ok(())
    }
}

/// How callers prove who they are, and for a bearer token, whether the
/// identity provider's keys can be had and how far its clock is from this
/// machine's: a token's times are judged by this machine's clock.
async fn sign_in_findings(cfg: &Config) -> Vec<Finding> {
    let auth = &cfg.gateway.auth;
    if !auth.enabled {
        return vec![Finding::note(
            "[gateway.auth] is off: callers are not asked who they are",
        )];
    }
    if !auth.takes(AuthMethod::Bearer) {
        let with: Vec<&str> = [
            (AuthMethod::Mtls, "a client certificate"),
            (AuthMethod::Key, "a client key the gateway issued ([[key]])"),
        ]
        .into_iter()
        .filter(|(method, _)| auth.takes(*method))
        .map(|(_, with)| with)
        .collect();
        return vec![Finding::ok(format!(
            "callers sign in with {}: there is no identity provider to reach",
            with.join(joined(auth))
        ))];
    }
    let fetching = Fetching::of(cfg);
    let tls = match fetching.tls.load_async().await {
        Ok(tls) => tls,
        Err(e) => {
            return vec![Finding::fail(format!(
                "reading [gateway.upstream_tls], to reach the identity provider: {e}"
            ))]
        }
    };
    let issuer = auth.issuer.clone().unwrap_or_default();
    let resource = auth.resource.clone().unwrap_or_default();
    let keys = |json: &str| -> Result<usize> {
        Verifier::from_jwks_json(json, issuer.clone(), resource.clone())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let jwks: serde_json::Value = serde_json::from_str(json)?;
        Ok(jwks["keys"].as_array().map_or(0, Vec::len))
    };
    let mut findings = Vec::new();
    // `discovery` finds `jwks_uri` as the gateway does when it starts.
    let jwks_uri = match (&auth.jwks_uri, auth.discovery && auth.jwks.is_none()) {
        (Some(uri), _) => Some(uri.clone()),
        (None, true) => match mcpdef::discovery::metadata(&issuer, &fetching.egress, &tls).await {
            Ok(found) => match found.jwks_uri {
                Some(uri) => {
                    findings.push(Finding::ok(format!(
                        "discovery: the issuer's metadata names jwks_uri {}",
                        redact_url(&uri)
                    )));
                    Some(uri)
                }
                None => {
                    findings.push(Finding::fail(
                        "discovery: the issuer's metadata names no jwks_uri, and the gateway \
                             does not start without its keys",
                    ));
                    return findings;
                }
            },
            Err(e) => {
                findings.push(Finding::fail(format!(
                    "discovery: {}. The gateway finds its keys so as it starts, and does not \
                         start without them",
                    redact_urls(&e)
                )));
                return findings;
            }
        },
        (None, false) => None,
    };
    // The provider's clock is read from the answer the gateway needs from it,
    // the JWKS at `jwks_uri`; with the keys pinned in the config, from the
    // issuer's own answer, whatever it is.
    let answered = match &jwks_uri {
        Some(uri) => {
            let at = redact_url(uri);
            let answer = match mcpdef_transport::fetch_dated(uri, &fetching.egress, &tls).await {
                Ok(answer) => answer,
                Err(e) => {
                    findings.push(Finding::fail(format!(
                        "jwks_uri {at}: {}. The gateway fetches its keys from it as it starts, \
                         and does not start without them",
                        redact_urls(&e.to_string())
                    )));
                    return findings;
                }
            };
            let body = String::from_utf8_lossy(&answer.body);
            findings.push(match answer.status {
                200..=299 => match keys(&body) {
                    Ok(n) => Finding::ok(format!("jwks_uri {at}: {n} key(s)")),
                    Err(e) => Finding::fail(format!(
                        "jwks_uri {at}: no keys a token can be checked with: {e:#}"
                    )),
                },
                status => Finding::fail(format!(
                    "jwks_uri {at} answered {status}. The gateway fetches its keys from it as it \
                     starts, and does not start without them"
                )),
            });
            answer
        }
        None => {
            let pinned = auth.jwks.as_deref().unwrap_or_default();
            findings.push(match pinned_jwks(pinned).and_then(|json| keys(&json)) {
                Ok(n) => Finding::ok(format!(
                    "{n} key(s) pinned in the config: the gateway needs no identity provider to \
                     start"
                )),
                Err(e) => Finding::fail(format!("[gateway.auth] jwks: {e:#}")),
            });
            match mcpdef_transport::fetch_dated(&issuer, &fetching.egress, &tls).await {
                Ok(answer) => answer,
                Err(e) => {
                    findings.push(Finding::note(format!(
                        "the issuer {} did not answer ({}), so its clock was not compared with \
                         this machine's",
                        redact_url(&issuer),
                        redact_urls(&e.to_string())
                    )));
                    return findings;
                }
            }
        }
    };
    findings.push(match answered.date {
        Some(date) => doctor::clock(
            answered.sent,
            answered.received,
            date,
            mcpdef_auth::clock_leeway(),
        ),
        None => Finding::note(
            "the identity provider's answer had no `Date`, so its clock was not compared with \
             this machine's",
        ),
    });
    findings
}

/// The JWKS `[gateway.auth] jwks` pins: the JSON itself, if it starts with
/// `{`, or else the file it names.
fn pinned_jwks(jwks: &str) -> Result<String> {
    match jwks.trim_start().starts_with('{') {
        true => Ok(jwks.to_string()),
        false => std::fs::read_to_string(jwks).with_context(|| format!("reading JWKS file {jwks}")),
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
        // Where each variable it is given comes from, never its value.
        if !s.env.is_empty() {
            let env: Vec<String> = s
                .env
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            println!("{:<12} env {}", "", env.join(" "));
        }
        // How it proves itself to the upstream, and where the secret comes
        // from, never the secret: a header's name, or where tokens come from.
        if let Some(auth) = &s.auth {
            let header = auth
                .name
                .as_deref()
                .or(auth.token_url.as_deref())
                .map(|n| format!(" {}", redact_url(n)))
                .unwrap_or_default();
            let secret = auth
                .secret()
                .map(|(field, from)| format!(" {field}={from}"))
                .unwrap_or_default();
            println!("{:<12} auth {}{header}{secret}", "", auth.kind.as_str());
        }
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
        "{} server(s) governed · allowlist deny-by-default · `mcpdef tools list` for the live tool list",
        cfg.servers.len()
    );
    Ok(())
}

/// List the tools the gateway lists, each with its server; or with `cost`,
/// what each server's tools add to every agent's context.
async fn cmd_tools_list(path: &Path, profile_override: Option<String>, cost: bool) -> Result<()> {
    let cfg = load_validated(path, profile_override)?;
    let gw = build_gateway(&cfg).await?;
    if cost {
        print_tool_costs(&gw.tool_costs());
    } else {
        let reply = gw
            .handle(Message::request(Id::Num(1), method::TOOLS_LIST, None))
            .await?
            .context("gateway returned no response to tools/list")?;
        let tools = reply
            .result
            .as_ref()
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        println!("{:<12} TOOL", "SERVER");
        for tool in &tools {
            let server = tool["_meta"]["mcpdef/server"].as_str().unwrap_or("-");
            let name = tool["name"].as_str().unwrap_or("-");
            println!("{:<12} {name}", truncate(server, 12));
        }
        println!("{} tool(s) listed", tools.len());
    }
    // A server that did not open lists nothing; the log above says why.
    for status in gw.upstream_status() {
        let state = match status.health {
            HealthState::Starting => "starting",
            HealthState::Down => "down",
            HealthState::Up | HealthState::Degraded => continue,
        };
        println!("server '{}' is {state}", status.id);
    }
    if let Some(profile) = &cfg.gateway.profile {
        println!("listed under the gateway profile '{profile}'");
    }
    Ok(())
}

/// Each server's cost in `tools/list`, then all of theirs.
fn print_tool_costs(costs: &[ToolCost]) {
    let row = |server: &str, tools: &str, bytes: &str, tokens: &str| {
        println!(
            "{:<12} {tools:<12} {bytes:>8} {tokens:>9}",
            truncate(server, 12)
        );
    };
    let cost = |server: &str, listed: usize, offered: usize, bytes: usize| {
        let tools = format!("{listed} of {offered}");
        row(
            server,
            &tools,
            &bytes.to_string(),
            &format!("~{}", ToolCost::tokens(bytes)),
        );
    };
    row("SERVER", "TOOLS", "BYTES", "~TOKENS");
    for c in costs {
        cost(&c.id, c.listed, c.offered, c.bytes);
    }
    let (listed, offered, bytes) = costs.iter().fold((0, 0, 0), |(l, o, b), c| {
        (l + c.listed, o + c.offered, b + c.bytes)
    });
    cost("total", listed, offered, bytes);
    println!(
        "BYTES is what the tools take up in tools/list, which every agent reads into its context."
    );
    println!("~TOKENS is BYTES ÷ 4, an estimate: the real count depends on the model.");
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
            if !report.ambiguous.is_empty() {
                eprintln!(
                    "warning: {} record(s) hold U+001F inside a field (seq {:?}): the chain \
                     covers them, but their hash does not pin where one field ends and the next \
                     begins, so their fields could have been re-split without breaking it. A \
                     current gateway never writes such a record; an older one did, for a \
                     crafted tool or method name",
                    report.ambiguous.len(),
                    report.ambiguous
                );
            }
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

/// Load + validate a config, applying a `--profile` override. The shared front
/// half of `run`/`up`/`call`.
fn load_validated(path: &Path, profile_override: Option<String>) -> Result<Config> {
    validated(path, Config::load(path)?, profile_override)
}

/// [`load_validated`], and the [`Snapshot`] of what it read, which hot reload
/// starts from.
fn load_for_reload(path: &Path, profile_override: Option<String>) -> Result<(Config, Snapshot)> {
    let (cfg, text) = Config::load_text(path)?;
    // Taken before the gateway reads the files the config names.
    let snapshot = Snapshot::take(text.as_bytes(), &cfg);
    Ok((validated(path, cfg, profile_override)?, snapshot))
}

fn validated(path: &Path, mut cfg: Config, profile_override: Option<String>) -> Result<Config> {
    // A `--profile` flag overrides the config's active gateway profile; validate
    // afterwards so an unknown override is reported like any bad config.
    if profile_override.is_some() {
        cfg.gateway.profile = profile_override;
    }
    let errs = cfg.check(false).errors;
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

    let gw = build_gateway(&cfg).await?;
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
    let (cfg, snapshot) = load_for_reload(path, profile_override.clone())?;
    // The listeners' TLS before anything starts: a certificate that does not
    // read fails the start, as it would a reload, and a local CA that
    // self-signed mode wants is made now, if there is none.
    let serving = Serving::of(&cfg, http);
    let listener_tls = match ListenerTls::start(&cfg, serving).map_err(anyhow::Error::msg)? {
        Some((listener_tls, notes)) => {
            for note in notes {
                eprintln!("mcpdef: {note}");
            }
            Some(listener_tls)
        }
        None => None,
    };
    // The listeners are bound before anything starts, and the ready line,
    // printed once all has, names the addresses they took: with port 0, the
    // one the system gave. A connection made before then waits to be
    // accepted. One that cannot bind fails the start.
    let mcp_listener = match http {
        true => {
            let listen = &cfg.gateway.listen;
            Some(
                tokio::net::TcpListener::bind(listen)
                    .await
                    .with_context(|| format!("binding the MCP listener on {listen}"))?,
            )
        }
        false => None,
    };
    let admin_listener = match cfg.gateway.admin.enabled {
        true => {
            let listen = &cfg.gateway.admin.listen;
            Some(
                tokio::net::TcpListener::bind(listen)
                    .await
                    .with_context(|| format!("binding the admin listener on {listen}"))?,
            )
        }
        false => None,
    };
    // Only built when the admin server is enabled — nothing else ever reads it, and it
    // otherwise sits accumulating (server, tool, decision, rule) label tuples in memory
    // for a caller who never asked for it.
    let metrics = cfg
        .gateway
        .admin
        .enabled
        .then(|| Arc::new(Metrics::new(cfg.servers.len() as u64)));
    let mut gw = build_gateway(&cfg).await?;
    if let Some(m) = &metrics {
        gw = gw.with_metrics(m.clone());
    }

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
    let down: Vec<String> = gw
        .upstream_status()
        .into_iter()
        .filter(|u| u.health == HealthState::Down)
        .map(|u| format!("'{}'", u.id))
        .collect();
    let down_note = if down.is_empty() {
        String::new()
    } else {
        format!(" · ⚠ {} down, retrying: {}", down.len(), down.join(", "))
    };
    // How the gateway's own fetches go out; a reload replaces it.
    let fetching = Arc::new(ArcSwap::from_pointee(Fetching::of(&cfg)));
    // Build the OAuth 2.1 verifier (HTTP listener only). Done before printing the
    // ready line so a bad JWKS / blocked jwks_uri fails fast.
    let auth = if http {
        build_verifier(&cfg, &fetching).await?
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
        (Some(_), 0) => format!(" · {}", auth_methods(&cfg.gateway.auth)),
        (Some(_), n) => format!(" · {} · {n} role(s)", auth_methods(&cfg.gateway.auth)),
        (None, _) => String::new(),
    };
    let g = &cfg.gateway;
    let tls_on = g.tls.mode.is_on();
    let tls_note = match tls_on {
        true => format!(" · tls {}", g.tls.mode.as_str()),
        false => String::new(),
    };
    let mtls_note = match g.tls.client_auth.mode.is_on() && serving.mcp {
        true => format!(" · client certificates {}", g.tls.client_auth.mode.as_str()),
        false => String::new(),
    };
    let proxy_note = match &g.trusted_proxy {
        Some(proxy) => format!(
            " · {} from a trusted proxy",
            proxy.client_cert_header.as_str()
        ),
        None => String::new(),
    };
    let transport_note = match &mcp_listener {
        Some(listener) => format!(
            "streamable-http {}{tls_note}{mtls_note}{proxy_note}",
            listener.local_addr()?
        ),
        None => "stdio".to_string(),
    };

    // The admin API's way to ask the reloader below for a reload.
    let (admin_reloads, reload_requests) = mcpdef::reload::channel();
    // OSS admin / observability server (Prometheus /metrics + JSON API + status
    // UI) on a separate port. Runs for stdio and HTTP gateways alike — it just
    // reads the shared metrics registry, the gateway, and the ledger file.
    // The console's sessions, when it signs people in: the key is read, or
    // made, now, so that a key that does not read stops the start.
    let sessions = match cfg.gateway.admin.enabled && cfg.gateway.admin.oidc.is_some() {
        true => Some(mcpdef::admin::session::keys(&cfg).map_err(anyhow::Error::msg)?),
        false => None,
    };
    let admin = cfg.gateway.admin.enabled.then(|| {
        let state = AdminState::new(
            &cfg,
            metrics
                .clone()
                .expect("metrics is built whenever admin is enabled"),
            gw.clone(),
            env!("CARGO_PKG_VERSION"),
        )
        .with_reloads(admin_reloads.clone())
        .with_config_path(path)
        .with_listening(
            mcp_listener.as_ref().and_then(|l| l.local_addr().ok()),
            admin_listener.as_ref().and_then(|l| l.local_addr().ok()),
        );
        Arc::new(match sessions {
            Some(sessions) => state.with_sign_in(&cfg, sessions),
            None => state,
        })
    });

    let strict_note = if cfg.gateway.strict { " · strict" } else { "" };
    let ready = format!(
        "mcpdef {} ready · {} upstream(s){} · audit {}{}{}{}{} · listening {}",
        env!("CARGO_PKG_VERSION"),
        gw.upstream_count(),
        down_note,
        cfg.gateway.audit,
        profile_note,
        drift_note,
        auth_note,
        strict_note,
        transport_note
    );
    let http_cfg = HttpConfig {
        listen: cfg.gateway.listen.clone(),
        allowed_origins: cfg.gateway.allowed_origins.clone(),
        max_inflight: cfg.gateway.max_inflight,
        wire: cfg.gateway.wire,
    };

    // Hot reload: on SIGHUP, and with `watch_config` when the config changes.
    // It listens for SIGHUP from here, before the ready line, so that a SIGHUP
    // sent once the gateway says it is ready reloads it rather than ending it.
    let reloads = {
        let admin = admin.clone();
        let reloader = Reloader::new(path, profile_override, gw.clone(), cfg, snapshot).on_applied(
            move |cfg| {
                fetching.store(Arc::new(Fetching::of(cfg)));
                if let Some(admin) = &admin {
                    admin.reconfigure(cfg);
                    admin.metrics.set_upstreams(cfg.servers.len() as u64);
                }
            },
        );
        let reloader = reloader.with_requests(reload_requests);
        match &listener_tls {
            Some(listener_tls) => reloader.with_listener_tls(listener_tls.clone()),
            None => reloader,
        }
        .run(WATCH_INTERVAL)
    };
    let (mcp_tls, admin_tls) = match &listener_tls {
        Some(listener_tls) => (listener_tls.mcp(), listener_tls.admin()),
        None => (None, None),
    };

    eprintln!("{ready}");
    if let (Some(admin_state), Some(listener)) = (admin, admin_listener) {
        let scheme = if admin_tls.is_some() { "https" } else { "http" };
        eprintln!(
            "mcpdef: admin/metrics UI on {scheme}://{}",
            listener.local_addr()?
        );
        tokio::spawn(async move {
            if let Err(e) = serve_admin_on(admin_state, listener, admin_tls).await {
                eprintln!("mcpdef: admin server error: {e}");
            }
        });
    }

    let serving = async move {
        match (mcp_listener, mcp_tls) {
            (Some(listener), Some(tls)) if tls_on => {
                serve_https_on(listener, gw, http_cfg, auth, tls).await
            }
            (Some(listener), Some(slot)) => {
                serve_proxied_on(listener, gw, http_cfg, auth, slot).await
            }
            (Some(listener), None) => serve_http_on(listener, gw, http_cfg, auth).await,
            (None, _) => serve_stdio(&gw).await,
        }
    };
    // The reload loop runs on this task, beside the listener: it waits nearly
    // always, and a task of its own would wake a worker thread to do that.
    tokio::select! {
        served = serving => served,
        // It never ends: it runs until dropped.
        () = reloads => Ok(()),
    }
}

/// What the ready line says `[gateway.auth]` takes: `oauth` for a bearer
/// token, `mtls` for a client certificate and `keys` for a client key the
/// gateway issued, joined by `or` or `and` as `require` says: `oauth on`, as
/// it always has, for a bearer token alone, `oauth or mtls on` for both.
fn auth_methods(auth: &AuthConfig) -> String {
    let taken: Vec<&str> = [
        (AuthMethod::Bearer, "oauth"),
        (AuthMethod::Mtls, "mtls"),
        (AuthMethod::Key, "keys"),
    ]
    .into_iter()
    .filter(|(method, _)| auth.takes(*method))
    .map(|(_, name)| name)
    .collect();
    format!("{} on", taken.join(joined(auth)))
}

/// How `[gateway.auth] require` joins its methods: ` or `, or ` and `.
fn joined(auth: &AuthConfig) -> &'static str {
    match auth.require.unwrap_or_default() {
        AuthRequire::Any => " or ",
        AuthRequire::All => " and ",
    }
}

/// What `[gateway.auth]` requires of a request, or `None` when auth is
/// disabled: a client certificate, a bearer token, or either or both, as
/// `methods` and `require` say. For a bearer token, the OAuth 2.1 [`Verifier`]:
/// the JWKS comes from inline JSON / a file (`jwks`) or is fetched from
/// `jwks_uri` through the egress/SSRF guard, with `[gateway.upstream_tls]`: as
/// `fetching` says, now and at each refresh.
async fn build_verifier(
    cfg: &Config,
    fetching: &Arc<ArcSwap<Fetching>>,
) -> Result<Option<AuthState>> {
    let auth = &cfg.gateway.auth;
    if !auth.enabled {
        return Ok(None);
    }
    let state = if auth.takes(AuthMethod::Bearer) {
        let (verifier, refresher) = token_verifier(cfg, fetching).await?;
        let state = match refresher {
            Some(r) => AuthState::with_refresher(verifier, r),
            None => AuthState::new(verifier),
        };
        match auth.takes(AuthMethod::Key) {
            true => state.or_keys(),
            false => state,
        }
    } else if auth.takes(AuthMethod::Key) {
        AuthState::keys()
    } else {
        // validate() refused `mtls` on a listener that asks for no certificate.
        return Ok(Some(AuthState::certificate()));
    };
    let state = match auth.takes(AuthMethod::Mtls) {
        true => state.or_certificate(auth.require == Some(AuthRequire::All)),
        false => state,
    };
    Ok(Some(state))
}

/// The verifier of `cfg`'s bearer tokens, reading them by its `[identity]`,
/// and what re-fetches its keys when they come from a `jwks_uri`.
async fn token_verifier(
    cfg: &Config,
    fetching: &Arc<ArcSwap<Fetching>>,
) -> Result<(Verifier, Option<JwksRefresher>)> {
    let auth = &cfg.gateway.auth;
    // validate() already guaranteed these are present when enabled.
    let issuer = auth
        .issuer
        .clone()
        .context("[gateway.auth] enabled but `issuer` is unset")?;
    let resource = auth
        .resource
        .clone()
        .context("[gateway.auth] enabled but `resource` is unset")?;

    // Keys come from a static inline/file JWKS, or a `jwks_uri`, set or found
    // from the issuer's metadata, that we can re-fetch to pick up an
    // authorization-server signing-key rotation at runtime.
    let (jwks_json, refresher) = match &auth.jwks {
        Some(j) => (pinned_jwks(j)?, None),
        None => {
            let uri = match (&auth.jwks_uri, auth.discovery) {
                (Some(uri), _) => uri.clone(),
                (None, true) => discovered_jwks_uri(&issuer, fetching).await?,
                (None, false) => {
                    anyhow::bail!("[gateway.auth] enabled but neither `jwks` nor `jwks_uri` is set")
                }
            };
            let via = fetching.load_full();
            let tls = via
                .tls
                .load_async()
                .await
                .context("reading [gateway.upstream_tls] to fetch jwks_uri")?;
            let json = mcpdef_transport::fetch_text(&uri, &via.egress, &tls)
                .await
                .with_context(|| format!("fetching jwks_uri {uri}"))?;
            (
                json,
                Some(JwksRefresher::following(uri, Arc::clone(fetching))),
            )
        }
    };

    let verifier = Verifier::from_jwks_json(&jwks_json, issuer, resource)
        .map_err(|e| anyhow::anyhow!("building OAuth verifier: {e}"))?
        .with_audiences(auth.audiences.clone())
        .with_identity(cfg.identity.model());
    Ok((verifier, refresher))
}

/// The `jwks_uri` `issuer`'s metadata names, for `[gateway.auth] discovery`.
async fn discovered_jwks_uri(issuer: &str, fetching: &Arc<ArcSwap<Fetching>>) -> Result<String> {
    let via = fetching.load_full();
    let tls = via
        .tls
        .load_async()
        .await
        .context("reading [gateway.upstream_tls] to find the issuer's metadata")?;
    let found = mcpdef::discovery::metadata(issuer, &via.egress, &tls)
        .await
        .map_err(|e| anyhow::anyhow!("[gateway.auth] discovery: {e}"))?;
    found.jwks_uri.with_context(|| {
        format!("[gateway.auth] discovery: the metadata of {issuer} names no jwks_uri")
    })
}

/// `mcpdef sso init`: the config for `provider`, printed or merged into
/// `config`.
fn cmd_sso_init(
    provider: &str,
    issuer: Option<String>,
    client_id: String,
    public_url: Option<String>,
    config: &Path,
    write: bool,
) -> Result<()> {
    use mcpdef::sso::{Init, Provider};
    let Some(provider) = Provider::parse(provider) else {
        let names: Vec<&str> = Provider::ALL.iter().map(|p| p.name()).collect();
        anyhow::bail!("no provider {provider:?}: name one of {}", names.join(", "));
    };
    // The console's origin, from the config when it is not given.
    let configured = std::fs::read_to_string(config)
        .ok()
        .and_then(|text| Config::parse(&text).ok())
        .and_then(|cfg| cfg.gateway.admin.public_url);
    let init = Init {
        provider,
        issuer,
        client_id,
        public_url: public_url.or(configured),
    };
    if !write {
        print!("{}", init.printed());
        return Ok(());
    }
    let backup = mcpdef::sso::write(config, &init)?;
    for (n, step) in init.steps().iter().enumerate() {
        println!("{}. {step}", n + 1);
    }
    println!(
        "\nwrote [gateway.admin.oidc] and [identity] into {} (as it was: {}). Set {} where \
         MCPdef runs, and restart it.",
        config.display(),
        backup.display(),
        mcpdef::sso::SECRET_VAR
    );
    Ok(())
}

/// `mcpdef keys create`: 32 random bytes, as `mcpdef_key_` and their
/// base64url, and the `[[key]]` that keeps their SHA-256.
fn cmd_keys_create(name: &str, roles: &[String]) -> Result<()> {
    use base64::Engine as _;
    use ring::rand::SecureRandom as _;
    use sha2::Digest as _;
    let named = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !named {
        anyhow::bail!("--name {name:?}: one word, of letters, digits, '.', '_' and '-'");
    }
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("the system's random source failed"))?;
    let key = format!(
        "{}{}",
        mcpdef::listener::KEY_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let digest = hex::encode(sha2::Sha256::digest(key.as_bytes()));
    let roles: Vec<String> = roles.iter().map(|r| format!("{r:?}")).collect();
    println!(
        "# A client key for the MCP listener, sent as `Authorization: Bearer <key>`,\n\
         # where [gateway.auth] methods names \"key\". It is shown this once: give it\n\
         # to its client, as a secret.\n\
         {key}\n\n\
         # For the config; a reload takes it, and takes it away again:\n\
         [[key]]\n\
         name = {name:?}\n\
         sha256 = \"{digest}\"\n\
         roles = [{}]",
        roles.join(", ")
    );
    Ok(())
}

/// `mcpdef admin token`: 32 random bytes, as `mcpdef_bg_` and their
/// base64url, and the table that keeps their SHA-256.
fn cmd_admin_token() -> Result<()> {
    use base64::Engine as _;
    use ring::rand::SecureRandom as _;
    use sha2::Digest as _;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("the system's random source failed"))?;
    // A prefix of its own, so a secret scanner can find the token where it
    // should not be.
    let token = format!(
        "mcpdef_bg_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let digest = hex::encode(sha2::Sha256::digest(token.as_bytes()));
    println!(
        "# A break-glass token. It holds console:admin on the admin API, as\n\
         # `Authorization: Bearer <token>`, and every request it makes is recorded.\n\
         # It is shown this once: keep it offline, where those who may use it in\n\
         # an emergency can reach it.\n\
         {token}\n\n\
         # Its SHA-256, for the config; a reload takes it:\n\
         [gateway.admin.break_glass]\n\
         token_sha256 = \"{digest}\""
    );
    Ok(())
}

/// `mcpdef auth test`: the token verified as the listener verifies it, and
/// what it names.
async fn cmd_auth_test(path: &Path, token: Option<String>, file: Option<&Path>) -> Result<()> {
    let cfg = Config::load(path)?;
    let auth = &cfg.gateway.auth;
    let takes_tokens = auth.takes(AuthMethod::Bearer) || auth.takes(AuthMethod::Key);
    if !auth.enabled || !takes_tokens {
        anyhow::bail!(
            "{} takes no bearer token: [gateway.auth] is off, or takes client certificates alone",
            path.display()
        );
    }
    let token = match (token, file) {
        (Some(t), _) if t == "-" => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
            text
        }
        (Some(t), _) => t,
        (None, Some(file)) => std::fs::read_to_string(file)
            .with_context(|| format!("reading the token in {}", file.display()))?,
        (None, None) => anyhow::bail!("give the token: --token <jwt>, --token - or --token-file"),
    };
    let token = token.trim();
    let principal =
        if auth.takes(AuthMethod::Key) && token.starts_with(mcpdef::listener::KEY_PREFIX) {
            // A client key: looked for as the listener looks for it.
            match mcpdef::gateway::issued(&cfg.issued_keys(), token) {
                Some(principal) => principal,
                None => anyhow::bail!("not verified: no [[key]] of this config is that key"),
            }
        } else if auth.takes(AuthMethod::Bearer) {
            let fetching = Arc::new(ArcSwap::from_pointee(Fetching::of(&cfg)));
            let (verifier, _) = token_verifier(&cfg, &fetching).await?;
            match verifier.verify(token) {
                Ok(principal) => principal,
                Err(e) => anyhow::bail!("not verified: {e}"),
            }
        } else {
            anyhow::bail!("not verified: this listener takes client keys alone, and that is none");
        };
    let none = || "(none)".to_string();
    let list = |items: &[String]| match items.is_empty() {
        true => none(),
        false => items.join(", "),
    };
    match principal.issuer.as_str() {
        "mcpdef" => println!("verified · a client key this gateway issued"),
        issuer => println!("verified · issuer {}", redact_url(issuer)),
    }
    match principal.issuer.as_str() {
        "mcpdef" => println!("caller  : key:{}", principal.subject),
        _ => println!("subject : {}", principal.subject),
    }
    println!("roles   : {}", list(&principal.roles));
    println!("scopes  : {}", list(&principal.scopes));
    if let Some(client) = &principal.client_id {
        println!("client  : {client}");
    }
    if cfg.roles.is_empty() {
        println!("grants  : no [[role]] is defined, so each server's allowlist alone decides");
        return Ok(());
    }
    // What each role the token holds, by its roles or its scopes, grants
    // on each server, as `"server-glob:tool-glob"` reads.
    let held: Vec<&str> = principal.grants_subjects().collect();
    println!("grants  :");
    for server in &cfg.servers {
        let mut tools: Vec<String> = Vec::new();
        for role in cfg.roles.iter().filter(|r| held.contains(&r.name.as_str())) {
            for grant in &role.grants {
                let (servers, tool) = grant.split_once(':').unwrap_or(("*", grant));
                if mcpdef_policy::glob::names(servers, &server.id) {
                    tools.push(format!("{tool} ({})", role.name));
                }
            }
        }
        let tools = match tools.is_empty() {
            true => "nothing: each call to it is refused under rbac".to_string(),
            false => tools.join(", "),
        };
        println!("  {} : {tools}", server.id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{auth_methods, sign_in_findings, truncate, ToolCost};
    use mcpdef::Config;

    fn auth(methods: &str) -> Config {
        Config::parse(&format!(
            "[gateway.auth]\nenabled = true\n{methods}\n\n\
             [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n"
        ))
        .unwrap()
    }

    #[test]
    fn the_ready_line_names_each_way_in_that_auth_takes() {
        let said = |methods: &str| auth_methods(&auth(methods).gateway.auth);
        assert_eq!(said(""), "oauth on");
        assert_eq!(said("methods = [\"mtls\"]"), "mtls on");
        assert_eq!(said("methods = [\"bearer\", \"mtls\"]"), "oauth or mtls on");
        assert_eq!(
            said("methods = [\"bearer\", \"mtls\"]\nrequire = \"all\""),
            "oauth and mtls on"
        );
        assert_eq!(said("methods = [\"key\"]"), "keys on");
        assert_eq!(said("methods = [\"bearer\", \"key\"]"), "oauth or keys on");
        assert_eq!(said("methods = [\"mtls\", \"key\"]"), "mtls or keys on");
    }

    #[tokio::test]
    async fn doctor_says_how_callers_sign_in_without_a_bearer_token() {
        let said = |methods: &'static str| async move {
            let findings = sign_in_findings(&auth(methods)).await;
            assert_eq!(findings.len(), 1);
            findings[0].text.clone()
        };
        assert_eq!(
            said("methods = [\"mtls\"]").await,
            "callers sign in with a client certificate: there is no identity provider to reach"
        );
        assert_eq!(
            said("methods = [\"key\"]").await,
            "callers sign in with a client key the gateway issued ([[key]]): there is no \
             identity provider to reach"
        );
        assert_eq!(
            said("methods = [\"mtls\", \"key\"]").await,
            "callers sign in with a client certificate or a client key the gateway issued \
             ([[key]]): there is no identity provider to reach"
        );
    }

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

    #[test]
    fn tokens_are_bytes_over_four_rounded() {
        let tokens = ToolCost::tokens;
        assert_eq!(tokens(0), 0);
        assert_eq!(tokens(1), 0);
        assert_eq!(tokens(2), 1);
        assert_eq!(tokens(4), 1);
        assert_eq!(tokens(5), 1);
        assert_eq!(tokens(6), 2);
        assert_eq!(tokens(4_000), 1_000);
    }
}
