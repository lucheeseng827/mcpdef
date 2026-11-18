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
//!   mcpdef bundle sign  --config F --key K --revision N [--out F]   a config, signed, as a bundle
//!   mcpdef bundle apply <bundle> --trust KEYS [--config F]   check one, then put its config in place
//!   mcpdef up --bundle-trust KEYS            run only a config the signed bundle beside it holds
//!   mcpdef filter       --config mcpdef.toml [--bundle-trust KEYS]   answer a proxy's ext_authz checks
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
use mcpdef::bundle;
use mcpdef::clients::{self, Ask, Client, Target, Wrote};
use mcpdef::config::{
    AuthConfig, AuthMethod, AuthRequire, CertIdentity, ClientAuthConfig, ListenerTlsConfig,
    ListenerTlsMode,
};
use mcpdef::connect::{build_gateway, examine, opener, tool_findings, warn};
use mcpdef::doctor::{self, Finding, Mark, Section};
use mcpdef::import;
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
use mcpdef_audit::receipt::{self, Keys, SigningKey};
use mcpdef_audit::{tail, verify, verify_against, ExportFormat};
use mcpdef_auth::Verifier;
use mcpdef_core::wire::{WireMode, KNOWN_SPEC_VERSIONS};
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::{tool_hash, DiffKind, Judgement, PinStore};
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
        #[command(flatten)]
        lock: BundleLock,
    },
    /// Bring the gateway up on the Streamable HTTP listener — shorthand for
    /// `mcpdef run --http` (the shared-gateway shape: one endpoint, govern centrally).
    Up {
        /// The config to run [default: mcpdef.toml]. With none given and no
        /// mcpdef.toml here, one is written first from the MCP servers this
        /// machine's clients run, as `mcpdef import` writes it, unless
        /// --bundle-trust is given.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override the active gateway profile for this run (e.g. `--profile readonly`).
        #[arg(long)]
        profile: Option<String>,
        #[command(flatten)]
        lock: BundleLock,
    },
    /// Write the gateway config that fronts the MCP servers this machine's
    /// clients already run, read from the clients' own config files. None of
    /// those files is changed. Every tool, resource and prompt is let through,
    /// every call is audited, and inspection warns without blocking.
    Import {
        /// Read only this client's files: claude-code, claude-desktop, cursor,
        /// vscode or codex. Repeatable; every client's when not given.
        #[arg(long = "from")]
        from: Vec<String>,
        /// Write the config to this file, instead of printing it.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace the file --out names, if there is one.
        #[arg(long, requires = "out")]
        force: bool,
        /// Where the gateway will listen. A client entry that already reaches
        /// it is MCPdef itself, and is not fronted again.
        #[arg(long, default_value = mcpdef::config::DEFAULT_LISTEN)]
        listen: String,
        /// Front the servers only this directory's own files name as well,
        /// those no client was told to run here: a repository's `.mcp.json`,
        /// `.cursor/mcp.json` or `.vscode/mcp.json`. Read what they run first.
        #[arg(long)]
        project_servers: bool,
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
        /// Also take out of that file each server the gateway fronts, the same
        /// command or URL, so that the client reaches it through the gateway only.
        #[arg(long, requires = "write")]
        replace: bool,
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
    /// Judge one MCP tool call as an agent client's pre-tool-call hook, with
    /// no proxy in the path: the client sends the call on standard input
    /// before it makes it, and MCPdef answers on standard output and records
    /// the decision in the config's ledger. `mcpdef hook install` sets a
    /// client up to ask.
    #[command(args_conflicts_with_subcommands = true)]
    Hook {
        #[command(subcommand)]
        cmd: Option<HookCmd>,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// The client whose hook this is: claude-code or codex.
        #[arg(long, default_value = "claude-code")]
        client: String,
        #[command(flatten)]
        lock: BundleLock,
    },
    /// Answer a proxy's checks, as Envoy's `ext_authz` filter makes them, with
    /// the proxy routing MCP requests itself: each request it is about to
    /// route is judged by the config, by the server its path names
    /// (`filter_path`), and recorded in the config's ledger. Serves
    /// `[gateway.filter] listen`.
    Filter {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        #[command(flatten)]
        lock: BundleLock,
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
    /// Signed receipts: the ledger's tool calls as decision receipts that
    /// anyone with the public key can check offline
    /// (draft-farley-acta-signed-receipts-03).
    Receipts {
        #[command(subcommand)]
        cmd: ReceiptsCmd,
    },
    /// Signed policy bundles: a config at a revision, signed, for a node to
    /// check before it takes it, as one with no route out is given its policy.
    Bundle {
        #[command(subcommand)]
        cmd: BundleCmd,
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
    /// (read-only), grading each change; exits non-zero if a pinned tool
    /// changed in a way the gateway would hold (a possible rug-pull).
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
        /// Output format: json (default), ocsf, cef, syslog, or otlp.
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
enum HookCmd {
    /// Print the hook a client needs to ask MCPdef before each MCP tool call,
    /// or merge it into the client's settings.
    Install {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// The client: claude-code or codex.
        #[arg(long, default_value = "claude-code")]
        client: String,
        /// Seconds the client waits for the hook before giving up on it. Both
        /// clients wait 600 for a hook that names none.
        #[arg(long, default_value_t = mcpdef::hook::DEFAULT_TIMEOUT_SECS,
              value_parser = clap::value_parser!(u32).range(1..=600))]
        timeout: u32,
        /// Merge the hook into the client's settings, keeping a `.bak` of them.
        #[arg(long)]
        write: bool,
        /// The settings to merge into, in place of the project's own:
        /// `.claude/settings.local.json` for Claude Code, `.codex/hooks.json`
        /// for Codex.
        #[arg(long, requires = "write")]
        file: Option<PathBuf>,
        /// Have the hook judge only by a config the signed bundle beside it
        /// holds, as `mcpdef hook --bundle-trust` does: the keys a bundle may
        /// be signed with. The bundle must hold the config now.
        #[arg(long, value_name = "KEYS")]
        bundle_trust: Option<PathBuf>,
    },
}

/// `--bundle-trust`, on `run`, `up`, `filter` and `hook`.
#[derive(clap::Args)]
struct BundleLock {
    /// Run only a config the signed bundle beside it holds: the keys a bundle
    /// may be signed with, as a JWK Set or one JWK. Each time the config is
    /// read, at the start, at each reload of a gateway and at each call a
    /// hook judges, it checks the bundle `mcpdef bundle apply` keeps beside
    /// the config (mcpdef.toml.bundle), and refuses a config it does not
    /// hold, or one older than the last this node ran. Keep the keys where
    /// whoever may write the config may not.
    #[arg(long, env = "MCPDEF_BUNDLE_TRUST", value_name = "KEYS")]
    bundle_trust: Option<PathBuf>,
}

#[derive(Subcommand)]
enum BundleCmd {
    /// Make an Ed25519 key to sign bundles with, as a private JWK file only
    /// its owner can read. A file that is there is never replaced.
    Key {
        #[arg(long, default_value = "mcpdef-bundle.jwk")]
        out: PathBuf,
    },
    /// Print a key's public half as a JWK Set: what each node is given to
    /// trust.
    Jwks {
        /// The private JWK file `mcpdef bundle key` wrote.
        #[arg(long)]
        key: PathBuf,
    },
    /// Check a config, then sign it at a revision as a bundle.
    Sign {
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// The private JWK file `mcpdef bundle key` wrote.
        #[arg(long)]
        key: PathBuf,
        /// Higher than any revision a node has applied: a node takes no
        /// bundle older than its last.
        #[arg(long)]
        revision: u64,
        #[arg(long, default_value = "mcpdef.bundle")]
        out: PathBuf,
        /// Replace the --out file if it is there.
        #[arg(long)]
        force: bool,
    },
    /// Check a bundle against keys you trust, and say what it holds.
    Verify {
        bundle: PathBuf,
        /// The keys a bundle may be signed with, as a JWK Set or one JWK,
        /// got from somewhere other than the bundle.
        #[arg(long)]
        trust: PathBuf,
        /// Write the config it holds to this file, to read before applying it.
        #[arg(long)]
        config_out: Option<PathBuf>,
    },
    /// Check a bundle against keys you trust and, if it is newer than the
    /// last this node applied, put its config in place, and record it in the
    /// ledger. A running gateway takes it at its next reload.
    Apply {
        bundle: PathBuf,
        /// The keys a bundle may be signed with, as a JWK Set or one JWK.
        #[arg(long)]
        trust: PathBuf,
        /// The config the bundle's takes the place of.
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ReceiptsCmd {
    /// Make an Ed25519 key to sign receipts with, as a private JWK file only
    /// its owner can read. A file that is there is never replaced.
    Key {
        #[arg(long, default_value = "mcpdef-receipts.jwk")]
        out: PathBuf,
    },
    /// Print a key's public half as a JWK Set, to publish where whoever
    /// checks receipts can fetch it.
    Jwks {
        /// The private JWK file `mcpdef receipts key` wrote.
        #[arg(long)]
        key: PathBuf,
    },
    /// Sign the ledger's tool calls as receipts, one JSON line each, after
    /// checking its chain (and, with --head and --count, a seal).
    Export {
        /// The private JWK file `mcpdef receipts key` wrote.
        #[arg(long)]
        key: PathBuf,
        /// Ledger file. Overrides the audit path from --config.
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value = "mcpdef.toml")]
        config: PathBuf,
        /// Expected head hash sealed out-of-band (use with --count).
        #[arg(long, requires = "count")]
        head: Option<String>,
        /// Expected record count sealed out-of-band (use with --head).
        #[arg(long, requires = "head")]
        count: Option<u64>,
        /// Write the receipts to this file, not to standard output.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace the --out file if it is there.
        #[arg(long, requires = "out")]
        force: bool,
    },
    /// Check receipts offline against public keys you trust: each one's
    /// signature, issuer and link to the one before. With --last and
    /// --count, also that none were taken off the end.
    Verify {
        /// The receipts, one JSON object per line.
        receipts: PathBuf,
        /// The issuer's public keys, as a JWK Set or one JWK, got from
        /// somewhere other than the receipts.
        #[arg(long)]
        jwks: PathBuf,
        /// The last receipt's hash, recorded somewhere else (use with --count).
        #[arg(long, requires = "count")]
        last: Option<String>,
        /// How many receipts there were, recorded with --last.
        #[arg(long, requires = "last")]
        count: Option<u64>,
    },
}

/// A static musl build, which the release tarballs and the container image
/// carry, allocates with mimalloc. With musl's own allocator, an allowed call
/// took 30–80 µs longer at the median, and sixteen clients got half as many
/// calls a second through (docs/PERFORMANCE.md). Other builds keep the system's.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
            lock,
        } => cmd_run(&config, profile, http, lock.bundle_trust.as_deref()).await,
        Cmd::Up {
            config,
            profile,
            lock,
        } => {
            let config = match (config, &lock.bundle_trust) {
                (Some(path), _) => path,
                // One written now no bundle holds: it would not run.
                (None, Some(_)) => PathBuf::from("mcpdef.toml"),
                (None, None) => up_config()?,
            };
            cmd_run(&config, profile, true, lock.bundle_trust.as_deref()).await
        }
        Cmd::Import {
            from,
            out,
            force,
            listen,
            project_servers,
        } => {
            let projects = match project_servers {
                true => import::Projects::All,
                false => import::Projects::Approved,
            };
            cmd_import(&from, out.as_deref(), force, &listen, projects)
        }
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
            replace,
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
            replace,
        ),
        Cmd::Call {
            config,
            profile,
            tool,
            args,
            json,
        } => cmd_call(&config, profile, &tool, &args, json).await,
        Cmd::Hook {
            cmd: None,
            config,
            client,
            lock,
        } => cmd_hook(&config, &client, lock.bundle_trust.as_deref()),
        Cmd::Hook {
            cmd:
                Some(HookCmd::Install {
                    config,
                    client,
                    timeout,
                    write,
                    file,
                    bundle_trust,
                }),
            ..
        } => cmd_hook_install(
            &config,
            &client,
            timeout,
            write,
            file.as_deref(),
            bundle_trust.as_deref(),
        ),
        Cmd::Filter { config, lock } => cmd_filter(&config, lock.bundle_trust.as_deref()).await,
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
        Cmd::Receipts { cmd } => cmd_receipts(cmd),
        Cmd::Bundle { cmd } => cmd_bundle(cmd),
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
async fn collect_tools(cfg: &Config) -> Result<Vec<(String, BTreeMap<String, serde_json::Value>)>> {
    warn(cfg);
    let mut out = Vec::new();
    for s in &cfg.servers {
        let mut transport = opener(cfg, s)().await?;
        let tools = list_tools_speaking(&s.id, &mut *transport, s.spec)
            .await
            .with_context(|| format!("listing tools for upstream '{}'", s.id))?;
        let mut map = BTreeMap::new();
        for t in tools {
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                map.insert(name.to_string(), t.clone());
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
    for (server, tools) in collect_tools(&cfg).await? {
        for tool in tools.values() {
            // With its definition, so that its next change is graded.
            store.record_tool(&server, tool);
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

/// `mcpdef diff-tools` — compare current tool definitions against the pins,
/// each change graded; exit non-zero if a pinned tool's definition changed in
/// a way the gateway would hold: worse than `[gateway] pin_accept`, or
/// ungraded (a suspected rug-pull).
async fn cmd_diff_tools(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let pins_path = cfg.gateway.pins.clone().context(
        "`mcpdef diff-tools` needs a pin store: set `[gateway] pins = \"…\"` (run `mcpdef pin` first)",
    )?;
    let store = PinStore::load(&pins_path).with_context(|| format!("loading {pins_path}"))?;
    let accept = cfg.gateway.pin_accept.severity();
    let mut held = 0usize;
    for (server, tools) in collect_tools(&cfg).await? {
        let current: BTreeMap<String, String> = tools
            .iter()
            .map(|(name, t)| (name.clone(), tool_hash(t)))
            .collect();
        let diff = store.diff(&server, &current);
        if diff.is_empty() {
            println!("{server}: ok · {} tool(s) match pins", current.len());
            continue;
        }
        for d in &diff {
            let (mark, lines) = match d.kind {
                DiffKind::Added => ("+ added   (new, unpinned)".to_string(), Vec::new()),
                DiffKind::Removed => ("- removed (was pinned)".to_string(), Vec::new()),
                DiffKind::Changed => match tools.get(&d.tool).map(|t| store.judge(&server, t)) {
                    Some(Judgement::Drift(Some(grading))) if grading.severity <= accept => (
                        format!(
                            "~ changed, {}: within [gateway] pin_accept, the gateway pins it again",
                            grading.severity
                        ),
                        grading.lines(20),
                    ),
                    Some(Judgement::Drift(Some(grading))) => {
                        held += 1;
                        (
                            format!("~ CHANGED, {} (held: possible rug-pull)", grading.severity),
                            grading.lines(20),
                        )
                    }
                    _ => {
                        held += 1;
                        (
                            "~ CHANGED, ungraded (held: possible rug-pull)".to_string(),
                            vec!["its pin holds the hash alone: `mcpdef pin` keeps the definition, so the next change is graded".to_string()],
                        )
                    }
                },
            };
            println!("{server}: {mark}  {}", d.tool);
            for line in lines {
                println!("    {line}");
            }
        }
    }
    if held > 0 {
        anyhow::bail!(
            "{held} pinned tool definition(s) changed in a way the gateway holds (possible rug-pull); \
             review above, then `mcpdef pin` to re-approve"
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
/// The user's home directory, if there is one.
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// `mcpdef import`: the config that fronts what the clients run, printed or
/// written.
fn cmd_import(
    from: &[String],
    out: Option<&Path>,
    force: bool,
    listen: &str,
    projects: import::Projects,
) -> Result<()> {
    let clients = from
        .iter()
        .map(|c| c.parse::<Client>())
        .collect::<Result<Vec<_>>>()?;
    let found = import::discover(
        home().as_deref(),
        &std::env::current_dir()?,
        &clients,
        listen,
        projects,
    );
    tell_found(&found);
    if found.found.is_empty() {
        anyhow::bail!("no MCP server to front was found in any client's config");
    }
    let text = import::render(&found, listen);
    match out {
        None => print!("{text}"),
        Some(path) => {
            write_imported(path, &text, force)?;
            eprintln!("mcpdef: wrote {}", path.display());
        }
    }
    Ok(())
}

/// `mcpdef up` with no `--config`: `mcpdef.toml` here, and when there is none,
/// one written first from what the clients run. A server only this directory's
/// own files name is not started unless a client was told to run it here.
fn up_config() -> Result<PathBuf> {
    let path = PathBuf::from("mcpdef.toml");
    if path.exists() {
        return Ok(path);
    }
    let listen = mcpdef::config::DEFAULT_LISTEN;
    let found = import::discover(
        home().as_deref(),
        &std::env::current_dir()?,
        &[],
        listen,
        import::Projects::Approved,
    );
    if found.found.is_empty() {
        tell_found(&found);
        anyhow::bail!(
            "there is no mcpdef.toml here, and no MCP server in any client's config to front: \
             write one (mcpdef.example.toml is a start), or give --config"
        );
    }
    eprintln!(
        "mcpdef: there is no mcpdef.toml here, so one is written from what your clients run:"
    );
    tell_found(&found);
    write_imported(&path, &import::render(&found, listen), false)?;
    eprintln!(
        "mcpdef: wrote mcpdef.toml. Point a client at the gateway with \
         `mcpdef connect <client> --write --replace`: it also takes the servers the gateway \
         fronts out of the file it writes, so that the client does not see their tools twice, \
         and names any it still has in another file"
    );
    Ok(path)
}

/// What a search of the clients' files found, on stderr. What a client's file
/// holds is written with its control characters escaped: none reaches the
/// terminal as one.
fn tell_found(found: &import::Discovered) {
    use import::one_line;
    for f in &found.found {
        let what = match &f.server {
            import::Server::Stdio { command, .. } => command.join(" "),
            import::Server::Http { url, .. } => url.clone(),
        };
        let from: Vec<_> = f.sources.iter().map(|s| s.client.title()).collect();
        eprintln!(
            "  {}: {} (from {})",
            one_line(&f.name),
            one_line(&what),
            from.join(", ")
        );
    }
    for s in &found.skipped {
        eprintln!(
            "  not fronted: {}, from {}: {}",
            one_line(&s.name),
            one_line(&s.source.describe()),
            one_line(&s.why)
        );
    }
    for u in &found.unread {
        eprintln!("  could not read {}: {}", u.source.shown, one_line(&u.why));
    }
}

/// Write a config `mcpdef import` made: never over a file unless `force`, and
/// readable by its owner alone, a file it replaces included. A value a client
/// wrote in can be anywhere in it, in a server's arguments or its URL as well.
fn write_imported(path: &Path, text: &str, force: bool) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| match force {
        true => format!("writing {}", path.display()),
        false => format!(
            "writing {} (give --force to replace a file that is there)",
            path.display()
        ),
    })?;
    // A mode given at opening applies to a file it creates, not one it replaces.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

fn cmd_connect(
    client: &str,
    config: &Path,
    url: Option<String>,
    ask: Ask,
    write: bool,
    file: Option<PathBuf>,
    replace: bool,
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
    // The servers the gateway fronts now, read from the file as import reads it.
    let fronted: Vec<String> = match replace {
        false => Vec::new(),
        true => {
            let root = match entry.format {
                clients::Format::Json { root } => root,
                clients::Format::Toml => "mcp_servers",
            };
            import::servers_in(client, &file, root, &cfg.gateway.listen)?
                .into_iter()
                .filter(|(name, server)| *name != entry.name && import::fronts(&cfg, server))
                .map(|(name, _)| name)
                .collect()
        }
    };
    match clients::write_replacing(&entry, &file, &fronted)? {
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
    if replace {
        match fronted.as_slice() {
            [] => println!(
                "nothing else in {} is a server the gateway fronts",
                file.display()
            ),
            names => println!(
                "took {} out of {}: the client reaches {} through the gateway now",
                names.join(", "),
                file.display(),
                if names.len() == 1 { "it" } else { "them" }
            ),
        }
        // The client reads other files too, which `--replace` leaves alone.
        let cwd = std::env::current_dir()?;
        for (name, shown) in import::fronted_elsewhere(client, home.as_deref(), &cwd, &file, &cfg) {
            println!(
                "{} is in {shown} too, which this does not change: take it out there as well, \
                 or the client sees its tools twice",
                import::one_line(&name)
            );
        }
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
            for line in records.iter().filter_map(|rec| rec.export(fmt)) {
                println!("{line}");
            }
            Ok(())
        }
    }
}

/// `mcpdef receipts`.
fn cmd_receipts(cmd: ReceiptsCmd) -> Result<()> {
    match cmd {
        ReceiptsCmd::Key { out } => {
            let jwk = SigningKey::generate()?;
            let key = SigningKey::from_jwk(&jwk)?;
            write_key(&out, &jwk)?;
            eprintln!(
                "wrote {path}: the key receipts are signed with, named {kid}. Keep it to yourself: \
                 whoever holds it can sign receipts. Publish its public half, `mcpdef receipts \
                 jwks --key {path}`, where whoever checks them can fetch it",
                path = out.display(),
                kid = key.kid(),
            );
            Ok(())
        }
        ReceiptsCmd::Jwks { key } => {
            let key = receipt_key(&key)?;
            println!("{}", serde_json::to_string_pretty(&key.jwks())?);
            Ok(())
        }
        ReceiptsCmd::Export {
            key,
            path,
            config,
            head,
            count,
            out,
            force,
        } => {
            let key = receipt_key(&key)?;
            let ledger = resolve_audit_path(path, &config)?;
            let seal = head.as_deref().zip(count);
            let done = match &out {
                Some(file) => export_to(file, force, |w| receipt::export(&ledger, &key, seal, w)),
                None => spool_to_stdout(|w| receipt::export(&ledger, &key, seal, w)),
            }
            .with_context(|| format!("signing {}: no receipt was written", ledger.display()))?;
            eprintln!(
                "signed {} receipt(s), for the tool calls among {} record(s) · ledger head={}",
                done.receipts, done.records, done.head
            );
            if let Some(last) = &done.last {
                eprintln!(
                    "record the last receipt's hash and the count somewhere else, so that a later \
                     check finds any taken off the end: `mcpdef receipts verify <receipts> --jwks \
                     <keys> --last {last} --count {}`",
                    done.receipts
                );
            }
            Ok(())
        }
        ReceiptsCmd::Verify {
            receipts,
            jwks,
            last,
            count,
        } => {
            let text = std::fs::read_to_string(&jwks)
                .with_context(|| format!("reading {}", jwks.display()))?;
            let keys = Keys::from_jwks(&text)
                .with_context(|| format!("reading the keys in {}", jwks.display()))?;
            let file = std::fs::File::open(&receipts)
                .with_context(|| format!("reading {}", receipts.display()))?;
            let checked = receipt::verify(std::io::BufReader::new(file), &keys)
                .with_context(|| format!("reading {}", receipts.display()))?;
            if let Some((line, why)) = &checked.broken {
                eprintln!(
                    "receipts BROKEN at line {line}: {why} · {} receipt(s) before it verified",
                    checked.receipts
                );
                anyhow::bail!("{} failed verification", receipts.display());
            }
            let ends = checked.last.as_deref().unwrap_or("(none)");
            if let (Some(last), Some(count)) = (&last, count) {
                if !checked.matches(last, count) {
                    eprintln!(
                        "receipts do NOT match the seal: {} receipt(s) ending at {ends}, and the \
                         seal says {count} ending at {last}",
                        checked.receipts
                    );
                    anyhow::bail!("{} failed verification", receipts.display());
                }
            }
            println!(
                "receipts OK · {} receipt(s) · {} chain(s) · last={ends}",
                checked.receipts, checked.chains
            );
            if checked.starts_mid_chain {
                eprintln!(
                    "the first receipt links to one before it that is not in {}: these start in \
                     the middle of a chain, or its first receipts were taken off",
                    receipts.display()
                );
            }
            if last.is_none() {
                eprintln!(
                    "this finds a receipt changed, taken out or moved, not one taken off the end: \
                     give --last and --count from a seal recorded somewhere else to check that too"
                );
            }
            Ok(())
        }
    }
}

/// The receipt key a private JWK file holds. A file others can read is
/// named: whoever reads it can sign receipts.
fn receipt_key(path: &Path) -> Result<SigningKey> {
    signing_key(path, "receipts", "a receipt key")
}

/// The key a private JWK file holds, that signs `signs`. A file others can
/// read is named: whoever reads it can sign them.
fn signing_key(path: &Path, signs: &str, is: &str) -> Result<SigningKey> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
            eprintln!(
                "mcpdef: warning: others than its owner can read {}, and whoever reads it can sign \
                 {signs} (chmod 600 it)",
                path.display()
            );
        }
    }
    SigningKey::from_jwk(&text).with_context(|| format!("{} is not {is}", path.display()))
}

/// `mcpdef bundle`.
fn cmd_bundle(cmd: BundleCmd) -> Result<()> {
    match cmd {
        BundleCmd::Key { out } => {
            let jwk = SigningKey::generate_named(bundle::KID_PREFIX)?;
            let key = SigningKey::from_jwk(&jwk)?;
            write_key(&out, &jwk)?;
            eprintln!(
                "wrote {path}: the key bundles are signed with, named {kid}. Keep it off the \
                 nodes: whoever holds it can sign their policy. Give each node its public half, \
                 `mcpdef bundle jwks --key {path}`, to trust",
                path = out.display(),
                kid = key.kid(),
            );
            Ok(())
        }
        BundleCmd::Jwks { key } => {
            let key = signing_key(&key, "bundles", "a bundle key")?;
            println!("{}", serde_json::to_string_pretty(&key.jwks())?);
            Ok(())
        }
        BundleCmd::Sign {
            config,
            key,
            revision,
            out,
            force,
        } => {
            let text = std::fs::read_to_string(&config)
                .with_context(|| format!("reading {}", config.display()))?;
            let cfg = Config::parse(&text)
                .with_context(|| format!("parsing TOML {}", config.display()))?;
            let checked = cfg.check(false);
            if !checked.errors.is_empty() {
                for e in &checked.errors {
                    eprintln!("  ✗ {e}");
                }
                anyhow::bail!(
                    "{} validation error(s) in {}: a node would refuse it, so it is not signed",
                    checked.errors.len(),
                    config.display()
                );
            }
            let key = signing_key(&key, "bundles", "a bundle key")?;
            let signed = bundle::sign(&text, revision, &bundle::now(), &key)?;
            write_new(&out, force, &signed)?;
            println!(
                "signed {} as revision {revision}, with {}: {} · config {}",
                config.display(),
                key.kid(),
                out.display(),
                bundle::sha256(text.as_bytes()),
            );
            Ok(())
        }
        BundleCmd::Verify {
            bundle: path,
            trust,
            config_out,
        } => {
            let keys = trusted(&trust)?;
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let opened = bundle::open(&text, &keys)
                .with_context(|| format!("{} failed verification", path.display()))?;
            if let Some(out) = &config_out {
                write_new(out, false, &opened.config)?;
            }
            println!(
                "bundle OK · revision {} · signed by {} · issued {} · config {}",
                opened.revision,
                opened.kid,
                opened.issued_at,
                opened.config_digest()
            );
            Ok(())
        }
        BundleCmd::Apply {
            bundle: path,
            trust,
            config,
        } => {
            let keys = trusted(&trust)?;
            match bundle::apply(&path, &keys, &config)? {
                bundle::Applied::Applied { bundle, from } => {
                    let over = match from {
                        Some(from) if from == bundle.revision => {
                            "again: what was in place was not this bundle's".to_string()
                        }
                        Some(from) => format!("over revision {from}"),
                        None => "the first this node applied".to_string(),
                    };
                    println!(
                        "applied revision {} ({over}), signed by {}, to {} · config {} · a \
                         running gateway takes it at its next reload: `kill -HUP <pid>`, or \
                         `[gateway] watch_config = true`",
                        bundle.revision,
                        bundle.kid,
                        config.display(),
                        bundle.config_digest()
                    );
                }
                bundle::Applied::Already(bundle) => println!(
                    "revision {} is the one this node applied last: {} is as it was",
                    bundle.revision,
                    config.display()
                ),
            }
            Ok(())
        }
    }
}

/// The keys a JWK Set file holds, to check a bundle with.
fn trusted(path: &Path) -> Result<Keys> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Keys::from_jwks(&text).with_context(|| format!("reading the keys in {}", path.display()))
}

/// Write `text` to `path` at once, and over a file that is there only with
/// `force`.
fn write_new(path: &Path, force: bool, text: &str) -> Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut builder = tempfile::Builder::new();
    builder.prefix(".mcpdef-bundle-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o644));
    }
    let mut partial = builder
        .tempfile_in(dir)
        .with_context(|| format!("writing beside {}", path.display()))?;
    partial
        .write_all(text.as_bytes())
        .and_then(|()| partial.as_file().sync_all())
        .with_context(|| format!("writing beside {}", path.display()))?;
    let placed = match force {
        true => partial.persist(path),
        false => partial.persist_noclobber(path),
    };
    placed.map_err(|e| e.error).with_context(|| match force {
        true => format!("writing {}", path.display()),
        false => format!(
            "writing {} (give --force to replace a file that is there)",
            path.display()
        ),
    })?;
    Ok(())
}

/// Write a new receipt key, readable by its owner alone, and never over a
/// file that is there: that may be the key earlier receipts were signed with.
fn write_key(path: &Path, text: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "writing {} (a file that is there is never replaced: give --out another name)",
            path.display()
        )
    })?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// What an export writes into: a file of its own, through a buffer.
type Spool<'f> = std::io::BufWriter<&'f mut std::fs::File>;

/// Run `write` into a new file beside `path`, under a name no one can guess,
/// and move it into place only once `write` succeeds: no one reads half an
/// export, nor one of a ledger that then failed. A file at `path` is replaced
/// only with `force`, and not one that appears meanwhile.
fn export_to<T>(
    path: &Path,
    force: bool,
    write: impl FnOnce(&mut Spool<'_>) -> Result<T, receipt::ExportError>,
) -> Result<T> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut builder = tempfile::Builder::new();
    builder.prefix(".mcpdef-receipts-");
    // As `File::create` makes it: receipts are there to be passed on.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o666));
    }
    let mut partial = builder
        .tempfile_in(dir)
        .with_context(|| format!("writing beside {}", path.display()))?;
    let done = {
        let mut out = std::io::BufWriter::new(partial.as_file_mut());
        let done = write(&mut out)?;
        out.flush()?;
        done
    };
    partial.as_file().sync_all()?;
    let placed = match force {
        true => partial.persist(path),
        false => partial.persist_noclobber(path),
    };
    placed.map_err(|e| e.error).with_context(|| match force {
        true => format!("writing {}", path.display()),
        false => format!(
            "writing {} (give --force to replace a file that is there)",
            path.display()
        ),
    })?;
    Ok(done)
}

/// Run `write` into a file of its own, and copy it to standard output only
/// once `write` succeeds: the receipts of a ledger that then fails reach no
/// one.
fn spool_to_stdout<T>(
    write: impl FnOnce(&mut Spool<'_>) -> Result<T, receipt::ExportError>,
) -> Result<T> {
    use std::io::Seek as _;
    let mut spool = tempfile::tempfile().context("making a file to hold the receipts")?;
    let done = {
        let mut out = std::io::BufWriter::new(&mut spool);
        let done = write(&mut out)?;
        out.flush()?;
        done
    };
    spool.rewind()?;
    std::io::copy(&mut spool, &mut std::io::stdout().lock())?;
    Ok(done)
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
/// starts from. With `lock`, as [`load_held`] reads it.
fn load_for_reload(
    path: &Path,
    profile_override: Option<String>,
    lock: Option<&Keys>,
) -> Result<(Config, Snapshot, Option<bundle::Bundle>)> {
    let (cfg, text, held) = load_held(path, lock)?;
    // Taken before the gateway reads the files the config names.
    let snapshot = Snapshot::take(text.as_bytes(), &cfg);
    Ok((validated(path, cfg, profile_override)?, snapshot, held))
}

/// The config at `path`, and its text. With `lock`, the keys `--bundle-trust`
/// names, only a config the signed bundle beside it holds: that bundle is
/// returned too, for the node's floor to be raised to once the config runs
/// ([`raise_floor`]).
fn load_held(path: &Path, lock: Option<&Keys>) -> Result<(Config, String, Option<bundle::Bundle>)> {
    match lock {
        None => {
            let (cfg, text) = Config::load_text(path)?;
            Ok((cfg, text, None))
        }
        Some(keys) => {
            let admitted = bundle::admit(path, keys)?;
            Ok((admitted.config, admitted.text, Some(admitted.bundle)))
        }
    }
}

/// Raise the node's floor to `held`, the bundle `cfg` came from, where it is
/// lower. Call it once nothing is left that can stop the start: a start that
/// failed leaves the floor where it was, as a reload refused does.
fn raise_floor(path: &Path, cfg: &Config, held: &bundle::Bundle) -> Result<()> {
    let state_dir = Path::new(&cfg.gateway.state_dir);
    if bundle::holding(path, || bundle::raise(state_dir, held))? {
        eprintln!(
            "mcpdef: the bundle floor is now revision {}, in {}",
            held.revision,
            state_dir.join(bundle::FLOOR_FILE).display()
        );
    }
    Ok(())
}

/// ` · bundle r<revision>`, for a ready line, under `--bundle-trust`.
fn bundle_note(held: Option<&bundle::Bundle>) -> String {
    held.map(|held| format!(" · bundle r{}", held.revision))
        .unwrap_or_default()
}

/// The keys `--bundle-trust` names, for the config at `config`. Kept in the
/// config's directory, they can be replaced by whoever can replace the
/// config: said, not refused.
fn bundle_keys(path: &Path, config: &Path) -> Result<Keys> {
    let keys = trusted(path).context("--bundle-trust")?;
    let dir = |file: &Path| match file.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.canonicalize().ok(),
        _ => Path::new(".").canonicalize().ok(),
    };
    if dir(path).is_some_and(|d| Some(d) == dir(config)) {
        eprintln!(
            "mcpdef: warning — the keys --bundle-trust names, {}, are in the config's directory: \
             whoever can replace the config there can replace them too. Keep them where only \
             the service's own setup writes",
            path.display()
        );
    }
    Ok(keys)
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

/// `mcpdef hook`: one decision, for the hook `client` runs. The event comes on
/// standard input. A call MCPdef allows, or that is not its to judge, gets
/// no answer and exit status 0, and the client goes on as it would. A refusal
/// exits with status 2, which blocks the call whatever else the client reads,
/// with why on standard error and the client's answer on standard output.
///
/// Fail closed: an MCP tool call MCPdef cannot judge, its config unread say,
/// is refused, and so is anything at all when the event, or the hook's own
/// command line, does not read, or the hook panics. Any exit status other
/// than 0 and 2 a client takes as the hook failing, and goes on with the call.
/// With `bundle_trust`, a config the signed bundle beside it does not hold is
/// one MCPdef cannot judge by: the call is refused, by the bundle's rule.
fn cmd_hook(path: &Path, client: &str, bundle_trust: Option<&Path>) -> Result<()> {
    use std::io::{Read as _, Write as _};
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        report(panic);
        std::process::exit(2);
    }));
    let Some(client) = mcpdef::hook::Client::parse(client) else {
        refuse(&format!(
            "MCPdef refused the call: its hook names an unknown --client {client:?}: {}",
            mcpdef::hook::Client::NAMES
        ));
    };
    let mut text = String::new();
    let event = std::io::stdin()
        .read_to_string(&mut text)
        .map_err(anyhow::Error::from)
        .and_then(|_| client.event(&text));
    let event = match event {
        Ok(event) => event,
        Err(e) => refuse(&format!(
            "MCPdef refused the call: its hook could not read it: {e:#}"
        )),
    };
    let Some(call) = event.call() else {
        return Ok(());
    };
    let verdict = match hook_config(path, bundle_trust) {
        Ok(cfg) => {
            let (verdict, recorded) = mcpdef::hook::decide(&cfg, client.name(), &call);
            if let Some(Err(e)) = recorded {
                eprintln!("mcpdef: the decision is not recorded: {e:#}");
            }
            verdict
        }
        // Not recorded: a ledger is a config's, and there is no config the
        // hook may judge by.
        Err(e) => match e.downcast_ref::<bundle::Refused>() {
            Some(refused) => mcpdef::hook::Verdict::Denied {
                rule: refused.rule().into(),
                reason: format!(
                    "--bundle-trust judges a call only by a config the signed bundle beside it \
                     holds: {refused}"
                ),
            },
            None => mcpdef::hook::Verdict::Denied {
                rule: "config".into(),
                reason: format!("{e:#}"),
            },
        },
    };
    let (Some(answer), Some(refusal)) = (client.answer(&event, &verdict), verdict.refusal()) else {
        return Ok(());
    };
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{answer}").and_then(|()| out.flush());
    refuse(&refusal)
}

/// End a hook with a refusal: `why` on standard error, as a client tells its
/// agent, and exit status 2, which blocks the call.
fn refuse(why: &str) -> ! {
    eprintln!("{why}");
    std::process::exit(2)
}

/// The config at `path`, checked as `mcpdef run` checks it, and its relative
/// paths, the ledger's among them, read from its directory, as a gateway
/// started there reads them: a hook runs in whatever directory its client
/// does, and writes to the ledger the gateway would. With `bundle_trust`,
/// only a config the signed bundle beside it holds, as `run` holds one: each
/// call's hook reads the config afresh, as a gateway does as it starts, and
/// raises the floor to that bundle where it is lower.
fn hook_config(path: &Path, bundle_trust: Option<&Path>) -> Result<Config> {
    // Named from where the hook runs, as the config is.
    let keys = bundle_trust
        .map(|keys| trusted(keys).context("its --bundle-trust keys do not read"))
        .transpose()?;
    let (path, cfg, held) = hook_read(path, keys.as_ref())
        .with_context(|| format!("its config {} does not read", path.display()))?;
    if let Some(held) = held {
        let state_dir = Path::new(&cfg.gateway.state_dir);
        bundle::holding(&path, || bundle::raise(state_dir, &held)).with_context(|| {
            format!(
                "the bundle floor is not raised to revision {}",
                held.revision
            )
        })?;
    }
    Ok(cfg)
}

/// [`hook_config`]'s config, by its absolute path, read from its directory,
/// and with `keys`, the bundle beside it that holds it.
fn hook_read(
    path: &Path,
    keys: Option<&Keys>,
) -> Result<(PathBuf, Config, Option<bundle::Bundle>)> {
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("finding the config {}", path.display()))?;
    if let Some(dir) = path.parent() {
        std::env::set_current_dir(dir)
            .with_context(|| format!("entering the config's directory {}", dir.display()))?;
    }
    let (cfg, _, held) = load_held(&path, keys)?;
    let errors = cfg.check(false).errors;
    if !errors.is_empty() {
        anyhow::bail!("{}", errors.join("; "));
    }
    Ok((path, cfg, held))
}

/// `mcpdef hook install`: the hook `client` needs to ask MCPdef before each
/// MCP tool call, printed, or merged into its settings with `--write`. With
/// `bundle_trust`, a hook that judges only by a config the signed bundle
/// beside it holds, as the bundle must now: a hook that would refuse every
/// MCP call is not one to install.
fn cmd_hook_install(
    path: &Path,
    client: &str,
    timeout: u32,
    write: bool,
    file: Option<&Path>,
    bundle_trust: Option<&Path>,
) -> Result<()> {
    let Some(client) = mcpdef::hook::Client::parse(client) else {
        anyhow::bail!(
            "unknown --client {client:?}: {}",
            mcpdef::hook::Client::NAMES
        );
    };
    let config = std::fs::canonicalize(path)
        .with_context(|| format!("finding the config {}", path.display()))?;
    let (cfg, lock) = match bundle_trust {
        None => (load_validated(&config, None)?, None),
        Some(keys) => {
            let (keys, held, cfg) = hook_lock(keys, &config)?;
            (validated(&config, cfg, None)?, Some((keys, held)))
        }
    };
    let program = std::env::current_exe().context("finding this mcpdef")?;
    let hook = client
        .hook(
            &program,
            &config,
            timeout,
            lock.as_ref().map(|(keys, _)| keys.as_path()),
        )
        .map_err(|why| anyhow::anyhow!("no {} hook: {why}", client.title()))?;
    if !write {
        let held = lock.as_ref().map_or_else(String::new, |(_, held)| {
            format!(
                ", held to the signed bundle beside it, revision {}",
                held.revision
            )
        });
        println!("{}", serde_json::to_string_pretty(&hook)?);
        eprintln!(
            "the hook {} needs to ask MCPdef before each MCP tool call, for the {} server(s) in \
             {}{held}. `--write` merges it into {}",
            client.title(),
            cfg.servers.len(),
            config.display(),
            file.map_or_else(
                || client.settings().display().to_string(),
                |f| f.display().to_string()
            ),
        );
        return Ok(());
    }
    let target = file.map_or_else(|| client.settings(), Path::to_path_buf);
    match mcpdef::hook::install(&hook, &target)? {
        clients::Wrote::Unchanged => eprintln!("{} already asks MCPdef", target.display()),
        clients::Wrote::Created => eprintln!("wrote {}", target.display()),
        clients::Wrote::Updated { backup } => eprintln!(
            "updated {}, the old one kept as {}",
            target.display(),
            backup.display()
        ),
    }
    // The hook reads the config's relative paths from its directory.
    let audit = Path::new(&cfg.gateway.audit);
    let audit = audit.strip_prefix(".").unwrap_or(audit);
    let ledger = config
        .parent()
        .map_or_else(|| audit.to_path_buf(), |dir| dir.join(audit));
    eprintln!(
        "{} now asks MCPdef before each MCP tool call: a server not in {} is refused. Its \
         decisions go to {}",
        client.title(),
        config.display(),
        ledger.display()
    );
    if let Some((_, held)) = &lock {
        eprintln!(
            "It judges by that config only while the signed bundle beside it holds it, revision \
             {} now: a config changed by hand refuses every MCP call, until a bundle is applied. \
             Whoever can edit {} can still take the hook out",
            held.revision,
            target.display()
        );
    }
    if client == mcpdef::hook::Client::Codex {
        // Without this, the hook looks installed and refuses nothing.
        eprintln!(
            "Codex runs a new or changed hook only once you trust it: open /hooks in Codex and \
             trust this one. A project's .codex/hooks.json runs only in a trusted project. A \
             hook that fails or times out does not stop the call in Codex"
        );
    }
    Ok(())
}

/// What a hook of the config at `config`, held to its bundle, is installed
/// with: the keys `--bundle-trust` names, by their absolute path, as it names
/// the config, since it runs wherever its client does; the bundle beside the
/// config, which must hold it now at a revision no lower than the floor, as
/// the hook checks at each call; and the config that bundle holds.
fn hook_lock(keys: &Path, config: &Path) -> Result<(PathBuf, bundle::Bundle, Config)> {
    let keys = std::fs::canonicalize(keys)
        .with_context(|| format!("finding the --bundle-trust keys {}", keys.display()))?;
    let trusted = bundle_keys(&keys, config)?;
    let refuses = |refused: bundle::Refused| {
        anyhow::Error::new(refused).context(
            "the hook would refuse every MCP call: --bundle-trust judges a call only by a \
             config the signed bundle beside it holds",
        )
    };
    let held = bundle::holding(config, || {
        std::fs::read(config)
            .with_context(|| format!("reading config {}", config.display()))
            .map(|text| bundle::held(config, &text, &trusted).verdict)
    })?
    .map_err(refuses)?;
    let cfg = Config::parse(&held.config)
        .with_context(|| format!("parsing TOML {}", config.display()))?;
    // The floor, from the config's directory, as the hook reads it.
    let state_dir = Path::new(&cfg.gateway.state_dir);
    let state_dir = config.parent().map_or_else(
        || state_dir.to_path_buf(),
        |dir| dir.join(state_dir.strip_prefix(".").unwrap_or(state_dir)),
    );
    let floor = bundle::highest_floor(&[state_dir])?;
    bundle::admits(floor.as_ref(), &held).map_err(refuses)?;
    Ok((keys, held, cfg))
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

async fn cmd_run(
    path: &Path,
    profile_override: Option<String>,
    http: bool,
    bundle_trust: Option<&Path>,
) -> Result<()> {
    let keys = bundle_trust
        .map(|keys| bundle_keys(keys, path))
        .transpose()?;
    let (cfg, snapshot, held) = load_for_reload(path, profile_override.clone(), keys.as_ref())?;
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
    // The spans of the records appended from here on, sent where
    // `[gateway.otel]` says.
    let otel_note = match &cfg.gateway.otel {
        Some(otel) => {
            let exporter = mcpdef::otel::Exporter::new(
                otel,
                PathBuf::from(&cfg.gateway.audit),
                Arc::clone(&fetching),
            );
            let note = format!(" · spans to {}", exporter.shown());
            let (written, _) = gw.audit_written();
            exporter
                .start(written.checked_sub(1), gw.audit_appends())
                .with_context(|| format!("following the ledger {}", cfg.gateway.audit))?;
            note
        }
        None => String::new(),
    };
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

    // Nothing is left that can stop the start.
    if let Some(held) = &held {
        raise_floor(path, &cfg, held)?;
    }
    let strict_note = if cfg.gateway.strict { " · strict" } else { "" };
    let bundle_note = bundle_note(held.as_ref());
    let ready = format!(
        "mcpdef {} ready · {} upstream(s){} · audit {}{}{}{}{}{}{} · listening {}",
        env!("CARGO_PKG_VERSION"),
        gw.upstream_count(),
        down_note,
        cfg.gateway.audit,
        otel_note,
        profile_note,
        drift_note,
        auth_note,
        strict_note,
        bundle_note,
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
        let reloader = match (keys, held) {
            (Some(keys), Some(held)) => reloader.with_bundle_lock(keys, held),
            _ => reloader,
        };
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

/// `mcpdef filter`: answer the checks of a proxy that routes MCP requests
/// itself, on `[gateway.filter] listen`, judging each request by the config
/// and recording each decision in its ledger, as the gateway in the path
/// would. No upstream is opened: the proxy reaches them. With
/// `bundle_trust`, only a config the signed bundle beside it holds: the
/// filter reads its config once, as it starts, and that is where it is held.
async fn cmd_filter(path: &Path, bundle_trust: Option<&Path>) -> Result<()> {
    let keys = bundle_trust
        .map(|keys| bundle_keys(keys, path))
        .transpose()?;
    let (cfg, _, held) = load_held(path, keys.as_ref())?;
    let cfg = validated(path, cfg, None)?;
    let routes = mcpdef::filter::Routes::of(&cfg);
    if routes.is_empty() {
        anyhow::bail!(
            "no [[server]] in {} has a filter_path: filter mode judges a request by the server \
             its path names, so give each server the path the proxy routes to it",
            path.display()
        );
    }
    if cfg.gateway.auth.enabled && cfg.gateway.auth.takes(AuthMethod::Mtls) {
        anyhow::bail!(
            "[gateway.auth] takes client certificates, which filter mode never sees: the proxy \
             holds the client's connection. Take bearer tokens or client keys in filter mode"
        );
    }
    let gw = mcpdef::connect::build_filter(&cfg)?;
    // How the gateway's own fetches go out, a JWKS's among them.
    let fetching = Arc::new(ArcSwap::from_pointee(Fetching::of(&cfg)));
    let otel_note = match &cfg.gateway.otel {
        Some(otel) => {
            let exporter = mcpdef::otel::Exporter::new(
                otel,
                PathBuf::from(&cfg.gateway.audit),
                Arc::clone(&fetching),
            );
            let note = format!(" · spans to {}", exporter.shown());
            let (written, _) = gw.audit_written();
            exporter
                .start(written.checked_sub(1), gw.audit_appends())
                .with_context(|| format!("following the ledger {}", cfg.gateway.audit))?;
            note
        }
        None => String::new(),
    };
    let auth = build_verifier(&cfg, &fetching).await?;
    let auth_note = match &auth {
        Some(_) => format!(" · {}", auth_methods(&cfg.gateway.auth)),
        None => String::new(),
    };
    let listen = &cfg.gateway.filter.listen;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding the filter listener on {listen}"))?;
    let addr = listener.local_addr()?;
    // Nothing is left that can stop the start.
    if let Some(held) = &held {
        raise_floor(path, &cfg, held)?;
    }
    let bundle_note = bundle_note(held.as_ref());
    eprintln!(
        "mcpdef {} filter ready · {} server(s) routed · audit {}{otel_note}{auth_note}{bundle_note} · listening {addr}",
        env!("CARGO_PKG_VERSION"),
        routes.len(),
        cfg.gateway.audit,
    );
    let filter = mcpdef::filter::Filter::new(gw, &cfg, auth);
    mcpdef::filter::serve_filter_on(listener, filter)
        .await
        .context("serving the filter")
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
