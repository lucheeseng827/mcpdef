// SPDX-License-Identifier: Apache-2.0
//! `mcpdef bridge <url>`: a stdio MCP client on one side, a remote MCPdef —
//! or any Streamable-HTTP MCP endpoint — on the other.
//!
//! It is the gateway with one upstream, not a second program. The config it
//! runs is built here, parsed by the same [`Config::parse`] a file goes
//! through, checked by the same [`Config::validate`], and served by the same
//! [`serve_stdio`](crate::serve_stdio), so a bridge cannot drift from what
//! `mcpdef run` does with that config. `--print-config` shows it, and a user
//! who outgrows the bridge can save it as a file and carry on from there.
//!
//! Governance passes through: every tool, resource, resource template and
//! prompt the remote end offers is offered here, and the remote end decides.
//! That has to be written into the config, because MCPdef is deny-by-default
//! and an unset `resources` list exposes nothing. A bridge that opened
//! only `tools` would carry tools and silently drop every resource and prompt.
//!
//! It stands in for Node shims such as `mcp-remote`, whose CVE-2025-6514 ran
//! an OS command through an `authorization_endpoint` the server supplied.
//! Nothing the remote end sends chooses what the bridge runs: its upstream,
//! its CAs, its certificate and its token all come from the command line.

use crate::config::Config;
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

/// The `[[server]]` id the remote end has inside the bridge.
pub const REMOTE: &str = "remote";

/// What `mcpdef bridge` was asked for.
#[derive(Debug, Clone)]
pub struct Bridge {
    /// The remote end's MCP endpoint.
    pub url: String,
    /// CAs to trust for it, PEM, in place of the system's.
    pub ca: Vec<PathBuf>,
    /// A client certificate to present, with its chain, PEM.
    pub cert: Option<PathBuf>,
    /// That certificate's private key, PEM. The pair, or neither.
    pub key: Option<PathBuf>,
    /// A file holding the bearer token to send. Read when needed, never printed.
    pub token_file: Option<PathBuf>,
    /// The MCP revision the remote end speaks: `auto`, `2025-11-25` or `2026-07-28`.
    pub spec: String,
    /// Where the bridge's own ledger goes.
    pub audit: PathBuf,
    /// Where the bridge keeps its state.
    pub state_dir: PathBuf,
}

impl Bridge {
    /// The config this bridge runs, as TOML.
    ///
    /// Built as a table and serialized, never formatted as a string: a URL or
    /// a path holding a quote must not become config syntax.
    pub fn config_text(&self) -> Result<String> {
        if self.cert.is_some() != self.key.is_some() {
            bail!("a client certificate is presented with its key: give --cert and --key together");
        }

        let mut server = toml::Table::new();
        server.insert("id".into(), REMOTE.into());
        server.insert("transport".into(), "streamable-http".into());
        server.insert("url".into(), self.url.clone().into());
        server.insert("spec".into(), self.spec.clone().into());
        // Pass-through. Each of these is an allowlist, and unset means none.
        for list in ["tools", "resources", "resource_templates", "prompts"] {
            server.insert(list.into(), toml::Value::Array(vec!["*".into()]));
        }

        let mut tls = toml::Table::new();
        if !self.ca.is_empty() {
            let ca = self
                .ca
                .iter()
                .map(|p| path_value(p, "--ca"))
                .collect::<Result<Vec<_>>>()?;
            tls.insert("ca".into(), toml::Value::Array(ca));
        }
        if let (Some(cert), Some(key)) = (&self.cert, &self.key) {
            tls.insert("client_cert".into(), path_value(cert, "--cert")?);
            tls.insert("client_key".into(), file_ref(key, "--key")?);
        }
        if !tls.is_empty() {
            server.insert("tls".into(), tls.into());
        }

        if let Some(token) = &self.token_file {
            let mut auth = toml::Table::new();
            auth.insert("kind".into(), "bearer".into());
            auth.insert("token".into(), file_ref(token, "--token-file")?);
            server.insert("auth".into(), auth.into());
        }

        let mut gateway = toml::Table::new();
        gateway.insert("audit".into(), path_value(&self.audit, "--audit")?);
        gateway.insert(
            "state_dir".into(),
            path_value(&self.state_dir, "--state-dir")?,
        );

        let mut root = toml::Table::new();
        root.insert("gateway".into(), gateway.into());
        root.insert(
            "server".into(),
            toml::Value::Array(vec![toml::Value::Table(server)]),
        );
        toml::to_string(&root).context("writing the bridge's config")
    }

    /// The config this bridge runs, parsed and checked as a file's would be.
    pub fn config(&self) -> Result<Config> {
        let text = self.config_text()?;
        let cfg = Config::parse(&text)?;
        let problems = cfg.validate();
        if !problems.is_empty() {
            bail!("the bridge's config is not valid: {}", problems.join("; "));
        }
        Ok(cfg)
    }
}

/// Where a bridge keeps its ledger and state when not told: under the user's
/// home directory, never the working directory.
///
/// A client launches a bridge as a subprocess from wherever the client runs —
/// for a desktop app that is often `/` — so a path relative to the working
/// directory would be unwritable, or would leave a ledger somewhere nobody
/// chose. With no home to go to, the bridge says so and names the flags,
/// rather than picking a place.
pub fn default_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".mcpdef").join("bridge"))
        .ok_or_else(|| {
            anyhow!(
                "HOME is not set, so the bridge has no directory of its own for its ledger \
                 and state: give --audit and --state-dir"
            )
        })
}

/// A path as a TOML string. TOML strings are UTF-8, so a path that is not
/// cannot be written into the config at all, and is refused by the flag
/// that named it.
fn path_value(path: &Path, flag: &str) -> Result<toml::Value> {
    path.to_str()
        .map(|p| toml::Value::String(p.to_string()))
        .ok_or_else(|| anyhow!("{flag} {} is not UTF-8", path.display()))
}

/// `{ file = "<path>" }`: a secret read from a file when it is needed, into
/// memory that is wiped when dropped, and never printed.
fn file_ref(path: &Path, flag: &str) -> Result<toml::Value> {
    let mut table = toml::Table::new();
    table.insert("file".into(), path_value(path, flag)?);
    Ok(table.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge() -> Bridge {
        Bridge {
            url: "https://mcpdef.example.com/mcp".into(),
            ca: Vec::new(),
            cert: None,
            key: None,
            token_file: None,
            spec: "auto".into(),
            audit: PathBuf::from("/home/u/.mcpdef/bridge/audit.log"),
            state_dir: PathBuf::from("/home/u/.mcpdef/bridge/state"),
        }
    }

    /// The bridge's config is a gateway config, parsed and valid as one.
    #[test]
    fn a_bridge_config_parses_and_validates_as_a_gateway_config() {
        let cfg = bridge().config().unwrap();
        assert_eq!(cfg.servers.len(), 1);
        let s = &cfg.servers[0];
        assert_eq!(s.id, REMOTE);
        assert_eq!(s.transport, "streamable-http");
        assert_eq!(s.url.as_deref(), Some("https://mcpdef.example.com/mcp"));
    }

    /// Every allowlist is opened, not just `tools`. An unset `resources`
    /// exposes nothing, so a bridge that opened only `tools` would
    /// carry tools and silently drop every resource and prompt.
    #[test]
    fn governance_passes_through_every_allowlist() {
        let cfg = bridge().config().unwrap();
        let s = &cfg.servers[0];
        let all = Some(vec!["*".to_string()]);
        assert_eq!(s.tools, all, "tools");
        assert_eq!(s.resources, all, "resources");
        assert_eq!(s.resource_templates, all, "resource_templates");
        assert_eq!(s.prompts, all, "prompts");
    }

    /// The key and the token are file references: no secret is written into
    /// the config, so `--print-config` can never show one.
    #[test]
    fn the_key_and_the_token_are_file_references_never_values() {
        let mut b = bridge();
        b.ca = vec!["/etc/ca.pem".into()];
        b.cert = Some("/etc/agent.crt".into());
        b.key = Some("/etc/agent.key".into());
        b.token_file = Some("/run/secrets/token".into());
        // Read back by meaning, not by layout: the serializer may write a
        // file reference inline or as a table of its own.
        let text = b.config_text().unwrap();
        let root: toml::Table = toml::from_str(&text).unwrap();
        let server = &root["server"][0];
        assert_eq!(
            server["tls"]["client_key"]["file"].as_str(),
            Some("/etc/agent.key"),
            "{text}"
        );
        assert_eq!(
            server["auth"]["token"]["file"].as_str(),
            Some("/run/secrets/token"),
            "{text}"
        );
        assert_eq!(server["auth"]["kind"].as_str(), Some("bearer"), "{text}");
        assert_eq!(
            server["tls"]["client_cert"].as_str(),
            Some("/etc/agent.crt"),
            "{text}"
        );
        // Not `config()`: validation reads these files, and they are made up
        // here. `tests/bridge.rs` validates one with real files on disk.
    }

    /// A certificate without its key, or a key without its certificate, is
    /// refused rather than half-applied.
    #[test]
    fn a_certificate_and_its_key_go_together() {
        let mut b = bridge();
        b.cert = Some("/etc/agent.crt".into());
        assert!(b.config_text().is_err());
        let mut b = bridge();
        b.key = Some("/etc/agent.key".into());
        assert!(b.config_text().is_err());
    }

    /// A URL holding characters TOML treats as syntax stays a value.
    #[test]
    fn a_url_cannot_inject_config() {
        let mut b = bridge();
        b.url = "https://x.example/mcp\"\n[[server]]\nid = \"evil\"".into();
        let text = b.config_text().unwrap();
        let parsed: toml::Table = toml::from_str(&text).unwrap();
        let servers = parsed["server"].as_array().unwrap();
        assert_eq!(servers.len(), 1, "a URL must not add a server: {text}");
    }
}
